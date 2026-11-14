// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/spf13/pflag"
)

// the flags more than one command has, one command runs per process
var (
	selection    redirect.Filter
	packageNames []string
	scopeFilter  *filter.Filter
	libssl       string
	flowTable    bool
	blockQuic    bool
)

// the processes whose flows and secrets decerter reads: run, capture and keylog
func addProcessFlags(flags *pflag.FlagSet) {
	flags.Func("uid", "select the processes of the user with this `uid`, repeatable or comma separated (default is none; without --uid, --pid or --package nothing is selected)", parseUIDs)
	flags.Func("pid", "select the process with this `pid`, repeatable or comma separated, its children are not followed (default is none)", parsePIDs)
	flags.Func("package", "select the Android app with this package `name` by its uid from /data/system/packages.list, like --uid; an unknown name fails with the closest installed ones, repeatable or comma separated (default is none; Android only, on Linux select with --uid)", parsePackageNames)
}

// which flows of the selected processes are in scope: run and capture
func addScopeFlags(flags *pflag.FlagSet) {
	flags.Func("dst-cidr", "only flows to this destination `prefix`, IPv4 or IPv6, a bare address is a /32 or /128, repeatable or comma separated (default is every address)", parseDestinationCIDRs)
	flags.Func("dst-port", "only flows to this destination `port`: tcp/<port>, udp/<port> or <port> for both, repeatable or comma separated (default is every port; with --dst-cidr both have to match)", parseDestinationPorts)
	flags.Func("filter", "narrow the flows selected by the flags above with this `filter` in a subset of Wireshark's display filter language, see decerter help filter (default is none, every selected flow is in scope)", parseFilter)
}

// QUIC is never decrypted, the flag makes the selected apps fall back to TLS over TCP: run and capture
func addBlockQuicFlag(flags *pflag.FlagSet) {
	flags.BoolVar(&blockQuic, "block-quic", false, "make UDP connects and sends of the selected processes to port 443 fail with EPERM, whatever the destination filters, so QUIC (HTTP/3) falls back to TLS over TCP, which decerter can decrypt; QUIC itself is only relayed (default is false)")
}

func addLibsslFlag(flags *pflag.FlagSet) {
	flags.StringVar(&libssl, "libssl", "", "attach the secrets uprobe only to the OpenSSL 3 or 4, or BoringSSL, libssl.so at this `path`, OpenSSL's libcrypto with the same suffix (libcrypto.so.3 for libssl.so.3) has to be next to it (default is the libssl.so.3 and libssl.so.4 of the dynamic linker cache plus the libssl the selected processes map, also in a container, on Linux, Conscrypt's libssl on Android)")
}

func addFlowTableFlag(flags *pflag.FlagSet) {
	flags.BoolVar(&flowTable, "flow-table", false, "print the kernel's flow_map table every 5 seconds, for debugging (default is false)")
}

func parseUIDs(value string) (err error) {
	for part := range strings.SplitSeq(value, ",") {
		uid, parseErr := strconv.ParseUint(strings.TrimSpace(part), 10, 32)

		if err = parseErr; err != nil {
			err = fmt.Errorf("invalid uid %q: %w", part, err)
			return
		}

		selection.UIDs = append(selection.UIDs, uint32(uid))
	}

	return
}

// the names are resolved to uids when the command runs, on the device
func parsePackageNames(value string) (err error) {
	for part := range strings.SplitSeq(value, ",") {
		name := strings.TrimSpace(part)

		if (name == "") || strings.ContainsFunc(name, unicode.IsSpace) {
			err = fmt.Errorf("invalid package name %q", part)
			return
		}

		packageNames = append(packageNames, name)
	}

	return
}

// a pid of the command line is the thread group id the bpf programs see
func parsePIDs(value string) (err error) {
	for part := range strings.SplitSeq(value, ",") {
		pid, parseErr := strconv.ParseUint(strings.TrimSpace(part), 10, 32)

		if err = parseErr; err != nil {
			err = fmt.Errorf("invalid pid %q: %w", part, err)
			return
		}

		if pid == 0 {
			err = fmt.Errorf("invalid pid %q: must be positive", part)
			return
		}

		selection.Tgids = append(selection.Tgids, uint32(pid))
	}

	return
}

func parseDestinationCIDRs(value string) (err error) {
	for part := range strings.SplitSeq(value, ",") {
		cidr := strings.TrimSpace(part)

		// a bare address is the prefix of one host: /32 or /128
		if !strings.Contains(cidr, "/") {
			address, parseErr := netip.ParseAddr(cidr)

			if err = parseErr; err != nil {
				err = fmt.Errorf("invalid destination cidr %q: %w", part, err)
				return
			}

			// the destination of a connect has no zone to compare
			if address.Zone() != "" {
				err = fmt.Errorf("invalid destination cidr %q: zones are not supported", part)
				return
			}

			selection.DestinationCIDRs = append(selection.DestinationCIDRs, netip.PrefixFrom(address, address.BitLen()))
			continue
		}

		prefix, parseErr := netip.ParsePrefix(cidr)

		if err = parseErr; err != nil {
			err = fmt.Errorf("invalid destination cidr %q: %w", part, err)
			return
		}

		selection.DestinationCIDRs = append(selection.DestinationCIDRs, prefix.Masked())
	}

	return
}

func parseDestinationPorts(value string) (err error) {
	for part := range strings.SplitSeq(value, ",") {
		protocolName, portString, hasProtocol := strings.Cut(strings.TrimSpace(part), "/")
		ipProtocols := []uint8{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP}

		// a port without a protocol is both tcp and udp
		if hasProtocol {
			switch strings.ToLower(protocolName) {
			case "tcp":
				ipProtocols = []uint8{syscall.IPPROTO_TCP}
			case "udp":
				ipProtocols = []uint8{syscall.IPPROTO_UDP}
			default:
				err = fmt.Errorf("invalid destination port %q: protocol must be tcp or udp", part)
				return
			}
		} else {
			portString = protocolName
		}

		port, parseErr := strconv.ParseUint(portString, 10, 16)

		if err = parseErr; err != nil {
			err = fmt.Errorf("invalid destination port %q: %w", part, err)
			return
		}

		if port == 0 {
			err = fmt.Errorf("invalid destination port %q: must be between 1 and 65535", part)
			return
		}

		for _, ipProtocol := range ipProtocols {
			selection.DestinationPorts = append(selection.DestinationPorts, redirect.DestinationPort{
				Port:       uint16(port),
				IPProtocol: ipProtocol,
			})
		}
	}

	return
}

// the parse error says where in the filter it is, the filter and a marker under it show it like tshark does
func parseFilter(value string) (err error) {
	parsed, parseErr := filter.Parse(value)

	if err = parseErr; err != nil {
		if positionErr, ok := errors.AsType[*filter.PositionError](err); ok {
			err = fmt.Errorf("invalid filter: %w\n%s", err, positionErr.Marker())
			return
		}

		err = fmt.Errorf("invalid filter: %w", err)
		return
	}

	err = parsed.CheckFlowScope()

	if err != nil {
		err = fmt.Errorf("invalid filter: %w", err)
		return
	}

	scopeFilter = &parsed
	return
}
