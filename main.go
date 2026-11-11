// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/decerter/decerter/app"
	"github.com/decerter/decerter/internal/bpf/redirect"
)

var (
	filter         redirect.Filter
	proxyPort      uint16        = 15001
	udpIdleTimeout time.Duration = 30 * time.Second
	flowTable      bool
)

func main() {
	flag.Func("uid", "uid of an inspected user, repeatable or comma separated (default is none; a process is selected by -uid or -pid, without both nothing is redirected)", parseUIDs)
	flag.Func("pid", "pid of an inspected process, repeatable or comma separated (default is none; selects the process next to -uid, its children are not followed)", parsePIDs)
	flag.Func("dst-cidr", "only redirect flows of the selected processes to these destination prefixes, IPv4 or IPv6, a bare address is a /32 or /128, repeatable or comma separated (default is every address)", parseDestinationCIDRs)
	flag.Func("dst-port", "only redirect flows of the selected processes to these destination ports, tcp/<port> or udp/<port>, <port> alone is both, repeatable or comma separated (default is every port; with -dst-cidr both have to match)", parseDestinationPorts)
	flag.Func("port", "port of the tcp proxy listener and the udp proxy socket on lo (default is 15001)", parsePort)
	flag.Func("udp-idle-timeout", "a udp session ends after this long without a datagram in either direction (default is 30s)", parseIdleTimeout)
	flag.BoolVar(&flowTable, "flow-table", false, "print the flow_map table every 5 seconds, for debugging")
	flag.Parse()
	err := run()

	if err != nil {
		os.Exit(1)
	}
}

func parseUIDs(value string) (err error) {
	for part := range strings.SplitSeq(value, ",") {
		uid, parseErr := strconv.ParseUint(strings.TrimSpace(part), 10, 32)

		if err = parseErr; err != nil {
			err = fmt.Errorf("invalid uid %q: %w", part, err)
			return
		}

		filter.UIDs = append(filter.UIDs, uint32(uid))
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

		filter.Tgids = append(filter.Tgids, uint32(pid))
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

			filter.DestinationCIDRs = append(filter.DestinationCIDRs, netip.PrefixFrom(address, address.BitLen()))
			continue
		}

		prefix, parseErr := netip.ParsePrefix(cidr)

		if err = parseErr; err != nil {
			err = fmt.Errorf("invalid destination cidr %q: %w", part, err)
			return
		}

		filter.DestinationCIDRs = append(filter.DestinationCIDRs, prefix.Masked())
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
			filter.DestinationPorts = append(filter.DestinationPorts, redirect.DestinationPort{
				Port:       uint16(port),
				IPProtocol: ipProtocol,
			})
		}
	}

	return
}

func parsePort(value string) (err error) {
	port, parseErr := strconv.ParseUint(value, 10, 16)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid port %q: %w", value, err)
		return
	}

	// the port is a load-time constant in the bpf programs, so it can't be picked by the kernel
	if port == 0 {
		err = fmt.Errorf("invalid port %q: must be between 1 and 65535", value)
		return
	}

	proxyPort = uint16(port)
	return
}

func parseIdleTimeout(value string) (err error) {
	timeout, parseErr := time.ParseDuration(value)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid udp idle timeout %q: %w", value, err)
		return
	}

	if timeout <= 0 {
		err = fmt.Errorf("invalid udp idle timeout %q: must be positive", value)
		return
	}

	udpIdleTimeout = timeout
	return
}

func run() (err error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	logger := slog.Default()
	decerter := app.New(ctx, filter, proxyPort, udpIdleTimeout, flowTable, logger)

	defer func() {
		err = errors.Join(err, decerter.Shutdown())
	}()

	err = decerter.LoadBpfObjects()

	if err != nil {
		return
	}

	err = decerter.UpdateBpfMaps()

	if err != nil {
		return
	}

	err = decerter.StartRouteSync()

	if err != nil {
		return
	}

	err = decerter.StartProxy()

	if err != nil {
		return
	}

	err = decerter.AttachRedirect()

	if err != nil {
		return
	}

	decerter.StartFlowTable()
	<-ctx.Done()
	logger.Info("Got shutdown signal", "cause", context.Cause(ctx))
	return
}
