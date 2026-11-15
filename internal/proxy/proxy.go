// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// the lookups in the bpf maps, the tests have no maps and set their own
var (
	flowByClient    = redirect.FlowByClient
	secretsByRandom = secrets.Lookup
)

// the process can be gone by the time the proxy accepts, the flow is still proxied then, comm comes from the bpf flow instead
func processCmdline(tgid uint32) (cmdline string, err error) {
	cmdline, err = filter.ReadCmdline(tgid)
	return
}

// what the scope filter knows of a flow when the proxy takes it: the flow of the kernel, the client endpoint (the local end of the app's socket) and /proc; the ClientHello comes later
// cmdline is empty when it could not be read, exe is only read when the filter asks for it or the flow goes into the API's history (isRecorded)
func scopeValues(flow redirect.Flow, cmdline string, client netip.AddrPort, scope *filter.Filter, isRecorded bool) (values filter.Values) {
	values = filter.Values{
		PID:         flow.Tgid,
		UID:         flow.UID,
		GID:         flow.GID,
		Comm:        flow.Comm,
		Cmdline:     cmdline,
		Exe:         "",
		IPProtocol:  flow.IPProtocol,
		Source:      client,
		Destination: flow.OriginalDestination,
		TLS:         filter.UnknownTLSState,
		TLSVersion:  0,
		ServerName:  "",
		Protocols:   nil,
		HTTP:        nil,
	}

	if isRecorded || ((scope != nil) && scope.Uses(filter.ExeField)) {
		exe, exeErr := filter.ReadExe(flow.Tgid)

		if exeErr == nil {
			values.Exe = exe
		}
	}

	return
}

// a nil scope is everything in scope; an undecided result can only come from a ClientHello field, the caller reads the ClientHello for it
func isInScope(scope *filter.Filter, values filter.Values) (result filter.Result) {
	if scope == nil {
		result = filter.TrueResult
		return
	}

	result = scope.Evaluate(values)
	return
}

// one line per finished flow, up and down are already formatted: bytes for TCP, datagrams/bytes for UDP
// the mark is only printed when the app's socket has one, as on Android
func printFlow(flow redirect.Flow, cmdline string, client netip.AddrPort, up string, down string, duration time.Duration) {
	mark := ""

	if flow.Mark != 0 {
		mark = fmt.Sprintf(" mark=%#x", flow.Mark)
	}

	fmt.Printf("%s pid=%d uid=%d comm=%s %s client=%s%s up=%s down=%s duration=%s cmdline=%q\n", redirect.ProtocolName(flow.IPProtocol), flow.Tgid, flow.UID, intercept.EscapeField(flow.Comm), flow.OriginalDestination, client, mark, up, down, duration.Round(time.Millisecond), cmdline)
}

// a redirected connection or datagram to the proxy port itself would make the proxy send to itself
func isLoop(destination netip.AddrPort, local netip.AddrPort) (loop bool) {
	loop = destination.Addr().IsLoopback() && (destination.Port() == local.Port())
	return
}

// the upstream socket gets the mark of the app's socket before it connects, so policy routing sends it over the app's network (on Android netd's fwmark selects Wi-Fi, cellular or a VPN)
// mark 0 is a socket without a mark, nothing is set then
func markControl(mark uint32) (control func(network string, address string, rawConnection syscall.RawConn) error) {
	if mark == 0 {
		return
	}

	control = func(network string, address string, rawConnection syscall.RawConn) (err error) {
		controlErr := rawConnection.Control(func(fileDescriptor uintptr) {
			err = unix.SetsockoptInt(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		})
		err = errors.Join(err, controlErr)

		if err != nil {
			err = fmt.Errorf("%w %#x: %w", ErrMark, mark, err)
		}

		return
	}
	return
}

// dial the original destination of the app's flow from a socket with the mark of the app's socket
// with captureBpfMaps the cookie of the socket goes into upstream_map with flowCookie, the cookie of the app's flow, before it connects, so the capture programs copy the packets on the wire from its first SYN on
// upstreamCookie is the cookie of the socket then, releaseUpstream needs it after the close; 0 when nothing is captured: no capture, or a cookie that could not be written, which only costs the capture of this flow
func dialUpstream(ctx context.Context, network string, flow redirect.Flow, flowCookie uint64, timeout time.Duration, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, logger *slog.Logger) (connection net.Conn, upstreamCookie uint64, err error) {
	mark := markControl(flow.Mark)
	dialer := net.Dialer{
		Timeout: timeout,
		Control: func(network string, address string, rawConnection syscall.RawConn) (controlErr error) {
			if mark != nil {
				controlErr = mark(network, address, rawConnection)

				if controlErr != nil {
					return
				}
			}

			if captureBpfMaps == nil {
				return
			}

			// a dial that tries a second socket leaves the first one's entry released
			releaseUpstream(upstreamCookie, captureBpfMaps, logger)
			cookie, addErr := addUpstream(rawConnection, flowCookie, captureBpfMaps)
			upstreamCookie = cookie

			if addErr != nil {
				logger.Warn("Could not add upstream socket to the capture, its packets are not captured", "error", addErr)
			}

			return
		},
	}
	connection, err = dialer.DialContext(ctx, network, flow.OriginalDestination.String())

	if err != nil {
		releaseUpstream(upstreamCookie, captureBpfMaps, logger)
		upstreamCookie = 0
	}

	return
}

// SO_COOKIE is the socket cookie bpf_get_socket_cookie gives the capture programs for its packets
func addUpstream(rawConnection syscall.RawConn, flowCookie uint64, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map) (upstreamCookie uint64, err error) {
	var cookieErr error

	controlErr := rawConnection.Control(func(fileDescriptor uintptr) {
		upstreamCookie, cookieErr = unix.GetsockoptUint64(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_COOKIE)
	})
	err = errors.Join(cookieErr, controlErr)

	if err != nil {
		upstreamCookie = 0
		err = fmt.Errorf("%w: %w", ErrCookie, err)
		return
	}

	err = capturebpf.AddUpstream(upstreamCookie, flowCookie, captureBpfMaps)

	if err != nil {
		upstreamCookie = 0
	}

	return
}

// the upstream socket is closed, its last packets are still captured for a grace time; 0 is a socket that is not captured
func releaseUpstream(upstreamCookie uint64, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, logger *slog.Logger) {
	if (upstreamCookie == 0) || (captureBpfMaps == nil) {
		return
	}

	releaseErr := capturebpf.ReleaseUpstream(upstreamCookie, captureBpfMaps)

	if releaseErr != nil {
		logger.Debug("Could not release upstream socket of the capture", "error", releaseErr, "upstreamCookie", upstreamCookie)
	}
}
