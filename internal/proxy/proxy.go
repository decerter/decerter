// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf/redirect"
	"golang.org/x/sys/unix"
)

// the process can be gone by the time the proxy accepts, the flow is still proxied then, comm comes from the bpf flow instead
func processCmdline(tgid uint32) (cmdline string, err error) {
	cmdlineBytes, readErr := os.ReadFile("/proc/" + strconv.FormatUint(uint64(tgid), 10) + "/cmdline")

	if err = readErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrProcessInfo, err)
		return
	}

	// arguments are NUL separated with a trailing NUL
	cmdline = string(bytes.ReplaceAll(bytes.TrimRight(cmdlineBytes, "\x00"), []byte{0}, []byte{' '}))
	return
}

// one line per finished flow, up and down are already formatted: bytes for TCP, datagrams/bytes for UDP
// the mark is only printed when the app's socket has one, as on Android
func printFlow(flow redirect.Flow, cmdline string, client netip.AddrPort, up string, down string, duration time.Duration) {
	mark := ""

	if flow.Mark != 0 {
		mark = fmt.Sprintf(" mark=%#x", flow.Mark)
	}

	fmt.Printf("%s pid=%d uid=%d comm=%s %s client=%s%s up=%s down=%s duration=%s cmdline=%q\n", redirect.ProtocolName(flow.IPProtocol), flow.Tgid, flow.UID, flow.Comm, flow.OriginalDestination, client, mark, up, down, duration.Round(time.Millisecond), cmdline)
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
