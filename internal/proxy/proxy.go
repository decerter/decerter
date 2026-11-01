// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/decerter/decerter/internal/bpf/redirect"
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
func printFlow(flow redirect.Flow, cmdline string, client netip.AddrPort, up string, down string, duration time.Duration) {
	fmt.Printf("%s pid=%d uid=%d comm=%s %s client=%s up=%s down=%s duration=%s cmdline=%q\n", redirect.ProtocolName(flow.IPProtocol), flow.Tgid, flow.UID, flow.Comm, flow.OriginalDestination, client, up, down, duration.Round(time.Millisecond), cmdline)
}

// a redirected connection or datagram to the proxy port itself would make the proxy send to itself
func isLoop(destination netip.AddrPort, local netip.AddrPort) (loop bool) {
	loop = destination.Addr().IsLoopback() && (destination.Port() == local.Port())
	return
}
