// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"bytes"
	"net/netip"
	"slices"
	"syscall"
	"time"

	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// the decision of the scope filter about a flow
type scopeState string

const (
	// written to the file
	inScopeState scopeState = "in"
	// not written, its earlier packets neither
	outScopeState scopeState = "out"
	// the filter needs the ClientHello, the packets wait in opening until the first bytes decide it
	pendingScopeState scopeState = "pending"
)

// what a flow keeps while its scope waits for its first bytes
// values are the fields known from the start, packets the packets so far with their bytes copied
// hello is the client's TCP stream from its first payload byte on, next the sequence number of the byte behind it; isTLS is true once it starts with a ClientHello
type opening struct {
	values  filter.Values
	packets []capturebpf.Packet
	bytes   int
	start   time.Time
	hello   []byte
	next    uint32
	isTLS   bool
}

// decide a new flow with what flow_map and its first packet tell, a flow the filter can't decide without its ClientHello waits for it
// a flow that is gone from flow_map can't be decided and is left out
func (recorder *recorder) startScope(cookie uint64, newFlow *flow, packet capturebpf.Packet, now time.Time) {
	if recorder.scope == nil {
		newFlow.scope = inScopeState
		return
	}

	kernelFlow, lookupErr := redirect.FlowByCookie(cookie, recorder.captureBpfMaps[capturebpf.FlowMap])

	if lookupErr != nil {
		recorder.logger.Debug("Could not find flow to decide its scope, it is not written", "error", lookupErr, "cookie", cookie)
		newFlow.scope = outScopeState
		return
	}

	// the local end of the socket: the source of what it sends, the destination of what it gets
	header, _ := parsePacket(packet.Data)
	local := header.source

	if packet.IsIngress {
		local = header.destination
	}

	values := filter.Values{
		PID:         kernelFlow.Tgid,
		UID:         kernelFlow.UID,
		GID:         kernelFlow.GID,
		Comm:        kernelFlow.Comm,
		Cmdline:     "",
		Exe:         "",
		IPProtocol:  kernelFlow.IPProtocol,
		Source:      netip.AddrPortFrom(local.Address, local.Port),
		Destination: kernelFlow.OriginalDestination,
		TLS:         filter.UnknownTLSState,
		TLSVersion:  0,
		ServerName:  "",
		Protocols:   nil,
	}

	// the process can be gone by now, the fields are empty then
	if recorder.scope.Uses(filter.CmdlineField) {
		values.Cmdline, _ = filter.ReadCmdline(kernelFlow.Tgid)
	}

	if recorder.scope.Uses(filter.ExeField) {
		values.Exe, _ = filter.ReadExe(kernelFlow.Tgid)
	}

	switch recorder.scope.Evaluate(values) {
	case filter.TrueResult:
		newFlow.scope = inScopeState
	case filter.FalseResult:
		newFlow.scope = outScopeState
	default:
		newFlow.scope = pendingScopeState
		newFlow.opening = &opening{values: values, packets: nil, bytes: 0, start: now, hello: nil, next: 0, isTLS: false}
		recorder.pending = append(recorder.pending, cookie)
	}
}

// keep the packet of a flow that waits for its scope and decide it when its first bytes are there:
// a whole ClientHello, first client bytes that are no ClientHello, the server speaking first, the end of the flow, or more bytes than a flow may keep
func (recorder *recorder) wait(cookie uint64, pendingFlow *flow, packet capturebpf.Packet, now time.Time) (err error) {
	pendingFlow.lastPacket = now
	state := pendingFlow.opening
	packet.Data = bytes.Clone(packet.Data)
	state.packets = append(state.packets, packet)
	state.bytes += len(packet.Data)
	header, ok := parsePacket(packet.Data)
	var payload []byte
	var hello tlsrecord.Hello

	if ok && (len(packet.Data) > header.payloadOffset) {
		payload = packet.Data[header.payloadOffset:]
	}

	isCut := uint32(len(packet.Data)) < packet.Length
	isDecided := false

	switch {
	case !ok:
		// no TCP or UDP header to read the first bytes from
		isDecided = true
	case len(payload) == 0:
	case packet.IsIngress:
		// the server spoke first
		isDecided = true
	case header.protocol == syscall.IPPROTO_UDP:
		// a DTLS session starts with a ClientHello datagram, one fragmented over more datagrams is decided without its fields
		state.isTLS = tlsrecord.IsDTLSClientHello(payload)
		hello, _, _ = tlsrecord.ReadDTLSClientHello(payload)
		isDecided = true
	default:
		hello, isDecided = state.readHello(header.sequence, payload)
	}

	// the end of the flow, a cut segment or too much waiting: decided with what is there
	isEnd := ok && (header.protocol == syscall.IPPROTO_TCP) && (header.flags&(FINFlag|RSTFlag) != 0)

	if !isDecided && !isEnd && !isCut && (state.bytes <= maxHoldBytes) {
		return
	}

	err = recorder.decide(cookie, pendingFlow, hello, now)
	return
}

// the client's segments in the order of their sequence numbers from the first one on, a segment sent again or out of order is not read
func (state *opening) readHello(sequence uint32, payload []byte) (hello tlsrecord.Hello, isDecided bool) {
	if len(state.hello) == 0 {
		state.next = sequence
	}

	if sequence != state.next {
		return
	}

	state.hello = append(state.hello, payload...)
	state.next += uint32(len(payload))
	isClientHello, isPrefixDecided := tlsrecord.IsClientHello(state.hello)

	if !isPrefixDecided {
		return
	}

	if !isClientHello {
		isDecided = true
		return
	}

	state.isTLS = true
	parsed, isComplete, helloErr := tlsrecord.ReadClientHello(state.hello)

	// a ClientHello that can't be read is TLS without its fields
	if isComplete {
		hello = parsed
	}

	isDecided = isComplete || (helloErr != nil)
	return
}

// decide the flow with the ClientHello it had, write its packets when it is in scope and drop them when not
func (recorder *recorder) decide(cookie uint64, pendingFlow *flow, hello tlsrecord.Hello, now time.Time) (err error) {
	state := pendingFlow.opening
	pendingFlow.opening = nil
	recorder.pending = slices.DeleteFunc(recorder.pending, func(pendingCookie uint64) bool {
		return pendingCookie == cookie
	})
	values := state.values.WithClientHello(state.isTLS, hello.Version, hello.ServerName, hello.Protocols)

	if recorder.scope.Evaluate(values) != filter.TrueResult {
		pendingFlow.scope = outScopeState
		recorder.logger.Debug("Flow is out of scope, it is not written", "cookie", cookie, "packets", len(state.packets))
		return
	}

	pendingFlow.scope = inScopeState

	for _, packet := range state.packets {
		err = recorder.record(cookie, pendingFlow, packet, now)

		if err != nil {
			return
		}
	}

	return
}

// decide the flows that waited holdTimeout for their first bytes, or every waiting flow when the capture stops
func (recorder *recorder) decideLate(now time.Time, isStopping bool) (err error) {
	for _, cookie := range slices.Clone(recorder.pending) {
		pendingFlow := recorder.flows[cookie]

		if !isStopping && (now.Sub(pendingFlow.opening.start) < holdTimeout) {
			continue
		}

		err = recorder.decide(cookie, pendingFlow, tlsrecord.Hello{}, now)

		if err != nil {
			return
		}
	}

	return
}
