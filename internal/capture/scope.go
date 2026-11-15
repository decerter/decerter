// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"bytes"
	"log/slog"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
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
// packets are the packets so far with their bytes copied
// hello is the client's TCP stream from its first payload byte on, next the sequence number of the byte behind it
type opening struct {
	packets []capturebpf.Packet
	bytes   int
	start   time.Time
	hello   []byte
	next    uint32
}

// what the gate knows of one flow: values are the fields its scope was decided with, hasValues is false when nothing was looked up (no scope) or flow_map had no entry
// hello is the ClientHello at the start of the flow when its opening was read, isTLS true when the flow began with one
type gateFlow struct {
	scope      scopeState
	values     filter.Values
	hasValues  bool
	hello      tlsrecord.Hello
	isTLS      bool
	opening    *opening
	lastPacket time.Time
}

// decides once per flow whether its packets go on, a flow out of scope gives nothing, its earlier packets neither
// scope nil takes every flow; isReadingOpenings decides every flow with its first bytes even without a scope, so the values have the fields of its ClientHello
// lookup reads a flow from flow_map; pending are the cookies of the flows that wait for their first bytes, in the order they came
// the gate of a capture writer and the one of the capture hub are separate, each is used by one goroutine only
type gate struct {
	scope             *filter.Filter
	isReadingOpenings bool
	captureBpfMaps    map[bpf.BpfMapName]*ebpf.Map
	lookup            func(cookie uint64) (flow redirect.Flow, err error)
	flows             map[uint64]*gateFlow
	pending           []uint64
	logger            *slog.Logger
}

// gets the packets of the flows in scope in their order, decided is the flow as the gate decided it
type emitFunction func(cookie uint64, packet capturebpf.Packet, decided *gateFlow, now time.Time) (err error)

// captureBpfMaps has the flow_map of the recorded sockets, nil only where nothing is looked up
func newGate(scope *filter.Filter, isReadingOpenings bool, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, logger *slog.Logger) (newGate gate) {
	newGate = gate{
		scope:             scope,
		isReadingOpenings: isReadingOpenings,
		captureBpfMaps:    captureBpfMaps,
		lookup:            nil,
		flows:             map[uint64]*gateFlow{},
		pending:           nil,
		logger:            logger,
	}
	newGate.lookup = func(cookie uint64) (flow redirect.Flow, err error) {
		flow, err = lookupFlow(cookie, captureBpfMaps)
		return
	}
	return
}

// hand the packet on when its flow is in scope, keep it while the flow waits for its first bytes
func (gate *gate) handle(packet capturebpf.Packet, now time.Time, emit emitFunction) (err error) {
	current, ok := gate.flows[packet.Cookie]

	if !ok {
		current = gate.start(packet, now)
	}

	current.lastPacket = now

	switch current.scope {
	case outScopeState:
	case pendingScopeState:
		err = gate.wait(packet.Cookie, current, packet, now, emit)
	default:
		err = emit(packet.Cookie, packet, current, now)
	}

	return
}

// decide a new flow with what flow_map and its first packet tell, a flow the filter can't decide without its ClientHello waits for it
// a flow that is gone from flow_map can't be decided and is left out by a scope; without a scope its packets go on without values
func (gate *gate) start(packet capturebpf.Packet, now time.Time) (newFlow *gateFlow) {
	newFlow = &gateFlow{
		scope:      inScopeState,
		values:     filter.Values{},
		hasValues:  false,
		hello:      tlsrecord.Hello{},
		isTLS:      false,
		opening:    nil,
		lastPacket: now,
	}
	gate.flows[packet.Cookie] = newFlow

	if (gate.scope == nil) && !gate.isReadingOpenings {
		return
	}

	// in run mode the socket is an upstream socket of the proxy, the process and the original destination are the ones of the app's flow it carries
	kernelFlow, lookupErr := gate.lookup(packet.FlowCookie)

	if lookupErr != nil {
		if gate.scope != nil {
			gate.logger.Debug("Could not find flow to decide its scope, it is not written", "error", lookupErr, "cookie", packet.Cookie, "flowCookie", packet.FlowCookie)
			newFlow.scope = outScopeState
		}

		return
	}

	// the local end of the socket: the source of what it sends, the destination of what it gets; in run mode the proxy's end on the wire
	header, _ := parsePacket(packet.Data)
	local := header.source

	if packet.IsIngress {
		local = header.destination
	}

	newFlow.values = filter.Values{
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
		HTTP:        nil,
	}
	newFlow.hasValues = true

	// the process can be gone by now, the fields are empty then; the history shows them too
	if gate.isReadingOpenings || gate.scope.Uses(filter.CmdlineField) {
		newFlow.values.Cmdline, _ = filter.ReadCmdline(kernelFlow.Tgid)
	}

	if gate.isReadingOpenings || gate.scope.Uses(filter.ExeField) {
		newFlow.values.Exe, _ = filter.ReadExe(kernelFlow.Tgid)
	}

	result := filter.UnknownResult

	if gate.scope != nil {
		result = gate.scope.Evaluate(newFlow.values)
	}

	switch {
	case result == filter.FalseResult:
		newFlow.scope = outScopeState
	case (result == filter.TrueResult) && !gate.isReadingOpenings:
		newFlow.scope = inScopeState
	default:
		newFlow.scope = pendingScopeState
		newFlow.opening = &opening{packets: nil, bytes: 0, start: now, hello: nil, next: 0}
		gate.pending = append(gate.pending, packet.Cookie)
	}

	return
}

func lookupFlow(cookie uint64, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map) (flow redirect.Flow, err error) {
	if captureBpfMaps == nil {
		err = ErrNoFlowMap
		return
	}

	flow, err = flowByCookie(cookie, captureBpfMaps[capturebpf.FlowMap])
	return
}

// keep the packet of a flow that waits for its scope and decide it when its first bytes are there:
// a whole ClientHello, first client bytes that are no ClientHello, the server speaking first, the end of the flow, or more bytes than a flow may keep
func (gate *gate) wait(cookie uint64, pendingFlow *gateFlow, packet capturebpf.Packet, now time.Time, emit emitFunction) (err error) {
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
		pendingFlow.isTLS = tlsrecord.IsDTLSClientHello(payload)
		hello, _, _ = tlsrecord.ReadDTLSClientHello(payload)
		isDecided = true
	default:
		sequence := header.sequence

		// the SYN takes one sequence number, data in a SYN (TCP fast open) is behind it
		if header.flags&SYNFlag != 0 {
			sequence++
		}

		hello, isDecided = pendingFlow.readHello(sequence, payload)
	}

	// the end of the flow, a cut segment or too much waiting: decided with what is there
	isEnd := ok && (header.protocol == syscall.IPPROTO_TCP) && (header.flags&(FINFlag|RSTFlag) != 0)

	if !isDecided && !isEnd && !isCut && (state.bytes <= maxHoldBytes) {
		return
	}

	err = gate.decide(cookie, pendingFlow, hello, now, emit)
	return
}

// the client's segments in the order of their sequence numbers from the first one on, a segment sent again or out of order is not read
func (pendingFlow *gateFlow) readHello(sequence uint32, payload []byte) (hello tlsrecord.Hello, isDecided bool) {
	state := pendingFlow.opening

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

	pendingFlow.isTLS = true
	parsed, isComplete, helloErr := tlsrecord.ReadClientHello(state.hello)

	// a ClientHello that can't be read is TLS without its fields
	if isComplete {
		hello = parsed
	}

	isDecided = isComplete || (helloErr != nil)
	return
}

// decide the flow with the ClientHello it had, hand its packets on when it is in scope and drop them when not
func (gate *gate) decide(cookie uint64, pendingFlow *gateFlow, hello tlsrecord.Hello, now time.Time, emit emitFunction) (err error) {
	state := pendingFlow.opening
	pendingFlow.opening = nil
	gate.pending = slices.DeleteFunc(gate.pending, func(pendingCookie uint64) bool {
		return pendingCookie == cookie
	})
	pendingFlow.hello = hello
	pendingFlow.values = pendingFlow.values.WithClientHello(pendingFlow.isTLS, hello.Version, hello.ServerName, hello.Protocols)

	if (gate.scope != nil) && (gate.scope.Evaluate(pendingFlow.values) != filter.TrueResult) {
		pendingFlow.scope = outScopeState
		gate.logger.Debug("Flow is out of scope, it is not written", "cookie", cookie, "packets", len(state.packets))
		return
	}

	pendingFlow.scope = inScopeState

	for _, packet := range state.packets {
		err = emit(cookie, packet, pendingFlow, now)

		if err != nil {
			return
		}
	}

	return
}

// decide the flows that waited holdTimeout for their first bytes, or every waiting flow when the capture stops
func (gate *gate) decideLate(now time.Time, isStopping bool, emit emitFunction) (err error) {
	for _, cookie := range slices.Clone(gate.pending) {
		pendingFlow := gate.flows[cookie]

		if !isStopping && (now.Sub(pendingFlow.opening.start) < holdTimeout) {
			continue
		}

		err = gate.decide(cookie, pendingFlow, tlsrecord.Hello{}, now, emit)

		if err != nil {
			return
		}
	}

	return
}

// the flow starts as a new one with its next packet, its owner forgot it; a flow that waits for its first bytes stays
func (gate *gate) forget(cookie uint64) {
	current, ok := gate.flows[cookie]

	if ok && (current.scope != pendingScopeState) {
		delete(gate.flows, cookie)
	}
}

// a flow out of scope is kept while its socket is in flow_map, so it is not decided again in the middle of its stream, without its first bytes
func (gate *gate) forgetOutOfScope(now time.Time) {
	for cookie, current := range gate.flows {
		if (current.scope != outScopeState) || (now.Sub(current.lastPacket) < flowIdleTimeout) {
			continue
		}

		if gate.captureBpfMaps != nil {
			isOpen, lookupErr := isFlowOpen(cookie, gate.captureBpfMaps)

			if lookupErr != nil {
				gate.logger.Debug("Could not look up flow", "error", lookupErr, "cookie", cookie)
			}

			if isOpen {
				continue
			}
		}

		delete(gate.flows, cookie)
	}
}
