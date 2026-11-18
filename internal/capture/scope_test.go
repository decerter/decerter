// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture

import (
	"bytes"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/tlsrecord"
)

var errTestEmit = errors.New("the writer of the test failed")

// what a gate handed on in a test, emitErr is what the next emit returns
type emitted struct {
	packets []capturebpf.Packet
	emitErr error
}

func (collected *emitted) emit(cookie uint64, packet capturebpf.Packet, decided *gateFlow, now time.Time) (err error) {
	err = collected.emitErr

	if err == nil {
		collected.packets = append(collected.packets, packet)
	}

	return
}

// a gate of the tests: scope is parsed, "" is no scope, and the flows are looked up with lookup
func testGate(scope string, isReadingOpenings bool, lookup func(cookie uint64) (flow redirect.Flow, err error)) (current gate, err error) {
	var parsed *filter.Filter

	if scope != "" {
		scopeFilter, parseErr := filter.Parse(scope)

		if err = parseErr; err != nil {
			return
		}

		parsed = &scopeFilter
	}

	current = newGate(parsed, isReadingOpenings, nil, slog.New(slog.DiscardHandler))
	current.lookup = lookup
	return
}

// a ClientHello whose handshake message is larger than a flow may keep while it waits: it never becomes whole, in segments of 60000 bytes
func endlessHello() (chunks []sessionChunk) {
	data := []byte{}

	for index := range maxHoldBytes/16384 + 2 {
		data = append(data, byte(tlsrecord.HandshakeContentType), 3, 1, 0x40, 0)
		fragment := make([]byte, 16384)

		// the handshake header of a ClientHello of 16 MiB
		if index == 0 {
			copy(fragment, []byte{1, 0xFF, 0xFF, 0xFF, 3, 3})
		}

		data = append(data, fragment...)
	}

	for chunk := range slices.Chunk(data, 60000) {
		chunks = append(chunks, sessionChunk{direction: tlsrecord.ClientDirection, data: chunk})
	}

	return
}

// Test if capture.gate decides the scope of a flow with flow_map and its first bytes: what the filter can decide without the ClientHello at once, the rest with the ClientHello,
// the first bytes that are no ClientHello, the server speaking first, the end of the flow, a cut segment or too many bytes
func TestGatePositive(state *testing.T) {
	session := testSessions(state)[1]
	hello := session.chunks[0].data
	dtls := testDTLSSession(state)
	client := hubClient
	server := hubServer
	helloFlow := tcpPackets(1, client, server, []sessionChunk{{direction: tlsrecord.ClientDirection, data: hello}}, true)
	// the first segment comes twice, the second copy is not read
	splitFlow := tcpPackets(1, client, server, []sessionChunk{{direction: tlsrecord.ClientDirection, data: hello[:3]}, {direction: tlsrecord.ClientDirection, data: hello[3:]}}, true)
	splitFlow = slices.Insert(splitFlow, 4, splitFlow[3])
	cutFlow := tcpPackets(1, client, server, []sessionChunk{{direction: tlsrecord.ClientDirection, data: hello[:50]}}, true)
	cutFlow[3].Length += uint32(len(hello) - 50)
	icmp := slices.Clone(helloFlow[0].Data)
	icmp[ipv4ProtocolOffset] = 1
	noTransport := slices.Concat([]capturebpf.Packet{{Cookie: 1, FlowCookie: 1, TimestampNs: 1, Length: uint32(len(icmp)), IsIngress: false, Data: icmp}}, helloFlow)
	badHello := []byte{byte(tlsrecord.HandshakeContentType), 3, 1, 0, 4, 1, 0, 0, 0}
	failingLookup := func(cookie uint64) (flow redirect.Flow, err error) {
		err = errors.New("no such flow")
		return
	}
	notOther := "!(tls.sni == \"other.com\")"
	// a TCP fast open SYN with the start of the ClientHello, the rest behind the SYN's own sequence number
	fastOpen := []capturebpf.Packet{}

	for index, data := range [][]byte{
		TCPPacket(nil, client, server, testClientISN, 0, SYNFlag, hello[:100]),
		TCPPacket(nil, server, client, testServerISN, testClientISN+101, SYNFlag|ACKFlag, nil),
		TCPPacket(nil, client, server, testClientISN+101, testServerISN+1, ACKFlag|PSHFlag, hello[100:]),
	} {
		fastOpen = append(fastOpen, capturebpf.Packet{Cookie: 1, FlowCookie: 1, TimestampNs: uint64(index+1) * 1000, Length: uint32(len(data)), IsIngress: index == 1, Data: data})
	}

	positiveCases := []struct {
		Name              string
		Scope             string
		IsReadingOpenings bool
		Lookup            func(cookie uint64) (flow redirect.Flow, err error)
		Packets           []capturebpf.Packet
		// the packets handed on, the scope of the flow after them and what it read of its ClientHello
		Emitted    int
		Decided    scopeState
		IsTLS      bool
		ServerName string
		HasValues  bool
	}{
		{Name: "no scope", Scope: "", Packets: helloFlow, Emitted: len(helloFlow), Decided: inScopeState},
		{Name: "no scope, reading openings", Scope: "", IsReadingOpenings: true, Packets: helloFlow, Emitted: len(helloFlow), Decided: inScopeState, IsTLS: true, ServerName: "example.com", HasValues: true},
		{Name: "in scope by flow_map", Scope: "tcp.dstport == 80", Packets: helloFlow, Emitted: len(helloFlow), Decided: inScopeState, HasValues: true},
		{Name: "out of scope by flow_map", Scope: "tcp.dstport == 443", Packets: helloFlow, Emitted: 0, Decided: outScopeState, HasValues: true},
		{Name: "in scope by the client hello", Scope: "tls.sni == \"example.com\"", Packets: helloFlow, Emitted: len(helloFlow), Decided: inScopeState, IsTLS: true, ServerName: "example.com", HasValues: true},
		{Name: "out of scope by the client hello", Scope: "tls.sni == \"other.com\"", Packets: helloFlow, Emitted: 0, Decided: outScopeState, IsTLS: true, ServerName: "example.com", HasValues: true},
		{Name: "client hello in two segments, one sent again", Scope: "tls.sni == \"example.com\"", Packets: splitFlow, Emitted: len(splitFlow), Decided: inScopeState, IsTLS: true, ServerName: "example.com", HasValues: true},
		{Name: "client hello in a tcp fast open syn", Scope: "tls.sni == \"example.com\"", Packets: fastOpen, Emitted: len(fastOpen), Decided: inScopeState, IsTLS: true, ServerName: "example.com", HasValues: true},
		{Name: "no tls", Scope: "tls.sni == \"example.com\"", Packets: tcpPackets(1, client, server, []sessionChunk{{direction: tlsrecord.ClientDirection, data: []byte("GET / HTTP/1.1\r\n\r\n")}}, true), Emitted: 0, Decided: outScopeState, HasValues: true},
		{Name: "server speaks first", Scope: notOther, Packets: tcpPackets(1, client, server, []sessionChunk{{direction: tlsrecord.ServerDirection, data: []byte("220 smtp\r\n")}, {direction: tlsrecord.ClientDirection, data: hello}}, true), Emitted: 8, Decided: inScopeState, HasValues: true},
		{Name: "fin before the first bytes", Scope: notOther, Packets: tcpPackets(1, client, server, nil, true), Emitted: 6, Decided: inScopeState, HasValues: true},
		{Name: "cut segment", Scope: notOther, Packets: cutFlow, Emitted: len(cutFlow), Decided: inScopeState, IsTLS: true, HasValues: true},
		{Name: "client hello that can't be read", Scope: "tls", Packets: tcpPackets(1, client, server, []sessionChunk{{direction: tlsrecord.ClientDirection, data: badHello}}, true), Emitted: 7, Decided: inScopeState, IsTLS: true, HasValues: true},
		{Name: "too many bytes", Scope: "tls", Packets: tcpPackets(1, client, server, endlessHello(), false), Emitted: 3 + len(endlessHello()), Decided: inScopeState, IsTLS: true, HasValues: true},
		{Name: "no transport header", Scope: notOther, Packets: noTransport, Emitted: len(noTransport), Decided: inScopeState, HasValues: true},
		{Name: "dtls client hello", Scope: "tls", Packets: udpPackets(1, client, server, dtls.chunks[:2]), Emitted: 2, Decided: inScopeState, IsTLS: true, HasValues: true},
		{Name: "datagram that is no dtls", Scope: "tls", Packets: udpPackets(1, client, server, []sessionChunk{{direction: tlsrecord.ClientDirection, data: []byte("query")}}), Emitted: 0, Decided: outScopeState, HasValues: true},
		{Name: "first packet from the server", Scope: "tcp.dstport == 80", Packets: helloFlow[1:], Emitted: len(helloFlow) - 1, Decided: inScopeState, HasValues: true},
		{Name: "process fields", Scope: "proc.cmdline contains \"decerter-test\" || proc.exe == \"/decerter-test\"", Packets: helloFlow, Emitted: 0, Decided: outScopeState, HasValues: true},
		{Name: "flow not in flow_map", Scope: "tcp", Lookup: failingLookup, Packets: helloFlow, Emitted: 0, Decided: outScopeState},
		{Name: "flow not in flow_map, reading openings", Scope: "", IsReadingOpenings: true, Lookup: failingLookup, Packets: helloFlow, Emitted: len(helloFlow), Decided: inScopeState},
	}

	for _, positive := range positiveCases {
		lookup := positive.Lookup

		if lookup == nil {
			lookup = testLookup
		}

		current, err := testGate(positive.Scope, positive.IsReadingOpenings, lookup)

		if err != nil {
			state.Fatalf("Test of capture.gate failed, case %q, cannot parse filter, error: %s", positive.Name, err.Error())
		}

		collected := emitted{packets: nil, emitErr: nil}
		now := time.Now()

		for _, packet := range positive.Packets {
			err = current.handle(packet, now, collected.emit)

			if err != nil {
				state.Fatalf("Test of capture.gate failed, case %q, error: %s", positive.Name, err.Error())
			}
		}

		decided := current.flows[1]

		if (len(collected.packets) != positive.Emitted) || (decided.scope != positive.Decided) || (decided.isTLS != positive.IsTLS) || (decided.hello.ServerName != positive.ServerName) || (decided.hasValues != positive.HasValues) || (len(current.pending) != 0) {
			state.Errorf("Test of capture.gate failed, case %q, %d packets should be handed on, the flow should be %q, tls %v, server name %q, values %v, emitted: %d, flow: %+v, pending: %v", positive.Name, positive.Emitted, positive.Decided, positive.IsTLS, positive.ServerName, positive.HasValues, len(collected.packets), decided, current.pending)
			return
		}

		// the packets in their order with their bytes
		if !slices.EqualFunc(collected.packets, positive.Packets[:len(collected.packets)], func(left capturebpf.Packet, right capturebpf.Packet) bool { return bytes.Equal(left.Data, right.Data) }) {
			state.Errorf("Test of capture.gate failed, case %q, the packets should be handed on in their order", positive.Name)
			return
		}

		// the local end of the socket is the client, the destination the one of flow_map; the end is not known when the first packet has no transport header
		if _, isParsed := parsePacket(positive.Packets[0].Data); isParsed && decided.hasValues && ((decided.values.Source != netip.AddrPortFrom(client.Address, client.Port)) || (decided.values.Destination != netip.AddrPortFrom(server.Address, server.Port)) || (decided.values.Comm != "curl")) {
			state.Errorf("Test of capture.gate failed, case %q, the values should be the ones of the client socket of curl, values: %+v", positive.Name, decided.values)
			return
		}
	}
}

// Test if capture.gate decides the flows that wait for their first bytes once they waited the hold timeout or when the capture stops, and forgets them only when it is told to and they are not waiting.
func TestGateDecideLatePositive(state *testing.T) {
	positiveCases := []struct {
		Name       string
		Scope      string
		IsStopping bool
		Emitted    int
	}{
		{Name: "out of scope after the hold timeout", Scope: "tls.sni == \"example.com\"", IsStopping: false, Emitted: 0},
		{Name: "in scope after the hold timeout", Scope: "!(tls.sni == \"other.com\")", IsStopping: false, Emitted: 3},
		{Name: "in scope when the capture stops", Scope: "!(tls.sni == \"other.com\")", IsStopping: true, Emitted: 3},
	}

	for _, positive := range positiveCases {
		current, err := testGate(positive.Scope, false, testLookup)

		if err != nil {
			state.Fatalf("Test of capture.gate failed, case %q, cannot parse filter, error: %s", positive.Name, err.Error())
		}

		collected := emitted{packets: nil, emitErr: nil}
		start := time.Now()

		for _, packet := range tcpPackets(1, hubClient, hubServer, nil, false) {
			err = current.handle(packet, start, collected.emit)

			if err != nil {
				state.Fatalf("Test of capture.gate failed, case %q, error: %s", positive.Name, err.Error())
			}
		}

		// a flow that waits is not forgotten
		current.forget(1)
		err = current.decideLate(start.Add(holdTimeout/2), false, collected.emit)

		if (err != nil) || !slices.Equal(current.pending, []uint64{1}) || (current.flows[1] == nil) {
			state.Errorf("Test of capture.gate failed, case %q, the flow should still wait half the hold timeout later, pending: %v, error: %v", positive.Name, current.pending, err)
			return
		}

		now := start.Add(holdTimeout)

		if positive.IsStopping {
			now = start
		}

		err = current.decideLate(now, positive.IsStopping, collected.emit)

		if (err != nil) || (len(current.pending) != 0) || (len(collected.packets) != positive.Emitted) {
			state.Errorf("Test of capture.gate failed, case %q, the flow should be decided with %d packets, pending: %v, emitted: %d, error: %v", positive.Name, positive.Emitted, current.pending, len(collected.packets), err)
			return
		}

		current.forget(1)

		if current.flows[1] != nil {
			state.Errorf("Test of capture.gate failed, case %q, a decided flow should be forgotten", positive.Name)
			return
		}
	}
}

// Test if capture.gate returns with the expected errors: a writer that fails ends the handing on of a flow in scope, of a flow decided by its ClientHello and of the flows decided late.
func TestGateNegative(state *testing.T) {
	session := testSessions(state)[1]
	negativeCases := []struct {
		Name    string
		Scope   string
		Packets []capturebpf.Packet
		IsLate  bool
	}{
		{Name: "in scope at once", Scope: "", Packets: tcpPackets(1, hubClient, hubServer, nil, false)},
		{Name: "decided by the client hello", Scope: "tls", Packets: tcpPackets(1, hubClient, hubServer, session.chunks[:1], false)},
		{Name: "decided late", Scope: "!tls", Packets: tcpPackets(1, hubClient, hubServer, nil, false), IsLate: true},
	}

	for _, negative := range negativeCases {
		current, err := testGate(negative.Scope, false, testLookup)

		if err != nil {
			state.Fatalf("Test of capture.gate failed, case %q, cannot parse filter, error: %s", negative.Name, err.Error())
		}

		collected := emitted{packets: nil, emitErr: errTestEmit}
		now := time.Now()

		for _, packet := range negative.Packets {
			err = errors.Join(err, current.handle(packet, now, collected.emit))
		}

		if negative.IsLate {
			err = current.decideLate(now, true, collected.emit)
		}

		if !errors.Is(err, errTestEmit) {
			state.Errorf("Test of capture.gate failed, case %q, error should be %v, error: %v", negative.Name, errTestEmit, err)
			return
		}
	}
}

// Test if capture.gate forgets a flow out of scope once it had no packet for the idle timeout and its socket is gone from flow_map, or flow_map is not there.
func TestGateForgetOutOfScopePositive(state *testing.T) {
	// 1 is open, 2 is gone, the lookup of 3 fails, 4 had a packet a moment ago, 5 is in scope
	useTestFlows(state, map[uint64]bool{1: true, 2: false, 4: false, 5: false})
	positiveCases := []struct {
		Name      string
		BpfMaps   map[bpf.BpfMapName]*ebpf.Map
		Remaining []uint64
	}{
		{Name: "with flow_map", BpfMaps: testBpfMaps, Remaining: []uint64{1, 4, 5}},
		{Name: "without flow_map", BpfMaps: nil, Remaining: []uint64{4, 5}},
	}

	for _, positive := range positiveCases {
		current, err := testGate("tcp.dstport == 443", false, testLookup)

		if err != nil {
			state.Fatalf("Test of capture.gate failed, case %q, cannot parse filter, error: %s", positive.Name, err.Error())
		}

		current.captureBpfMaps = positive.BpfMaps
		collected := emitted{packets: nil, emitErr: nil}
		start := time.Now()

		for cookie := range uint64(5) {
			packet := tcpPackets(cookie+1, hubClient, hubServer, nil, false)[0]
			moment := start

			// testLookup gives cookie 7 port 443, it is in scope
			if cookie == 4 {
				packet.FlowCookie = 7
			}

			if cookie == 3 {
				moment = start.Add(flowIdleTimeout)
			}

			err = current.handle(packet, moment, collected.emit)

			if err != nil {
				state.Fatalf("Test of capture.gate failed, case %q, error: %s", positive.Name, err.Error())
			}
		}

		current.forgetOutOfScope(start.Add(flowIdleTimeout + time.Second))
		remaining := []uint64{}

		for cookie := range uint64(6) {
			if current.flows[cookie] != nil {
				remaining = append(remaining, cookie)
			}
		}

		if !slices.Equal(remaining, positive.Remaining) {
			state.Errorf("Test of capture.gate failed, case %q, the flows %v should stay, flows: %v", positive.Name, positive.Remaining, remaining)
			return
		}
	}
}

// Test if capture.lookupFlow returns with the expected output: the flow of the cookie in flow_map.
func TestLookupFlowPositive(state *testing.T) {
	oldFlowByCookie := flowByCookie
	state.Cleanup(func() {
		flowByCookie = oldFlowByCookie
	})
	flowByCookie = func(cookie uint64, flowMap *ebpf.Map) (flow redirect.Flow, err error) {
		flow, err = testLookup(cookie)
		return
	}
	flow, err := lookupFlow(7, testBpfMaps)

	if (err != nil) || (flow.OriginalDestination.Port() != 443) || (flow.Comm != "curl") {
		state.Errorf("Test of capture.lookupFlow function failed, the flow should be the one of cookie 7, flow: %+v, error: %v", flow, err)
		return
	}
}

// Test if capture.lookupFlow returns with the expected errors: without the maps there is no flow_map to look in, a gate without them decides every flow out of its scope.
func TestLookupFlowNegative(state *testing.T) {
	_, err := lookupFlow(7, nil)

	if !errors.Is(err, ErrNoFlowMap) {
		state.Errorf("Test of capture.lookupFlow function failed, error should be %v, error: %v", ErrNoFlowMap, err)
		return
	}

	scope, err := filter.Parse("tcp")

	if err != nil {
		state.Fatalf("Test of capture.lookupFlow function failed, cannot parse filter, error: %s", err.Error())
	}

	current := newGate(&scope, false, nil, slog.New(slog.DiscardHandler))
	collected := emitted{packets: nil, emitErr: nil}
	err = current.handle(tcpPackets(1, hubClient, hubServer, nil, false)[0], time.Now(), collected.emit)

	if (err != nil) || (len(collected.packets) != 0) || (current.flows[1].scope != outScopeState) {
		state.Errorf("Test of capture.lookupFlow function failed, a flow that can't be looked up should be out of scope, emitted: %d, error: %v", len(collected.packets), err)
		return
	}
}
