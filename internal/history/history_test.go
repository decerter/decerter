// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package history_test

import (
	"bytes"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// the values of a tcp flow of curl to port, tls tells whether its ClientHello was read
func testValues(port uint16, tls filter.TLSState) (values filter.Values) {
	values = filter.Values{PID: 42, UID: 1001, GID: 1001, Comm: "curl", Cmdline: "curl", Exe: "/usr/bin/curl", IPProtocol: syscall.IPPROTO_TCP, Source: netip.MustParseAddrPort("[::ffff:127.0.0.1]:40000"), Destination: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), TLS: tls}
	return
}

// a message of the flow, as the pipeline gives it
func testMessage(flowID uint64, id uint64, direction tlsrecord.Direction, plain string) (message intercept.Message) {
	message = intercept.Message{Flow: intercept.Flow{ID: flowID}, ID: id, Direction: direction, Layer: intercept.TCPLayer, Plain: []byte(plain)}
	return
}

func forward(plain string) (result intercept.Result) {
	result = intercept.Result{Plain: []byte(plain), Verdict: intercept.ForwardVerdict, Changed: false}
	return
}

// Test if history.History.Flows returns with the expected output: newest first, in pages, with a filter that sees TLS as present or absent.
func TestFlowsPositive(state *testing.T) {
	recorded := []api.Event{}
	flows := history.New(history.DefaultLimits(), func(event api.Event) {
		recorded = append(recorded, event)
	})

	for port := range uint16(5) {
		flows.OpenFlow(uint64(port), testValues(8000+port, filter.UnknownTLSState), [32]byte{})
	}

	// flow 5 turned out to be TLS: the record layer knew its session
	session := tlsrecord.Session{ClientRandom: [32]byte{9}, ServerName: "example.com", Protocol: "h2", Version: tlsrecord.VersionTLS13, CipherSuite: 0x1301}
	flows.Record(intercept.Message{Flow: intercept.Flow{ID: 5, Session: session}, ID: 1, Direction: tlsrecord.ClientDirection, Layer: intercept.TLSLayer, Plain: []byte("GET /")}, forward("GET /"), intercept.RulesOrigin)
	flows.CloseFlow(5, history.Counters{Bytes: 100, Datagrams: 0}, history.Counters{Bytes: 200, Datagrams: 0})
	pages := [][]uint64{}
	cursor := uint64(0)

	for {
		page, next := flows.Flows(nil, cursor, 2)
		pages = append(pages, flowIDs(page))
		cursor = next

		if next == 0 {
			break
		}
	}

	if !slices.EqualFunc(pages, [][]uint64{{5, 4}, {3, 2}, {1}}, slices.Equal) {
		state.Errorf("Test of history.History.Flows function failed, pages should be [[5 4] [3 2] [1]], pages: %v", pages)
		return
	}

	positiveCases := []struct {
		Filter   string
		Expected []uint64
	}{
		{Filter: "tls", Expected: []uint64{5}},
		{Filter: "!tls", Expected: []uint64{4, 3, 2, 1}},
		{Filter: `tls.sni == "example.com" && tcp.dstport == 8004`, Expected: []uint64{5}},
		{Filter: "ip.src == 127.0.0.1 && tcp.dstport in {8000 8001}", Expected: []uint64{2, 1}},
	}

	for _, positive := range positiveCases {
		scope, err := filter.Parse(positive.Filter)

		if err != nil {
			state.Fatalf("Test of history.History.Flows failed, cannot parse %q, error: %s", positive.Filter, err.Error())
		}

		page, _ := flows.Flows(&scope, 0, 100)

		if ids := flowIDs(page); !slices.Equal(ids, positive.Expected) {
			state.Errorf("Test of history.History.Flows function failed, filter %q should take %v, flows: %v", positive.Filter, positive.Expected, ids)
			return
		}
	}

	flow, found := flows.Flow(5)

	if !found || (flow.State != api.ClosedFlowState) || (flow.Client != "127.0.0.1:40000") || (flow.TLS == nil) || (flow.TLS.Version != "TLS1.3") || (flow.TLS.ALPN != "h2") || (flow.TLS.ClientRandom[:2] != "09") || (flow.Up.Bytes != 100) || (flow.Up.Messages != 1) || (flow.Layer != api.TLSLayer) {
		state.Errorf("Test of history.History.Flow function failed, flow: %+v, tls: %+v", flow, flow.TLS)
		return
	}

	// five opened, one message, one closed
	if (len(recorded) != 7) || (recorded[5].Type != api.MessageEventType) || (recorded[6].Type != api.FlowClosedEventType) {
		state.Errorf("Test of history.History failed, 7 events should be published, events: %d", len(recorded))
		return
	}
}

// Test if history.History keeps its bounds: the oldest flow goes first, a flow over its own bounds is truncated, an edited message keeps what the peer sent.
func TestLimitsPositive(state *testing.T) {
	limits := history.Limits{Flows: 3, Messages: 4, FlowMessages: 3, PayloadBytes: 10, FlowPayloadBytes: 6}
	flows := history.New(limits, nil)

	for port := range uint16(4) {
		flows.OpenFlow(0, testValues(8000+port, filter.AbsentTLSState), [32]byte{})
	}

	if _, found := flows.Flow(1); found || (flows.Status().EvictedFlows != 1) || (flows.Status().Flows != 3) || (flows.Status().OpenFlows != 3) {
		state.Errorf("Test of history.History.OpenFlow function failed, flow 1 should be evicted, status: %+v", flows.Status())
		return
	}

	// flow 2: an edited message keeps both, the rest of its room is 2 bytes
	flows.Record(testMessage(2, 1, tlsrecord.ClientDirection, "ab"), intercept.Result{Plain: []byte("abc"), Verdict: intercept.ForwardVerdict, Changed: true}, intercept.RulesOrigin)
	message, payload, original, found := flows.Message(1)

	if !found || !message.Edited || (string(payload) != "abc") || (string(original) != "ab") || (message.Length != 3) || (message.OriginalLength != 2) {
		state.Errorf("Test of history.History.Message function failed, message: %+v, payload: %q, original: %q", message, payload, original)
		return
	}

	flows.Record(testMessage(2, 2, tlsrecord.ServerDirection, "defg"), forward("defg"), intercept.RulesOrigin)
	message, payload, _, _ = flows.Message(2)
	flow, _ := flows.Flow(2)

	if (string(payload) != "d") || (message.StoredLength != 1) || (message.Length != 4) || !flow.Truncated || (flow.PayloadBytes != 6) {
		state.Errorf("Test of history.History.Record function failed, the flow should be cut at 6 bytes, payload: %q, flow: %+v", payload, flow)
		return
	}

	// a third message fits, a fourth is over the flow's bound
	flows.Record(testMessage(2, 3, tlsrecord.ServerDirection, ""), forward(""), intercept.RulesOrigin)
	flows.Record(testMessage(2, 4, tlsrecord.ServerDirection, "x"), forward("x"), intercept.RulesOrigin)

	if _, _, _, found = flows.Message(4); found {
		state.Errorf("Test of history.History.Record function failed, a message over the flow's bound should not be kept")
		return
	}

	// flow 3 needs room: the oldest other flow, 2, goes
	flows.Record(testMessage(3, 5, tlsrecord.ClientDirection, "hijklm"), forward("hijklm"), intercept.RulesOrigin)

	if _, found = flows.Flow(2); found || (flows.Status().PayloadBytes != 6) || (flows.Status().Messages != 1) {
		state.Errorf("Test of history.History.Record function failed, flow 2 should be evicted for the room, status: %+v", flows.Status())
		return
	}

	// a message of a flow that is gone is not kept
	flows.Record(testMessage(2, 6, tlsrecord.ClientDirection, "x"), forward("x"), intercept.RulesOrigin)
	flows.CloseFlow(2, history.Counters{}, history.Counters{})

	if _, _, _, found = flows.Message(6); found || (flows.Status().OpenFlows != 2) {
		state.Errorf("Test of history.History.Record function failed, a message of an evicted flow should not be kept, status: %+v", flows.Status())
		return
	}
}

// Test if history.History.Messages and ClientRandoms return with the expected output: messages in id order in pages, client randoms once each.
func TestMessagesPositive(state *testing.T) {
	flows := history.New(history.DefaultLimits(), nil)
	first := flows.OpenFlow(1, testValues(443, filter.PresentTLSState), [32]byte{1})
	second := flows.OpenFlow(2, testValues(443, filter.PresentTLSState), [32]byte{1})
	third := flows.OpenFlow(3, testValues(80, filter.AbsentTLSState), [32]byte{})

	// a held message comes after the one behind it
	for _, id := range []uint64{1, 3, 2, 4} {
		flows.Record(testMessage(first, id, tlsrecord.ClientDirection, "m"), forward("m"), intercept.RulesOrigin)
	}

	flows.Observe(intercept.Flow{ID: third}, tlsrecord.ServerDirection, intercept.TCPLayer, []byte("observed"))
	page, next, found := flows.Messages(first, 0, 3)
	rest, last, _ := flows.Messages(first, next, 3)
	_, _, missing := flows.Messages(99, 0, 3)
	observed, _, _ := flows.Messages(third, 0, 3)

	if !found || missing || (next != 3) || (last != 0) || !slices.Equal(messageIDs(page), []uint64{1, 2, 3}) || !slices.Equal(messageIDs(rest), []uint64{4}) || (len(observed) != 1) || (observed[0].Origin != api.ObservedOrigin) || (observed[0].Direction != api.DownDirection) {
		state.Errorf("Test of history.History.Messages function failed, pages: %v %v next %d, observed: %+v", messageIDs(page), messageIDs(rest), next, observed)
		return
	}

	clientRandoms := flows.ClientRandoms(nil)
	scope, err := filter.Parse("tcp.dstport == 80")

	if err != nil {
		state.Fatalf("Test of history.History.ClientRandoms failed, cannot parse filter, error: %s", err.Error())
	}

	if (len(clientRandoms) != 1) || (clientRandoms[0] != [32]byte{1}) || (len(flows.ClientRandoms(&scope)) != 0) || (second == first) {
		state.Errorf("Test of history.History.ClientRandoms function failed, client randoms: %v", clientRandoms)
		return
	}

	// nil records nothing and does not fail
	var none *history.History
	none.Record(testMessage(1, 1, tlsrecord.ClientDirection, "x"), forward("x"), intercept.RulesOrigin)

	if id := none.OpenFlow(1, filter.Values{}, [32]byte{}); id != 0 {
		state.Errorf("Test of history.History.OpenFlow function failed, a nil history should give id 0, id: %d", id)
		return
	}

	none.CloseFlow(1, history.Counters{}, history.Counters{})
	none.Observe(intercept.Flow{}, tlsrecord.ClientDirection, intercept.TCPLayer, bytes.Repeat([]byte{1}, 3))
}

func flowIDs(flows []api.Flow) (ids []uint64) {
	ids = []uint64{}

	for _, flow := range flows {
		ids = append(ids, flow.ID)
	}

	return
}

func messageIDs(messages []api.Message) (ids []uint64) {
	ids = []uint64{}

	for _, message := range messages {
		ids = append(ids, message.ID)
	}

	return
}
