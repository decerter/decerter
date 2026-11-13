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

// Test if history.History.Export returns with the expected output: the flows a filter takes, oldest first, with what went on of each message and the client random of the session.
func TestExportPositive(state *testing.T) {
	flows := history.New(history.DefaultLimits(), nil)
	plainID := flows.OpenFlow(1, testValues(8000, filter.AbsentTLSState), [32]byte{})
	tlsID := flows.OpenFlow(2, testValues(443, filter.UnknownTLSState).WithClientHello(true, tlsrecord.VersionTLS13, "example.com", nil), [32]byte{7})
	flows.Record(testMessage(tlsID, 1, tlsrecord.ClientDirection, "GET / HTTP/1.1"), intercept.Result{Plain: []byte("GET /test HTTP/1.1"), Verdict: intercept.ForwardVerdict, Changed: true}, intercept.RulesOrigin)
	flows.Record(testMessage(tlsID, 2, tlsrecord.ServerDirection, "x"), intercept.Result{Plain: nil, Verdict: intercept.DropVerdict, Changed: true}, intercept.RulesOrigin)
	flows.Record(testMessage(plainID, 3, tlsrecord.ClientDirection, "ping"), forward("ping"), intercept.RulesOrigin)
	all := flows.Export(nil)

	if (len(all) != 2) || (all[0].Flow.ID != plainID) || (all[1].Flow.ID != tlsID) || (all[1].ClientRandom != [32]byte{7}) || (all[0].Values.Destination.Port() != 8000) {
		state.Fatalf("Test of history.History.Export function failed, both flows should be there oldest first, flows: %+v", all)
	}

	messages := all[1].Messages

	if (len(messages) != 2) || (string(messages[0].Payload) != "GET /test HTTP/1.1") || !messages[0].Message.Edited || (messages[0].Message.OriginalLength != 14) || (messages[1].Message.Verdict != api.DropVerdict) || (len(messages[1].Payload) != 0) {
		state.Errorf("Test of history.History.Export function failed, the TLS flow should have the edited request as it went on and the drop, messages: %+v", messages)
		return
	}

	scope, err := filter.Parse(`tls.sni == "example.com"`)

	if err != nil {
		state.Fatalf("Test of history.History.Export function failed, cannot parse filter, error: %s", err.Error())
	}

	if selected := flows.Export(&scope); (len(selected) != 1) || (selected[0].Flow.ID != tlsID) {
		state.Errorf("Test of history.History.Export function failed, the filter should take the TLS flow, flows: %+v", selected)
		return
	}

	var nothing *history.History

	if exported := nothing.Export(nil); exported != nil {
		state.Errorf("Test of history.History.Export function failed, a nil history should export nothing, flows: %+v", exported)
		return
	}
}

// a request head of an exchange, as the HTTP layer gives it
func testRequest(method string, target string) (message api.HTTPMessage) {
	message = api.HTTPMessage{HTTPHead: api.HTTPHead{Method: method, Target: target, Version: "HTTP/1.1", Headers: []api.Header{{Name: "Host", Value: "example.com"}, {Name: "User-Agent", Value: "curl/8"}}}, URL: "http://example.com" + target, Framing: api.NoneFraming, State: api.HeadHTTPState}
	return
}

// Test if the exchanges of history.History return with the expected output: heads, bodies and their edit, paging, the http fields of a flow for the filter, and the limits.
func TestExchangesPositive(state *testing.T) {
	recorded := []api.Event{}
	limits := history.DefaultLimits()
	limits.FlowExchanges = 3
	limits.FlowExchangeBytes = 1000
	flows := history.New(limits, func(event api.Event) {
		recorded = append(recorded, event)
	})
	flowID := flows.OpenFlow(1, testValues(80, filter.AbsentTLSState), [32]byte{})
	first := flows.OpenExchange(flowID, "HTTP/1.1", api.RequestSide, testRequest("POST", "/login"))
	flows.AppendBody(first, api.RequestSide, []byte("user=a"))
	flows.EndMessage(first, api.RequestSide, history.HTTPEnd{State: api.CompleteHTTPState, Trailers: nil, Note: "", Edit: &history.HTTPEdit{Head: testRequest("POST", "/login").HTTPHead, URL: "", Body: []byte("user=admin"), Verdict: api.ForwardVerdict}})
	flows.AddHead(first, api.ResponseSide, api.HTTPMessage{HTTPHead: api.HTTPHead{Version: "HTTP/1.1", Status: 100, Reason: "Continue"}, State: api.CompleteHTTPState}, true)
	flows.AddHead(first, api.ResponseSide, api.HTTPMessage{HTTPHead: api.HTTPHead{Version: "HTTP/1.1", Status: 302, Reason: "Found"}, Framing: api.CloseFraming, State: api.HeadHTTPState}, false)
	flows.AppendBody(first, api.ResponseSide, bytes.Repeat([]byte("x"), 2000))
	flows.EndMessage(first, api.ResponseSide, history.HTTPEnd{State: api.IncompleteHTTPState, Trailers: nil, Note: "the stream ended before the message", Edit: nil})
	second := flows.OpenExchange(flowID, "HTTP/1.1", api.RequestSide, testRequest("GET", "/"))
	third := flows.OpenExchange(flowID, "HTTP/1.1", api.ResponseSide, api.HTTPMessage{HTTPHead: api.HTTPHead{Version: "HTTP/1.1", Status: 408}, State: api.HeadHTTPState})
	// over the flow's exchanges
	fourth := flows.OpenExchange(flowID, "HTTP/1.1", api.RequestSide, testRequest("GET", "/x"))
	exchange, found := flows.Exchange(first)
	body, original, isEdited, hasSide, _ := flows.ExchangeBody(first, api.RequestSide)
	responseBody, _, _, _, _ := flows.ExchangeBody(first, api.ResponseSide)

	if !found || (second == 0) || (third == 0) || (fourth != 0) || (len(exchange.Interim) != 1) || (exchange.Response.Status != 302) || (exchange.Response.State != api.IncompleteHTTPState) || (exchange.Response.BodyLength != 2000) || (exchange.Response.StoredLength >= 2000) ||
		!exchange.Request.Edited || (exchange.Request.Original == nil) || (exchange.Request.BodyLength != 10) || (exchange.Request.OriginalBodyLength != 6) || !isEdited || !hasSide || (string(body) != "user=admin") || (string(original) != "user=a") || (len(responseBody) != exchange.Response.StoredLength) {
		state.Errorf("Test of history.History exchanges failed, exchange: %+v, body: %q, original: %q, ids: %d %d %d %d", exchange, body, original, first, second, third, fourth)
		return
	}

	page, next, _ := flows.Exchanges(flowID, 0, 2)
	rest, last, _ := flows.Exchanges(flowID, next, 2)
	flow, _ := flows.Flow(flowID)

	if (len(page) != 2) || (next != second) || (len(rest) != 1) || (rest[0].Response.Status != 408) || (last != 0) || !flow.Truncated {
		state.Errorf("Test of history.History.Exchanges function failed, pages: %+v %+v, next: %d, flow: %+v", page, rest, next, flow)
		return
	}

	positiveCases := []struct {
		Filter   string
		Expected int
	}{
		{Filter: `http.request.method == "POST" && http.response.code == 302 && http.host == "example.com" && http.user_agent contains "curl"`, Expected: 1},
		{Filter: `http.request.uri in {"/" "/nothing"} && http.response.code == 408`, Expected: 1},
		{Filter: `http.request.method == "PUT"`, Expected: 0},
	}

	for _, positive := range positiveCases {
		parsed, err := filter.Parse(positive.Filter)
		matched, _ := flows.Flows(&parsed, 0, 10)

		if (err != nil) || (len(matched) != positive.Expected) {
			state.Errorf("Test of history.History.Flows function failed, %s should take %d flows, flows: %d, error: %v", positive.Filter, positive.Expected, len(matched), err)
			return
		}
	}

	exchangeEvents := 0

	for _, event := range recorded {
		if event.Type == api.ExchangeEventType {
			exchangeEvents++
		}
	}

	status := flows.Status()

	if (exchangeEvents != 7) || (status.Exchanges != 3) || (status.ExchangeBytes == 0) {
		state.Errorf("Test of history.History exchanges failed, there should be 7 exchange events and 3 exchanges, events: %d, status: %+v", exchangeEvents, status)
		return
	}

	// a closed flow evicted by a newer one takes its exchanges and their bytes along
	limits.Flows = 1
	flows = history.New(limits, nil)
	flowID = flows.OpenFlow(1, testValues(80, filter.AbsentTLSState), [32]byte{})
	first = flows.OpenExchange(flowID, "HTTP/1.1", api.RequestSide, testRequest("GET", "/"))
	flows.OpenFlow(2, testValues(81, filter.AbsentTLSState), [32]byte{})

	if _, found = flows.Exchange(first); found || (flows.Status().ExchangeBytes != 0) || (flows.Status().Exchanges != 0) {
		state.Errorf("Test of history.History exchanges failed, an evicted flow should take its exchanges, status: %+v", flows.Status())
	}
}
