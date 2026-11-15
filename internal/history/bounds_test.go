// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package history_test

import (
	"testing"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// Test if the exchanges of history.History return with the expected output for a nil history, id 0, empty data and exchanges, flows or sides it
// doesn't have: nothing is recorded or published.
func TestExchangesNegative(state *testing.T) {
	var nilHistory *history.History

	if id := nilHistory.OpenExchange(1, "HTTP/1.1", api.RequestSide, testRequest("GET", "/")); id != 0 {
		state.Errorf("Test of history.History.OpenExchange function failed, a nil history should give 0, id: %d", id)
		return
	}

	nilHistory.AddHead(1, api.ResponseSide, testRequest("GET", "/"), false)
	nilHistory.AppendBody(1, api.RequestSide, []byte("x"))
	nilHistory.AppendGRPC(1, api.RequestSide, []api.GRPCMessage{{Offset: 0, Length: 1, Compressed: false}})
	nilHistory.EndMessage(1, api.RequestSide, history.HTTPEnd{State: api.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	events := 0
	flows := history.New(history.DefaultLimits(), func(event api.Event) {
		if event.Type == api.ExchangeEventType {
			events++
		}
	})
	flowID := flows.OpenFlow(1, testValues(80, filter.AbsentTLSState), [32]byte{})
	id := flows.OpenExchange(flowID, "HTTP/1.1", api.RequestSide, testRequest("GET", "/"))
	before, _ := flows.Exchange(id)

	if unknown := flows.OpenExchange(flowID+1, "HTTP/1.1", api.RequestSide, testRequest("GET", "/")); (id == 0) || (unknown != 0) {
		state.Errorf("Test of history.History.OpenExchange function failed, an unknown flow should give 0, ids: %d %d", id, unknown)
		return
	}

	// ids 0 and unknown, empty data, the response side the exchange doesn't have
	for _, exchangeID := range []uint64{0, id + 1} {
		flows.AddHead(exchangeID, api.ResponseSide, testRequest("GET", "/"), false)
		flows.EndMessage(exchangeID, api.RequestSide, history.HTTPEnd{State: api.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	}

	flows.AppendBody(id, api.RequestSide, nil)
	flows.AppendBody(id+1, api.RequestSide, []byte("x"))
	flows.AppendBody(id, api.ResponseSide, []byte("x"))
	flows.AppendGRPC(id, api.RequestSide, nil)
	flows.AppendGRPC(id+1, api.RequestSide, []api.GRPCMessage{{Offset: 0, Length: 1, Compressed: false}})
	flows.EndMessage(id, api.ResponseSide, history.HTTPEnd{State: api.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	after, _ := flows.Exchange(id)

	if (events != 1) || (after.Response != nil) || (after.Request.BodyLength != before.Request.BodyLength) || (len(after.Request.GRPCMessages) != 0) {
		state.Errorf("Test of history.History exchanges failed, nothing should change after the first event, events: %d, exchange: %+v", events, after)
		return
	}

	exchanges, next, found := flows.Exchanges(flowID+1, 0, 10)

	if found || (len(exchanges) != 0) || (next != 0) {
		state.Errorf("Test of history.History.Exchanges function failed, an unknown flow should not be found, exchanges: %+v", exchanges)
		return
	}

	_, _, _, hasSide, found := flows.ExchangeBody(id+1, api.RequestSide)

	if found || hasSide {
		state.Errorf("Test of history.History.ExchangeBody function failed, an unknown exchange should not be found")
		return
	}

	body, original, isEdited, hasSide, found := flows.ExchangeBody(id, api.ResponseSide)

	if !found || hasSide || (body != nil) || (original != nil) || isEdited {
		state.Errorf("Test of history.History.ExchangeBody function failed, a side without a message should be found without it, found: %v, hasSide: %v", found, hasSide)
		return
	}
}

// Test if history.History keeps its bounds when the only flow is the one over them: it is never evicted for itself, its exchange or message is not
// kept and the flow is truncated; a head is kept even over the bytes.
func TestOwnLimitsPositive(state *testing.T) {
	limits := history.Limits{Flows: 0, Messages: 1, FlowMessages: 10, PayloadBytes: 4, FlowPayloadBytes: 100, Exchanges: 1, FlowExchanges: 10, ExchangeBytes: 10, FlowExchangeBytes: 100}
	flows := history.New(limits, nil)
	// a limit of 0 flows keeps the newest one
	first := flows.OpenFlow(1, testValues(80, filter.AbsentTLSState), [32]byte{})
	flowID := flows.OpenFlow(2, testValues(81, filter.AbsentTLSState), [32]byte{})

	if _, found := flows.Flow(first); found || (flows.Status().Flows != 1) {
		state.Errorf("Test of history.History.OpenFlow function failed, only the newest flow should stay, status: %+v", flows.Status())
		return
	}

	id := flows.OpenExchange(flowID, "HTTP/1.1", api.RequestSide, testRequest("GET", "/"))
	over := flows.OpenExchange(flowID, "HTTP/1.1", api.RequestSide, testRequest("GET", "/x"))
	exchange, found := flows.Exchange(id)

	if (id == 0) || (over != 0) || !found || (exchange.Request == nil) || (flows.Status().ExchangeBytes <= limits.ExchangeBytes) {
		state.Errorf("Test of history.History.OpenExchange function failed, one exchange with its head over the bytes should stay, ids: %d %d, status: %+v", id, over, flows.Status())
		return
	}

	flows.Record(testMessage(flowID, 1, tlsrecord.ClientDirection, "abcdef"), forward("abcdef"), intercept.RulesOrigin)
	flows.Record(testMessage(flowID, 2, tlsrecord.ServerDirection, "gh"), forward("gh"), intercept.RulesOrigin)
	flow, _ := flows.Flow(flowID)
	status := flows.Status()

	if !flow.Truncated || (status.Messages != 1) || (status.PayloadBytes != limits.PayloadBytes) || (status.EvictedFlows != 1) {
		state.Errorf("Test of history.History.Record function failed, one message cut to the payload bytes should stay, flow: %+v, status: %+v", flow, status)
		return
	}
}

// Test if history.History evicts the oldest flow that is not the one recording, also when that is not the first flow.
func TestEvictPositive(state *testing.T) {
	limits := history.Limits{Flows: 10, Messages: 1, FlowMessages: 10, PayloadBytes: 100, FlowPayloadBytes: 100, Exchanges: 10, FlowExchanges: 10, ExchangeBytes: 10000, FlowExchangeBytes: 10000}
	flows := history.New(limits, nil)
	oldest := flows.OpenFlow(1, testValues(80, filter.AbsentTLSState), [32]byte{})
	newer := flows.OpenFlow(2, testValues(81, filter.AbsentTLSState), [32]byte{})
	newest := flows.OpenFlow(3, testValues(82, filter.AbsentTLSState), [32]byte{})
	flows.Record(testMessage(newer, 1, tlsrecord.ClientDirection, "a"), forward("a"), intercept.RulesOrigin)
	// the oldest flow records, the newer one goes for it
	flows.Record(testMessage(oldest, 2, tlsrecord.ClientDirection, "b"), forward("b"), intercept.RulesOrigin)
	_, isOldest := flows.Flow(oldest)
	_, isNewer := flows.Flow(newer)
	_, isNewest := flows.Flow(newest)
	page, _ := flows.Flows(nil, 0, 10)

	if !isOldest || isNewer || !isNewest || (len(page) != 2) || (page[0].ID != newest) || (page[1].ID != oldest) || (flows.Status().Messages != 1) {
		state.Errorf("Test of history.History evict failed, the newer flow should be evicted, flows: %v %v %v, page: %d, status: %+v", isOldest, isNewer, isNewest, len(page), flows.Status())
		return
	}
}
