// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/ui"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func writeJSONAnswer(state *testing.T, writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", jsonMediaType)
	writer.WriteHeader(status)

	if encodeErr := json.NewEncoder(writer).Encode(value); encodeErr != nil {
		state.Errorf("Could not write the fake api answer, error: %s", encodeErr.Error())
	}
}

// Test if every tool returns a tool error with the api's message when the api answers each request with 500.
func TestToolsAPIErrorNegative(state *testing.T) {
	target := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		writeJSONAnswer(state, writer, http.StatusInternalServerError, v1.Error{Error: "boom"})
	})
	session := connect(state, target, state.TempDir(), true)
	negativeCases := []struct {
		Name      string
		Arguments map[string]any
	}{
		{Name: "status", Arguments: nil},
		{Name: "list_flows", Arguments: map[string]any{"filter": "tls", "cursor": "c1"}},
		{Name: "get_flow", Arguments: map[string]any{"id": 1}},
		{Name: "list_messages", Arguments: map[string]any{"flow_id": 1, "cursor": "c1"}},
		{Name: "get_message", Arguments: map[string]any{"id": 1}},
		{Name: "list_exchanges", Arguments: map[string]any{"flow_id": 1, "cursor": "c1"}},
		{Name: "get_exchange", Arguments: map[string]any{"id": 1}},
		{Name: "get_exchange_body", Arguments: map[string]any{"id": 1}},
		{Name: "tail_events", Arguments: map[string]any{"seconds": 1}},
		{Name: "list_held", Arguments: nil},
		{Name: "list_rules", Arguments: nil},
		{Name: "export_keylog", Arguments: map[string]any{"filter": "tls"}},
		{Name: "export_pcap", Arguments: map[string]any{"filter": "tls", "format": "plaintext"}},
		{Name: "list_captures", Arguments: nil},
		{Name: "download_pcap", Arguments: map[string]any{"id": 1}},
		{Name: "set_intercept", Arguments: map[string]any{"enabled": true}},
		{Name: "edit_held", Arguments: map[string]any{"id": 1, "payload": "x"}},
		{Name: "forward_held", Arguments: map[string]any{"id": 1}},
		{Name: "drop_held", Arguments: map[string]any{"id": 1}},
		{Name: "delete_rule", Arguments: map[string]any{"id": 1}},
		{Name: "stop_capture", Arguments: map[string]any{"id": 1}},
	}

	for _, negative := range negativeCases {
		text, isError := call(state, session, negative.Name, negative.Arguments, nil)

		if !isError || !strings.Contains(text, "500 Internal Server Error: boom") {
			state.Errorf("Test of %s failed, %v should be a tool error with the api's message, error: %t, text: %s", negative.Name, negative.Arguments, isError, text)
			return
		}
	}
}

// Test if the tools that decode a payload return a tool error when the api sends one that is not hex, in the payload or in the original.
func TestToolsHexNegative(state *testing.T) {
	good := v1.Payload{Offset: 0, Length: 1, Total: 1, Hex: "41", Escaped: "A"}
	bad := v1.Payload{Offset: 0, Length: 1, Total: 1, Hex: "zz", Escaped: "?"}
	target := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "GET /api/v1/messages/1":
			writeJSONAnswer(state, writer, http.StatusOK, v1.MessageDetail{Message: v1.Message{ID: 1}, Payload: bad, Original: nil})
		case "GET /api/v1/messages/2":
			writeJSONAnswer(state, writer, http.StatusOK, v1.MessageDetail{Message: v1.Message{ID: 2}, Payload: good, Original: &bad})
		case "GET /api/v1/exchanges/1/body":
			writeJSONAnswer(state, writer, http.StatusOK, v1.ExchangeBody{ExchangeID: 1, Side: v1.RequestSide, Payload: bad, Original: nil})
		case "GET /api/v1/exchanges/2/body":
			writeJSONAnswer(state, writer, http.StatusOK, v1.ExchangeBody{ExchangeID: 2, Side: v1.RequestSide, Payload: good, Original: &bad})
		case "GET /api/v1/holds":
			writeJSONAnswer(state, writer, http.StatusOK, v1.HoldList{Holds: []v1.Hold{{ID: 1, Payload: &bad}}})
		case "PUT /api/v1/holds/1":
			writeJSONAnswer(state, writer, http.StatusOK, v1.Hold{ID: 1, Payload: &bad})
		default:
			writeJSONAnswer(state, writer, http.StatusNotFound, v1.Error{Error: "not found"})
		}
	})
	session := connect(state, target, state.TempDir(), true)
	negativeCases := []struct {
		Name      string
		Arguments map[string]any
	}{
		{Name: "get_message", Arguments: map[string]any{"id": 1}},
		{Name: "get_message", Arguments: map[string]any{"id": 2}},
		{Name: "get_exchange_body", Arguments: map[string]any{"id": 1}},
		{Name: "get_exchange_body", Arguments: map[string]any{"id": 2}},
		{Name: "list_held", Arguments: nil},
		{Name: "edit_held", Arguments: map[string]any{"id": 1, "payload": "x"}},
	}

	for _, negative := range negativeCases {
		text, isError := call(state, session, negative.Name, negative.Arguments, nil)

		if !isError || !strings.Contains(text, ErrHex.Error()) {
			state.Errorf("Test of %s failed, %v should be a tool error with %q, error: %t, text: %s", negative.Name, negative.Arguments, ErrHex, isError, text)
			return
		}
	}
}

// Test if the read tools pass the cursors, the filter of export_pcap and the default side of get_exchange_body to the api, list a held message without a payload and join the notes of an exchange.
func TestReadToolsArgumentsPositive(state *testing.T) {
	target := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()

		switch request.URL.Path {
		case "/api/v1/flows":
			if query.Get("cursor") != "c1" {
				writeJSONAnswer(state, writer, http.StatusBadRequest, v1.Error{Error: "no cursor"})
				return
			}

			writeJSONAnswer(state, writer, http.StatusOK, v1.FlowList{Flows: []v1.Flow{}, NextCursor: ""})
		case "/api/v1/flows/1/messages":
			if query.Get("cursor") != "c2" {
				writeJSONAnswer(state, writer, http.StatusBadRequest, v1.Error{Error: "no cursor"})
				return
			}

			writeJSONAnswer(state, writer, http.StatusOK, v1.MessageList{Messages: []v1.Message{}})
		case "/api/v1/flows/1/exchanges":
			if query.Get("cursor") != "c3" {
				writeJSONAnswer(state, writer, http.StatusBadRequest, v1.Error{Error: "no cursor"})
				return
			}

			writeJSONAnswer(state, writer, http.StatusOK, v1.ExchangeList{Exchanges: []v1.Exchange{{ID: 4, FlowID: 1, Protocol: "HTTP/1.1", Request: &v1.HTTPMessage{HTTPHead: v1.HTTPHead{Method: "GET"}, Note: "request note"}, Response: &v1.HTTPMessage{HTTPHead: v1.HTTPHead{Status: 200}, Note: "response note"}}}})
		case "/api/v1/exchanges/4/body":
			if query.Get("side") != string(v1.RequestSide) {
				writeJSONAnswer(state, writer, http.StatusBadRequest, v1.Error{Error: "side " + query.Get("side")})
				return
			}

			writeJSONAnswer(state, writer, http.StatusOK, v1.ExchangeBody{ExchangeID: 4, Side: v1.RequestSide, Payload: v1.Payload{Offset: 0, Length: 1, Total: 1, Hex: "41", Escaped: "A"}, Original: nil})
		case "/api/v1/holds":
			writeJSONAnswer(state, writer, http.StatusOK, v1.HoldList{Holds: []v1.Hold{{ID: 5, FlowID: 1, Length: 3, Payload: nil}}})
		case "/api/v1/flows/pcap":
			if query.Get("filter") != "tls" {
				writeJSONAnswer(state, writer, http.StatusBadRequest, v1.Error{Error: "no filter"})
				return
			}

			writer.Header().Set("Content-Type", pcapngMediaType)

			if _, writeErr := io.WriteString(writer, testPcapng); writeErr != nil {
				state.Errorf("Could not write the fake api answer, error: %s", writeErr.Error())
			}
		default:
			writeJSONAnswer(state, writer, http.StatusNotFound, v1.Error{Error: "not found " + request.URL.Path})
		}
	})
	session := connect(state, target, state.TempDir(), false)
	positiveCases := []struct {
		Name      string
		Arguments map[string]any
		Text      string
	}{
		{Name: "list_flows", Arguments: map[string]any{"cursor": "c1"}, Text: `{"flows":[]}`},
		{Name: "list_messages", Arguments: map[string]any{"flow_id": 1, "cursor": "c2"}, Text: ""},
		{Name: "list_exchanges", Arguments: map[string]any{"flow_id": 1, "cursor": "c3"}, Text: `"note":"request: request note; response: response note"`},
		{Name: "get_exchange_body", Arguments: map[string]any{"id": 4}, Text: `<untrusted-traffic id="x4-request">`},
		{Name: "list_held", Arguments: nil, Text: `"id":5`},
		{Name: "export_pcap", Arguments: map[string]any{"filter": "tls"}, Text: ""},
	}

	for _, positive := range positiveCases {
		text, isError := call(state, session, positive.Name, positive.Arguments, nil)

		if isError || !strings.Contains(text, positive.Text) {
			state.Errorf("Test of %s failed, %v should succeed with %q, error: %t, text: %s", positive.Name, positive.Arguments, positive.Text, isError, text)
			return
		}
	}

	// a result without traffic data has no note
	text, isError := call(state, session, "list_flows", map[string]any{"cursor": "c1"}, nil)

	if isError || (text != "{\"flows\":[]}\n") {
		state.Errorf("Test of list_flows failed, an empty page should be its JSON alone, text: %q", text)
		return
	}

	// the held message without a payload has none and is not omitted
	held := HeldResult{}
	_, isError = call(state, session, "list_held", nil, &held)

	if isError || (len(held.Holds) != 1) || (held.Holds[0].Payload != nil) || held.Holds[0].PayloadOmitted {
		state.Errorf("Test of list_held failed, a hold without a payload should have none and not be omitted, holds: %+v", held.Holds)
		return
	}
}

// Test if tail_events returns with the expected output: an overflow event ends the tail and is kept, an exchange event is escaped with its 1xx and original heads, a stream decerter ends is closed.
func TestTailEventsStopPositive(state *testing.T) {
	mutex := &sync.Mutex{}
	requests := 0
	exchange := v1.Exchange{ID: 1, FlowID: 1, Protocol: "HTTP/1.1\x00", Request: &v1.HTTPMessage{HTTPHead: v1.HTTPHead{Method: "GET", Target: "/\x1b", Headers: nil}, Original: &v1.HTTPHead{Method: "POST\x00"}}, Interim: []v1.HTTPMessage{{HTTPHead: v1.HTTPHead{Status: 103, Reason: "Early\x01"}}}}
	target := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		requests++
		current := requests
		mutex.Unlock()
		events := []v1.Event{{Seq: 1, Type: v1.ExchangeEventType, Exchange: &exchange}, {Seq: 2, Type: v1.OverflowEventType, Reason: "slow reader"}, {Seq: 3, Type: v1.RuleAddedEventType}}

		// the second stream ends after one event, as when decerter stops
		if current > 1 {
			events = []v1.Event{{Seq: 1, Type: v1.RuleDeletedEventType}}
		}

		var body strings.Builder

		for _, event := range events {
			data, _ := json.Marshal(event)
			body.WriteString("data: " + string(data) + "\n\n")
		}

		writer.Header().Set("Content-Type", eventMediaType)

		if _, writeErr := io.WriteString(writer, body.String()); writeErr != nil {
			state.Errorf("Could not write the fake api answer, error: %s", writeErr.Error())
		}
	})
	session := connect(state, target, state.TempDir(), false)
	events := struct {
		Events  []v1.Event `json:"events"`
		Stopped StopReason `json:"stopped"`
	}{}
	_, isError := call(state, session, "tail_events", map[string]any{"seconds": 5, "full": true}, &events)

	if isError || (events.Stopped != OverflowStopReason) || (len(events.Events) != 2) || (events.Events[1].Type != v1.OverflowEventType) {
		state.Errorf("Test of tail_events failed, an overflow should end the tail and be kept, events: %+v", events)
		return
	}

	escaped := events.Events[0].Exchange

	if (escaped == nil) || (escaped.Protocol != `HTTP/1.1\x00`) || (escaped.Request.Target != `/\x1b`) || (escaped.Request.Headers == nil) || (escaped.Request.Original == nil) || (escaped.Request.Original.Method != `POST\x00`) || (len(escaped.Interim) != 1) || (escaped.Interim[0].Reason != `Early\x01`) {
		state.Errorf("Test of tail_events failed, the exchange event should be escaped with its 1xx and original heads, exchange: %+v", escaped)
		return
	}

	short := struct {
		Events  []EventSummary `json:"events"`
		Stopped StopReason     `json:"stopped"`
	}{}
	_, isError = call(state, session, "tail_events", map[string]any{"seconds": 5}, &short)

	if isError || (short.Stopped != ClosedStopReason) || (len(short.Events) != 1) || (short.Events[0].Type != v1.RuleDeletedEventType) {
		state.Errorf("Test of tail_events failed, a stream decerter ends should stop the tail as closed, events: %+v", short)
		return
	}
}

// closes responded once the api answered the first request, its body is still open
type respondedTransport struct {
	next      http.RoundTripper
	responded chan struct{}
	once      *sync.Once
}

func (transport respondedTransport) RoundTrip(request *http.Request) (response *http.Response, err error) {
	response, err = transport.next.RoundTrip(request)
	transport.once.Do(func() {
		close(transport.responded)
	})
	return
}

// Test if mcp.tailEvents returns with the expected errors: the caller going away while the stream runs is its context's error, not a result.
func TestTailEventsNegative(state *testing.T) {
	target := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", eventMediaType)
		writer.WriteHeader(http.StatusOK)

		if flushErr := http.NewResponseController(writer).Flush(); flushErr != nil {
			state.Errorf("Could not flush the fake api answer, error: %s", flushErr.Error())
		}

		<-request.Context().Done()
	})
	client := NewClient(target)
	responded := make(chan struct{})
	client.client.Transport = respondedTransport{next: client.client.Transport, responded: responded, once: &sync.Once{}}
	ctx, cancel := context.WithCancel(state.Context())
	defer cancel()

	// the caller goes away once the stream runs
	go func() {
		select {
		case <-responded:
		case <-time.After(10 * time.Second):
		}

		cancel()
	}()

	result, events, err := tailEvents(client)(ctx, nil, TailEventsInput{Seconds: 30, MaxEvents: 10, Types: nil, Full: false})

	if !errors.Is(err, context.Canceled) || (result != nil) || (events != nil) {
		state.Errorf("Test of mcp.tailEvents function failed, a caller that went away should be %v, events: %+v, error: %v", context.Canceled, events, err)
		return
	}
}

// Test if mcp.addTool returns with the expected errors: an input type without a schema, an integer or enum property the input does not have.
func TestAddToolNegative(state *testing.T) {
	server, err := NewServer(NewClient(ui.Target{Network: ui.UnixNetwork, Address: "/missing.sock"}), Output{root: nil, directory: ""}, false, slog.New(slog.DiscardHandler))

	if err != nil {
		state.Fatalf("Could not make the mcp server, error: %s", err.Error())
	}

	handle := func(ctx context.Context, request *sdk.CallToolRequest, input ListFlowsInput) (result *sdk.CallToolResult, output NoInput, err error) {
		return
	}
	negativeCases := []struct {
		Name     string
		Integers []integerProperty
		Enums    []enumProperty
		Text     string
	}{
		{Name: "integer", Integers: []integerProperty{{Name: "offset", Minimum: 0, Maximum: -1, Default: 0}}, Enums: nil, Text: "tool test: no property offset"},
		{Name: "enum", Integers: nil, Enums: []enumProperty{{Name: "side", Values: []any{"a"}}}, Text: "tool test: no property side"},
		{Name: "nested enum", Integers: nil, Enums: []enumProperty{{Name: "find.type", Values: []any{"a"}}}, Text: "tool test: no property find.type"},
	}

	for _, negative := range negativeCases {
		err = addTool(server, readTool("test", "Test", "a test"), handle, negative.Integers, negative.Enums)

		if (err == nil) || (err.Error() != negative.Text) {
			state.Errorf("Test of mcp.addTool function failed, %s, error should be %q, error: %v", negative.Name, negative.Text, err)
			return
		}
	}

	channelHandle := func(ctx context.Context, request *sdk.CallToolRequest, input chan int) (result *sdk.CallToolResult, output NoInput, err error) {
		return
	}
	err = addTool(server, readTool("channel", "Channel", "a test"), channelHandle, nil, nil)

	if (err == nil) || !strings.HasPrefix(err.Error(), "tool channel: ") {
		state.Errorf("Test of mcp.addTool function failed, an input without a schema should fail, error: %v", err)
		return
	}
}
