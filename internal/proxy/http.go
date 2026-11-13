// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/http1"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// the body a message of layer http may have, a larger one goes on as its records with a note
	maxHTTPBodyBytes int = 1 << 20
	// the protocol of the exchanges of this layer
	http1Protocol string = "HTTP/1.1"
	// the ALPN protocol of HTTP/1.1, a TLS flow that agreed on another one (h2) is no HTTP/1
	http1ALPN string = "http/1.1"
	// the handshake message type of NewSessionTicket (RFC 8446 section 4)
	newSessionTicketType byte = 4
)

// the HTTP layer of the tcp flows in scope: their exchanges go into the history, and with Pipeline their whole messages go through the rules of layer http
// Timeout is how long a message may take to come whole once its first byte is kept back, the hold timeout of the API
type HTTPLayer struct {
	Pipeline *intercept.Pipeline
	Timeout  time.Duration
}

// the HTTP/1 layer of one tcp flow: both sides parse into one conn, which pairs the requests with their responses
// exchanges are the history's exchanges by the index of the conn, requests the filter fields of each request for its response
// the conn, the maps and isOff are shared by both directions under mutex; a side is used only by the sender of its direction
type httpFlow struct {
	mutex     *sync.Mutex
	conn      *http1.Conn
	flowID    uint64
	recorder  *history.History
	layer     HTTPLayer
	exchanges map[int]uint64
	requests  map[int]filter.HTTPValues
	isOff     bool
	sides     [2]httpSide
}

// one direction: offset is the stream offset of the next byte; kept are the bytes of the open message held back for the rules, from its first byte on, while isKeeping
// deadline ends the wait for the rest of a kept message
type httpSide struct {
	direction tlsrecord.Direction
	offset    int64
	kept      []byte
	isKeeping bool
	deadline  time.Time
	message   *httpMessage
}

// the open message of a side: its exchange and head once they are there, body the content while it is assembled for the rules, note why it is not taken as a whole
type httpMessage struct {
	index       int
	exchange    uint64
	head        http1.Head
	framing     http1.Framing
	isHead      bool
	isAssembled bool
	body        []byte
	note        string
}

// what one feed does: output goes on now, isWhole is true when it is exactly the bytes given, nothing kept back or replaced
type httpOutput struct {
	output  []byte
	isWhole bool
}

func newHTTPFlow(flowID uint64, recorder *history.History, layer HTTPLayer) (flow *httpFlow) {
	flow = &httpFlow{
		mutex:     &sync.Mutex{},
		conn:      http1.New(),
		flowID:    flowID,
		recorder:  recorder,
		layer:     layer,
		exchanges: map[int]uint64{},
		requests:  map[int]filter.HTTPValues{},
		isOff:     false,
		sides:     [2]httpSide{{direction: tlsrecord.ClientDirection}, {direction: tlsrecord.ServerDirection}},
	}
	return
}

// parse the next bytes of a direction, under the mutex; a TLS flow whose ALPN is not HTTP/1.1 is not parsed at all
func (httpFlow *httpFlow) parse(direction tlsrecord.Direction, data []byte, session tlsrecord.Session, isClose bool) (events []http1.Event, isOff bool) {
	httpFlow.mutex.Lock()
	defer httpFlow.mutex.Unlock()

	if !httpFlow.isOff && (session.Protocol != "") && (session.Protocol != http1ALPN) {
		httpFlow.isOff = true
	}

	isOff = httpFlow.isOff

	if isOff {
		return
	}

	if isClose {
		events = httpFlow.conn.Close(http1.Side(direction))
		return
	}

	events = httpFlow.conn.Feed(http1.Side(direction), data)
	return
}

// the next plaintext of a direction after the record rules; flow is the flow with its TLS session, canKeep is false for bytes that went on already
// a message of layer http is kept back from its first byte while a rule or the hold queue may want it, and goes on whole, edited or not, once it ends
func (httpFlow *httpFlow) feed(ctx context.Context, flow intercept.Flow, direction tlsrecord.Direction, data []byte, canKeep bool, logger *slog.Logger) (result httpOutput) {
	side := &httpFlow.sides[direction]
	start := side.offset
	side.offset += int64(len(data))
	events, isOff := httpFlow.parse(direction, data, flow.Session, false)

	if isOff {
		result = httpOutput{output: data, isWhole: true}
		return
	}

	result = httpFlow.handle(ctx, flow, side, events, data, start, canKeep, logger)
	return
}

// the stream of a direction ended: a body delimited by the end is whole now, a kept message that is not goes on as it came
func (httpFlow *httpFlow) close(ctx context.Context, flow intercept.Flow, direction tlsrecord.Direction, logger *slog.Logger) (output []byte) {
	side := &httpFlow.sides[direction]
	events, isOff := httpFlow.parse(direction, nil, flow.Session, true)

	if isOff {
		return
	}

	output = httpFlow.handle(ctx, flow, side, events, nil, side.offset, true, logger).output
	return
}

// the kept message waited too long for its end: what came of it goes on as it came, the rest follows as it comes
func (httpFlow *httpFlow) expire(direction tlsrecord.Direction, logger *slog.Logger) (output []byte) {
	side := &httpFlow.sides[direction]

	if !side.isKeeping || time.Now().Before(side.deadline) {
		return
	}

	output = httpFlow.release(side, fmt.Sprintf("not whole after %s, went on as it came", httpFlow.layer.Timeout), logger)
	return
}

// the kept message can't wait for its end any more, note says why
func (httpFlow *httpFlow) expireNow(direction tlsrecord.Direction, note string, logger *slog.Logger) (output []byte) {
	side := &httpFlow.sides[direction]

	if !side.isKeeping {
		return
	}

	output = httpFlow.release(side, note, logger)
	return
}

// the time the kept message of a direction may wait for its end, zero when nothing is kept
func (httpFlow *httpFlow) deadline(direction tlsrecord.Direction) (deadline time.Time) {
	side := &httpFlow.sides[direction]

	if side.isKeeping {
		deadline = side.deadline
	}

	return
}

// whether a direction keeps bytes back now
func (httpFlow *httpFlow) isKeeping(direction tlsrecord.Direction) (isKeeping bool) {
	isKeeping = httpFlow.sides[direction].isKeeping
	return
}

// the events of one feed in order: cursor is the stream offset up to which the bytes of data are decided, output what goes on of them and of the kept bytes before them
func (httpFlow *httpFlow) handle(ctx context.Context, flow intercept.Flow, side *httpSide, events []http1.Event, data []byte, start int64, canKeep bool, logger *slog.Logger) (result httpOutput) {
	isTouched := side.isKeeping
	cursor := start
	output := []byte(nil)

	for _, event := range events {
		switch event.Type {
		case http1.BeginEventType:
			side.message = &httpMessage{index: -1}
			pipeline := httpFlow.layer.Pipeline

			if canKeep && (pipeline != nil) && pipeline.Wants(intercept.HTTPLayer) {
				output = append(output, data[cursor-start:event.Start-start]...)
				cursor = event.Start
				side.kept = nil
				side.isKeeping = true
				side.deadline = time.Now().Add(httpFlow.layer.Timeout)
				isTouched = true
			}
		case http1.HeadEventType:
			output = append(output, httpFlow.head(flow, side, event, logger)...)
		case http1.BodyEventType:
			output = append(output, httpFlow.body(side, event.Data, logger)...)
		case http1.EndEventType:
			if side.isKeeping && (side.message != nil) && side.message.isAssembled && event.IsComplete {
				raw := append(side.kept, data[cursor-start:event.End-start]...)
				output = append(output, httpFlow.process(ctx, flow, side, raw, event, logger)...)
				cursor = event.End
				side.kept = nil
				side.isKeeping = false
				break
			}

			note := ""

			if !event.IsComplete {
				note = "the stream ended before the message"
			}

			output = append(output, httpFlow.release(side, note, logger)...)
			httpFlow.end(side, event, note)
		case http1.StopEventType:
			note := fmt.Sprintf("the stream is no HTTP/1 from here: %v", event.Err)
			output = append(output, httpFlow.release(side, note, logger)...)

			if (side.message != nil) && side.message.isHead {
				httpFlow.end(side, http1.Event{Type: http1.EndEventType, IsComplete: false}, note)
			}

			side.message = nil
			logger.Debug("Http layer stopped", "error", event.Err, "direction", intercept.DirectionName(side.direction))
		}
	}

	if side.isKeeping {
		side.kept = append(side.kept, data[cursor-start:]...)
	} else {
		output = append(output, data[cursor-start:]...)
	}

	result = httpOutput{output: output, isWhole: !isTouched}

	if result.isWhole {
		result.output = data
	}

	return
}

// a whole head: into the history, and a kept message stays kept only when a rule or the hold queue matches it
func (httpFlow *httpFlow) head(flow intercept.Flow, side *httpSide, event http1.Event, logger *slog.Logger) (output []byte) {
	message := side.message
	message.index = event.Index
	message.head = event.Head
	message.framing = event.Framing
	message.isHead = true
	view := httpFlow.view(flow, event.Head, event.Framing)
	httpFlow.mutex.Lock()
	exchange, isKnown := httpFlow.exchanges[event.Index]

	if side.direction == tlsrecord.ClientDirection {
		httpFlow.requests[event.Index] = requestValues(event.Head)
	}

	httpFlow.mutex.Unlock()

	switch {
	case side.direction == tlsrecord.ClientDirection:
		exchange = httpFlow.recorder.OpenExchange(httpFlow.flowID, http1Protocol, api.RequestSide, view)
	case !isKnown:
		exchange = httpFlow.recorder.OpenExchange(httpFlow.flowID, http1Protocol, api.ResponseSide, view)
	default:
		httpFlow.recorder.AddHead(exchange, api.ResponseSide, view, event.IsInterim)
	}

	if !event.IsInterim {
		message.exchange = exchange
	}

	httpFlow.mutex.Lock()
	httpFlow.exchanges[event.Index] = exchange
	httpFlow.mutex.Unlock()

	if !side.isKeeping {
		return
	}

	if event.IsInterim || !httpFlow.layer.Pipeline.Matches(httpFlow.message(flow, side, event.Head.Raw, false)) {
		output = httpFlow.release(side, "", logger)
		return
	}

	message.isAssembled = true
	return
}

// body bytes: kept with the message while it is assembled, a body over the limit goes on as it came; otherwise into the history at once
func (httpFlow *httpFlow) body(side *httpSide, data []byte, logger *slog.Logger) (output []byte) {
	message := side.message

	if (message == nil) || (len(data) == 0) {
		return
	}

	if !message.isAssembled {
		httpFlow.recorder.AppendBody(message.exchange, sideOf(side.direction), data)
		return
	}

	message.body = append(message.body, data...)

	if len(message.body) > maxHTTPBodyBytes {
		output = httpFlow.release(side, fmt.Sprintf("the body is larger than %d bytes, it went on as it came, the record layer still sees it", maxHTTPBodyBytes), logger)
	}

	return
}

// the kept bytes go on as they came and the message is no longer assembled: its body so far goes into the history, the rest of it as it comes
func (httpFlow *httpFlow) release(side *httpSide, note string, logger *slog.Logger) (output []byte) {
	message := side.message

	if message != nil {
		if message.isAssembled {
			httpFlow.recorder.AppendBody(message.exchange, sideOf(side.direction), message.body)
			message.body = nil
			message.isAssembled = false
		}

		if note != "" {
			message.note = note
			logger.Info("Http message left to the record layer", "reason", note, "exchangeID", message.exchange, "direction", intercept.DirectionName(side.direction))
		}
	}

	output = side.kept
	side.kept = nil
	side.isKeeping = false
	return
}

// the message ended without the rules: complete or not, with its trailers
func (httpFlow *httpFlow) end(side *httpSide, event http1.Event, note string) {
	message := side.message

	if (message == nil) || !message.isHead {
		return
	}

	state := api.CompleteHTTPState

	if !event.IsComplete {
		state = api.IncompleteHTTPState
	}

	if message.note != "" {
		note = message.note
	}

	httpFlow.recorder.EndMessage(message.exchange, sideOf(side.direction), history.HTTPEnd{State: state, Trailers: headersOf(event.Trailers), Note: note, Edit: nil})
	httpFlow.forget(side, message)
	side.message = nil
}

// a response is the last message of its exchange, the conn's index of it is not needed any more
func (httpFlow *httpFlow) forget(side *httpSide, message *httpMessage) {
	if (side.direction != tlsrecord.ServerDirection) || (message.head.Status < 200) {
		return
	}

	httpFlow.mutex.Lock()
	defer httpFlow.mutex.Unlock()
	delete(httpFlow.exchanges, message.index)
	delete(httpFlow.requests, message.index)
}

// a whole assembled message through the rules of layer http: unchanged it goes on as it came, edited it is rebuilt, dropped nothing goes on
func (httpFlow *httpFlow) process(ctx context.Context, flow intercept.Flow, side *httpSide, raw []byte, event http1.Event, logger *slog.Logger) (wire []byte) {
	message := side.message
	original := http1.Message{Head: message.head, Framing: message.framing, Body: message.body, TrailerRaw: event.TrailerRaw, Raw: raw}
	form := original.Form()
	result := httpFlow.layer.Pipeline.Process(ctx, httpFlow.message(flow, side, form, true), logger)
	sideName := sideOf(side.direction)
	httpFlow.recorder.AppendBody(message.exchange, sideName, message.body)
	end := history.HTTPEnd{State: api.CompleteHTTPState, Trailers: headersOf(event.Trailers), Note: message.note, Edit: nil}

	switch {
	case result.Verdict == intercept.DropVerdict:
		end.Edit = &history.HTTPEdit{Head: api.HTTPHead{}, URL: "", Body: nil, Verdict: api.DropVerdict}

		// the server never sees a dropped request, the next response answers the request after it
		if side.direction == tlsrecord.ClientDirection {
			httpFlow.mutex.Lock()
			httpFlow.conn.Cancel(message.index)
			httpFlow.mutex.Unlock()
		}
	case !result.Changed:
		wire = raw
	default:
		rebuilt := http1.Rebuild(original, result.Plain)
		wire = rebuilt.Wire
		head, body := rebuilt.Head, rebuilt.Body

		if rebuilt.Err != nil {
			end.Note = fmt.Sprintf("the edit is no HTTP/1 message (%v), it went on as it was written", rebuilt.Err)
			logger.Warn("Http message edit went on as written", "error", rebuilt.Err, "exchangeID", message.exchange)
			head, body = message.head, result.Plain
		}

		if (side.direction == tlsrecord.ClientDirection) && (rebuilt.Err == nil) && (head.Method != message.head.Method) {
			httpFlow.mutex.Lock()
			httpFlow.conn.SetMethod(message.index, head.Method)
			httpFlow.mutex.Unlock()
		}

		view := httpFlow.view(flow, head, message.framing)
		end.Edit = &history.HTTPEdit{Head: view.HTTPHead, URL: view.URL, Body: body, Verdict: api.ForwardVerdict}
	}

	httpFlow.recorder.EndMessage(message.exchange, sideName, end)
	httpFlow.forget(side, message)
	side.message = nil
	return
}

// the intercept message of the open message of a side: Plain is its form, the filter sees the fields of its request and a response its status too
// isNext gives it the next message id, a message only asked whether a rule matches it needs none
func (httpFlow *httpFlow) message(flow intercept.Flow, side *httpSide, form []byte, isNext bool) (message intercept.Message) {
	values := requestValues(side.message.head)

	if side.direction == tlsrecord.ServerDirection {
		httpFlow.mutex.Lock()
		values = httpFlow.requests[side.message.index]
		httpFlow.mutex.Unlock()
		values.Codes = []uint16{uint16(side.message.head.Status)}
	}

	flow.Values.HTTP = &values

	if isNext {
		message = httpFlow.layer.Pipeline.Message(flow, side.direction, intercept.HTTPLayer, form)
	} else {
		message = intercept.Message{Flow: flow, ID: 0, Direction: side.direction, Layer: intercept.HTTPLayer, Plain: form, Exchange: 0}
	}

	message.Exchange = side.message.exchange
	return
}

// the filter fields of a request
func requestValues(head http1.Head) (values filter.HTTPValues) {
	values = filter.HTTPValues{Methods: nil, URIs: nil, Hosts: nil, Codes: nil, UserAgents: nil}

	if head.Method == "" {
		return
	}

	values.Methods = []string{head.Method}
	values.URIs = []string{head.Target}

	if host, found := head.Get("Host"); found {
		values.Hosts = []string{host}
	}

	if agent, found := head.Get("User-Agent"); found {
		values.UserAgents = []string{agent}
	}

	return
}

// the API's view of a head, URL from the scheme of the flow, the Host field (or the destination) and an origin-form target
func (httpFlow *httpFlow) view(flow intercept.Flow, head http1.Head, framing http1.Framing) (message api.HTTPMessage) {
	message = api.HTTPMessage{
		HTTPHead: api.HTTPHead{
			Method:  head.Method,
			Target:  head.Target,
			Version: head.Version,
			Status:  head.Status,
			Reason:  head.Reason,
			Headers: headersOf(head.Headers),
		},
		URL:     "",
		Time:    time.Now(),
		Framing: api.Framing(framing),
		State:   api.HeadHTTPState,
	}

	if message.Headers == nil {
		message.Headers = []api.Header{}
	}

	switch {
	case strings.HasPrefix(head.Target, "/"):
		scheme := "http"

		if flow.Session.Version != 0 {
			scheme = "https"
		}

		host, found := head.Get("Host")

		if !found {
			destination := flow.Destination
			host = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port()).String()
		}

		message.URL = scheme + "://" + host + head.Target
	case strings.Contains(head.Target, "://"):
		message.URL = head.Target
	default:
	}

	return
}

func headersOf(headers []http1.Header) (views []api.Header) {
	for _, header := range headers {
		views = append(views, api.Header{Name: header.Name, Value: header.Value})
	}

	return
}

func sideOf(direction tlsrecord.Direction) (side api.Side) {
	side = api.RequestSide

	if direction == tlsrecord.ServerDirection {
		side = api.ResponseSide
	}

	return
}

// a TLS 1.3 handshake record that holds only NewSessionTicket messages: it changes no keys, held HTTP bytes may go on after it
func isTicketRecord(record tlsrecord.Record) (isTicket bool) {
	isTicket = (record.ContentType == tlsrecord.HandshakeContentType) && (len(record.Payload) > 0) && bytes.Equal(record.Payload[:1], []byte{newSessionTicketType})
	return
}
