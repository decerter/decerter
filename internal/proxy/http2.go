// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/http2"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// the protocol of the exchanges of HTTP/2 flows
	http2Protocol string = "HTTP/2"
	// the ALPN protocol of HTTP/2 over TLS
	http2ALPN string = "h2"
	// a flow without ALPN waits for the client's first bytes to tell the HTTP/2 preface from HTTP/1, the server's bytes before them are copied up to this
	maxUndecidedBytes int = 64 << 10
	// the note of the request of a stream a rule or hold of layer http dropped
	http2DropNote string = "a rule or hold of layer http dropped a message of the stream, both peers that knew it got RST_STREAM (CANCEL)"
)

// the note of the request of a stream the editor refused
var http2RefusedNote = fmt.Sprintf("decerter refused the stream: it waited to open behind a kept message with more than %d bytes of DATA waiting, the client got RST_STREAM (REFUSED_STREAM) and may send it again", http2.MaxGatedData)

// which protocol the HTTP layer reads on a flow: decided by the ALPN of a TLS session, or by the client's first bytes (the HTTP/2 preface or not) without one
type httpVersion string

const (
	undecidedHTTPVersion httpVersion = "undecided"
	http1HTTPVersion     httpVersion = "http/1"
	http2HTTPVersion     httpVersion = "http/2"
	// another ALPN protocol, not read at all
	offHTTPVersion httpVersion = "off"
)

// the HTTP/2 layer of one tcp flow: the conn reads the frames of both peers, its streams become exchanges of the history
// with a pipeline the editor carries the frames: whole messages of layer http are kept back on their stream, go through the rules (a hold on its own goroutine) and on as they came, edited or not at all
// notify tells the sender of a direction that the editor has frames for it outside of its feeds; processing counts the messages of each direction a rule holds now
// the mutex orders both directions, the conn, the editor and the streams
type http2Flow struct {
	mutex      *sync.Mutex
	conn       *http2.Conn
	editor     *http2.Editor
	flowID     uint64
	recorder   *history.History
	layer      HTTPLayer
	streams    map[uint32]*http2Exchange
	notify     func(direction tlsrecord.Direction)
	processing [2]int
	isFailed   bool
}

// the exchange of an open stream: id in the history (0 when it keeps no more), how each side ended, the notes each side gets at its end, the filter fields of its request
// kept are the messages of each side the editor keeps back for the rules
type http2Exchange struct {
	id       uint64
	streamID uint32
	ends     [2]*history.HTTPEnd
	notes    [2]string
	values   filter.HTTPValues
	kept     [2]*http2Kept
}

// a message kept back for the rules: its head, the body so far with its gRPC messages, until when it may take to come whole, and whether the rules have it now
type http2Kept struct {
	head         http2.Head
	body         []byte
	grpc         []api.GRPCMessage
	deadline     time.Time
	isProcessing bool
}

func newHTTP2Flow(flowID uint64, recorder *history.History, layer HTTPLayer, notify func(direction tlsrecord.Direction)) (flow *http2Flow) {
	flow = &http2Flow{
		mutex:      &sync.Mutex{},
		conn:       http2.New(http2.DefaultMaxStreams),
		editor:     nil,
		flowID:     flowID,
		recorder:   recorder,
		layer:      layer,
		streams:    map[uint32]*http2Exchange{},
		notify:     notify,
		processing: [2]int{0, 0},
		isFailed:   false,
	}

	if layer.Pipeline != nil {
		flow.conn.EmitFrames()
		flow.editor = http2.NewEditor(0)
	}

	return
}

// the next bytes a peer sent, after the record rules; canKeep is false for bytes that went on already
// they go on whole while no message was ever kept and no rule or hold of layer http may want one, otherwise as whole frames from the editor
func (http2Flow *http2Flow) feed(ctx context.Context, flow intercept.Flow, direction tlsrecord.Direction, data []byte, canKeep bool, logger *slog.Logger) (result httpOutput) {
	result = httpOutput{output: data, isWhole: true}
	http2Flow.mutex.Lock()
	peer := http2.Peer(direction)
	editor := http2Flow.editor

	switch {
	case editor == nil:
		http2Flow.handle(ctx, flow, direction, http2Flow.conn.Feed(peer, data), false, logger)
	case !canKeep || editor.IsStopped() || (!editor.IsTouched() && !http2Flow.wants() && editor.IsClean(peer)):
		pending := []byte(nil)

		if canKeep {
			pending = editor.Output(peer)
		}

		editor.Pass(peer, data)
		http2Flow.handle(ctx, flow, direction, http2Flow.conn.Feed(peer, data), false, logger)
		editor.Settle()

		if len(pending) > 0 {
			result = httpOutput{output: append(pending, data...), isWhole: false}
		}
	default:
		editor.Take(peer, data)
		http2Flow.handle(ctx, flow, direction, http2Flow.conn.Feed(peer, data), true, logger)
		editor.Settle()
		result = httpOutput{output: editor.Output(peer), isWhole: false}
	}

	waiting := http2Flow.waiting(logger)
	http2Flow.mutex.Unlock()
	http2Flow.wake(waiting)
	return
}

// the stream of a peer ended: what the editor has for it goes on
func (http2Flow *http2Flow) close(ctx context.Context, flow intercept.Flow, direction tlsrecord.Direction, logger *slog.Logger) (output []byte) {
	http2Flow.mutex.Lock()
	http2Flow.handle(ctx, flow, direction, http2Flow.conn.Close(http2.Peer(direction)), false, logger)
	output = http2Flow.take(direction)
	waiting := http2Flow.waiting(logger)
	http2Flow.mutex.Unlock()
	http2Flow.wake(waiting)
	return
}

// what the editor has for a direction now, outside of a feed
func (http2Flow *http2Flow) flush(direction tlsrecord.Direction, logger *slog.Logger) (output []byte) {
	http2Flow.mutex.Lock()
	output = http2Flow.take(direction)
	waiting := http2Flow.waiting(logger)
	http2Flow.mutex.Unlock()
	http2Flow.wake(waiting)
	return
}

// the kept messages of a direction that waited too long to come whole go on as they came
func (http2Flow *http2Flow) expire(direction tlsrecord.Direction, logger *slog.Logger) (output []byte) {
	http2Flow.mutex.Lock()
	now := time.Now()
	side := http2.Side(direction)

	for _, id := range slices.Sorted(maps.Keys(http2Flow.streams)) {
		exchange := http2Flow.streams[id]
		kept := exchange.kept[side]

		if (kept != nil) && !kept.isProcessing && !now.Before(kept.deadline) {
			http2Flow.release(direction, exchange, fmt.Sprintf("not whole after %s, went on as it came", http2Flow.layer.Timeout), logger)
		}
	}

	output = http2Flow.take(direction)
	waiting := http2Flow.waiting(logger)
	http2Flow.mutex.Unlock()
	http2Flow.wake(waiting)
	return
}

// the earliest time a kept message of a direction may wait for its end, zero when none waits
func (http2Flow *http2Flow) deadline(direction tlsrecord.Direction) (deadline time.Time) {
	http2Flow.mutex.Lock()
	defer http2Flow.mutex.Unlock()
	side := http2.Side(direction)

	for _, exchange := range http2Flow.streams {
		kept := exchange.kept[side]

		if (kept != nil) && !kept.isProcessing && (deadline.IsZero() || kept.deadline.Before(deadline)) {
			deadline = kept.deadline
		}
	}

	return
}

// whether a message of the direction is with the rules now, its frames come later
func (http2Flow *http2Flow) isProcessing(direction tlsrecord.Direction) (isProcessing bool) {
	http2Flow.mutex.Lock()
	defer http2Flow.mutex.Unlock()
	isProcessing = http2Flow.processing[direction] > 0
	return
}

// whether the frames went on other than they came at some point: raw bytes can't follow any more
func (http2Flow *http2Flow) isTouched() (isTouched bool) {
	http2Flow.mutex.Lock()
	defer http2Flow.mutex.Unlock()
	isTouched = (http2Flow.editor != nil) && http2Flow.editor.IsTouched()
	return
}

func (http2Flow *http2Flow) wants() (isWanted bool) {
	isWanted = (http2Flow.layer.Pipeline != nil) && http2Flow.layer.Pipeline.Wants(intercept.HTTPLayer)
	return
}

// what the editor has for the direction, after the decisions so far
func (http2Flow *http2Flow) take(direction tlsrecord.Direction) (output []byte) {
	if http2Flow.editor == nil {
		return
	}

	http2Flow.editor.Settle()
	output = http2Flow.editor.Output(http2.Peer(direction))
	return
}

// the directions the editor has frames for, under the mutex; an editor error is logged once
func (http2Flow *http2Flow) waiting(logger *slog.Logger) (directions []tlsrecord.Direction) {
	if http2Flow.editor == nil {
		return
	}

	if err := http2Flow.editor.Err(); (err != nil) && !http2Flow.isFailed {
		http2Flow.isFailed = true
		logger.Warn("Http/2 frames may have gone on broken", "error", err)
	}

	for _, direction := range []tlsrecord.Direction{tlsrecord.ClientDirection, tlsrecord.ServerDirection} {
		if http2Flow.editor.HasOutput(http2.Peer(direction)) {
			directions = append(directions, direction)
		}
	}

	return
}

// tell the senders of the directions, without the mutex
func (http2Flow *http2Flow) wake(directions []tlsrecord.Direction) {
	if http2Flow.notify == nil {
		return
	}

	for _, direction := range directions {
		http2Flow.notify(direction)
	}
}

// the events of the conn into the history, and with the editor the frames to it and the decisions on the messages of the peer of direction
// canKeep is false for bytes that went on already and for events no frame made
func (http2Flow *http2Flow) handle(ctx context.Context, flow intercept.Flow, direction tlsrecord.Direction, events []http2.Event, canKeep bool, logger *slog.Logger) {
	for _, event := range events {
		side := api.RequestSide

		if event.Side == http2.ResponseSide {
			side = api.ResponseSide
		}

		exchange := http2Flow.streams[event.StreamID]
		kept := (*http2Kept)(nil)

		if exchange != nil {
			kept = exchange.kept[event.Side]
		}

		switch event.Type {
		case http2.FrameEventType:
			http2Flow.editor.Frame(http2.Peer(direction), event)
		case http2.HeadEventType:
			http2Flow.head(flow, event, side, exchange)
			http2Flow.keep(flow, direction, event, canKeep)
		case http2.BodyEventType:
			if exchange == nil {
				break
			}

			if (kept != nil) && !kept.isProcessing {
				kept.body = append(kept.body, event.Data...)
				kept.grpc = append(kept.grpc, grpcMessagesOf(event.GRPC)...)

				if len(kept.body) > maxHTTPBodyBytes {
					http2Flow.release(direction, exchange, fmt.Sprintf("the body is larger than %d bytes, it went on as it came", maxHTTPBodyBytes), logger)
				}

				break
			}

			http2Flow.recorder.AppendBody(exchange.id, side, event.Data)

			if len(event.GRPC) > 0 {
				http2Flow.recorder.AppendGRPC(exchange.id, side, grpcMessagesOf(event.GRPC))
			}
		case http2.EndEventType:
			if exchange == nil {
				break
			}

			if (kept != nil) && !kept.isProcessing {
				if event.IsComplete {
					http2Flow.process(ctx, flow, http2Direction(event.Side), exchange, event, logger)
					break
				}

				http2Flow.release(http2Direction(event.Side), exchange, "the stream ended before the message", logger)
			}

			state := api.CompleteHTTPState

			if !event.IsComplete {
				state = api.IncompleteHTTPState
			}

			end := history.HTTPEnd{State: state, Trailers: fieldsOf(event.Trailers), Note: joinNote(exchange.notes[event.Side], event.Note), Edit: nil}
			exchange.ends[event.Side] = &end
			http2Flow.recorder.EndMessage(exchange.id, side, end)
		case http2.CloseEventType:
			// a stream that ended without a response says why on its request
			if (exchange != nil) && !event.HasResponse && (event.Note != "") && (exchange.ends[http2.RequestSide] != nil) {
				end := *exchange.ends[http2.RequestSide]
				end.Note = joinNote(end.Note, "no response: "+event.Note)
				http2Flow.recorder.EndMessage(exchange.id, api.RequestSide, end)
			}

			delete(http2Flow.streams, event.StreamID)
		case http2.SkipEventType:
			logger.Warn("Http/2 streams not shown", "reason", event.Note)
		case http2.StopEventType:
			logger.Info("Http/2 layer stopped", "error", event.Err)

			if http2Flow.editor != nil {
				http2Flow.editor.Stop()
			}
		}
	}

	// the streams the editor refused end in the history too
	if http2Flow.editor != nil {
		for _, id := range http2Flow.editor.Refused() {
			http2Flow.handle(ctx, flow, direction, http2Flow.conn.Abort(id, http2RefusedNote), false, logger)
		}
	}
}

// a head: a request opens the exchange of its stream, a response (or a 1xx before it) is added to it
func (http2Flow *http2Flow) head(flow intercept.Flow, event http2.Event, side api.Side, exchange *http2Exchange) {
	view := http2View(flow, event)
	note := ""

	if event.Head.IsCut {
		note = "the header fields are larger than 64 KiB, the later ones are not shown"
	}

	switch {
	case event.Side == http2.RequestSide:
		stream := history.Stream{ID: event.StreamID, PromisedBy: event.PromisedBy}
		exchange = &http2Exchange{id: http2Flow.recorder.OpenStream(http2Flow.flowID, http2Protocol, stream, side, view), streamID: event.StreamID, ends: [2]*history.HTTPEnd{}, notes: [2]string{}, values: http2Values(event), kept: [2]*http2Kept{}}
		http2Flow.streams[event.StreamID] = exchange
	case exchange == nil:
		return
	default:
		http2Flow.recorder.AddHead(exchange.id, side, view, event.IsInterim)
	}

	if !event.IsInterim {
		exchange.notes[event.Side] = note
	}
}

// a final head the peer of direction sent: its message is kept back while a rule or the hold queue of layer http takes it
func (http2Flow *http2Flow) keep(flow intercept.Flow, direction tlsrecord.Direction, event http2.Event, canKeep bool) {
	exchange := http2Flow.streams[event.StreamID]

	if !canKeep || (exchange == nil) || event.IsInterim || event.Head.IsCut || (uint8(event.Side) != uint8(direction)) || !http2Flow.wants() {
		return
	}

	kept := &http2Kept{head: event.Head, body: nil, grpc: nil, deadline: time.Now().Add(http2Flow.layer.Timeout), isProcessing: false}
	exchange.kept[event.Side] = kept

	if !http2Flow.layer.Pipeline.Matches(http2Flow.message(flow, exchange, event.Side, http2.Form(event.Head.Fields, nil), false)) || !http2Flow.editor.Keep(http2.Peer(direction), event.StreamID) {
		exchange.kept[event.Side] = nil
	}
}

// a kept message is whole: through the rules at once, or on a goroutine of its own when a hold may take it, so the other streams go on meanwhile
func (http2Flow *http2Flow) process(ctx context.Context, flow intercept.Flow, direction tlsrecord.Direction, exchange *http2Exchange, event http2.Event, logger *slog.Logger) {
	kept := exchange.kept[event.Side]
	message := http2Flow.message(flow, exchange, event.Side, http2.Form(kept.head.Fields, kept.body), true)
	end := history.HTTPEnd{State: api.CompleteHTTPState, Trailers: fieldsOf(event.Trailers), Note: joinNote(exchange.notes[event.Side], event.Note), Edit: nil}
	pipeline := http2Flow.layer.Pipeline

	if !pipeline.Blocks(message) {
		http2Flow.finish(ctx, flow, direction, exchange, kept, end, pipeline.Process(ctx, message, logger), logger)
		return
	}

	kept.isProcessing = true
	http2Flow.processing[direction]++

	// held message, the frames of its stream go on once the hold queue let it go
	go func() {
		result := pipeline.Process(ctx, message, logger)
		http2Flow.mutex.Lock()
		http2Flow.finish(ctx, flow, direction, exchange, kept, end, result, logger)
		http2Flow.editor.Settle()
		http2Flow.processing[direction]--
		waiting := http2Flow.waiting(logger)
		http2Flow.mutex.Unlock()
		http2Flow.wake(append(waiting, direction))
	}()
}

// what the rules made of a kept message goes to the editor and the history: as it came, edited, or dropped; an edit that is no HTTP/2 message goes on as the message came, with a note
func (http2Flow *http2Flow) finish(ctx context.Context, flow intercept.Flow, direction tlsrecord.Direction, exchange *http2Exchange, kept *http2Kept, end history.HTTPEnd, result intercept.Result, logger *slog.Logger) {
	peer := http2.Peer(direction)
	messageSide := http2.Side(direction)
	side := sideOf(direction)
	http2Flow.recorder.AppendBody(exchange.id, side, kept.body)

	if len(kept.grpc) > 0 {
		http2Flow.recorder.AppendGRPC(exchange.id, side, kept.grpc)
	}

	exchange.kept[messageSide] = nil
	isDropped := false

	switch {
	case result.Verdict == intercept.DropVerdict:
		end.Edit = &history.HTTPEdit{Head: api.HTTPHead{}, URL: "", Body: nil, Verdict: api.DropVerdict}
		http2Flow.editor.Drop(peer, exchange.streamID)
		isDropped = true
	case !result.Changed:
		http2Flow.editor.Release(peer, exchange.streamID)
	default:
		edit, editErr := http2Edit(kept, result.Plain)

		if editErr != nil {
			end.Note = joinNote(end.Note, fmt.Sprintf("the edit is no HTTP/2 message (%v), the message went on as it came", editErr))
			logger.Warn("Http/2 message edit not taken", "error", editErr, "exchangeID", exchange.id)
			http2Flow.editor.Release(peer, exchange.streamID)
			break
		}

		http2Flow.editor.Replace(peer, exchange.streamID, edit)
		view := http2View(flow, http2.Event{Type: http2.HeadEventType, Side: messageSide, Head: http2.HeadOf(edit.Fields, false)})
		end.Edit = &history.HTTPEdit{Head: view.HTTPHead, URL: view.URL, Body: edit.Body, Verdict: api.ForwardVerdict}
	}

	exchange.ends[messageSide] = &end
	http2Flow.recorder.EndMessage(exchange.id, side, end)

	if isDropped {
		http2Flow.handle(ctx, flow, direction, http2Flow.conn.Abort(exchange.streamID, http2DropNote), false, logger)
	}
}

// the kept message goes on as it came, note says why; its body so far goes into the history, the rest of it as it comes
func (http2Flow *http2Flow) release(direction tlsrecord.Direction, exchange *http2Exchange, note string, logger *slog.Logger) {
	messageSide := http2.Side(direction)
	side := sideOf(direction)
	kept := exchange.kept[messageSide]
	http2Flow.recorder.AppendBody(exchange.id, side, kept.body)

	if len(kept.grpc) > 0 {
		http2Flow.recorder.AppendGRPC(exchange.id, side, kept.grpc)
	}

	exchange.kept[messageSide] = nil
	exchange.notes[messageSide] = joinNote(exchange.notes[messageSide], note)
	http2Flow.editor.Release(http2.Peer(direction), exchange.streamID)
	logger.Info("Http message left to the record layer", "reason", note, "exchangeID", exchange.id, "direction", intercept.DirectionName(direction))
}

// the intercept message of a message of an exchange: the filter sees the fields of its request and a response its status too; isNext gives it the next message id
func (http2Flow *http2Flow) message(flow intercept.Flow, exchange *http2Exchange, side http2.Side, form []byte, isNext bool) (message intercept.Message) {
	values := exchange.values

	if (side == http2.ResponseSide) && (exchange.kept[side] != nil) {
		values.Codes = []uint16{uint16(exchange.kept[side].head.Status)}
	}

	flow.Values.HTTP = &values
	direction := http2Direction(side)

	if isNext {
		message = http2Flow.layer.Pipeline.Message(flow, direction, intercept.HTTPLayer, form)
	} else {
		message = intercept.Message{Flow: flow, ID: 0, Direction: direction, Layer: intercept.HTTPLayer, Plain: form, Exchange: 0}
	}

	message.Exchange = exchange.id
	return
}

// the edit of a kept message from the form the rules returned: content-length follows the body when the message has one, before or after
func http2Edit(kept *http2Kept, form []byte) (edit http2.Edit, err error) {
	fields, body, err := http2.ParseForm(form)

	if err != nil {
		return
	}

	if (len(body) > 0) || (len(kept.body) > 0) {
		for index := range fields {
			if fields[index].Name == "content-length" {
				fields[index].Value = strconv.Itoa(len(body))
			}
		}
	}

	edit = http2.Edit{Fields: fields, Body: body, IsHeadChanged: !slices.Equal(fields, kept.head.Fields), IsBodyChanged: !bytes.Equal(body, kept.body)}
	return
}

// the filter fields of the request of a stream
func http2Values(event http2.Event) (values filter.HTTPValues) {
	head := event.Head
	values = filter.HTTPValues{Methods: nil, URIs: nil, Hosts: nil, Codes: nil, UserAgents: nil, StreamIDs: []uint32{event.StreamID}}

	if head.Method != "" {
		values.Methods = []string{head.Method}
	}

	if head.Path != "" {
		values.URIs = []string{head.Path}
	}

	host := head.Authority

	if host == "" {
		host, _ = head.Get("host")
	}

	if host != "" {
		values.Hosts = []string{host}
	}

	if agent, found := head.Get("user-agent"); found {
		values.UserAgents = []string{agent}
	}

	return
}

// the direction whose peer sends a side of a stream (the request of a server push excepted)
func http2Direction(side http2.Side) (direction tlsrecord.Direction) {
	direction = tlsrecord.ClientDirection

	if side == http2.ResponseSide {
		direction = tlsrecord.ServerDirection
	}

	return
}

// the API's view of a head: method, :path as the target and :status, every field in the order it came (the pseudo-header fields too)
// URL from :scheme, :authority (or Host, or the destination) and :path; a request without :path (CONNECT) has none
func http2View(flow intercept.Flow, event http2.Event) (message api.HTTPMessage) {
	head := event.Head
	framing := api.FramesFraming

	if event.EndsMessage || event.IsInterim {
		framing = api.NoneFraming
	}

	message = api.HTTPMessage{
		HTTPHead: api.HTTPHead{
			Method:  head.Method,
			Target:  head.Path,
			Version: http2Protocol,
			Status:  head.Status,
			Reason:  "",
			Headers: fieldsOf(head.Fields),
		},
		URL:     "",
		Time:    time.Now(),
		Framing: framing,
		State:   api.HeadHTTPState,
	}

	if message.Headers == nil {
		message.Headers = []api.Header{}
	}

	if (event.Side != http2.RequestSide) || (head.Path == "") {
		if head.Method == "CONNECT" {
			message.Target = head.Authority
		}

		return
	}

	scheme := head.Scheme

	if scheme == "" {
		scheme = "http"

		if flow.Session.Version != 0 {
			scheme = "https"
		}
	}

	authority := history.HostOf(message.HTTPHead)

	if authority == "" {
		destination := flow.Destination
		authority = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port()).String()
	}

	message.URL = scheme + "://" + authority

	if strings.HasPrefix(head.Path, "/") {
		message.URL += head.Path
	}

	return
}

func fieldsOf(fields []http2.Field) (views []api.Header) {
	for _, field := range fields {
		views = append(views, api.Header{Name: field.Name, Value: field.Value})
	}

	return
}

func grpcMessagesOf(messages []http2.GRPCMessage) (views []api.GRPCMessage) {
	for _, message := range messages {
		views = append(views, api.GRPCMessage{Offset: message.Offset, Length: message.Length, Compressed: message.IsCompressed})
	}

	return
}

func joinNote(first string, second string) (note string) {
	switch {
	case first == "":
		note = second
	case second == "":
		note = first
	default:
		note = first + "; " + second
	}

	return
}

// the version of a flow whose HTTP layer has not decided yet, from the next bytes of a direction; undecided are what each direction sent before, data the new bytes
// a TLS session decides by its ALPN; without one the client's first bytes do: the HTTP/2 preface or anything else, which is HTTP/1; the server's bytes alone never decide
func versionOf(direction tlsrecord.Direction, undecided [2][]byte, data []byte, session tlsrecord.Session, isClose bool) (version httpVersion) {
	switch {
	case session.Protocol == http2ALPN:
		version = http2HTTPVersion
	case session.Protocol == http1ALPN:
		version = http1HTTPVersion
	case session.Protocol != "":
		version = offHTTPVersion
	case isClose:
		version = http1HTTPVersion
	case direction == tlsrecord.ServerDirection:
		version = undecidedHTTPVersion

		if len(undecided[direction])+len(data) > maxUndecidedBytes {
			version = http1HTTPVersion
		}
	default:
		prefix := append(bytes.Clone(undecided[direction]), data...)
		length := min(len(prefix), len(http2.Preface))

		switch {
		case !bytes.Equal(prefix[:length], []byte(http2.Preface[:length])):
			version = http1HTTPVersion
		case length < len(http2.Preface):
			version = undecidedHTTPVersion
		default:
			version = http2HTTPVersion
		}
	}

	return
}
