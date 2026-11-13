// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/decerter/decerter/api"
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
	// the note of an HTTP/2 message while a rule or the hold queue of layer http may want messages: they take whole HTTP/1 messages only
	http2ReadOnlyNote string = "layer http rules and holds do not take HTTP/2 yet, the frames of this message went on through the record layer"
)

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
// it only reads, nothing is kept back, so the rules of layer http never see HTTP/2; the mutex orders both directions, the conn and the streams
type http2Flow struct {
	mutex    *sync.Mutex
	conn     *http2.Conn
	flowID   uint64
	recorder *history.History
	layer    HTTPLayer
	streams  map[uint32]*http2Exchange
	isNoted  bool
}

// the exchange of an open stream: id in the history (0 when it keeps no more), how each side ended, the notes each side gets at its end
type http2Exchange struct {
	id    uint64
	ends  [2]*history.HTTPEnd
	notes [2]string
}

func newHTTP2Flow(flowID uint64, recorder *history.History, layer HTTPLayer) (flow *http2Flow) {
	flow = &http2Flow{
		mutex:    &sync.Mutex{},
		conn:     http2.New(http2.DefaultMaxStreams),
		flowID:   flowID,
		recorder: recorder,
		layer:    layer,
		streams:  map[uint32]*http2Exchange{},
		isNoted:  false,
	}
	return
}

// the next bytes a peer sent, after the record rules
func (http2Flow *http2Flow) feed(flow intercept.Flow, direction tlsrecord.Direction, data []byte, logger *slog.Logger) {
	http2Flow.mutex.Lock()
	defer http2Flow.mutex.Unlock()
	http2Flow.handle(flow, http2Flow.conn.Feed(http2.Peer(direction), data), logger)
}

// the stream of a peer ended
func (http2Flow *http2Flow) close(flow intercept.Flow, direction tlsrecord.Direction, logger *slog.Logger) {
	http2Flow.mutex.Lock()
	defer http2Flow.mutex.Unlock()
	http2Flow.handle(flow, http2Flow.conn.Close(http2.Peer(direction)), logger)
}

// the events of the conn into the history
func (http2Flow *http2Flow) handle(flow intercept.Flow, events []http2.Event, logger *slog.Logger) {
	for _, event := range events {
		side := api.RequestSide

		if event.Side == http2.ResponseSide {
			side = api.ResponseSide
		}

		exchange := http2Flow.streams[event.StreamID]

		switch event.Type {
		case http2.HeadEventType:
			http2Flow.head(flow, event, side, exchange, logger)
		case http2.BodyEventType:
			if exchange == nil {
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
		}
	}
}

// a head: a request opens the exchange of its stream, a response (or a 1xx before it) is added to it
func (http2Flow *http2Flow) head(flow intercept.Flow, event http2.Event, side api.Side, exchange *http2Exchange, logger *slog.Logger) {
	view := http2View(flow, event)
	note := ""

	if event.Head.IsCut {
		note = "the header fields are larger than 64 KiB, the later ones are not shown"
	}

	// read-only: the rules and holds of layer http are not asked, the message only says that they skipped it
	if !event.IsInterim && (http2Flow.layer.Pipeline != nil) && http2Flow.layer.Pipeline.Wants(intercept.HTTPLayer) {
		note = joinNote(note, http2ReadOnlyNote)

		if !http2Flow.isNoted {
			http2Flow.isNoted = true
			logger.Info("Http/2 flow left to the record layer", "reason", http2ReadOnlyNote)
		}
	}

	switch {
	case event.Side == http2.RequestSide:
		stream := history.Stream{ID: event.StreamID, PromisedBy: event.PromisedBy}
		exchange = &http2Exchange{id: http2Flow.recorder.OpenStream(http2Flow.flowID, http2Protocol, stream, side, view), ends: [2]*history.HTTPEnd{}, notes: [2]string{}}
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
