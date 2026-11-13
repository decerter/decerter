// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// frames of one peer of a test flow, header blocks from its own encoder
type http2Writer struct {
	buffer  *bytes.Buffer
	framer  *http2.Framer
	block   *bytes.Buffer
	encoder *hpack.Encoder
	err     error
}

func newHTTP2Writer() (writer *http2Writer) {
	writer = &http2Writer{buffer: &bytes.Buffer{}, framer: nil, block: &bytes.Buffer{}, encoder: nil, err: nil}
	writer.framer = http2.NewFramer(writer.buffer, nil)
	writer.encoder = hpack.NewEncoder(writer.block)
	return
}

func (writer *http2Writer) headers(streamID uint32, endStream bool, pairs ...string) {
	writer.err = errors.Join(writer.err, writer.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: writer.encode(pairs...), EndStream: endStream, EndHeaders: true, PadLength: 0, Priority: http2.PriorityParam{}}))
}

func (writer *http2Writer) encode(pairs ...string) (block []byte) {
	writer.block.Reset()

	for index := 0; index+1 < len(pairs); index += 2 {
		writer.err = errors.Join(writer.err, writer.encoder.WriteField(hpack.HeaderField{Name: pairs[index], Value: pairs[index+1], Sensitive: false}))
	}

	block = bytes.Clone(writer.block.Bytes())
	return
}

func (writer *http2Writer) take() (data []byte) {
	data = bytes.Clone(writer.buffer.Bytes())
	writer.buffer.Reset()
	return
}

// one piece of a test flow: the bytes a direction sent, or the end of its stream
type http2Piece struct {
	Direction tlsrecord.Direction
	Data      []byte
	IsClose   bool
}

// feed the pieces through the HTTP layer as the intercepting senders do; every output must be what went in, the layer never changes HTTP/2
func feedHTTP2(flowHTTP *httpFlow, flow intercept.Flow, pieces []http2Piece) (err error) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, piece := range pieces {
		if piece.IsClose {
			if output := flowHTTP.close(context.Background(), flow, piece.Direction, logger); len(output) != 0 {
				err = errors.Join(err, errors.New("the close let bytes go on"))
			}

			continue
		}

		output := flowHTTP.feed(context.Background(), flow, piece.Direction, piece.Data, true, logger)

		if !output.isWhole || !bytes.Equal(output.output, piece.Data) {
			err = errors.Join(err, errors.New("the layer changed the bytes"))
		}
	}

	return
}

// Test if the HTTP layer of the proxy returns with the expected output for HTTP/2: h2c with prior knowledge whose server speaks first, and TLS with ALPN h2 with a gRPC call,
// a server push and a refused stream; a rule of layer http only adds its note, the bytes go on as they came.
func TestHTTP2LayerPositive(state *testing.T) {
	// h2c: the server's SETTINGS come before the preface, the preface is cut in two
	client, server := newHTTP2Writer(), newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.err = errors.Join(client.err, client.framer.WriteSettings())
	server.err = errors.Join(server.err, server.framer.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100}))
	serverStart := server.take()
	clientStart := client.take()
	client.headers(1, true, ":method", "GET", ":scheme", "http", ":authority", "h2c.test:8080", ":path", "/a?b=c", "user-agent", "go-test")
	server.err = errors.Join(server.err, server.framer.WriteSettingsAck())
	server.headers(1, false, ":status", "200", "content-type", "text/plain")
	server.err = errors.Join(server.err, server.framer.WriteData(1, true, []byte("hello")))
	pieces := []http2Piece{
		{Direction: tlsrecord.ServerDirection, Data: serverStart, IsClose: false},
		{Direction: tlsrecord.ClientDirection, Data: clientStart[:10], IsClose: false},
		{Direction: tlsrecord.ClientDirection, Data: append(clientStart[10:], client.take()...), IsClose: false},
		{Direction: tlsrecord.ServerDirection, Data: server.take(), IsClose: false},
		{Direction: tlsrecord.ClientDirection, Data: nil, IsClose: true},
		{Direction: tlsrecord.ServerDirection, Data: nil, IsClose: true},
	}
	recorder, flowHTTP, _ := httpTestLayer(state, []intercept.MatchSpec{{Directions: intercept.UpDirections, Layer: intercept.HTTPLayer, Find: "a", Replace: "b"}}, time.Second)
	flow := intercept.Flow{ID: 1, Destination: netip.MustParseAddrPort("127.0.0.1:8080")}
	err := errors.Join(client.err, server.err, feedHTTP2(flowHTTP, flow, pieces))
	exchanges, _, _ := recorder.Exchanges(1, 0, 10)

	if (err != nil) || (len(exchanges) != 1) || (exchanges[0].Protocol != "HTTP/2") || (exchanges[0].StreamID != 1) || (exchanges[0].Request == nil) || (exchanges[0].Response == nil) ||
		(exchanges[0].Request.Method != "GET") || (exchanges[0].Request.Target != "/a?b=c") || (exchanges[0].Request.URL != "http://h2c.test:8080/a?b=c") || (exchanges[0].Request.Framing != api.NoneFraming) ||
		(exchanges[0].Response.Status != 200) || (exchanges[0].Response.Framing != api.FramesFraming) || (exchanges[0].Response.BodyLength != 5) || (exchanges[0].Response.State != api.CompleteHTTPState) ||
		!strings.Contains(exchanges[0].Request.Note, "layer http rules and holds do not take HTTP/2") || (exchanges[0].Request.Headers[0].Name != ":method") {
		state.Errorf("Test of the http/2 layer failed, h2c should be one exchange, exchanges: %+v, error: %v", exchanges, err)
		return
	}

	// TLS with ALPN h2: a gRPC call, a pushed stream and a refused one, no rule of layer http
	client, server = newHTTP2Writer(), newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.err = errors.Join(client.err, client.framer.WriteSettings())
	client.headers(1, false, ":method", "POST", ":scheme", "https", ":authority", "grpc.test", ":path", "/decerter.Echo/Say", "content-type", "application/grpc", "te", "trailers")
	client.err = errors.Join(client.err, client.framer.WriteData(1, true, []byte("\x00\x00\x00\x00\x02hi")))
	client.headers(3, true, ":method", "GET", ":scheme", "https", ":authority", "grpc.test", ":path", "/refused")
	server.err = errors.Join(server.err, server.framer.WriteSettings())
	server.err = errors.Join(server.err, server.framer.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2, BlockFragment: server.encode(":method", "GET", ":scheme", "https", ":authority", "grpc.test", ":path", "/pushed"), EndHeaders: true, PadLength: 0}))
	server.headers(1, false, ":status", "200", "content-type", "application/grpc")
	server.err = errors.Join(server.err, server.framer.WriteData(1, false, []byte("\x00\x00\x00\x00\x03abc\x00\x00")))
	server.err = errors.Join(server.err, server.framer.WriteData(1, false, []byte("\x00\x00\x01z")))
	server.headers(1, true, "grpc-status", "0")
	server.headers(2, true, ":status", "204")
	server.err = errors.Join(server.err, server.framer.WriteRSTStream(3, http2.ErrCodeRefusedStream))
	session := tlsrecord.Session{Version: tls.VersionTLS13, Protocol: "h2"}
	flow = intercept.Flow{ID: 1, Destination: netip.MustParseAddrPort("127.0.0.1:443"), Session: session}
	recorder, flowHTTP, _ = httpTestLayer(state, nil, time.Second)
	err = errors.Join(client.err, server.err, feedHTTP2(flowHTTP, flow, []http2Piece{{Direction: tlsrecord.ClientDirection, Data: client.take(), IsClose: false}, {Direction: tlsrecord.ServerDirection, Data: server.take(), IsClose: false}}))
	exchanges, _, _ = recorder.Exchanges(1, 0, 10)

	if (err != nil) || (len(exchanges) != 3) {
		state.Errorf("Test of the http/2 layer failed, TLS should have three exchanges, exchanges: %+v, error: %v", exchanges, err)
		return
	}

	call, refused, pushed := exchanges[0], exchanges[1], exchanges[2]
	grpc := call.Response.GRPCMessages

	if (call.Request.URL != "https://grpc.test/decerter.Echo/Say") || (len(call.Request.GRPCMessages) != 1) || (call.Request.Note != "") || (len(grpc) != 2) || (grpc[0] != api.GRPCMessage{Offset: 0, Length: 3, Compressed: false}) || (grpc[1] != api.GRPCMessage{Offset: 8, Length: 1, Compressed: false}) ||
		(len(call.Response.Trailers) != 1) || (call.Response.Trailers[0].Value != "0") || (call.Response.State != api.CompleteHTTPState) {
		state.Errorf("Test of the http/2 layer failed, the gRPC call should list its messages, exchange: %+v, response: %+v", call, call.Response)
		return
	}

	if (pushed.StreamID != 2) || (pushed.PromiseStreamID != 1) || (pushed.Request.Target != "/pushed") || (pushed.Response == nil) || (pushed.Response.Status != 204) ||
		(refused.StreamID != 3) || (refused.Response != nil) || (refused.Request.Note != "no response: the server reset the stream: REFUSED_STREAM") || (refused.Request.State != api.CompleteHTTPState) {
		state.Errorf("Test of the http/2 layer failed, push and refused stream, pushed: %+v %+v, refused: %+v %+v", pushed, pushed.Request, refused, refused.Request)
		return
	}

	// the flow's http fields know the streams and the :authority
	for text, count := range map[string]int{`http2.streamid == 2 && http.host == "grpc.test" && http.response.code == 204`: 1, `http2.streamid == 4`: 0} {
		scope, parseErr := filter.Parse(text)
		flows, _ := recorder.Flows(&scope, 0, 10)

		if (parseErr != nil) || (len(flows) != count) {
			state.Errorf("Test of the http/2 layer failed, the filter %s should take %d flows, flows: %+v, error: %v", text, count, flows, parseErr)
			return
		}
	}
}

// Test if the HTTP layer of the proxy returns with the expected errors for HTTP/2: an HPACK error ends the open exchange with a note and stops reading, another ALPN is not read,
// and a client that starts like the preface but is HTTP/1 is read as HTTP/1.
func TestHTTP2LayerNegative(state *testing.T) {
	client := newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.headers(1, false, ":method", "POST", ":scheme", "https", ":authority", "a", ":path", "/")
	client.err = errors.Join(client.err, client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: []byte{0xff, 0x7f}, EndStream: true, EndHeaders: true, PadLength: 0, Priority: http2.PriorityParam{}}))
	data := client.take()
	session := tlsrecord.Session{Version: tls.VersionTLS12, Protocol: "h2"}
	recorder, flowHTTP, _ := httpTestLayer(state, nil, time.Second)
	err := errors.Join(client.err, feedHTTP2(flowHTTP, intercept.Flow{ID: 1, Session: session}, []http2Piece{{Direction: tlsrecord.ClientDirection, Data: data, IsClose: false}}))
	exchanges, _, _ := recorder.Exchanges(1, 0, 10)

	if (err != nil) || (len(exchanges) != 1) || (exchanges[0].Request.State != api.IncompleteHTTPState) || !strings.HasPrefix(exchanges[0].Request.Note, "http/2 parsing stopped: hpack decoding failed") {
		state.Errorf("Test of the http/2 layer failed, an hpack error should end the open stream, exchanges: %+v, error: %v", exchanges, err)
		return
	}

	// another ALPN protocol is not read at all
	session.Protocol = "spdy/3"
	recorder, flowHTTP, _ = httpTestLayer(state, nil, time.Second)
	err = feedHTTP2(flowHTTP, intercept.Flow{ID: 1, Session: session}, []http2Piece{{Direction: tlsrecord.ClientDirection, Data: data, IsClose: false}})
	exchanges, _, _ = recorder.Exchanges(1, 0, 10)

	if (err != nil) || (len(exchanges) != 0) {
		state.Errorf("Test of the http/2 layer failed, another ALPN should not be read, exchanges: %+v, error: %v", exchanges, err)
		return
	}

	// PRI is a method of HTTP/1 too: a request that only starts like the preface
	recorder, flowHTTP, _ = httpTestLayer(state, nil, time.Second)
	request := []byte("PRI * HTTP/1.1\r\nHost: a\r\n\r\n")
	err = feedHTTP2(flowHTTP, intercept.Flow{ID: 1}, []http2Piece{{Direction: tlsrecord.ClientDirection, Data: request[:8], IsClose: false}, {Direction: tlsrecord.ClientDirection, Data: request[8:], IsClose: false}})
	exchanges, _, _ = recorder.Exchanges(1, 0, 10)

	if (err != nil) || (len(exchanges) != 1) || (exchanges[0].Protocol != "HTTP/1.1") || (exchanges[0].Request.Method != "PRI") || (exchanges[0].StreamID != 0) {
		state.Errorf("Test of the http/2 layer failed, a request like the preface should be HTTP/1, exchanges: %+v, error: %v", exchanges, err)
		return
	}
}
