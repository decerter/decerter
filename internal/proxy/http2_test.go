// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	decerterhttp2 "github.com/decerter/decerter/internal/http2"
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

// feed the pieces through the HTTP layer as the intercepting senders do; what goes on in each direction must be what went in, a layer that edits nothing changes no byte
func feedHTTP2(flowHTTP *httpFlow, flow intercept.Flow, pieces []http2Piece) (err error) {
	outputs, inputs := relayHTTP2(flowHTTP, flow, pieces)

	for index := range outputs {
		if !bytes.Equal(outputs[index], inputs[index]) {
			err = errors.Join(err, fmt.Errorf("the layer changed the bytes of direction %d: %d bytes in, %d out", index, len(inputs[index]), len(outputs[index])))
		}
	}

	return
}

// the pieces through the HTTP layer as the intercepting senders do: what went on in each direction and what came in
func relayHTTP2(flowHTTP *httpFlow, flow intercept.Flow, pieces []http2Piece) (outputs [2][]byte, inputs [2][]byte) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, piece := range pieces {
		if piece.IsClose {
			outputs[piece.Direction] = append(outputs[piece.Direction], flowHTTP.close(context.Background(), flow, piece.Direction, logger)...)
			continue
		}

		inputs[piece.Direction] = append(inputs[piece.Direction], piece.Data...)
		outputs[piece.Direction] = append(outputs[piece.Direction], flowHTTP.feed(context.Background(), flow, piece.Direction, piece.Data, true, logger).output...)

		for _, direction := range []tlsrecord.Direction{tlsrecord.ClientDirection, tlsrecord.ServerDirection} {
			outputs[direction] = append(outputs[direction], flowHTTP.flush(direction, logger)...)
		}
	}

	return
}

// Test if the HTTP layer of the proxy returns with the expected output for HTTP/2: h2c with prior knowledge whose server speaks first, and TLS with ALPN h2 with a gRPC call,
// a server push and a refused stream; a rule of layer http that finds nothing changes no byte, though the frames go on whole.
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
	recorder, flowHTTP, _ := httpTestLayer(state, []intercept.MatchSpec{{Directions: intercept.UpDirections, Layer: intercept.HTTPLayer, Find: "nowhere", Replace: "b"}}, time.Second)
	flow := intercept.Flow{ID: 1, Destination: netip.MustParseAddrPort("127.0.0.1:8080")}
	err := errors.Join(client.err, server.err, feedHTTP2(flowHTTP, flow, pieces))
	exchanges, _, _ := recorder.Exchanges(1, 0, 10)

	if (err != nil) || (len(exchanges) != 1) || (exchanges[0].Protocol != "HTTP/2") || (exchanges[0].StreamID != 1) || (exchanges[0].Request == nil) || (exchanges[0].Response == nil) ||
		(exchanges[0].Request.Method != "GET") || (exchanges[0].Request.Target != "/a?b=c") || (exchanges[0].Request.URL != "http://h2c.test:8080/a?b=c") || (exchanges[0].Request.Framing != api.NoneFraming) ||
		(exchanges[0].Response.Status != 200) || (exchanges[0].Response.Framing != api.FramesFraming) || (exchanges[0].Response.BodyLength != 5) || (exchanges[0].Response.State != api.CompleteHTTPState) ||
		(exchanges[0].Request.Note != "") || exchanges[0].Request.Edited || (exchanges[0].Request.Headers[0].Name != ":method") {
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

// the messages of an HTTP/2 byte stream as its receiver decodes them: the fields of each stream's header blocks, joined as "name: value" lines, and its DATA
func readHTTP2(data []byte) (heads map[uint32][]string, bodies map[uint32][]byte, err error) {
	heads, bodies = map[uint32][]string{}, map[uint32][]byte{}
	framer := http2.NewFramer(nil, bytes.NewReader(bytes.TrimPrefix(data, []byte(http2.ClientPreface))))
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	for {
		frame, readErr := framer.ReadFrame()

		if errors.Is(readErr, io.EOF) {
			return
		}

		if err = readErr; err != nil {
			return
		}

		switch typed := frame.(type) {
		case *http2.MetaHeadersFrame:
			for _, field := range typed.Fields {
				heads[typed.StreamID] = append(heads[typed.StreamID], field.Name+": "+field.Value)
			}
		case *http2.DataFrame:
			bodies[typed.StreamID] = append(bodies[typed.StreamID], typed.Data()...)
		default:
		}
	}
}

// Test if the HTTP layer of proxy.interceptTCP returns with the expected output for HTTP/2 over h2c: a rule rewrites :path, others grow one response by 200 KiB and shrink another
// to a few bytes with its content-length; and a held response stalls only its stream, the others go on, and it follows edited once the hold queue lets it go.
func TestInterceptHTTP2Positive(state *testing.T) {
	grown := strings.Repeat("g", 200<<10)
	specs := []intercept.MatchSpec{
		{Directions: intercept.UpDirections, Layer: intercept.HTTPLayer, Find: ":path: /\r\n", Replace: ":path: /test\r\n"},
		{Directions: intercept.DownDirections, Layer: intercept.HTTPLayer, Find: "GROW", Replace: "GROW" + grown},
		{Directions: intercept.DownDirections, Layer: intercept.HTTPLayer, FindType: intercept.RegexValueType, Find: "z+", Replace: "tiny"},
	}
	recorder, flowHTTP, pipeline := httpTestLayer(state, specs, 5*time.Second)
	client, server := newHTTP2Writer(), newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.err = errors.Join(client.err, client.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20}), client.framer.WriteWindowUpdate(0, 1<<20))
	client.headers(1, true, ":method", "GET", ":scheme", "http", ":authority", "h2c.test", ":path", "/")
	client.headers(3, true, ":method", "GET", ":scheme", "http", ":authority", "h2c.test", ":path", "/grow")
	client.headers(5, true, ":method", "GET", ":scheme", "http", ":authority", "h2c.test", ":path", "/shrink")
	server.err = errors.Join(server.err, server.framer.WriteSettings(), server.framer.WriteSettingsAck())
	server.headers(1, false, ":status", "200")
	server.err = errors.Join(server.err, server.framer.WriteData(1, true, []byte("index")))
	server.headers(3, false, ":status", "200")
	server.err = errors.Join(server.err, server.framer.WriteData(3, true, []byte("GROW")))
	server.headers(5, false, ":status", "200", "content-length", "30000")

	for range 2 {
		server.err = errors.Join(server.err, server.framer.WriteData(5, false, bytes.Repeat([]byte("z"), 15000)))
	}

	server.err = errors.Join(server.err, server.framer.WriteData(5, true, nil))
	upstream, downstream, err := relayWith(state, client.take(), server.take(), pipeline, flowHTTP)
	requests, _, upErr := readHTTP2(upstream)
	responses, bodies, downErr := readHTTP2(downstream)

	if err = errors.Join(err, client.err, server.err, upErr, downErr); (err != nil) || !slices.Contains(requests[1], ":path: /test") || !slices.Contains(requests[3], ":path: /grow") ||
		(string(bodies[1]) != "index") || (string(bodies[3]) != "GROW"+grown) || (string(bodies[5]) != "tiny") || !slices.Equal(responses[5], []string{":status: 200", "content-length: 4"}) {
		state.Errorf("Test of the http/2 layer of proxy.interceptTCP failed, the rules should edit the messages, requests: %v, responses: %v, bodies: %d %d %q, error: %v", requests, responses, len(bodies[1]), len(bodies[3]), shorten(string(bodies[5])), err)
		return
	}

	exchanges, _, _ := recorder.Exchanges(1, 0, 10)

	if (len(exchanges) != 3) || !exchanges[0].Request.Edited || (exchanges[0].Response.State != api.CompleteHTTPState) || !exchanges[2].Response.Edited || (exchanges[2].Response.OriginalBodyLength != 30000) || (exchanges[2].Response.BodyLength != 4) {
		state.Errorf("Test of the http/2 layer of proxy.interceptTCP failed, the history should show the edits, exchanges: %+v", exchanges)
		return
	}

	// a hold on stream 1 while stream 3 goes on
	holds := intercept.NewHoldQueue(5*time.Second, nil)
	scope, err := filter.Parse("http2.streamid == 1")

	if err != nil {
		state.Fatalf("Could not parse the filter, error: %s", err.Error())
	}

	holds.Set(true, &scope, intercept.DownDirections, intercept.HTTPLayer)
	recorder = history.New(history.DefaultLimits(), nil)
	recorder.OpenFlow(1, filter.Values{}, [32]byte{})
	flowHTTP = newHTTPFlow(1, recorder, HTTPLayer{Pipeline: intercept.New(nil, nil, nil).Derive([]intercept.Rule{holds}), Timeout: 5 * time.Second})
	notifyChannel := make(chan tlsrecord.Direction, 16)
	flowHTTP.notify = func(direction tlsrecord.Direction) {
		notifyChannel <- direction
	}
	flow := intercept.Flow{ID: 1, Destination: netip.MustParseAddrPort("127.0.0.1:443"), Session: tlsrecord.Session{Version: tls.VersionTLS13, Protocol: "h2"}}
	client, server = newHTTP2Writer(), newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.err = errors.Join(client.err, client.framer.WriteSettings())
	client.headers(1, true, ":method", "GET", ":scheme", "https", ":authority", "hold.test", ":path", "/held")
	client.headers(3, true, ":method", "GET", ":scheme", "https", ":authority", "hold.test", ":path", "/free")
	server.err = errors.Join(server.err, server.framer.WriteSettings(), server.framer.WriteSettingsAck())
	server.headers(1, false, ":status", "200")
	server.err = errors.Join(server.err, server.framer.WriteData(1, true, []byte("one")))
	server.headers(3, false, ":status", "200")
	server.err = errors.Join(server.err, server.framer.WriteData(3, true, []byte("three")))
	outputs, _ := relayHTTP2(flowHTTP, flow, []http2Piece{{Direction: tlsrecord.ClientDirection, Data: client.take(), IsClose: false}, {Direction: tlsrecord.ServerDirection, Data: server.take(), IsClose: false}})
	_, bodies, err = readHTTP2(outputs[tlsrecord.ServerDirection])
	held := holds.List()

	// the hold queue takes the message on its own goroutine
	for start := time.Now(); (len(held) == 0) && (time.Since(start) < 5*time.Second); held = holds.List() {
		time.Sleep(time.Millisecond)
	}

	if err = errors.Join(err, client.err, server.err); (err != nil) || (string(bodies[3]) != "three") || (len(bodies[1]) != 0) || (len(held) != 1) || (string(held[0].Plain) != ":status: 200\r\n\r\none") || !flowHTTP.isWaiting(tlsrecord.ServerDirection) {
		state.Errorf("Test of the http/2 layer of proxy.interceptTCP failed, the held response should stall only its stream, bodies: %v, held: %+v, error: %v", bodies, held, err)
		return
	}

	_, err = holds.Edit(held[0].Message.ID, []byte(":status: 200\r\ncontent-type: text/plain\r\n\r\nedited body"))
	err = errors.Join(err, holds.Forward(held[0].Message.ID))

	// the server's direction is told, the client's may be told before for the window of the held body
	for isTold := false; !isTold && (err == nil); {
		select {
		case direction := <-notifyChannel:
			isTold = direction == tlsrecord.ServerDirection
		case <-time.After(5 * time.Second):
			err = errors.New("the sender was never told")
		}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	output := flowHTTP.flush(tlsrecord.ServerDirection, logger)
	responses, bodies, readErr := readHTTP2(append(outputs[tlsrecord.ServerDirection], output...))
	exchange, _ := recorder.Exchange(1)

	if err = errors.Join(err, readErr); (err != nil) || (string(bodies[1]) != "edited body") || !slices.Equal(responses[1], []string{":status: 200", "content-type: text/plain"}) || flowHTTP.isWaiting(tlsrecord.ServerDirection) ||
		(exchange.Response == nil) || !exchange.Response.Edited {
		state.Errorf("Test of the http/2 layer of proxy.interceptTCP failed, the released response should follow edited, responses: %v, bodies: %v, exchange: %+v, error: %v", responses, bodies, exchange, err)
	}
}

// Test if the HTTP layer of proxy.interceptTCP returns with the expected errors for HTTP/2: an edit that is no HTTP/2 message lets the message go on as it came with a note,
// and a message that does not come whole before the timeout goes on as it came, its stream is not stalled.
func TestInterceptHTTP2Negative(state *testing.T) {
	recorder, flowHTTP, _ := httpTestLayer(state, []intercept.MatchSpec{{Directions: intercept.DownDirections, Layer: intercept.HTTPLayer, Find: ":status: 200", Replace: ":status 200"}}, 100*time.Millisecond)
	flow := intercept.Flow{ID: 1, Destination: netip.MustParseAddrPort("127.0.0.1:443"), Session: tlsrecord.Session{Version: tls.VersionTLS13, Protocol: "h2"}}
	client, server := newHTTP2Writer(), newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.err = errors.Join(client.err, client.framer.WriteSettings())
	client.headers(1, true, ":method", "GET", ":scheme", "https", ":authority", "bad.test", ":path", "/")
	client.headers(3, true, ":method", "GET", ":scheme", "https", ":authority", "bad.test", ":path", "/slow")
	server.err = errors.Join(server.err, server.framer.WriteSettings(), server.framer.WriteSettingsAck())
	server.headers(1, true, ":status", "200")
	server.headers(3, false, ":status", "200")
	server.err = errors.Join(server.err, server.framer.WriteData(3, false, []byte("part")))
	serverData := server.take()
	outputs, _ := relayHTTP2(flowHTTP, flow, []http2Piece{{Direction: tlsrecord.ClientDirection, Data: client.take(), IsClose: false}, {Direction: tlsrecord.ServerDirection, Data: serverData, IsClose: false}})
	responses, _, err := readHTTP2(outputs[tlsrecord.ServerDirection])

	if err = errors.Join(err, client.err, server.err); (err != nil) || !slices.Equal(responses[1], []string{":status: 200"}) || (len(responses[3]) != 0) {
		state.Errorf("Test of the http/2 layer of proxy.interceptTCP failed, the bad edit should go on as it came and the slow response wait, responses: %v, error: %v", responses, err)
		return
	}

	// the slow response goes on as it came once its time is over
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	time.Sleep(150 * time.Millisecond)
	deadline := flowHTTP.deadline(tlsrecord.ServerDirection)
	expired := flowHTTP.expire(tlsrecord.ServerDirection, logger)
	all := append(bytes.Clone(outputs[tlsrecord.ServerDirection]), expired...)
	server.err = errors.Join(server.err, server.framer.WriteData(3, true, []byte(" and the end")))
	end := server.take()
	all = append(all, flowHTTP.feed(context.Background(), flow, tlsrecord.ServerDirection, end, true, logger).output...)
	serverData = append(serverData, end...)
	responses, bodies, err := readHTTP2(all)
	exchanges, _, _ := recorder.Exchanges(1, 0, 10)

	if (err != nil) || deadline.IsZero() || !bytes.Equal(all, serverData) || (string(bodies[3]) != "part and the end") || (len(exchanges) != 2) ||
		!strings.Contains(exchanges[0].Response.Note, "the edit is no HTTP/2 message") || exchanges[0].Response.Edited || !strings.Contains(exchanges[1].Response.Note, "not whole after 100ms") || !flowHTTP.deadline(tlsrecord.ServerDirection).IsZero() {
		state.Errorf("Test of the http/2 layer of proxy.interceptTCP failed, the slow response should go on as it came, responses: %v, exchanges: %+v, error: %v", responses, exchanges, err)
	}
}

// Test if the HTTP layer of the proxy returns with the expected output for HTTP/2 uploads behind a held request: they wait, and the one whose DATA would have
// more than http2.MaxGatedData wait in decerter is refused with REFUSED_STREAM and ends in the history with a note.
func TestInterceptHTTP2GatedPositive(state *testing.T) {
	holds := intercept.NewHoldQueue(5*time.Second, nil)
	scope, err := filter.Parse("http2.streamid == 1")

	if err != nil {
		state.Fatalf("Could not parse the filter, error: %s", err.Error())
	}

	holds.Set(true, &scope, intercept.UpDirections, intercept.HTTPLayer)
	recorder := history.New(history.DefaultLimits(), nil)
	recorder.OpenFlow(1, filter.Values{}, [32]byte{})
	flowHTTP := newHTTPFlow(1, recorder, HTTPLayer{Pipeline: intercept.New(nil, nil, nil).Derive([]intercept.Rule{holds}), Timeout: 5 * time.Second})
	flow := intercept.Flow{ID: 1, Destination: netip.MustParseAddrPort("127.0.0.1:443"), Session: tlsrecord.Session{Version: tls.VersionTLS13, Protocol: "h2"}}
	client, server := newHTTP2Writer(), newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.err = errors.Join(client.err, client.framer.WriteSettings(), client.framer.WriteSettingsAck())
	client.headers(1, true, ":method", "GET", ":scheme", "https", ":authority", "hold.test", ":path", "/held")
	server.err = errors.Join(server.err, server.framer.WriteSettings(), server.framer.WriteSettingsAck())
	pieces := []http2Piece{{Direction: tlsrecord.ServerDirection, Data: server.take(), IsClose: false}, {Direction: tlsrecord.ClientDirection, Data: client.take(), IsClose: false}}
	last := uint32(1 + 2*(decerterhttp2.MaxGatedData/65535+1))

	for id := uint32(3); id <= last; id += 2 {
		client.headers(id, false, ":method", "POST", ":scheme", "https", ":authority", "hold.test", ":path", fmt.Sprintf("/%d", id))

		for range 4 {
			client.err = errors.Join(client.err, client.framer.WriteData(id, false, bytes.Repeat([]byte("u"), 16383)))
		}

		client.err = errors.Join(client.err, client.framer.WriteData(id, false, []byte("uuu")))
		pieces = append(pieces, http2Piece{Direction: tlsrecord.ClientDirection, Data: client.take(), IsClose: false})
	}

	outputs, _ := relayHTTP2(flowHTTP, flow, pieces)
	resets := []uint32{}
	framer := http2.NewFramer(nil, bytes.NewReader(outputs[tlsrecord.ServerDirection]))

	for frame, readErr := framer.ReadFrame(); readErr == nil; frame, readErr = framer.ReadFrame() {
		if reset, isReset := frame.(*http2.RSTStreamFrame); isReset && (reset.ErrCode == http2.ErrCodeRefusedStream) {
			resets = append(resets, reset.StreamID)
		}
	}

	exchanges, _, _ := recorder.Exchanges(1, 0, 1000)
	refused := (*api.Exchange)(nil)

	for index := range exchanges {
		if exchanges[index].StreamID == last {
			refused = &exchanges[index]
		}
	}

	requests, _, readErr := readHTTP2(outputs[tlsrecord.ClientDirection])
	held := holds.List()

	// the hold queue takes the message on its own goroutine
	for start := time.Now(); (len(held) == 0) && (time.Since(start) < 5*time.Second); held = holds.List() {
		time.Sleep(time.Millisecond)
	}

	if err = errors.Join(client.err, server.err, readErr); (err != nil) || !slices.Equal(resets, []uint32{last}) || (len(requests) != 0) || (refused == nil) ||
		(refused.Request.State != api.IncompleteHTTPState) || !strings.Contains(refused.Request.Note, "decerter refused the stream") || (len(held) != 1) {
		state.Errorf("Test of the http/2 layer of proxy.interceptTCP failed, the last upload should be refused, resets: %v, requests: %v, exchange: %+v, error: %v", resets, requests, refused, err)
	}
}
