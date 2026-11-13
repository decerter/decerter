// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package http2_test

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	decerterhttp2 "github.com/decerter/decerter/internal/http2"
)

// what one peer writes: frames into buffer, header blocks with its own HPACK encoder
type testPeer struct {
	buffer  *bytes.Buffer
	framer  *http2.Framer
	encoder *hpack.Encoder
	block   *bytes.Buffer
	err     error
}

// one step of a case: the bytes a peer sent at that point, or the end of its stream
type step struct {
	Peer    decerterhttp2.Peer
	Data    []byte
	IsClose bool
}

// a case: the steps, what the events say, and the conn's max streams (0 is the default)
type connCase struct {
	Name       string
	Steps      []step
	Expected   []string
	MaxStreams int
}

func newTestPeer(isClient bool) (peer *testPeer) {
	peer = &testPeer{buffer: &bytes.Buffer{}, framer: nil, encoder: nil, block: &bytes.Buffer{}, err: nil}
	peer.framer = http2.NewFramer(peer.buffer, nil)
	peer.encoder = hpack.NewEncoder(peer.block)

	if isClient {
		peer.buffer.WriteString(http2.ClientPreface)
	}

	return
}

// a header block of name, value pairs
func (peer *testPeer) encode(pairs ...string) (block []byte) {
	peer.block.Reset()

	for index := 0; index+1 < len(pairs); index += 2 {
		peer.err = errors.Join(peer.err, peer.encoder.WriteField(hpack.HeaderField{Name: pairs[index], Value: pairs[index+1], Sensitive: false}))
	}

	block = bytes.Clone(peer.block.Bytes())
	return
}

// the bytes written since the last take, as one step
func (peer *testPeer) take(owner decerterhttp2.Peer) (taken step) {
	taken = step{Peer: owner, Data: bytes.Clone(peer.buffer.Bytes()), IsClose: false}
	peer.buffer.Reset()
	return
}

func (peer *testPeer) headers(streamID uint32, endStream bool, pairs ...string) {
	peer.err = errors.Join(peer.err, peer.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: peer.encode(pairs...), EndStream: endStream, EndHeaders: true, PadLength: 0, Priority: http2.PriorityParam{}}))
}

func (peer *testPeer) data(streamID uint32, endStream bool, data string) {
	peer.err = errors.Join(peer.err, peer.framer.WriteData(streamID, endStream, []byte(data)))
}

func (peer *testPeer) settings(settings ...http2.Setting) {
	peer.err = errors.Join(peer.err, peer.framer.WriteSettings(settings...))
}

func (peer *testPeer) ack() {
	peer.err = errors.Join(peer.err, peer.framer.WriteSettingsAck())
}

// the client's and the server's start: preface and SETTINGS each, both acknowledged
func handshake(client *testPeer, server *testPeer, clientSettings []http2.Setting, serverSettings []http2.Setting) (steps []step) {
	client.settings(clientSettings...)
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	server.settings(serverSettings...)
	server.ack()
	steps = append(steps, server.take(decerterhttp2.ServerPeer))
	client.ack()
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	return
}

// one line per event: the non-pseudo fields of a head, the body of each DATA frame, gRPC boundaries as offset+length
func summary(events []decerterhttp2.Event) (lines []string) {
	sides := []string{"request", "response"}

	for _, event := range events {
		stream := fmt.Sprint(event.StreamID)

		if event.PromisedBy != 0 {
			stream += fmt.Sprintf("<-%d", event.PromisedBy)
		}

		switch event.Type {
		case decerterhttp2.HeadEventType:
			head := event.Head
			fields := []string{}

			for _, field := range head.Fields {
				if !strings.HasPrefix(field.Name, ":") {
					fields = append(fields, field.Name+"="+field.Value)
				}
			}

			kind := "head"

			if event.IsInterim {
				kind = "interim"
			}

			start := fmt.Sprintf("%s %s %s %s", head.Method, head.Scheme, head.Authority, head.Path)

			if event.Side == decerterhttp2.ResponseSide {
				start = fmt.Sprint(head.Status)
			}

			lines = append(lines, fmt.Sprintf("%s %s %s %s [%s] ends=%t cut=%t", kind, sides[event.Side], stream, start, strings.Join(fields, " "), event.EndsMessage, head.IsCut))
		case decerterhttp2.BodyEventType:
			grpc := []string{}

			for _, message := range event.GRPC {
				grpc = append(grpc, fmt.Sprintf("%d+%d/%t", message.Offset, message.Length, message.IsCompressed))
			}

			data := fmt.Sprintf("%q", event.Data)

			if len(event.Data) > 64 {
				data = fmt.Sprintf("%d bytes", len(event.Data))
			}

			lines = append(lines, fmt.Sprintf("body %s %s %s grpc=[%s]", sides[event.Side], stream, data, strings.Join(grpc, " ")))
		case decerterhttp2.EndEventType:
			trailers := []string{}

			for _, field := range event.Trailers {
				trailers = append(trailers, field.Name+"="+field.Value)
			}

			lines = append(lines, fmt.Sprintf("end %s %s complete=%t trailers=[%s] note=%q", sides[event.Side], stream, event.IsComplete, strings.Join(trailers, " "), event.Note))
		case decerterhttp2.CloseEventType:
			lines = append(lines, fmt.Sprintf("close %s response=%t note=%q", stream, event.HasResponse, event.Note))
		case decerterhttp2.SkipEventType:
			lines = append(lines, "skip "+stream)
		case decerterhttp2.StopEventType:
			cause := "other"

			for _, sentinel := range []error{decerterhttp2.ErrPreface, decerterhttp2.ErrFrameTooLarge, decerterhttp2.ErrFrame, decerterhttp2.ErrFrameOrder, decerterhttp2.ErrHPACK} {
				if errors.Is(event.Err, sentinel) {
					cause = sentinel.Error()
				}
			}

			lines = append(lines, "stop "+cause)
		}
	}

	return
}

// feed the steps; the step at splitStep is fed in pieces of chunk bytes from splitAt on, the rest whole; every frame event must lie inside what its peer sent
func run(steps []step, maxStreams int, splitStep int, splitAt int, chunk int) (events []decerterhttp2.Event, err error) {
	conn := decerterhttp2.New(maxStreams)
	sent := [2]int64{}

	for index, current := range steps {
		if current.IsClose {
			events = append(events, conn.Close(current.Peer)...)
			continue
		}

		pieces := [][]byte{current.Data}

		if index == splitStep {
			pieces = [][]byte{current.Data[:splitAt]}

			for rest := current.Data[splitAt:]; len(rest) > 0; rest = rest[min(chunk, len(rest)):] {
				pieces = append(pieces, rest[:min(chunk, len(rest))])
			}
		}

		for _, piece := range pieces {
			// a copy that is wiped afterwards, no event may keep the fed bytes
			fed := bytes.Clone(piece)
			sent[current.Peer] += int64(len(fed))

			for _, event := range conn.Feed(current.Peer, fed) {
				if (event.Type != decerterhttp2.StopEventType) && (event.Type != decerterhttp2.SkipEventType) && ((event.Start > event.End) || (event.End > sent[current.Peer])) {
					err = fmt.Errorf("event %s of stream %d covers [%d,%d), the peer sent %d", event.Type, event.StreamID, event.Start, event.End, sent[current.Peer])
				}

				events = append(events, event)
			}

			clear(fed)
		}
	}

	return
}

// whole, at every split point of every step and byte by byte, the events must be the expected ones
func checkCase(state *testing.T, testCase connCase) {
	lines := []string(nil)
	events, err := run(testCase.Steps, testCase.MaxStreams, -1, 0, 0)

	if err == nil {
		lines = summary(events)
	}

	if (err != nil) || !slices.Equal(lines, testCase.Expected) {
		state.Errorf("Test of http2.Conn failed, case %s, error: %v, events:\n%s\nexpected:\n%s", testCase.Name, err, strings.Join(lines, "\n"), strings.Join(testCase.Expected, "\n"))
		return
	}

	for index, current := range testCase.Steps {
		// a step of a large frame is split at every 97th byte, the others at every byte
		stride := 1

		if len(current.Data) > 4096 {
			stride = 97
		}

		for splitAt := 1; splitAt < len(current.Data); splitAt += stride {
			for _, chunk := range []int{len(current.Data), 1} {
				events, err = run(testCase.Steps, testCase.MaxStreams, index, splitAt, chunk)

				if err == nil {
					lines = summary(events)
				}

				if (err != nil) || !slices.Equal(lines, testCase.Expected) {
					state.Errorf("Test of http2.Conn failed, case %s split in step %d at %d in pieces of %d, error: %v, events:\n%s", testCase.Name, index, splitAt, chunk, err, strings.Join(lines, "\n"))
					return
				}
			}
		}
	}
}

// Test if http2.Conn returns with the expected output: streams, the dynamic table and its size, CONTINUATION, padding, priority, trailers, server push, 1xx, resets, GOAWAY, gRPC framing and the stream limit, fed whole, split at every byte and byte by byte.
func TestConnPositive(state *testing.T) {
	testCases := []connCase{}

	// three parallel streams whose repeated fields come from the dynamic table, answered out of order, a body over two DATA frames
	client, server := newTestPeer(true), newTestPeer(false)
	steps := handshake(client, server, nil, nil)

	for index, path := range []string{"/a", "/b", "/c"} {
		client.headers(uint32(2*index+1), true, ":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", path, "user-agent", "curl/8.20.0", "x-repeat", "same value every time")
	}

	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	server.headers(3, false, ":status", "200", "content-type", "text/plain", "x-served", "yes")
	server.data(3, false, "hello ")
	server.headers(1, true, ":status", "204", "x-served", "yes")
	server.data(3, true, "world")
	server.headers(5, false, ":status", "200", "content-type", "text/plain", "x-served", "yes")
	server.data(5, true, "c")
	steps = append(steps, server.take(decerterhttp2.ServerPeer), step{Peer: decerterhttp2.ClientPeer, Data: nil, IsClose: true}, step{Peer: decerterhttp2.ServerPeer, Data: nil, IsClose: true})
	testCases = append(testCases, connCase{Name: "parallel", Steps: steps, MaxStreams: 0, Expected: []string{
		`head request 1 GET https example.com /a [user-agent=curl/8.20.0 x-repeat=same value every time] ends=true cut=false`,
		`end request 1 complete=true trailers=[] note=""`,
		`head request 3 GET https example.com /b [user-agent=curl/8.20.0 x-repeat=same value every time] ends=true cut=false`,
		`end request 3 complete=true trailers=[] note=""`,
		`head request 5 GET https example.com /c [user-agent=curl/8.20.0 x-repeat=same value every time] ends=true cut=false`,
		`end request 5 complete=true trailers=[] note=""`,
		`head response 3 200 [content-type=text/plain x-served=yes] ends=false cut=false`,
		`body response 3 "hello " grpc=[]`,
		`head response 1 204 [x-served=yes] ends=true cut=false`,
		`end response 1 complete=true trailers=[] note=""`,
		`close 1 response=true note=""`,
		`body response 3 "world" grpc=[]`,
		`end response 3 complete=true trailers=[] note=""`,
		`close 3 response=true note=""`,
		`head response 5 200 [content-type=text/plain x-served=yes] ends=false cut=false`,
		`body response 5 "c" grpc=[]`,
		`end response 5 complete=true trailers=[] note=""`,
		`close 5 response=true note=""`,
	}})

	// the server allows a larger table, the client's encoder grows into it after the ACK; then it is shrunk to 0, which empties it
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, []http2.Setting{{ID: http2.SettingHeaderTableSize, Val: 65536}})
	client.encoder.SetMaxDynamicTableSizeLimit(65536)
	client.encoder.SetMaxDynamicTableSize(65536)
	long := strings.Repeat("v", 6000)
	client.headers(1, true, ":method", "GET", ":scheme", "http", ":authority", "h", ":path", "/1", "x-long", long)
	client.headers(3, true, ":method", "GET", ":scheme", "http", ":authority", "h", ":path", "/2", "x-long", long)
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	server.settings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0})
	steps = append(steps, server.take(decerterhttp2.ServerPeer))
	client.ack()
	client.encoder.SetMaxDynamicTableSize(0)
	client.headers(5, true, ":method", "GET", ":scheme", "http", ":authority", "h", ":path", "/3", "x-long", "short")
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	testCases = append(testCases, connCase{Name: "table size", Steps: steps, MaxStreams: 0, Expected: []string{
		`head request 1 GET http h /1 [x-long=` + long + `] ends=true cut=false`,
		`end request 1 complete=true trailers=[] note=""`,
		`head request 3 GET http h /2 [x-long=` + long + `] ends=true cut=false`,
		`end request 3 complete=true trailers=[] note=""`,
		`head request 5 GET http h /3 [x-long=short] ends=true cut=false`,
		`end request 5 complete=true trailers=[] note=""`,
	}})

	// HEADERS with padding and priority continued in two CONTINUATION frames, a padded DATA frame, the request's trailers, a 100 before the response
	// and a server push whose PUSH_PROMISE is continued too
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, nil)
	block := client.encode(":method", "POST", ":scheme", "https", ":authority", "example.com", ":path", "/upload", "content-type", "text/plain", "expect", "100-continue")
	client.err = errors.Join(client.err, client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:5], EndStream: false, EndHeaders: false, PadLength: 7, Priority: http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 200}}))
	client.err = errors.Join(client.err, client.framer.WriteContinuation(1, false, block[5:10]))
	client.err = errors.Join(client.err, client.framer.WriteContinuation(1, true, block[10:]))
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	server.headers(1, false, ":status", "100")
	steps = append(steps, server.take(decerterhttp2.ServerPeer))
	client.err = errors.Join(client.err, client.framer.WriteDataPadded(1, false, []byte("body"), make([]byte, 20)))
	client.err = errors.Join(client.err, client.framer.WritePriority(1, http2.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 15}))
	client.err = errors.Join(client.err, client.framer.WriteWindowUpdate(0, 1000))
	client.headers(1, true, "x-checksum", "abc")
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	promise := server.encode(":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/style.css")
	server.err = errors.Join(server.err, server.framer.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2, BlockFragment: promise[:3], EndHeaders: false, PadLength: 2}))
	server.err = errors.Join(server.err, server.framer.WriteContinuation(1, true, promise[3:]))
	server.headers(1, false, ":status", "201")
	server.data(1, false, "created")
	server.headers(1, true, "x-trailer", "t")
	server.headers(2, false, ":status", "200", "content-type", "text/css")
	server.err = errors.Join(server.err, server.framer.WritePing(false, [8]byte{1}))
	server.data(2, true, "body{}")
	steps = append(steps, server.take(decerterhttp2.ServerPeer))
	testCases = append(testCases, connCase{Name: "continuation, padding, trailers, push", Steps: steps, MaxStreams: 0, Expected: []string{
		`head request 1 POST https example.com /upload [content-type=text/plain expect=100-continue] ends=false cut=false`,
		`interim response 1 100 [] ends=false cut=false`,
		`body request 1 "body" grpc=[]`,
		`end request 1 complete=true trailers=[x-checksum=abc] note=""`,
		`head request 2<-1 GET https example.com /style.css [] ends=true cut=false`,
		`end request 2<-1 complete=true trailers=[] note=""`,
		`head response 1 201 [] ends=false cut=false`,
		`body response 1 "created" grpc=[]`,
		`end response 1 complete=true trailers=[x-trailer=t] note=""`,
		`close 1 response=true note=""`,
		`head response 2<-1 200 [content-type=text/css] ends=false cut=false`,
		`body response 2<-1 "body{}" grpc=[]`,
		`end response 2<-1 complete=true trailers=[] note=""`,
		`close 2<-1 response=true note=""`,
	}})

	// a gRPC unary call: the request message in one frame, the response's two messages cut over frames at odd places, grpc-status in the trailers
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, nil)
	client.headers(1, false, ":method", "POST", ":scheme", "http", ":authority", "localhost", ":path", "/decerter.Echo/Say", "content-type", "application/grpc", "te", "trailers")
	client.data(1, true, "\x00\x00\x00\x00\x03abc")
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	server.headers(1, false, ":status", "200", "content-type", "application/grpc+proto")
	server.data(1, false, "\x00\x00")
	server.data(1, false, "\x00\x00\x02hi\x01\x00\x00")
	server.data(1, false, "\x00\x00\x00\x00\x00\x00\x01")
	server.data(1, false, "z")
	server.headers(1, true, "grpc-status", "0", "grpc-message", "")
	steps = append(steps, server.take(decerterhttp2.ServerPeer))
	testCases = append(testCases, connCase{Name: "grpc", Steps: steps, MaxStreams: 0, Expected: []string{
		`head request 1 POST http localhost /decerter.Echo/Say [content-type=application/grpc te=trailers] ends=false cut=false`,
		`body request 1 "\x00\x00\x00\x00\x03abc" grpc=[0+3/false]`,
		`end request 1 complete=true trailers=[] note=""`,
		`head response 1 200 [content-type=application/grpc+proto] ends=false cut=false`,
		`body response 1 "\x00\x00" grpc=[]`,
		`body response 1 "\x00\x00\x02hi\x01\x00\x00" grpc=[0+2/false]`,
		`body response 1 "\x00\x00\x00\x00\x00\x00\x01" grpc=[7+0/true 12+1/false]`,
		`body response 1 "z" grpc=[]`,
		`end response 1 complete=true trailers=[grpc-status=0 grpc-message=] note=""`,
		`close 1 response=true note=""`,
	}})

	// a reset in the middle of a response body, a stream reset before any response, GOAWAY that leaves stream 5 unprocessed, the end of the connection
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, nil)
	client.headers(1, true, ":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/big")
	client.headers(3, true, ":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/refused")
	client.headers(5, true, ":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/late")
	client.headers(7, false, ":method", "POST", ":scheme", "https", ":authority", "a", ":path", "/open")
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	server.headers(1, false, ":status", "200")
	server.data(1, false, "part")
	server.err = errors.Join(server.err, server.framer.WriteRSTStream(3, http2.ErrCodeRefusedStream))
	server.err = errors.Join(server.err, server.framer.WriteGoAway(3, http2.ErrCodeNo, []byte("bye")))
	steps = append(steps, server.take(decerterhttp2.ServerPeer))
	client.err = errors.Join(client.err, client.framer.WriteRSTStream(1, http2.ErrCodeCancel))
	steps = append(steps, client.take(decerterhttp2.ClientPeer), step{Peer: decerterhttp2.ServerPeer, Data: nil, IsClose: true})
	testCases = append(testCases, connCase{Name: "reset and goaway", Steps: steps, MaxStreams: 0, Expected: []string{
		`head request 1 GET https a /big [] ends=true cut=false`,
		`end request 1 complete=true trailers=[] note=""`,
		`head request 3 GET https a /refused [] ends=true cut=false`,
		`end request 3 complete=true trailers=[] note=""`,
		`head request 5 GET https a /late [] ends=true cut=false`,
		`end request 5 complete=true trailers=[] note=""`,
		`head request 7 POST https a /open [] ends=false cut=false`,
		`head response 1 200 [] ends=false cut=false`,
		`body response 1 "part" grpc=[]`,
		`close 3 response=false note="the server reset the stream: REFUSED_STREAM"`,
		`close 5 response=false note="not processed: the server sent GOAWAY (NO_ERROR) with last stream 3"`,
		`end request 7 complete=false trailers=[] note="not processed: the server sent GOAWAY (NO_ERROR) with last stream 3"`,
		`close 7 response=false note="not processed: the server sent GOAWAY (NO_ERROR) with last stream 3"`,
		`end response 1 complete=false trailers=[] note="the client reset the stream: CANCEL"`,
		`close 1 response=true note="the client reset the stream: CANCEL"`,
	}})

	// the connection ends while a gRPC response is cut short and a request still sends its body; two open streams at most, the third is skipped
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, []http2.Setting{{ID: http2.SettingMaxFrameSize, Val: 32768}}, nil)
	client.headers(1, false, ":method", "POST", ":scheme", "https", ":authority", "a", ":path", "/x.Y/Z", "content-type", "application/grpc")
	client.data(1, true, "\x00\x00\x00\x00\x00")
	client.headers(3, false, ":method", "POST", ":scheme", "https", ":authority", "a", ":path", "/upload")
	client.headers(5, true, ":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/skipped")
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	server.headers(1, false, ":status", "200", "content-type", "application/grpc")
	server.data(1, false, "\x00\x00\x00\x00\x09"+strings.Repeat("m", 20000))
	server.headers(5, true, ":status", "200")
	steps = append(steps, server.take(decerterhttp2.ServerPeer), step{Peer: decerterhttp2.ClientPeer, Data: nil, IsClose: true}, step{Peer: decerterhttp2.ServerPeer, Data: nil, IsClose: true})
	testCases = append(testCases, connCase{Name: "connection end and limits", Steps: steps, MaxStreams: 2, Expected: []string{
		`head request 1 POST https a /x.Y/Z [content-type=application/grpc] ends=false cut=false`,
		`body request 1 "\x00\x00\x00\x00\x00" grpc=[0+0/false]`,
		`end request 1 complete=true trailers=[] note=""`,
		`head request 3 POST https a /upload [] ends=false cut=false`,
		`skip 5`,
		`head response 1 200 [content-type=application/grpc] ends=false cut=false`,
		`body response 1 20005 bytes grpc=[0+9/false 14+1835887981/true]`,
		`end request 3 complete=false trailers=[] note="the connection ended before the message"`,
		`end response 1 complete=false trailers=[] note="the connection ended before the stream; the last gRPC message is cut short"`,
		`close 1 response=true note="the connection ended before the stream"`,
		`close 3 response=false note="the connection ended before the stream"`,
	}})

	for _, testCase := range testCases {
		checkCase(state, testCase)
	}

	if err := errors.Join(client.err, server.err); err != nil {
		state.Fatalf("Could not write the frames of the cases, error: %s", err.Error())
	}
}

// Test if http2.Conn returns with the expected errors: a bad preface, a frame over the max frame size, an HPACK error, a header block cut by another frame, a table size update over the setting, garbage; each case stops the conn after ending its open streams.
func TestConnNegative(state *testing.T) {
	testCases := []connCase{}

	// not the preface: an HTTP/1 request
	testCases = append(testCases, connCase{Name: "preface", Steps: []step{{Peer: decerterhttp2.ClientPeer, Data: []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), IsClose: false}}, MaxStreams: 0, Expected: []string{`stop the client did not start with the http/2 connection preface`}})

	// a DATA frame of 20000 bytes while the client allows 16384, the stream that was open ends with the reason
	client, server := newTestPeer(true), newTestPeer(false)
	steps := handshake(client, server, nil, nil)
	client.headers(1, true, ":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/")
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	server.headers(1, false, ":status", "200")
	server.data(1, true, strings.Repeat("x", 20000))
	steps = append(steps, server.take(decerterhttp2.ServerPeer))
	testCases = append(testCases, connCase{Name: "frame too large", Steps: steps, MaxStreams: 0, Expected: []string{
		`head request 1 GET https a / [] ends=true cut=false`,
		`end request 1 complete=true trailers=[] note=""`,
		`head response 1 200 [] ends=false cut=false`,
		`end response 1 complete=false trailers=[] note="http/2 parsing stopped: http/2 frame larger than the max frame size of its receiver: 20000 bytes, at most 16384"`,
		`close 1 response=true note="http/2 parsing stopped: http/2 frame larger than the max frame size of its receiver: 20000 bytes, at most 16384"`,
		`stop http/2 frame larger than the max frame size of its receiver`,
	}})

	// an index past the dynamic table
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, nil)
	client.err = errors.Join(client.err, client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82, 0xff, 0x7f}, EndStream: true, EndHeaders: true, PadLength: 0, Priority: http2.PriorityParam{}}))
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	testCases = append(testCases, connCase{Name: "hpack index", Steps: steps, MaxStreams: 0, Expected: []string{`stop hpack decoding failed`}})

	// the client's encoder grows its table to 65536 although the server allows only 4096
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, nil)
	client.encoder.SetMaxDynamicTableSizeLimit(65536)
	client.encoder.SetMaxDynamicTableSize(65536)
	client.headers(1, true, ":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/")
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	testCases = append(testCases, connCase{Name: "table size over the setting", Steps: steps, MaxStreams: 0, Expected: []string{`stop hpack decoding failed`}})

	// a header block interrupted by a DATA frame, and a CONTINUATION without a block
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, nil)
	block := client.encode(":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/")
	client.err = errors.Join(client.err, client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:2], EndStream: false, EndHeaders: false, PadLength: 0, Priority: http2.PriorityParam{}}))
	client.data(1, true, "x")
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	testCases = append(testCases, connCase{Name: "interrupted block", Steps: steps, MaxStreams: 0, Expected: []string{`stop http/2 header block interrupted`}})
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, nil)
	client.err = errors.Join(client.err, client.framer.WriteContinuation(1, true, []byte{0x82}))
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	testCases = append(testCases, connCase{Name: "lone continuation", Steps: steps, MaxStreams: 0, Expected: []string{`stop http/2 header block interrupted`}})

	// a DATA frame on stream 0 and padding longer than the frame
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, nil)
	steps = append(steps, step{Peer: decerterhttp2.ServerPeer, Data: []byte{0, 0, 1, 0, 0, 0, 0, 0, 0, 'x'}, IsClose: false})
	testCases = append(testCases, connCase{Name: "data on stream 0", Steps: steps, MaxStreams: 0, Expected: []string{`stop malformed http/2 frame`}})
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, nil)
	steps = append(steps, step{Peer: decerterhttp2.ServerPeer, Data: []byte{0, 0, 2, 0, 0x8, 0, 0, 0, 1, 9, 'x'}, IsClose: false})
	testCases = append(testCases, connCase{Name: "padding too long", Steps: steps, MaxStreams: 0, Expected: []string{`stop malformed http/2 frame`}})

	for _, testCase := range testCases {
		checkCase(state, testCase)
	}

	if err := errors.Join(client.err, server.err); err != nil {
		state.Fatalf("Could not write the frames of the cases, error: %s", err.Error())
	}

	// a stopped conn reads nothing more
	conn := decerterhttp2.New(0)
	conn.Feed(decerterhttp2.ClientPeer, []byte("XYZ"))
	client, server = newTestPeer(true), newTestPeer(false)
	steps = handshake(client, server, nil, nil)

	if events := conn.Feed(decerterhttp2.ClientPeer, steps[0].Data); (len(events) != 0) || !errors.Is(conn.Err(), decerterhttp2.ErrPreface) || (len(conn.Close(decerterhttp2.ServerPeer)) != 0) {
		state.Errorf("Test of http2.Conn failed, a stopped conn should read nothing, events: %v, error: %v", summary(events), conn.Err())
		return
	}
}

// Test if http2.Conn.Settings returns with the expected output: what a peer announced counts once the other acknowledged it.
func TestSettingsPositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	conn := decerterhttp2.New(0)
	client.settings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 100}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	conn.Feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data)
	before := conn.Settings(decerterhttp2.ClientPeer)
	server.settings()
	server.ack()
	conn.Feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data)
	after := conn.Settings(decerterhttp2.ClientPeer)

	if (client.err != nil) || (server.err != nil) || (len(before) != 0) || (after[http2.SettingHeaderTableSize] != 100) || (after[http2.SettingInitialWindowSize] != 1<<20) || (len(conn.Settings(decerterhttp2.ServerPeer)) != 0) {
		state.Errorf("Test of http2.Conn.Settings function failed, before: %v, after: %v, error: %v", before, after, errors.Join(client.err, server.err))
		return
	}
}
