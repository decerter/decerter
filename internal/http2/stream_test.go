// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package http2_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2"

	decerterhttp2 "github.com/decerter/decerter/internal/http2"
)

// a header block in a HEADERS frame and as many CONTINUATION frames as it takes with fragments of size bytes
func (peer *testPeer) headersIn(streamID uint32, endStream bool, size int, block []byte) {
	first := block[:min(size, len(block))]
	block = block[len(first):]
	peer.err = errors.Join(peer.err, peer.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: first, EndStream: endStream, EndHeaders: len(block) == 0, PadLength: 0, Priority: http2.PriorityParam{}}))

	for len(block) > 0 {
		next := block[:min(size, len(block))]
		block = block[len(next):]
		peer.err = errors.Join(peer.err, peer.framer.WriteContinuation(streamID, len(block) == 0, next))
	}
}

func (peer *testPeer) promise(streamID uint32, promiseID uint32, pairs ...string) {
	peer.err = errors.Join(peer.err, peer.framer.WritePushPromise(http2.PushPromiseParam{StreamID: streamID, PromiseID: promiseID, BlockFragment: peer.encode(pairs...), EndHeaders: true, PadLength: 0}))
}

func (peer *testPeer) reset(streamID uint32, code http2.ErrCode) {
	peer.err = errors.Join(peer.err, peer.framer.WriteRSTStream(streamID, code))
}

func (peer *testPeer) windowUpdate(streamID uint32, increment uint32) {
	peer.err = errors.Join(peer.err, peer.framer.WriteWindowUpdate(streamID, increment))
}

// Test if http2.Conn returns with the expected output for frames that change nothing: a header block after the end of its message, frames of streams that are not open,
// a PUSH_PROMISE that promises a stream of the client or one that was promised before; the fields of every block still reach the dynamic table.
func TestConnIgnoredPositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	steps := handshake(client, server, nil, nil)
	client.headers(1, true, ":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/", "x-repeat", "same value every time")
	// the message of the client on stream 1 ended, streams 9 and 11 never opened
	client.headers(1, true, "x-late", "trailers after the end", "x-repeat", "same value every time")
	client.data(9, true, "nobody asked")
	client.reset(11, http2.ErrCodeCancel)
	client.windowUpdate(9, 100)
	client.err = errors.Join(client.err, client.framer.WritePriority(9, http2.PriorityParam{StreamDep: 1, Exclusive: false, Weight: 3}))
	steps = append(steps, client.take(decerterhttp2.ClientPeer))
	// stream 3 is one the client opens, stream 2 can only be promised once
	server.promise(1, 3, ":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/odd", "x-push", "a value the table repeats")
	server.promise(1, 2, ":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/pushed", "x-push", "a value the table repeats")
	server.promise(1, 2, ":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/again", "x-push", "a value the table repeats")
	server.headers(1, true, ":status", "200", "x-push", "a value the table repeats")
	server.data(1, true, "after the end")
	server.headers(2, false, ":status", "200", "x-push", "a value the table repeats")
	server.reset(2, http2.ErrCodeInternal)
	server.data(2, true, "after the reset")
	steps = append(steps, server.take(decerterhttp2.ServerPeer))
	client.headers(3, true, ":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/3", "x-repeat", "same value every time", "x-late", "trailers after the end")
	steps = append(steps, client.take(decerterhttp2.ClientPeer), step{Peer: decerterhttp2.ServerPeer, Data: nil, IsClose: true})

	if err := errors.Join(client.err, server.err); err != nil {
		state.Fatalf("Test of http2.Conn failed, cannot write the frames, error: %s", err.Error())
	}

	checkCase(state, connCase{Name: "ignored frames", Steps: steps, MaxStreams: 0, Expected: []string{
		`head request 1 GET https example.com / [x-repeat=same value every time] ends=true cut=false`,
		`end request 1 complete=true trailers=[] note=""`,
		`head request 2<-1 GET https example.com /pushed [x-push=a value the table repeats] ends=true cut=false`,
		`end request 2<-1 complete=true trailers=[] note=""`,
		`head response 1 200 [x-push=a value the table repeats] ends=true cut=false`,
		`end response 1 complete=true trailers=[] note=""`,
		`close 1 response=true note=""`,
		`head response 2<-1 200 [x-push=a value the table repeats] ends=false cut=false`,
		`end response 2<-1 complete=false trailers=[] note="the server reset the stream: INTERNAL_ERROR"`,
		`close 2<-1 response=true note="the server reset the stream: INTERNAL_ERROR"`,
		`head request 3 GET https example.com /3 [x-repeat=same value every time x-late=trailers after the end] ends=true cut=false`,
		`end request 3 complete=true trailers=[] note=""`,
		`close 3 response=false note="the connection ended before the stream"`,
	}})
}

// Test if http2.Conn returns with the expected output for a head over the limit of what is kept: the fields up to it, the cut told, and the dynamic table still in step for the next head.
func TestConnHeadLimitPositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	steps := handshake(client, server, nil, nil)
	pairs := []string{":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/", "x-repeat", "same value every time"}
	kept := []string{"x-repeat=same value every time"}

	// eight fields of 8000 bytes are under the 64 KiB of a head, the ninth is over it and nothing after it is kept
	for index := range 10 {
		name, value := fmt.Sprintf("x-large-%d", index), strings.Repeat(string(rune('a'+index)), 8000)
		pairs = append(pairs, name, value)

		if index < 8 {
			kept = append(kept, name+"="+value)
		}
	}

	pairs = append(pairs, "x-after", "small")
	client.headersIn(1, true, 16000, client.encode(pairs...))
	client.headers(3, true, ":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/3", "x-repeat", "same value every time")
	steps = append(steps, client.take(decerterhttp2.ClientPeer))

	if err := errors.Join(client.err, server.err); err != nil {
		state.Fatalf("Test of http2.Conn failed, cannot write the frames, error: %s", err.Error())
	}

	expected := []string{
		`head request 1 GET https example.com / [` + strings.Join(kept, " ") + `] ends=true cut=true`,
		`end request 1 complete=true trailers=[] note=""`,
		`head request 3 GET https example.com /3 [x-repeat=same value every time] ends=true cut=false`,
		`end request 3 complete=true trailers=[] note=""`,
	}
	last := len(steps) - 1

	// whole, cut once in the middle of the block, and in pieces of 1000 bytes
	for _, split := range [][2]int{{0, len(steps[last].Data)}, {30000, len(steps[last].Data)}, {1, 1000}} {
		events, err := run(steps, 0, last, split[0], split[1])

		if lines := summary(events); (err != nil) || !slices.Equal(lines, expected) {
			state.Errorf("Test of http2.Conn failed, split at %d in pieces of %d, the head should be cut after its eighth large field, error: %v, events: %d", split[0], split[1], err, len(lines))
			return
		}
	}
}

// Test if http2.Conn returns with the expected output for a gRPC body of more messages than are listed, cut short in the prefix of its last one.
func TestConnGRPCLimitPositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	steps := handshake(client, server, nil, nil)
	client.headers(1, false, ":method", "POST", ":scheme", "http", ":authority", "localhost", ":path", "/decerter.Echo/Say", "content-type", "application/grpc")
	// 1002 empty messages, the second of them compressed, and two bytes of the next prefix
	body := "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00" + strings.Repeat("\x00\x00\x00\x00\x00", decerterhttp2.MaxGRPCMessages) + "\x00\x00"
	client.data(1, true, body)
	steps = append(steps, client.take(decerterhttp2.ClientPeer))

	if err := errors.Join(client.err, server.err); err != nil {
		state.Fatalf("Test of http2.Conn failed, cannot write the frames, error: %s", err.Error())
	}

	listed := []string{"0+0/false", "5+0/true"}

	for index := 2; index < decerterhttp2.MaxGRPCMessages; index++ {
		listed = append(listed, fmt.Sprintf("%d+0/false", 5*index))
	}

	checkCase(state, connCase{Name: "grpc limit", Steps: steps, MaxStreams: 0, Expected: []string{
		`head request 1 POST http localhost /decerter.Echo/Say [content-type=application/grpc] ends=false cut=false`,
		fmt.Sprintf(`body request 1 %d bytes grpc=[%s]`, len(body), strings.Join(listed, " ")),
		`end request 1 complete=true trailers=[] note="the last gRPC message is cut short; more than 1000 gRPC messages, only the first 1000 are listed"`,
	}})
}

// Test if http2.Conn.Abort returns with the expected output: the open messages of the stream end incomplete with the note and the stream closes, nothing for a stream that is not open.
func TestAbortPositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	conn := decerterhttp2.New(0)

	for _, current := range handshake(client, server, nil, nil) {
		conn.Feed(current.Peer, current.Data)
	}

	// a gRPC request cut short in its message with a response that started, a request that waits for its response, a request without an end
	client.headers(1, false, ":method", "POST", ":scheme", "https", ":authority", "example.com", ":path", "/x.Y/Z", "content-type", "application/grpc")
	client.data(1, false, "\x00\x00\x00\x00\x09abc")
	client.headers(3, true, ":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/3")
	client.headers(5, false, ":method", "POST", ":scheme", "https", ":authority", "example.com", ":path", "/5")
	conn.Feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data)
	server.headers(1, false, ":status", "200", "content-type", "application/grpc")
	conn.Feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data)
	positiveCases := []struct {
		StreamID uint32
		Expected []string
	}{
		{StreamID: 1, Expected: []string{
			`end request 1 complete=false trailers=[] note="the rule dropped it; the last gRPC message is cut short"`,
			`end response 1 complete=false trailers=[] note="the rule dropped it"`,
			`close 1 response=true note="the rule dropped it"`,
		}},
		{StreamID: 3, Expected: []string{`close 3 response=false note="the rule dropped it"`}},
		{StreamID: 5, Expected: []string{
			`end request 5 complete=false trailers=[] note="the rule dropped it"`,
			`close 5 response=false note="the rule dropped it"`,
		}},
		// closed by the abort before, never opened, the connection
		{StreamID: 1, Expected: nil},
		{StreamID: 7, Expected: nil},
		{StreamID: 0, Expected: nil},
	}

	for _, positive := range positiveCases {
		if lines := summary(conn.Abort(positive.StreamID, "the rule dropped it")); !slices.Equal(lines, positive.Expected) {
			state.Errorf("Test of http2.Conn.Abort function failed, stream %d, events should be:\n%s\nevents:\n%s", positive.StreamID, strings.Join(positive.Expected, "\n"), strings.Join(lines, "\n"))
			return
		}
	}

	// the frames that still come on an aborted stream say nothing, a new stream does
	client.data(1, true, "defghi")
	client.headers(7, true, ":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/7")
	server.data(1, true, "late")
	lines := summary(append(conn.Feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data), conn.Feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data)...))
	expected := []string{
		`head request 7 GET https example.com /7 [] ends=true cut=false`,
		`end request 7 complete=true trailers=[] note=""`,
	}

	if err := errors.Join(client.err, server.err, conn.Err()); (err != nil) || !slices.Equal(lines, expected) {
		state.Errorf("Test of http2.Conn.Abort function failed, only the new stream should be told after it, error: %v, events:\n%s", err, strings.Join(lines, "\n"))
		return
	}

	// a stopped conn has no stream to abort
	conn.Feed(decerterhttp2.ServerPeer, []byte{0, 0, 1, 0, 0, 0, 0, 0, 0, 'x'})

	if events := conn.Abort(7, "the rule dropped it"); !errors.Is(conn.Err(), decerterhttp2.ErrFrame) || (len(events) != 0) {
		state.Errorf("Test of http2.Conn.Abort function failed, a stopped conn should abort nothing, events: %v, error: %v", summary(events), conn.Err())
		return
	}
}

// Test if http2.Conn.Settings returns with the expected output for a peer that never acknowledges: the oldest of more than 64 SETTINGS count as acknowledged, in their order.
func TestSettingsPendingPositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	conn := decerterhttp2.New(0)
	sent := 66

	for index := range sent {
		client.settings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: uint32(1000 + index)}, http2.Setting{ID: http2.SettingID(0x100 + index), Val: 1})
	}

	conn.Feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data)
	before := conn.Settings(decerterhttp2.ClientPeer)
	server.ack()
	conn.Feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data)
	after := conn.Settings(decerterhttp2.ClientPeer)

	// the first two went over the 64 that wait, the ACK takes the third; a setting only an older frame had stays
	if err := errors.Join(client.err, server.err, conn.Err()); (err != nil) || (before[http2.SettingHeaderTableSize] != 1001) || (len(before) != 3) || (after[http2.SettingHeaderTableSize] != 1002) || (len(after) != 4) || (after[http2.SettingID(0x100)] != 1) {
		state.Errorf("Test of http2.Conn.Settings function failed, the header table size should be 1001 before and 1002 after the ACK, before: %v, after: %v, error: %v", before, after, err)
		return
	}

	// the settings a peer got are a copy
	after[http2.SettingHeaderTableSize] = 0

	if again := conn.Settings(decerterhttp2.ClientPeer); again[http2.SettingHeaderTableSize] != 1002 {
		state.Errorf("Test of http2.Conn.Settings function failed, a change of the result should not reach the conn, settings: %v", again)
		return
	}
}

// Test if http2.HeadOf and http2.Head.Get return with the expected output.
func TestHeadOfPositive(state *testing.T) {
	positiveCases := []struct {
		Name     string
		Fields   []decerterhttp2.Field
		IsCut    bool
		Expected decerterhttp2.Head
	}{
		{Name: "no fields", Fields: nil, IsCut: false, Expected: decerterhttp2.Head{Method: "", Scheme: "", Authority: "", Path: "", Protocol: "", Status: 0, Fields: nil, IsCut: false}},
		{Name: "request", Fields: []decerterhttp2.Field{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/a?b"}, {Name: "accept", Value: "*/*"}}, IsCut: true, Expected: decerterhttp2.Head{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/a?b", Protocol: "", Status: 0, Fields: nil, IsCut: true}},
		{Name: "extended connect", Fields: []decerterhttp2.Field{{Name: ":method", Value: "CONNECT"}, {Name: ":protocol", Value: "websocket"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/chat"}}, IsCut: false, Expected: decerterhttp2.Head{Method: "CONNECT", Scheme: "https", Authority: "example.com", Path: "/chat", Protocol: "websocket", Status: 0, Fields: nil, IsCut: false}},
		{Name: "response", Fields: []decerterhttp2.Field{{Name: ":status", Value: "404"}, {Name: "content-type", Value: "text/plain"}}, IsCut: false, Expected: decerterhttp2.Head{Method: "", Scheme: "", Authority: "", Path: "", Protocol: "", Status: 404, Fields: nil, IsCut: false}},
		{Name: "status that is no number", Fields: []decerterhttp2.Field{{Name: ":status", Value: "ok"}}, IsCut: false, Expected: decerterhttp2.Head{Method: "", Scheme: "", Authority: "", Path: "", Protocol: "", Status: 0, Fields: nil, IsCut: false}},
		// the last one counts, a pseudo-header field nobody knows and a name without the colon are only fields
		{Name: "status twice", Fields: []decerterhttp2.Field{{Name: ":status", Value: "200"}, {Name: ":status", Value: "204"}, {Name: ":unknown", Value: "x"}, {Name: "status", Value: "500"}}, IsCut: false, Expected: decerterhttp2.Head{Method: "", Scheme: "", Authority: "", Path: "", Protocol: "", Status: 204, Fields: nil, IsCut: false}},
	}

	for _, positive := range positiveCases {
		head := decerterhttp2.HeadOf(positive.Fields, positive.IsCut)
		fields := head.Fields
		head.Fields = nil

		if !slices.Equal(fields, positive.Fields) || (fmt.Sprintf("%+v", head) != fmt.Sprintf("%+v", positive.Expected)) {
			state.Errorf("Test of http2.HeadOf function failed, case: %s, head should be %+v, head: %+v, fields: %v", positive.Name, positive.Expected, head, fields)
			return
		}
	}

	head := decerterhttp2.HeadOf([]decerterhttp2.Field{{Name: ":status", Value: "200"}, {Name: "set-cookie", Value: "a=1"}, {Name: "Set-Cookie", Value: "b=2"}, {Name: "x-empty", Value: ""}}, false)
	getCases := []struct {
		Name  string
		Value string
		Found bool
	}{
		{Name: "set-cookie", Value: "a=1", Found: true},
		{Name: "SET-COOKIE", Value: "a=1", Found: true},
		{Name: ":status", Value: "200", Found: true},
		{Name: "x-empty", Value: "", Found: true},
		{Name: "status", Value: "", Found: false},
		{Name: "", Value: "", Found: false},
	}

	for _, positive := range getCases {
		value, found := head.Get(positive.Name)

		if (value != positive.Value) || (found != positive.Found) {
			state.Errorf("Test of http2.Head.Get function failed, name: %q, result should be %q %v, result: %q %v", positive.Name, positive.Value, positive.Found, value, found)
			return
		}
	}
}
