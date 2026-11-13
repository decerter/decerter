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

// a conn with frame events and its editor, run as the proxy runs them: keep says which heads are kept, output is what went on towards each receiver
type editRun struct {
	conn   *decerterhttp2.Conn
	editor *decerterhttp2.Editor
	keep   func(event decerterhttp2.Event) (isKept bool)
	output [2][]byte
	kept   []uint32
}

// one frame as its receiver reads it: header blocks decoded with the receiver's own decoder, Length the payload with its padding
type readFrame struct {
	Type      http2.FrameType
	StreamID  uint32
	Flags     http2.Flags
	Length    uint32
	Fields    []string
	Data      []byte
	Increment uint32
	ErrCode   http2.ErrCode
}

func newEditRun(keep func(event decerterhttp2.Event) (isKept bool)) (run *editRun) {
	run = &editRun{conn: decerterhttp2.New(0), editor: decerterhttp2.NewEditor(0), keep: keep, output: [2][]byte{}, kept: nil}
	run.conn.EmitFrames()
	return
}

// the bytes of a peer in pieces of chunk bytes (0 is whole); isPassed sends them on before the editor sees them, as a transparent feed does
func (run *editRun) feed(peer decerterhttp2.Peer, data []byte, chunk int, isPassed bool) {
	if chunk <= 0 {
		chunk = max(len(data), 1)
	}

	for rest := data; len(rest) > 0; rest = rest[min(chunk, len(rest)):] {
		piece := rest[:min(chunk, len(rest))]

		if isPassed {
			run.output[peer] = append(run.output[peer], run.editor.Output(peer)...)
			run.output[peer] = append(run.output[peer], piece...)
			run.editor.Pass(peer, piece)
		} else {
			run.editor.Take(peer, piece)
		}

		for _, event := range run.conn.Feed(peer, piece) {
			switch event.Type {
			case decerterhttp2.FrameEventType:
				run.editor.Frame(peer, event)
			case decerterhttp2.HeadEventType:
				if (run.keep != nil) && !isPassed && run.keep(event) && run.editor.Keep(peer, event.StreamID) {
					run.kept = append(run.kept, event.StreamID)
				}
			case decerterhttp2.StopEventType:
				run.editor.Stop()
			default:
			}
		}

		run.collect()
	}
}

func (run *editRun) collect() {
	run.editor.Settle()

	for _, peer := range []decerterhttp2.Peer{decerterhttp2.ClientPeer, decerterhttp2.ServerPeer} {
		run.output[peer] = append(run.output[peer], run.editor.Output(peer)...)
	}
}

// the frames of what went on towards a receiver since the last call, after the preface when it starts with one
func (run *editRun) read(peer decerterhttp2.Peer, decoder *hpack.Decoder, maxFrameSize uint32) (frames []readFrame, err error) {
	data := run.output[peer]
	run.output[peer] = nil
	data = bytes.TrimPrefix(data, []byte(http2.ClientPreface))
	frames, err = readFrames(data, decoder, maxFrameSize)
	return
}

// the frames of the bytes; header blocks with the decoder, so a receiver's table carries over between calls
func readFrames(data []byte, decoder *hpack.Decoder, maxFrameSize uint32) (frames []readFrame, err error) {
	framer := http2.NewFramer(nil, bytes.NewReader(data))
	framer.ReadMetaHeaders = decoder
	framer.SetMaxReadFrameSize(maxFrameSize)

	for {
		frame, readErr := framer.ReadFrame()

		if readErr != nil {
			if !errors.Is(readErr, errEOF(readErr)) {
				err = readErr
			}

			return
		}

		header := frame.Header()
		read := readFrame{Type: header.Type, StreamID: header.StreamID, Flags: header.Flags, Length: header.Length, Fields: nil, Data: nil, Increment: 0, ErrCode: 0}

		switch typed := frame.(type) {
		case *http2.MetaHeadersFrame:
			for _, field := range typed.Fields {
				read.Fields = append(read.Fields, field.Name+": "+field.Value)
			}

			read.Flags = typed.Flags
		case *http2.DataFrame:
			read.Data = bytes.Clone(typed.Data())
		case *http2.WindowUpdateFrame:
			read.Increment = typed.Increment
		case *http2.RSTStreamFrame:
			read.ErrCode = typed.ErrCode
		default:
		}

		frames = append(frames, read)
	}
}

// the end of the bytes is no error
func errEOF(err error) (eof error) {
	eof = err

	if !strings.Contains(err.Error(), "EOF") {
		eof = errors.New("not the end")
	}

	return
}

// the frames of a type, on a stream (0 is any)
func framesOf(frames []readFrame, frameType http2.FrameType, streamID uint32) (selected []readFrame) {
	for _, frame := range frames {
		if (frame.Type == frameType) && ((streamID == 0) || (frame.StreamID == streamID)) {
			selected = append(selected, frame)
		}
	}

	return
}

// the payload bytes of the DATA frames of a stream
func dataOf(frames []readFrame, streamID uint32) (data []byte) {
	for _, frame := range framesOf(frames, http2.FrameData, streamID) {
		data = append(data, frame.Data...)
	}

	return
}

// the increments of the WINDOW_UPDATE frames of a stream, 0 is the connection
func incrementOf(frames []readFrame, streamID uint32) (increment int) {
	for _, frame := range frames {
		if (frame.Type == http2.FrameWindowUpdate) && (frame.StreamID == streamID) {
			increment += int(frame.Increment)
		}
	}

	return
}

// the streams of the header blocks in their order
func blockStreams(frames []readFrame) (streams []uint32) {
	for _, frame := range framesOf(frames, http2.FrameHeaders, 0) {
		streams = append(streams, frame.StreamID)
	}

	return
}

// heads to keep: the side's on the streams, both sides with sides 2
func keepStreams(side decerterhttp2.Side, ids ...uint32) (keep func(event decerterhttp2.Event) (isKept bool)) {
	keep = func(event decerterhttp2.Event) (isKept bool) {
		isKept = !event.IsInterim && ((side == 2) || (event.Side == side)) && slices.Contains(ids, event.StreamID)
		return
	}
	return
}

// a client and a server after their SETTINGS, both acknowledged, and requests on the streams with a field the dynamic table repeats
func editStart(run *editRun, client *testPeer, server *testPeer, clientSettings []http2.Setting, streams ...uint32) {
	client.settings(clientSettings...)
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	server.settings()
	server.ack()
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	client.ack()

	for _, id := range streams {
		client.headers(id, true, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", fmt.Sprintf("/%d", id), "x-repeat", "one value in every request")
	}

	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
}

// Test if http2.Editor returns with the expected output: frames nobody keeps go on byte for byte in any pieces, a released message goes on as it came, a kept response stalls only its stream,
// later header blocks are encoded again and decode the same with the receiver's own decoder, a new client stream waits for an earlier held one, and a drop resets the stream.
func TestEditorPositive(state *testing.T) {
	// byte for byte: padding, CONTINUATION, a push, PING and WINDOW_UPDATE, taken in pieces of 7 bytes, passed, and passed then taken
	client, server := newTestPeer(true), newTestPeer(false)
	client.settings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	client.headers(1, false, ":method", "POST", ":scheme", "https", ":authority", "edit.test", ":path", "/", "x-repeat", "value")
	client.err = errors.Join(client.err, client.framer.WriteDataPadded(1, true, []byte("body"), make([]byte, 9)))
	client.headers(3, true, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/3", "x-repeat", "value")
	client.err = errors.Join(client.err, client.framer.WriteWindowUpdate(0, 1000), client.framer.WritePing(false, [8]byte{1}))
	server.settings()
	server.ack()
	block := server.encode(":status", "200", "x-long", strings.Repeat("v", 100))
	server.err = errors.Join(server.err, server.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:10], EndStream: false, EndHeaders: false, PadLength: 0, Priority: http2.PriorityParam{}}))
	server.err = errors.Join(server.err, server.framer.WriteContinuation(1, true, block[10:]))
	server.err = errors.Join(server.err, server.framer.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2, BlockFragment: server.encode(":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/pushed"), EndHeaders: true, PadLength: 0}))
	server.err = errors.Join(server.err, server.framer.WriteDataPadded(1, true, []byte("answer"), make([]byte, 20)))
	server.headers(3, true, ":status", "204")
	clientData, serverData := client.take(decerterhttp2.ClientPeer).Data, server.take(decerterhttp2.ServerPeer).Data

	for _, mode := range []string{"taken", "passed", "half"} {
		run := newEditRun(keepStreams(2))

		switch mode {
		case "taken":
			run.feed(decerterhttp2.ClientPeer, clientData, 7, false)
			run.feed(decerterhttp2.ServerPeer, serverData, 7, false)
		case "passed":
			run.feed(decerterhttp2.ClientPeer, clientData, 7, true)
			run.feed(decerterhttp2.ServerPeer, serverData, 7, true)
		default:
			run.feed(decerterhttp2.ClientPeer, clientData[:50], 13, true)
			run.feed(decerterhttp2.ClientPeer, clientData[50:], 13, false)
			run.feed(decerterhttp2.ServerPeer, serverData[:31], 0, true)
			run.feed(decerterhttp2.ServerPeer, serverData[31:], 5, false)
		}

		if err := errors.Join(client.err, server.err, run.editor.Err()); (err != nil) || !bytes.Equal(run.output[decerterhttp2.ClientPeer], clientData) || !bytes.Equal(run.output[decerterhttp2.ServerPeer], serverData) || run.editor.IsTouched() {
			state.Errorf("Test of http2.Editor failed, %s, frames nobody keeps should go on byte for byte, client %d of %d bytes, server %d of %d bytes, error: %v", mode, len(run.output[0]), len(clientData), len(run.output[1]), len(serverData), err)
			return
		}
	}

	// a response held while the next two go on: they are encoded again, the held one after them too, and all decode as they came
	client, server = newTestPeer(true), newTestPeer(false)
	run := newEditRun(keepStreams(decerterhttp2.ResponseSide, 1))
	editStart(run, client, server, nil, 1, 3, 5)
	upstream, err := run.read(decerterhttp2.ClientPeer, hpack.NewDecoder(4096, nil), 16384)

	if (err != nil) || !slices.Equal(blockStreams(upstream), []uint32{1, 3, 5}) || (len(run.kept) != 0) {
		state.Errorf("Test of http2.Editor failed, the requests should go on, streams: %v, kept: %v, error: %v", blockStreams(upstream), run.kept, err)
		return
	}

	for _, id := range []uint32{1, 3, 5} {
		server.headers(id, false, ":status", "200", "x-repeat", "one value in every response", "x-stream", fmt.Sprint(id))
		server.data(id, true, fmt.Sprintf("body of %d", id))
	}

	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	decoder := hpack.NewDecoder(4096, nil)
	downstream, err := run.read(decerterhttp2.ServerPeer, decoder, 16384)

	if (err != nil) || !slices.Equal(blockStreams(downstream), []uint32{3, 5}) || (len(dataOf(downstream, 1)) != 0) || (string(dataOf(downstream, 5)) != "body of 5") || !slices.Equal(run.kept, []uint32{1}) {
		state.Errorf("Test of http2.Editor failed, the held response should stall only its stream, streams: %v, kept: %v, error: %v", blockStreams(downstream), run.kept, err)
		return
	}

	// the sender gets the window of the held DATA back at once
	if incrementOf(framesOf(mustRead(run, decerterhttp2.ClientPeer), http2.FrameWindowUpdate, 0), 0) != len("body of 1") {
		state.Errorf("Test of http2.Editor failed, the server should get the window of the held body back")
		return
	}

	run.editor.Release(decerterhttp2.ServerPeer, 1)
	run.collect()
	released, err := run.read(decerterhttp2.ServerPeer, decoder, 16384)
	expected := []string{":status: 200", "x-repeat: one value in every response", "x-stream: 1"}

	if (err != nil) || !slices.Equal(blockStreams(released), []uint32{1}) || !slices.Equal(released[0].Fields, expected) || (string(dataOf(released, 1)) != "body of 1") || !run.editor.IsTouched() {
		state.Errorf("Test of http2.Editor failed, the released response should decode as it came, frames: %+v, error: %v", released, err)
		return
	}

	// later blocks of the direction decode the same too
	server.headers(7, true, ":status", "404", "x-repeat", "one value in every response")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	later, err := run.read(decerterhttp2.ServerPeer, decoder, 16384)

	if (err != nil) || (len(later) != 1) || !slices.Equal(later[0].Fields, []string{":status: 404", "x-repeat: one value in every response"}) {
		state.Errorf("Test of http2.Editor failed, a later block should decode as it came, frames: %+v, error: %v", later, err)
		return
	}

	// a request held with its body while later streams wait to open; its edited head is encoded with a table size update to 0 first, the waiting streams follow in order
	client, server = newTestPeer(true), newTestPeer(false)
	run = newEditRun(keepStreams(decerterhttp2.RequestSide, 1))
	client.settings()
	server.settings()
	server.ack()
	client.ack()
	client.headers(1, false, ":method", "POST", ":scheme", "https", ":authority", "edit.test", ":path", "/", "content-length", "5")
	client.data(1, false, "hel")
	client.headers(3, true, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/3")
	client.data(1, true, "lo")
	client.headers(5, true, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/5")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	upstream, err = run.read(decerterhttp2.ClientPeer, hpack.NewDecoder(4096, nil), 16384)

	if (err != nil) || (len(blockStreams(upstream)) != 0) {
		state.Errorf("Test of http2.Editor failed, later streams should wait for the held one, streams: %v, error: %v", blockStreams(upstream), err)
		return
	}

	fields := []decerterhttp2.Field{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "edit.test"}, {Name: ":path", Value: "/test"}, {Name: "content-length", Value: "11"}}
	run.editor.Replace(decerterhttp2.ClientPeer, 1, decerterhttp2.Edit{Fields: fields, Body: []byte("hello world"), IsHeadChanged: true, IsBodyChanged: true})
	run.collect()
	raw := run.output[decerterhttp2.ClientPeer]
	upstream, err = run.read(decerterhttp2.ClientPeer, hpack.NewDecoder(4096, nil), 16384)
	data := framesOf(upstream, http2.FrameData, 1)

	if (err != nil) || !slices.Equal(blockStreams(upstream), []uint32{1, 3, 5}) || !slices.Equal(upstream[0].Fields, []string{":method: POST", ":scheme: https", ":authority: edit.test", ":path: /test", "content-length: 11"}) ||
		(len(raw) < 10) || (raw[9] != 0x20) || (len(data) != 1) || (string(data[0].Data) != "hello world") || !data[0].Flags.Has(http2.FlagDataEndStream) {
		state.Errorf("Test of http2.Editor failed, the edited request and then the waiting ones should go on, streams: %v, frames: %+v, error: %v", blockStreams(upstream), upstream, err)
		return
	}

	// a dropped request: the server never hears of it, the client gets RST_STREAM; a dropped response: both get it
	client, server = newTestPeer(true), newTestPeer(false)
	run = newEditRun(keepStreams(2, 1, 3))
	editStart(run, client, server, nil, 1)
	run.editor.Drop(decerterhttp2.ClientPeer, 1)
	run.collect()
	client.headers(3, true, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/3")
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	server.headers(3, true, ":status", "200")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	run.editor.Release(decerterhttp2.ClientPeer, 3)
	run.collect()
	run.editor.Drop(decerterhttp2.ServerPeer, 3)
	run.collect()
	upstream, err = run.read(decerterhttp2.ClientPeer, hpack.NewDecoder(4096, nil), 16384)
	downstream, downErr := run.read(decerterhttp2.ServerPeer, hpack.NewDecoder(4096, nil), 16384)
	upReset, downReset := framesOf(upstream, http2.FrameRSTStream, 0), framesOf(downstream, http2.FrameRSTStream, 0)

	if err = errors.Join(err, downErr); (err != nil) || !slices.Equal(blockStreams(upstream), []uint32{3}) || (len(upReset) != 1) || (upReset[0].StreamID != 3) || (len(downReset) != 2) ||
		(downReset[0].StreamID != 1) || (downReset[1].StreamID != 3) || (downReset[1].ErrCode != http2.ErrCodeCancel) || (len(blockStreams(downstream)) != 0) {
		state.Errorf("Test of http2.Editor failed, drops should reset the streams, up: %+v, down: %+v, error: %v", upstream, downstream, err)
	}
}

func mustRead(run *editRun, peer decerterhttp2.Peer) (frames []readFrame) {
	frames, _ = run.read(peer, hpack.NewDecoder(4096, nil), 1<<24-1)
	return
}

// Test if http2.Editor returns with the expected output for flow control: a body grown past the receiver's windows waits for its WINDOW_UPDATEs, which the sender does not get,
// a body shrunk gives the sender its window back at once, a change of SETTINGS_INITIAL_WINDOW_SIZE moves the stream windows, and frames are split at the max frame size.
func TestEditorWindowsPositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	run := newEditRun(keepStreams(decerterhttp2.ResponseSide, 1, 5, 7))
	editStart(run, client, server, []http2.Setting{{ID: http2.SettingInitialWindowSize, Val: 1000}}, 1, 3)
	mustRead(run, decerterhttp2.ClientPeer)
	mustRead(run, decerterhttp2.ServerPeer)

	// grow: 10 bytes become 3000 on a stream window of 1000
	server.headers(1, false, ":status", "200")
	server.data(1, true, "0123456789")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	topUp := mustRead(run, decerterhttp2.ClientPeer)
	grown := bytes.Repeat([]byte("g"), 3000)
	run.editor.Replace(decerterhttp2.ServerPeer, 1, decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":status", Value: "200"}}, Body: grown, IsHeadChanged: false, IsBodyChanged: true})
	run.collect()
	first := mustRead(run, decerterhttp2.ServerPeer)

	if (incrementOf(topUp, 0) != 10) || (incrementOf(topUp, 1) != 0) || (len(dataOf(first, 1)) != 1000) || (len(blockStreams(first)) != 1) {
		state.Errorf("Test of http2.Editor failed, the grown body should stop at the stream window, top-up: %+v, DATA: %d", topUp, len(dataOf(first, 1)))
		return
	}

	// the client's WINDOW_UPDATEs let 1000 more go, the server does not get them, it sent only 10
	client.err = errors.Join(client.err, client.framer.WriteWindowUpdate(1, 1000), client.framer.WriteWindowUpdate(0, 1000))
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	second, toServer := mustRead(run, decerterhttp2.ServerPeer), mustRead(run, decerterhttp2.ClientPeer)

	if (len(dataOf(second, 1)) != 1000) || (len(framesOf(toServer, http2.FrameWindowUpdate, 0)) != 0) {
		state.Errorf("Test of http2.Editor failed, a WINDOW_UPDATE should let the next part go and not reach the server, DATA: %d, to the server: %+v", len(dataOf(second, 1)), toServer)
		return
	}

	// a larger SETTINGS_INITIAL_WINDOW_SIZE, in effect once the server acknowledged it, lets the rest go
	client.settings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 2000})
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	server.ack()
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	third := mustRead(run, decerterhttp2.ServerPeer)
	mustRead(run, decerterhttp2.ClientPeer)
	ends := framesOf(third, http2.FrameData, 1)

	if (len(dataOf(third, 1)) != 1000) || (len(ends) == 0) || !ends[len(ends)-1].Flags.Has(http2.FlagDataEndStream) {
		state.Errorf("Test of http2.Editor failed, the setting should let the rest go with END_STREAM, DATA: %d", len(dataOf(third, 1)))
		return
	}

	// the client's next window goes on less the 2000 the server never sent
	client.err = errors.Join(client.err, client.framer.WriteWindowUpdate(0, 4000))
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)

	if forwarded := incrementOf(mustRead(run, decerterhttp2.ClientPeer), 0); forwarded != 4000-2000 {
		state.Errorf("Test of http2.Editor failed, the server should get what is left of the client's window, got %d", forwarded)
		return
	}

	// shrink: 1500 bytes become 10, the server gets the 1500 back at once and the client's 10 are not passed on
	shrinkClient, shrinkServer := newTestPeer(true), newTestPeer(false)
	shrinkRun := newEditRun(keepStreams(decerterhttp2.ResponseSide, 3))
	editStart(shrinkRun, shrinkClient, shrinkServer, nil, 3)
	mustRead(shrinkRun, decerterhttp2.ClientPeer)
	mustRead(shrinkRun, decerterhttp2.ServerPeer)
	shrinkServer.headers(3, false, ":status", "200")
	shrinkServer.data(3, true, string(bytes.Repeat([]byte("s"), 1500)))
	shrinkRun.feed(decerterhttp2.ServerPeer, shrinkServer.take(decerterhttp2.ServerPeer).Data, 0, false)
	shrinkRun.editor.Replace(decerterhttp2.ServerPeer, 3, decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":status", Value: "200"}}, Body: []byte("ten bytes!"), IsHeadChanged: false, IsBodyChanged: true})
	shrinkRun.collect()
	shrunk, back := mustRead(shrinkRun, decerterhttp2.ServerPeer), mustRead(shrinkRun, decerterhttp2.ClientPeer)
	shrinkClient.err = errors.Join(shrinkClient.err, shrinkClient.framer.WriteWindowUpdate(0, 10), shrinkClient.framer.WriteWindowUpdate(0, 4000))
	shrinkRun.feed(decerterhttp2.ClientPeer, shrinkClient.take(decerterhttp2.ClientPeer).Data, 0, false)
	afterShrink := mustRead(shrinkRun, decerterhttp2.ClientPeer)

	if (string(dataOf(shrunk, 3)) != "ten bytes!") || (incrementOf(back, 0) != 1500) || (incrementOf(back, 3) != 0) || (incrementOf(afterShrink, 0) != 4000) || (shrinkClient.err != nil) {
		state.Errorf("Test of http2.Editor failed, the shrunk body should give the window back, DATA: %q, back: %d, after: %d", dataOf(shrunk, 3), incrementOf(back, 0), incrementOf(afterShrink, 0))
		return
	}

	// splitting: a body of 40000 bytes and a field of 40000 bytes in frames of at most 16384, padding dropped on the edited body, kept on the released one
	client.headers(5, true, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/5")
	client.headers(7, true, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/7")
	client.err = errors.Join(client.err, client.framer.WriteWindowUpdate(0, 1<<20))
	client.settings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	server.ack()
	server.headers(5, false, ":status", "200")
	server.err = errors.Join(server.err, server.framer.WriteDataPadded(5, true, []byte("padded"), make([]byte, 30)))
	server.headers(7, false, ":status", "200")
	server.err = errors.Join(server.err, server.framer.WriteDataPadded(7, true, []byte("padded too"), make([]byte, 30)))
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	mustRead(run, decerterhttp2.ServerPeer)
	run.editor.Replace(decerterhttp2.ServerPeer, 5, decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":status", Value: "200"}, {Name: "x-large", Value: strings.Repeat("x", 40000)}}, Body: bytes.Repeat([]byte("b"), 40000), IsHeadChanged: true, IsBodyChanged: true})
	run.collect()
	split := run.output[decerterhttp2.ServerPeer]
	frames, err := readFrames(split, hpack.NewDecoder(4096, nil), 16384)
	run.output[decerterhttp2.ServerPeer] = nil
	run.editor.Release(decerterhttp2.ServerPeer, 7)
	run.collect()
	padded := mustRead(run, decerterhttp2.ServerPeer)
	sizes := frameSizes(split)
	paddedData := framesOf(padded, http2.FrameData, 7)

	if (err != nil) || (len(dataOf(frames, 5)) != 40000) || slices.ContainsFunc(sizes, func(size int) bool { return size > 16384 }) || (len(sizes) < 6) ||
		slices.ContainsFunc(framesOf(frames, http2.FrameData, 5), func(frame readFrame) bool { return int(frame.Length) != len(frame.Data) }) ||
		(len(paddedData) != 1) || (paddedData[0].Length != uint32(len("padded too")+31)) {
		state.Errorf("Test of http2.Editor failed, the edited message should be split without padding and the released one keep it, sizes: %v, padded: %+v, error: %v", sizes, paddedData, err)
	}
}

// the payload lengths of the frames in the bytes
func frameSizes(data []byte) (sizes []int) {
	for len(data) >= 9 {
		size := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		sizes = append(sizes, size)
		data = data[min(len(data), 9+size):]
	}

	return
}

// Test if http2.Editor returns with the expected errors: Keep refuses a block that is not waiting or went on already, a reset of a held request does not reach the server,
// and a frame the conn can't read stops the editor, which then lets every byte go on as it came.
func TestEditorNegative(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	run := newEditRun(nil)
	editStart(run, client, server, nil)
	client.headers(1, true, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/")
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, true)

	if run.editor.Keep(decerterhttp2.ClientPeer, 1) || run.editor.Keep(decerterhttp2.ClientPeer, 3) || run.editor.IsTouched() {
		state.Errorf("Test of http2.Editor failed, Keep should refuse a block that went on and an unknown stream")
		return
	}

	// a client resets the stream of its held request: the server never hears of either
	client, server = newTestPeer(true), newTestPeer(false)
	run = newEditRun(keepStreams(decerterhttp2.RequestSide, 3))
	editStart(run, client, server, nil, 3)
	mustRead(run, decerterhttp2.ClientPeer)
	client.err = errors.Join(client.err, client.framer.WriteRSTStream(3, http2.ErrCodeCancel))
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	run.editor.Release(decerterhttp2.ClientPeer, 3)
	run.collect()

	if frames := mustRead(run, decerterhttp2.ClientPeer); (len(frames) != 0) || !slices.Equal(run.kept, []uint32{3}) {
		state.Errorf("Test of http2.Editor failed, a reset held request should not reach the server, frames: %+v", frames)
		return
	}

	// a DATA frame on stream 0 stops the conn: what came and what comes goes on as it is
	client, server = newTestPeer(true), newTestPeer(false)
	run = newEditRun(keepStreams(decerterhttp2.ResponseSide, 1))
	editStart(run, client, server, nil, 1)
	mustRead(run, decerterhttp2.ClientPeer)
	client.data(1, false, "x")
	client.framer.AllowIllegalWrites = true
	client.data(0, false, "broken")
	tail := client.take(decerterhttp2.ClientPeer).Data
	run.feed(decerterhttp2.ClientPeer, tail, 0, false)
	more := []byte("anything")
	run.feed(decerterhttp2.ClientPeer, more, 0, true)

	if output := run.output[decerterhttp2.ClientPeer]; !run.editor.IsStopped() || !bytes.HasSuffix(output, append(bytes.Clone(tail[len(tail)-15:]), more...)) || (client.err != nil) {
		state.Errorf("Test of http2.Editor failed, a stopped editor should let the bytes go on, output: %q, error: %v", output, client.err)
	}
}

// Test if http2.Form and http2.ParseForm return with the expected output: the form of a head and body parses back to them, LF alone and upper case names are taken.
func TestFormPositive(state *testing.T) {
	fields := []decerterhttp2.Field{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "text/plain"}, {Name: "x-empty", Value: ""}}
	form := decerterhttp2.Form([]decerterhttp2.Field{fields[1], fields[0], fields[2]}, []byte("body\r\n\r\nmore"))
	parsed, body, err := decerterhttp2.ParseForm(form)

	if (err != nil) || (string(form) != ":status: 200\r\ncontent-type: text/plain\r\nx-empty: \r\n\r\nbody\r\n\r\nmore") || !slices.Equal(parsed, fields) || (string(body) != "body\r\n\r\nmore") {
		state.Errorf("Test of http2.Form failed, form: %q, fields: %+v, body: %q, error: %v", form, parsed, body, err)
		return
	}

	parsed, body, err = decerterhttp2.ParseForm([]byte(":path:  /a:b \nX-Upper: Value\n\n"))

	if (err != nil) || !slices.Equal(parsed, []decerterhttp2.Field{{Name: ":path", Value: "/a:b"}, {Name: "x-upper", Value: "Value"}}) || (len(body) != 0) {
		state.Errorf("Test of http2.ParseForm failed, fields: %+v, body: %q, error: %v", parsed, body, err)
	}
}

// Test if http2.ParseForm returns with the expected errors for forms that are no HTTP/2 message.
func TestFormNegative(state *testing.T) {
	for _, form := range []string{":status: 200\r\n", "\r\n\r\nbody", ":status 200\r\n\r\n", "a: b\r\n:status: 200\r\n\r\n", "bad name: x\r\n\r\n", "a: b\x00c\r\n\r\n", ": empty\r\n\r\n"} {
		_, _, err := decerterhttp2.ParseForm([]byte(form))

		if !errors.Is(err, decerterhttp2.ErrForm) {
			state.Errorf("Test of http2.ParseForm failed, %q should be refused, error: %v", form, err)
			return
		}
	}
}
