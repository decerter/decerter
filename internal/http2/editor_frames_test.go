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

// one piece of a peer taken by the editor and read by the conn, its frame events given to the editor; nothing is settled or collected
func (run *editRun) step(peer decerterhttp2.Peer, piece []byte) {
	run.editor.Take(peer, piece)

	for _, event := range run.conn.Feed(peer, piece) {
		if event.Type == decerterhttp2.FrameEventType {
			run.editor.Frame(peer, event)
		}
	}
}

// Test if http2.Editor.IsClean and http2.Editor.HasOutput return with the expected output while a frame, a header block and a head nobody decided on are in the editor.
func TestEditorCleanPositive(state *testing.T) {
	client := newTestPeer(true)
	client.settings()
	block := client.encode(":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/")
	client.err = errors.Join(client.err, client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:5], EndStream: true, EndHeaders: false, PadLength: 0, Priority: http2.PriorityParam{}}))
	client.err = errors.Join(client.err, client.framer.WriteContinuation(1, true, block[5:]))
	data := client.take(decerterhttp2.ClientPeer).Data

	if client.err != nil {
		state.Fatalf("Test of http2.Editor.IsClean failed, cannot write the frames, error: %s", client.err.Error())
	}

	// the preface and the empty SETTINGS frame, then the HEADERS frame with five bytes of the block
	settingsEnd := len(http2.ClientPreface) + 9
	headersEnd := settingsEnd + 9 + 5
	run := newEditRun(nil)
	steps := []struct {
		Name      string
		Do        func()
		IsClean   bool
		HasOutput bool
		Output    []byte
	}{
		{Name: "new editor", Do: func() {}, IsClean: true, HasOutput: false, Output: nil},
		{Name: "start of the preface", Do: func() { run.step(decerterhttp2.ClientPeer, data[:10]) }, IsClean: false, HasOutput: false, Output: nil},
		{Name: "frame of an open header block", Do: func() { run.step(decerterhttp2.ClientPeer, data[10:headersEnd]) }, IsClean: false, HasOutput: true, Output: data[:settingsEnd]},
		{Name: "whole header block nobody decided on", Do: func() { run.step(decerterhttp2.ClientPeer, data[headersEnd:]) }, IsClean: false, HasOutput: false, Output: nil},
		{Name: "settled", Do: func() { run.editor.Settle() }, IsClean: true, HasOutput: true, Output: data[settingsEnd:]},
		{Name: "settled again", Do: func() { run.editor.Settle() }, IsClean: true, HasOutput: false, Output: nil},
	}

	for _, current := range steps {
		current.Do()
		isClean, hasOutput := run.editor.IsClean(decerterhttp2.ClientPeer), run.editor.HasOutput(decerterhttp2.ClientPeer)
		output := run.editor.Output(decerterhttp2.ClientPeer)

		if (isClean != current.IsClean) || (hasOutput != current.HasOutput) || !bytes.Equal(output, current.Output) || run.editor.HasOutput(decerterhttp2.ClientPeer) {
			state.Errorf("Test of http2.Editor.IsClean function failed, step: %s, clean and output should be %v %v with %d bytes, result: %v %v with %d bytes", current.Name, current.IsClean, current.HasOutput, len(current.Output), isClean, hasOutput, len(output))
			return
		}

		// the frames of the server are another side
		if !run.editor.IsClean(decerterhttp2.ServerPeer) || run.editor.HasOutput(decerterhttp2.ServerPeer) || run.editor.IsTouched() || (run.editor.Err() != nil) {
			state.Errorf("Test of http2.Editor.IsClean function failed, step: %s, the side of the server should be clean without output, error: %v", current.Name, run.editor.Err())
			return
		}
	}
}

// Test if http2.Editor returns with the expected errors: bytes that go on while earlier ones are kept back, a header block that goes on as it came after decerter encoded one,
// a header block too large to encode again; and that decisions on a message that is not kept change nothing.
func TestEditorOrderNegative(state *testing.T) {
	// the last five bytes of a PING go on while its start waits in the editor
	client := newTestPeer(true)
	client.settings()
	client.err = errors.Join(client.err, client.framer.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	data := client.take(decerterhttp2.ClientPeer).Data
	run := newEditRun(nil)
	run.feed(decerterhttp2.ClientPeer, data[:len(data)-5], 0, false)
	run.feed(decerterhttp2.ClientPeer, data[len(data)-5:], 0, true)

	if output := run.output[decerterhttp2.ClientPeer]; !errors.Is(run.editor.Err(), decerterhttp2.ErrEditOrder) || (len(output) != len(data)) || !bytes.HasSuffix(output, data[len(data)-17:len(data)-5]) || (client.err != nil) {
		state.Errorf("Test of http2.Editor.Pass function failed, error should be %v with every byte sent on, error: %v, output: %d of %d bytes", decerterhttp2.ErrEditOrder, run.editor.Err(), len(output), len(data))
		return
	}

	// decisions without a kept message
	client, server := newTestPeer(true), newTestPeer(false)
	run = newEditRun(keepStreams(decerterhttp2.ResponseSide, 1))
	editStart(run, client, server, nil, 1, 3)
	server.headers(3, true, ":status", "204")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	before := [2]int{len(run.output[decerterhttp2.ClientPeer]), len(run.output[decerterhttp2.ServerPeer])}
	edit := decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":status", Value: "500"}}, Body: []byte("never sent"), IsHeadChanged: true, IsBodyChanged: true}

	for _, peer := range []decerterhttp2.Peer{decerterhttp2.ClientPeer, decerterhttp2.ServerPeer} {
		// the request that went on, the response nobody kept, a stream that never opened, the connection
		for _, id := range []uint32{1, 3, 9, 0} {
			isKept := run.editor.Keep(peer, id)
			run.editor.Release(peer, id)
			run.editor.Replace(peer, id, edit)
			run.editor.Drop(peer, id)
			run.collect()

			if isKept || (before != [2]int{len(run.output[decerterhttp2.ClientPeer]), len(run.output[decerterhttp2.ServerPeer])}) || run.editor.IsTouched() || (run.editor.Err() != nil) {
				state.Errorf("Test of http2.Editor failed, a decision on stream %d of peer %d should change nothing, kept: %v, output: %d %d bytes, error: %v", id, peer, isKept, len(run.output[0]), len(run.output[1]), run.editor.Err())
				return
			}
		}
	}

	// the response of stream 1 goes on with a head decerter encoded, the one of stream 5 follows it as it came
	client.headers(5, true, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/5")
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	server.headers(1, true, ":status", "200")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	run.editor.Replace(decerterhttp2.ServerPeer, 1, decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":status", Value: "201"}}, Body: nil, IsHeadChanged: true, IsBodyChanged: false})
	run.collect()
	edited, err := run.read(decerterhttp2.ServerPeer, hpack.NewDecoder(4096, nil), 16384)

	if (err != nil) || (run.editor.Err() != nil) || (len(edited) == 0) || !slices.Equal(edited[len(edited)-1].Fields, []string{":status: 201"}) || !slices.Equal(run.kept, []uint32{1}) {
		state.Errorf("Test of http2.Editor.Replace function failed, the edited head should go on, frames: %+v, error: %v", edited, errors.Join(err, run.editor.Err()))
		return
	}

	server.headers(5, true, ":status", "200")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, true)

	if err = errors.Join(client.err, server.err); (err != nil) || !errors.Is(run.editor.Err(), decerterhttp2.ErrEditOrder) {
		state.Errorf("Test of http2.Editor.Frame function failed, error should be %v, error: %v", decerterhttp2.ErrEditOrder, errors.Join(err, run.editor.Err()))
		return
	}

	// a header block of more than a mebibyte of fields goes on as it came, but can't be encoded again once decerter encodes the blocks of its side
	pairs := []string{":status", "200"}

	for index := range 18 {
		pairs = append(pairs, fmt.Sprintf("x-large-%d", index), strings.Repeat("a", 60000))
	}

	for _, isEncoded := range []bool{false, true} {
		client, server = newTestPeer(true), newTestPeer(false)
		run = newEditRun(keepStreams(decerterhttp2.ResponseSide, 1))
		editStart(run, client, server, nil, 1, 3)
		server.headers(1, true, ":status", "200")
		run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)

		if isEncoded {
			run.editor.Replace(decerterhttp2.ServerPeer, 1, decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":status", Value: "201"}}, Body: nil, IsHeadChanged: true, IsBodyChanged: false})
		} else {
			run.editor.Release(decerterhttp2.ServerPeer, 1)
		}

		run.collect()
		run.output[decerterhttp2.ServerPeer] = nil
		server.headersIn(3, true, 16384, server.encode(pairs...))
		large := server.take(decerterhttp2.ServerPeer).Data
		run.feed(decerterhttp2.ServerPeer, large, 0, false)
		err = errors.Join(client.err, server.err, run.conn.Err())

		if (err != nil) || (isEncoded != errors.Is(run.editor.Err(), decerterhttp2.ErrHeaderListTooLarge)) || (!isEncoded && ((run.editor.Err() != nil) || !bytes.Equal(run.output[decerterhttp2.ServerPeer], large))) {
			state.Errorf("Test of http2.Editor failed, encoded: %v, a block too large should go on as it came or fail with %v, output: %d of %d bytes, error: %v", isEncoded, decerterhttp2.ErrHeaderListTooLarge, len(run.output[decerterhttp2.ServerPeer]), len(large), errors.Join(err, run.editor.Err()))
			return
		}
	}
}

// Test if http2.Editor.Stop returns with the expected output: a kept message, the frames behind it and the bytes of the frame the conn could not read go on as they came,
// and nothing is decided or kept back after it.
func TestEditorStopPositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	run := newEditRun(keepStreams(decerterhttp2.ResponseSide, 1))
	editStart(run, client, server, nil, 1, 3)
	run.output = [2][]byte{}
	// the response of stream 1 is kept with its body, the one of stream 3 goes on; then half a header block and a DATA frame on stream 0
	server.headers(1, false, ":status", "200", "x-repeat", "one value in every response")
	server.data(1, false, "kept body")
	server.headers(3, true, ":status", "204", "x-repeat", "one value in every response")
	server.err = errors.Join(server.err, server.framer.WriteDataPadded(1, false, []byte("more"), make([]byte, 5)))
	server.framer.AllowIllegalWrites = true
	server.data(0, false, "broken")
	sent := server.take(decerterhttp2.ServerPeer).Data
	run.feed(decerterhttp2.ServerPeer, sent, 0, false)
	stopped := len(run.output[decerterhttp2.ServerPeer])
	isKept := run.editor.Keep(decerterhttp2.ServerPeer, 1)
	run.editor.Frame(decerterhttp2.ServerPeer, decerterhttp2.Event{Type: decerterhttp2.FrameEventType, StreamID: 1, Start: 0, End: 9, Frame: &decerterhttp2.Frame{Type: http2.FrameData, StreamID: 1, Length: 0}})
	run.editor.Release(decerterhttp2.ServerPeer, 1)
	run.editor.Replace(decerterhttp2.ServerPeer, 1, decerterhttp2.Edit{Fields: nil, Body: []byte("never sent"), IsHeadChanged: false, IsBodyChanged: true})
	run.editor.Drop(decerterhttp2.ServerPeer, 1)
	run.editor.Stop()
	run.collect()

	if !run.editor.IsStopped() || !errors.Is(run.conn.Err(), decerterhttp2.ErrFrame) || !slices.Equal(run.kept, []uint32{1}) || isKept || (len(run.output[decerterhttp2.ServerPeer]) != stopped) || (server.err != nil) {
		state.Errorf("Test of http2.Editor.Stop function failed, the editor should stop with the conn and decide nothing after it, stopped: %v, kept: %v, output: %d then %d bytes, error: %v", run.editor.IsStopped(), run.kept, stopped, len(run.output[decerterhttp2.ServerPeer]), errors.Join(run.conn.Err(), server.err))
		return
	}

	// the head of the other stream went first, so both heads are encoded again and read the same; the DATA frames keep their padding, the frame the conn could not read is the end
	frames, _ := readFrames(run.output[decerterhttp2.ServerPeer], hpack.NewDecoder(4096, nil), 16384)
	heads := framesOf(frames, http2.FrameHeaders, 0)
	held := framesOf(frames, http2.FrameData, 1)

	if !slices.Equal(blockStreams(frames), []uint32{3, 1}) || !slices.Equal(heads[1].Fields, []string{":status: 200", "x-repeat: one value in every response"}) || (len(held) != 2) || (string(dataOf(frames, 1)) != "kept bodymore") || (held[1].Length != 4+6) || !bytes.HasSuffix(run.output[decerterhttp2.ServerPeer], sent[len(sent)-15:]) {
		state.Errorf("Test of http2.Editor.Stop function failed, the kept message should go on with the frame that stopped the conn behind it, output: %d bytes, frames: %+v", len(run.output[decerterhttp2.ServerPeer]), frames)
		return
	}

	// later bytes go on as they come, taken or passed
	run.editor.Take(decerterhttp2.ServerPeer, []byte("taken"))
	run.editor.Pass(decerterhttp2.ServerPeer, []byte("passed"))
	run.editor.Take(decerterhttp2.ClientPeer, []byte("of the client"))
	run.editor.Settle()

	if toClient, toServer := run.editor.Output(decerterhttp2.ServerPeer), run.editor.Output(decerterhttp2.ClientPeer); (string(toClient) != "taken") || (string(toServer) != "of the client") || (run.editor.Err() != nil) {
		state.Errorf("Test of http2.Editor.Take function failed, a stopped editor should give the bytes on as they come, output: %q %q, error: %v", toClient, toServer, run.editor.Err())
		return
	}
}

// a header block as it is on the wire: its first frame, the CONTINUATION frames behind it and its fields
type wireBlock struct {
	Type      http2.FrameType
	StreamID  uint32
	Flags     http2.Flags
	Priority  http2.PriorityParam
	PromiseID uint32
	Frames    int
	Fields    []string
}

// the header blocks in the bytes, each decoded on its own: a block decerter encoded uses no dynamic table
func wireBlocks(data []byte) (blocks []wireBlock, err error) {
	framer := http2.NewFramer(nil, bytes.NewReader(data))
	fragment := []byte{}

	for {
		frame, readErr := framer.ReadFrame()

		if readErr != nil {
			if !errors.Is(readErr, errEOF(readErr)) {
				err = readErr
			}

			return
		}

		isEnd := false

		switch typed := frame.(type) {
		case *http2.HeadersFrame:
			blocks = append(blocks, wireBlock{Type: http2.FrameHeaders, StreamID: typed.StreamID, Flags: typed.Flags, Priority: typed.Priority, PromiseID: 0, Frames: 1, Fields: nil})
			fragment = append(fragment[:0], typed.HeaderBlockFragment()...)
			isEnd = typed.HeadersEnded()
		case *http2.PushPromiseFrame:
			blocks = append(blocks, wireBlock{Type: http2.FramePushPromise, StreamID: typed.StreamID, Flags: typed.Flags, Priority: http2.PriorityParam{}, PromiseID: typed.PromiseID, Frames: 1, Fields: nil})
			fragment = append(fragment[:0], typed.HeaderBlockFragment()...)
			isEnd = typed.HeadersEnded()
		case *http2.ContinuationFrame:
			if len(blocks) == 0 {
				err = errors.New("continuation without a header block")
				return
			}

			blocks[len(blocks)-1].Frames++
			fragment = append(fragment, typed.HeaderBlockFragment()...)
			isEnd = typed.HeadersEnded()
		default:
		}

		if !isEnd {
			continue
		}

		fields, decodeErr := hpack.NewDecoder(4096, nil).DecodeFull(fragment)

		if err = decodeErr; err != nil {
			return
		}

		for _, field := range fields {
			blocks[len(blocks)-1].Fields = append(blocks[len(blocks)-1].Fields, field.Name+": "+field.Value)
		}
	}
}

// Test if http2.Editor.Replace returns with the expected output for each kind of edit: only the head, only the body, a body taken away or added, nothing changed;
// trailers stay, END_STREAM is on the last frame of the message, DATA frames that did not change keep their padding.
func TestEditorReplacePositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	run := newEditRun(keepStreams(decerterhttp2.ResponseSide, 1, 3, 5, 7, 9))
	editStart(run, client, server, nil, 1, 3, 5, 7, 9)
	mustRead(run, decerterhttp2.ClientPeer)
	mustRead(run, decerterhttp2.ServerPeer)

	// two responses with a padded body in two frames and trailers, one with a body, one without, one more with a body
	for _, id := range []uint32{1, 3} {
		server.headers(id, false, ":status", "200", "x-stream", fmt.Sprint(id))
		server.err = errors.Join(server.err, server.framer.WriteDataPadded(id, false, []byte("abc"), make([]byte, 4)))
		server.data(id, false, "def")
		server.headers(id, true, "x-trailer", fmt.Sprint(id))
	}

	server.headers(5, false, ":status", "200")
	server.data(5, true, "x")
	server.headers(7, true, ":status", "204")
	server.headers(9, false, ":status", "200")
	server.data(9, true, "same")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	decoder := hpack.NewDecoder(4096, nil)
	downstream, err := run.read(decerterhttp2.ServerPeer, decoder, 16384)
	upstream := mustRead(run, decerterhttp2.ClientPeer)

	// every body is held, so the server gets its window back: 8+3 bytes twice, 1 and 4; all the streams ended
	if err = errors.Join(err, client.err, server.err, run.editor.Err()); (err != nil) || (len(downstream) != 0) || !slices.Equal(run.kept, []uint32{1, 3, 5, 7, 9}) || (incrementOf(upstream, 0) != 27) || (len(framesOf(upstream, http2.FrameWindowUpdate, 0)) != 1) {
		state.Errorf("Test of http2.Editor.Keep function failed, the five responses should be kept and their window given back, kept: %v, frames: %+v, to the server: %+v, error: %v", run.kept, downstream, upstream, err)
		return
	}

	status := []decerterhttp2.Field{{Name: ":status", Value: "200"}}
	positiveCases := []struct {
		Name      string
		StreamID  uint32
		Edit      decerterhttp2.Edit
		Heads     [][]string
		HeadEnds  []bool
		Data      string
		Lengths   []uint32
		IsDataEnd bool
	}{
		{Name: "head", StreamID: 1, Edit: decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":status", Value: "201"}, {Name: "x-edited", Value: "yes"}}, Body: nil, IsHeadChanged: true, IsBodyChanged: false},
			Heads: [][]string{{":status: 201", "x-edited: yes"}, {"x-trailer: 1"}}, HeadEnds: []bool{false, true}, Data: "abcdef", Lengths: []uint32{8, 3}, IsDataEnd: false},
		{Name: "body in front of trailers", StreamID: 3, Edit: decerterhttp2.Edit{Fields: nil, Body: []byte("new body"), IsHeadChanged: false, IsBodyChanged: true},
			Heads: [][]string{{":status: 200", "x-stream: 3"}, {"x-trailer: 3"}}, HeadEnds: []bool{false, true}, Data: "new body", Lengths: []uint32{8}, IsDataEnd: false},
		{Name: "body taken away", StreamID: 5, Edit: decerterhttp2.Edit{Fields: status, Body: nil, IsHeadChanged: false, IsBodyChanged: true},
			Heads: [][]string{{":status: 200"}}, HeadEnds: []bool{true}, Data: "", Lengths: nil, IsDataEnd: false},
		{Name: "body added", StreamID: 7, Edit: decerterhttp2.Edit{Fields: status, Body: []byte("added"), IsHeadChanged: false, IsBodyChanged: true},
			Heads: [][]string{{":status: 200"}}, HeadEnds: []bool{false}, Data: "added", Lengths: []uint32{5}, IsDataEnd: true},
		{Name: "nothing", StreamID: 9, Edit: decerterhttp2.Edit{Fields: nil, Body: []byte("not used"), IsHeadChanged: false, IsBodyChanged: false},
			Heads: [][]string{{":status: 200"}}, HeadEnds: []bool{false}, Data: "same", Lengths: []uint32{4}, IsDataEnd: true},
	}

	for _, positive := range positiveCases {
		run.editor.Replace(decerterhttp2.ServerPeer, positive.StreamID, positive.Edit)
		run.collect()
		frames, readErr := run.read(decerterhttp2.ServerPeer, decoder, 16384)
		var heads [][]string
		var headEnds []bool
		var lengths []uint32
		isDataEnd := false

		for _, frame := range frames {
			switch {
			case frame.StreamID != positive.StreamID:
				readErr = errors.Join(readErr, fmt.Errorf("frame %s of stream %d", frame.Type, frame.StreamID))
			case frame.Type == http2.FrameHeaders:
				heads = append(heads, frame.Fields)
				headEnds = append(headEnds, frame.Flags.Has(http2.FlagHeadersEndStream))
			case frame.Type == http2.FrameData:
				lengths = append(lengths, frame.Length)
				isDataEnd = frame.Flags.Has(http2.FlagDataEndStream)
			default:
				readErr = errors.Join(readErr, fmt.Errorf("frame %s", frame.Type))
			}
		}

		if (readErr != nil) || (run.editor.Err() != nil) || (fmt.Sprint(heads) != fmt.Sprint(positive.Heads)) || !slices.Equal(headEnds, positive.HeadEnds) || (string(dataOf(frames, positive.StreamID)) != positive.Data) || !slices.Equal(lengths, positive.Lengths) || (isDataEnd != positive.IsDataEnd) {
			state.Errorf("Test of http2.Editor.Replace function failed, case: %s, heads should be %v ending %v with DATA %q of %v ending %v, frames: %+v, error: %v", positive.Name, positive.Heads, positive.HeadEnds, positive.Data, positive.Lengths, positive.IsDataEnd, frames, errors.Join(readErr, run.editor.Err()))
			return
		}
	}

	// the server has the window of what it sent back already: of the client's next window it gets what is left after the DATA decerter sent, padding included
	client.windowUpdate(0, 100)
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	sent := 8 + 3 + len("new body") + len("added") + len("same")

	if forwarded := incrementOf(mustRead(run, decerterhttp2.ClientPeer), 0); (forwarded != 100-sent) || !run.editor.IsTouched() || (client.err != nil) {
		state.Errorf("Test of http2.Editor.Replace function failed, the server should get %d of the client's window, got: %d", 100-sent, forwarded)
		return
	}
}

// Test if http2.Editor returns with the expected output for header blocks it encodes again: a HEADERS frame keeps its priority and loses its padding, a PUSH_PROMISE stays one and opens its stream.
func TestEditorEncodePositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	run := newEditRun(keepStreams(2, 1))
	client.settings()
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	server.settings()
	server.ack()
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	client.ack()
	client.headers(1, true, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/1", "x-repeat", "one value in every request")
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	run.output = [2][]byte{}
	// the head of the request is edited, from then on decerter encodes the blocks of the client
	run.editor.Replace(decerterhttp2.ClientPeer, 1, decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "edit.test"}, {Name: ":path", Value: "/edited"}}, Body: nil, IsHeadChanged: true, IsBodyChanged: false})
	priority := http2.PriorityParam{StreamDep: 1, Exclusive: true, Weight: 77}
	client.err = errors.Join(client.err, client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: client.encode(":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/3", "x-repeat", "one value in every request"), EndStream: true, EndHeaders: true, PadLength: 6, Priority: priority}))
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	blocks, err := wireBlocks(run.output[decerterhttp2.ClientPeer])
	expected := []wireBlock{
		{Type: http2.FrameHeaders, StreamID: 1, Flags: http2.FlagHeadersEndStream | http2.FlagHeadersEndHeaders, Priority: http2.PriorityParam{}, PromiseID: 0, Frames: 1, Fields: []string{":method: GET", ":scheme: https", ":authority: edit.test", ":path: /edited"}},
		{Type: http2.FrameHeaders, StreamID: 3, Flags: http2.FlagHeadersEndStream | http2.FlagHeadersEndHeaders | http2.FlagHeadersPriority, Priority: priority, PromiseID: 0, Frames: 1, Fields: []string{":method: GET", ":scheme: https", ":authority: edit.test", ":path: /3", "x-repeat: one value in every request"}},
	}

	if err = errors.Join(err, client.err, run.editor.Err()); (err != nil) || (fmt.Sprintf("%+v", blocks) != fmt.Sprintf("%+v", expected)) {
		state.Errorf("Test of http2.Editor failed, the blocks of the client should be\n%+v\nblocks:\n%+v\nerror: %v", expected, blocks, err)
		return
	}

	// the same for the server: its edited head, then a padded PUSH_PROMISE in two frames, the response of the pushed stream and trailers
	server.headers(1, false, ":status", "200", "x-repeat", "one value in every response")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	run.output = [2][]byte{}
	run.editor.Replace(decerterhttp2.ServerPeer, 1, decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":status", Value: "203"}}, Body: nil, IsHeadChanged: true, IsBodyChanged: false})
	promise := server.encode(":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/pushed", "x-repeat", "one value in every response")
	server.err = errors.Join(server.err, server.framer.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2, BlockFragment: promise[:4], EndHeaders: false, PadLength: 3}))
	server.err = errors.Join(server.err, server.framer.WriteContinuation(1, true, promise[4:]))
	server.headers(2, false, ":status", "200", "x-repeat", "one value in every response")
	server.data(2, true, "pushed body")
	server.headers(1, true, "x-trailer", "end")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	blocks, err = wireBlocks(run.output[decerterhttp2.ServerPeer])
	frames := mustRead(run, decerterhttp2.ServerPeer)
	expected = []wireBlock{
		{Type: http2.FrameHeaders, StreamID: 1, Flags: http2.FlagHeadersEndHeaders, Priority: http2.PriorityParam{}, PromiseID: 0, Frames: 1, Fields: []string{":status: 203"}},
		{Type: http2.FramePushPromise, StreamID: 1, Flags: http2.FlagPushPromiseEndHeaders, Priority: http2.PriorityParam{}, PromiseID: 2, Frames: 1, Fields: []string{":method: GET", ":scheme: https", ":authority: edit.test", ":path: /pushed", "x-repeat: one value in every response"}},
		{Type: http2.FrameHeaders, StreamID: 2, Flags: http2.FlagHeadersEndHeaders, Priority: http2.PriorityParam{}, PromiseID: 0, Frames: 1, Fields: []string{":status: 200", "x-repeat: one value in every response"}},
		{Type: http2.FrameHeaders, StreamID: 1, Flags: http2.FlagHeadersEndStream | http2.FlagHeadersEndHeaders, Priority: http2.PriorityParam{}, PromiseID: 0, Frames: 1, Fields: []string{"x-trailer: end"}},
	}

	if err = errors.Join(err, server.err, run.editor.Err()); (err != nil) || (fmt.Sprintf("%+v", blocks) != fmt.Sprintf("%+v", expected)) || (string(dataOf(frames, 2)) != "pushed body") || !slices.Equal(run.kept, []uint32{1, 1}) {
		state.Errorf("Test of http2.Editor failed, the blocks of the server should be\n%+v\nblocks:\n%+v\nkept: %v, error: %v", expected, blocks, run.kept, err)
		return
	}

	// the response of the pushed stream is one the rules can keep
	server.promise(1, 4, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/second")
	server.headers(4, true, ":status", "204")
	run.keep = keepStreams(decerterhttp2.ResponseSide, 4)
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	held := mustRead(run, decerterhttp2.ServerPeer)
	run.editor.Drop(decerterhttp2.ServerPeer, 4)
	run.collect()
	toClient, toServer := mustRead(run, decerterhttp2.ServerPeer), mustRead(run, decerterhttp2.ClientPeer)

	// the client knows the stream from the PUSH_PROMISE and the server opened it, both get the reset
	if (len(held) != 1) || (held[0].Type != http2.FramePushPromise) || !slices.Equal(run.kept, []uint32{1, 1, 4}) || (len(toClient) != 1) || (toClient[0].Type != http2.FrameRSTStream) || (toClient[0].StreamID != 4) || (len(toServer) != 1) || (toServer[0].Type != http2.FrameRSTStream) || (toServer[0].StreamID != 4) || (toServer[0].ErrCode != http2.ErrCodeCancel) || (server.err != nil) || (run.editor.Err() != nil) {
		state.Errorf("Test of http2.Editor.Drop function failed, the kept response of the pushed stream should be reset for both peers, held: %+v, to the client: %+v, to the server: %+v, error: %v", held, toClient, toServer, errors.Join(server.err, run.editor.Err()))
		return
	}
}

// Test if http2.Editor returns with the expected output for flow control at the edges: padding that does not fit a window is dropped and given back, held DATA of an open stream is given back on the stream too,
// trailers wait behind the DATA that waits for a window, decerter's frames keep to an acknowledged SETTINGS_MAX_FRAME_SIZE, and a reset gives back what waited.
func TestEditorFlowPositive(state *testing.T) {
	// a padded DATA frame of 41 bytes on a stream window of 20: its 10 bytes of body go on, the server gets the 31 of the padding back
	client, server := newTestPeer(true), newTestPeer(false)
	run := newEditRun(nil)
	editStart(run, client, server, []http2.Setting{{ID: http2.SettingInitialWindowSize, Val: 20}}, 1)
	run.output = [2][]byte{}
	server.headers(1, false, ":status", "200")
	server.err = errors.Join(server.err, server.framer.WriteDataPadded(1, false, []byte("0123456789"), make([]byte, 30)))
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	toClient, toServer := mustRead(run, decerterhttp2.ServerPeer), mustRead(run, decerterhttp2.ClientPeer)
	data := framesOf(toClient, http2.FrameData, 1)

	if (len(data) != 1) || (data[0].Length != 10) || (string(data[0].Data) != "0123456789") || (incrementOf(toServer, 0) != 31) || (incrementOf(toServer, 1) != 31) {
		state.Errorf("Test of http2.Editor failed, the body should go on without its padding and the padding be given back, DATA: %+v, to the server: %+v", data, toServer)
		return
	}

	// the 10 bytes left of the window take the start of the next frame, its end waits for the client's WINDOW_UPDATE, which the server gets too: it sent those bytes
	server.data(1, true, "abcdefghijklmno")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	first := mustRead(run, decerterhttp2.ServerPeer)
	client.windowUpdate(1, 5)
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	second, toServer := mustRead(run, decerterhttp2.ServerPeer), mustRead(run, decerterhttp2.ClientPeer)
	ends := framesOf(second, http2.FrameData, 1)

	if err := errors.Join(client.err, server.err, run.editor.Err()); (err != nil) || (string(dataOf(first, 1)) != "abcdefghij") || first[len(first)-1].Flags.Has(http2.FlagDataEndStream) || (string(dataOf(second, 1)) != "klmno") || (len(ends) != 1) || !ends[0].Flags.Has(http2.FlagDataEndStream) || (incrementOf(toServer, 1) != 5) {
		state.Errorf("Test of http2.Editor failed, the frame should go on in two parts around the WINDOW_UPDATE, first: %+v, second: %+v, to the server: %+v, error: %v", first, second, toServer, err)
		return
	}

	// a kept response whose stream is still open: the server gets the window of the held DATA back on the connection and on the stream
	client, server = newTestPeer(true), newTestPeer(false)
	run = newEditRun(keepStreams(decerterhttp2.ResponseSide, 1, 3))
	editStart(run, client, server, []http2.Setting{{ID: http2.SettingInitialWindowSize, Val: 5}}, 1, 3)
	run.output = [2][]byte{}
	server.headers(1, false, ":status", "200")
	server.data(1, false, "held")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	toClient, toServer = mustRead(run, decerterhttp2.ServerPeer), mustRead(run, decerterhttp2.ClientPeer)

	if (len(toClient) != 0) || (incrementOf(toServer, 0) != 4) || (incrementOf(toServer, 1) != 4) || (len(toServer) != 2) {
		state.Errorf("Test of http2.Editor failed, the window of held DATA should be given back on the connection and the open stream, to the client: %+v, to the server: %+v", toClient, toServer)
		return
	}

	// a body grown to 10 bytes on a stream window of 5 in front of trailers: the trailers wait behind the DATA that waits
	server.headers(3, false, ":status", "200")
	server.data(3, false, "abc")
	server.headers(3, true, "x-trailer", "end")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	mustRead(run, decerterhttp2.ClientPeer)
	run.editor.Replace(decerterhttp2.ServerPeer, 3, decerterhttp2.Edit{Fields: nil, Body: []byte("0123456789"), IsHeadChanged: false, IsBodyChanged: true})
	run.collect()
	decoder := hpack.NewDecoder(4096, nil)
	first, firstErr := run.read(decerterhttp2.ServerPeer, decoder, 16384)
	client.windowUpdate(3, 3)
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	second, secondErr := run.read(decerterhttp2.ServerPeer, decoder, 16384)
	client.windowUpdate(3, 2)
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	third, thirdErr := run.read(decerterhttp2.ServerPeer, decoder, 16384)
	toServer = mustRead(run, decerterhttp2.ClientPeer)

	if err := errors.Join(firstErr, secondErr, thirdErr, client.err, server.err, run.editor.Err()); (err != nil) || (len(first) != 2) || (string(dataOf(first, 3)) != "01234") || (len(second) != 1) || (string(dataOf(second, 3)) != "567") || (len(third) != 2) || (string(dataOf(third, 3)) != "89") ||
		third[0].Flags.Has(http2.FlagDataEndStream) || !slices.Equal(third[1].Fields, []string{"x-trailer: end"}) || !third[1].Flags.Has(http2.FlagHeadersEndStream) || (len(toServer) != 0) {
		state.Errorf("Test of http2.Editor failed, the trailers should follow the last DATA once the window lets it go, first: %+v, second: %+v, third: %+v, to the server: %+v, error: %v", first, second, third, toServer, err)
		return
	}

	// the client allows frames of 20000 bytes: a head and a body decerter writes are cut at that
	client, server = newTestPeer(true), newTestPeer(false)
	run = newEditRun(keepStreams(decerterhttp2.ResponseSide, 1))
	editStart(run, client, server, []http2.Setting{{ID: http2.SettingMaxFrameSize, Val: 20000}}, 1)
	server.headers(1, true, ":status", "200")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	run.output = [2][]byte{}
	run.editor.Replace(decerterhttp2.ServerPeer, 1, decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":status", Value: "200"}, {Name: "x-large", Value: strings.Repeat("x", 50000)}}, Body: bytes.Repeat([]byte("b"), 50000), IsHeadChanged: true, IsBodyChanged: true})
	run.collect()
	sizes := frameSizes(run.output[decerterhttp2.ServerPeer])
	blocks, err := wireBlocks(run.output[decerterhttp2.ServerPeer])
	frames := mustRead(run, decerterhttp2.ServerPeer)

	if err = errors.Join(err, client.err, server.err, run.editor.Err()); (err != nil) || (len(blocks) != 1) || (blocks[0].Frames != 3) || (len(dataOf(frames, 1)) != 50000) || !slices.Equal(sizes[len(sizes)-3:], []int{20000, 20000, 10000}) || !slices.Equal(sizes[:2], []int{20000, 20000}) {
		state.Errorf("Test of http2.Editor failed, the frames should be cut at 20000 bytes, sizes: %v, blocks: %d, error: %v", sizes, len(blocks), err)
		return
	}

	// a WINDOW_UPDATE and a RST_STREAM of the client that went on before the editor saw them still count:
	// the stream window grows by 500, and the reset gives back the 1500 bytes of a grown body that waited for the window
	client, server = newTestPeer(true), newTestPeer(false)
	run = newEditRun(keepStreams(decerterhttp2.ResponseSide, 1))
	editStart(run, client, server, []http2.Setting{{ID: http2.SettingInitialWindowSize, Val: 1000}}, 1)
	client.windowUpdate(1, 500)
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, true)
	server.headers(1, false, ":status", "200")
	server.data(1, true, "0123456789")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	run.output = [2][]byte{}
	run.editor.Replace(decerterhttp2.ServerPeer, 1, decerterhttp2.Edit{Fields: nil, Body: bytes.Repeat([]byte("g"), 3000), IsHeadChanged: false, IsBodyChanged: true})
	run.collect()
	grown := mustRead(run, decerterhttp2.ServerPeer)
	client.reset(1, http2.ErrCodeCancel)
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, true)
	run.output[decerterhttp2.ClientPeer] = nil
	client.windowUpdate(0, 4000)
	client.windowUpdate(1, 4000)
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	toClient, toServer = mustRead(run, decerterhttp2.ServerPeer), mustRead(run, decerterhttp2.ClientPeer)

	if err = errors.Join(client.err, server.err, run.editor.Err()); (err != nil) || (len(dataOf(grown, 1)) != 1500) || (len(toClient) != 0) || (incrementOf(toServer, 0) != 4000-1500) {
		state.Errorf("Test of http2.Editor failed, 1500 bytes should go on and the rest be given back by the reset, DATA: %d, to the client: %+v, to the server: %+v, error: %v", len(dataOf(grown, 1)), toClient, toServer, err)
		return
	}
}

// Test if http2.Editor returns with the expected output for streams over its limit: their frames go on as they came and none of their heads can be kept, the other streams still can;
// a DATA frame longer than the receiver acknowledged is cut, and a RST_STREAM goes on for a stream the receiver knows or the editor does not.
func TestEditorLimitPositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	run := &editRun{conn: decerterhttp2.New(0), editor: decerterhttp2.NewEditor(1), keep: keepStreams(decerterhttp2.ResponseSide, 1, 3), output: [2][]byte{}, kept: nil}
	run.conn.EmitFrames()
	editStart(run, client, server, nil, 1, 3)
	// the client allows longer frames from now on, the server uses that before its ACK went through decerter
	client.settings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 32768})
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)
	upstream, upErr := run.read(decerterhttp2.ClientPeer, hpack.NewDecoder(4096, nil), 16384)
	mustRead(run, decerterhttp2.ServerPeer)
	body := strings.Repeat("u", 20000)
	server.headers(3, false, ":status", "200", "x-stream", "3")
	server.data(3, false, body)
	server.err = errors.Join(server.err, server.framer.WriteDataPadded(3, false, []byte("pad"), make([]byte, 4)))
	server.reset(3, http2.ErrCodeInternal)
	server.headers(1, true, ":status", "204", "x-stream", "1")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	isKept := run.editor.Keep(decerterhttp2.ServerPeer, 3)
	run.editor.Release(decerterhttp2.ServerPeer, 1)
	run.collect()
	downstream, downErr := run.read(decerterhttp2.ServerPeer, hpack.NewDecoder(4096, nil), 32768)
	var lengths []uint32

	for _, frame := range framesOf(downstream, http2.FrameData, 3) {
		lengths = append(lengths, frame.Length)
	}

	resets := framesOf(downstream, http2.FrameRSTStream, 0)

	if err := errors.Join(upErr, downErr, client.err, server.err, run.editor.Err()); (err != nil) || !slices.Equal(blockStreams(upstream), []uint32{1, 3}) || !slices.Equal(run.kept, []uint32{1}) || isKept || !slices.Equal(blockStreams(downstream), []uint32{3, 1}) ||
		!slices.Equal(lengths, []uint32{16384, 20000 - 16384, 3 + 5}) || (string(dataOf(downstream, 3)) != body+"pad") || (len(resets) != 1) || (resets[0].StreamID != 3) || (resets[0].ErrCode != http2.ErrCodeInternal) {
		state.Errorf("Test of http2.Editor failed, the frames of the stream over the limit should go on and only stream 1 be kept, kept: %v %v, streams: %v then %v, DATA: %v, resets: %+v, error: %v", run.kept, isKept, blockStreams(upstream), blockStreams(downstream), lengths, resets, err)
		return
	}

	// stream 1 is done and forgotten, so stream 5 is followed: its reset reaches the server, which knows it; the one of a stream that never opened goes on as well
	client.headers(5, false, ":method", "POST", ":scheme", "https", ":authority", "edit.test", ":path", "/5")
	client.reset(5, http2.ErrCodeCancel)
	client.reset(7, http2.ErrCodeStreamClosed)
	sent := client.take(decerterhttp2.ClientPeer).Data
	run.feed(decerterhttp2.ClientPeer, sent, 0, false)

	if !bytes.Equal(run.output[decerterhttp2.ClientPeer], sent) || (client.err != nil) || (run.editor.Err() != nil) {
		state.Errorf("Test of http2.Editor failed, the head and both resets should go on as they came, output: %d of %d bytes, error: %v", len(run.output[decerterhttp2.ClientPeer]), len(sent), errors.Join(client.err, run.editor.Err()))
		return
	}

	// stream 9 stays open and takes the place, the head of stream 11 went on before the editor saw it: its frames are not followed and go on as they came
	run.output = [2][]byte{}
	run.keep = keepStreams(decerterhttp2.ResponseSide, 11)
	client.headers(9, false, ":method", "POST", ":scheme", "https", ":authority", "edit.test", ":path", "/9")
	sent = client.take(decerterhttp2.ClientPeer).Data
	run.feed(decerterhttp2.ClientPeer, sent, 0, false)
	client.headers(11, false, ":method", "POST", ":scheme", "https", ":authority", "edit.test", ":path", "/11")
	passed := client.take(decerterhttp2.ClientPeer).Data
	run.feed(decerterhttp2.ClientPeer, passed, 0, true)
	client.err = errors.Join(client.err, client.framer.WriteDataPadded(11, true, []byte("body of 11"), make([]byte, 3)))
	padded := client.take(decerterhttp2.ClientPeer).Data
	run.feed(decerterhttp2.ClientPeer, padded, 0, false)
	server.headers(11, true, ":status", "200")
	answer := server.take(decerterhttp2.ServerPeer).Data
	run.feed(decerterhttp2.ServerPeer, answer, 0, false)

	if err := errors.Join(client.err, server.err, run.editor.Err(), run.conn.Err()); (err != nil) || !bytes.Equal(run.output[decerterhttp2.ClientPeer], slices.Concat(sent, passed, padded)) || !bytes.Equal(run.output[decerterhttp2.ServerPeer], answer) || !slices.Equal(run.kept, []uint32{1}) {
		state.Errorf("Test of http2.Editor failed, the frames of a stream over the limit whose head went on should go on as they came, kept: %v, output: %d of %d and %d of %d bytes, error: %v", run.kept, len(run.output[decerterhttp2.ClientPeer]), len(sent)+len(passed)+len(padded), len(run.output[decerterhttp2.ServerPeer]), len(answer), err)
		return
	}
}

// Test if http2.Editor returns with the expected errors for a header block it can't write again: a PUSH_PROMISE that promises stream 0, after decerter encoded a block of the server.
func TestEditorEncodeNegative(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	run := newEditRun(keepStreams(decerterhttp2.ResponseSide, 1))
	editStart(run, client, server, nil, 1)
	server.headers(1, false, ":status", "200")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	run.editor.Replace(decerterhttp2.ServerPeer, 1, decerterhttp2.Edit{Fields: []decerterhttp2.Field{{Name: ":status", Value: "201"}}, Body: nil, IsHeadChanged: true, IsBodyChanged: false})
	run.collect()
	run.output = [2][]byte{}

	if err := errors.Join(client.err, server.err, run.editor.Err(), run.conn.Err()); err != nil {
		state.Fatalf("Test of http2.Editor failed, cannot edit the head, error: %s", err.Error())
	}

	server.framer.AllowIllegalWrites = true
	server.promise(1, 0, ":method", "GET", ":scheme", "https", ":authority", "edit.test", ":path", "/nowhere")
	server.data(1, true, "body")
	run.feed(decerterhttp2.ServerPeer, server.take(decerterhttp2.ServerPeer).Data, 0, false)
	frames, err := run.read(decerterhttp2.ServerPeer, hpack.NewDecoder(4096, nil), 16384)

	// the conn reads on, the editor tells that it could not write the block; what goes on are still whole frames
	if err = errors.Join(err, server.err, run.conn.Err()); (err != nil) || (run.editor.Err() == nil) || run.editor.IsStopped() || (string(dataOf(frames, 1)) != "body") {
		state.Errorf("Test of http2.Editor failed, the editor should tell that it can't write a promise of stream 0 and go on, editor error: %v, frames: %+v, error: %v", run.editor.Err(), frames, err)
		return
	}
}

// Test if http2.Editor returns with the expected output for frames decerter adds while a frame or a header block of that side went on half: they wait for its end.
func TestEditorLaterPositive(state *testing.T) {
	client, server := newTestPeer(true), newTestPeer(false)
	run := newEditRun(keepStreams(decerterhttp2.RequestSide, 3))
	editStart(run, client, server, nil, 1)
	run.output = [2][]byte{}
	// six bytes of a PING of the server went on, then the body of a kept request is held: the WINDOW_UPDATEs for the client can't go into the PING
	server.err = errors.Join(server.err, server.framer.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	ping := server.take(decerterhttp2.ServerPeer).Data
	run.feed(decerterhttp2.ServerPeer, ping[:6], 0, true)
	client.headers(3, false, ":method", "POST", ":scheme", "https", ":authority", "edit.test", ":path", "/3")
	client.data(3, false, "held body")
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)

	if !bytes.Equal(run.output[decerterhttp2.ServerPeer], ping[:6]) || !slices.Equal(run.kept, []uint32{3}) || run.editor.HasOutput(decerterhttp2.ServerPeer) {
		state.Errorf("Test of http2.Editor failed, nothing should follow half a frame that went on, output: %x, kept: %v", run.output[decerterhttp2.ServerPeer], run.kept)
		return
	}

	run.feed(decerterhttp2.ServerPeer, ping[6:], 0, true)
	whole := bytes.Clone(run.output[decerterhttp2.ServerPeer])
	frames, err := run.read(decerterhttp2.ServerPeer, hpack.NewDecoder(4096, nil), 16384)

	if (err != nil) || !bytes.HasPrefix(whole, ping) || (len(frames) != 3) || (incrementOf(frames, 0) != 9) || (incrementOf(frames, 3) != 9) {
		state.Errorf("Test of http2.Editor failed, the WINDOW_UPDATEs should follow the whole PING, frames: %+v, error: %v", frames, err)
		return
	}

	// the same inside a header block: its HEADERS frame went on, the CONTINUATION is taken
	block := server.encode(":status", "200", "x-long", strings.Repeat("v", 50))
	server.err = errors.Join(server.err, server.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:10], EndStream: true, EndHeaders: false, PadLength: 0, Priority: http2.PriorityParam{}}))
	headers := server.take(decerterhttp2.ServerPeer).Data
	server.err = errors.Join(server.err, server.framer.WriteContinuation(1, true, block[10:]))
	continuation := server.take(decerterhttp2.ServerPeer).Data
	run.feed(decerterhttp2.ServerPeer, headers, 0, true)
	client.data(3, false, "more")
	run.feed(decerterhttp2.ClientPeer, client.take(decerterhttp2.ClientPeer).Data, 0, false)

	if !bytes.Equal(run.output[decerterhttp2.ServerPeer], headers) || run.editor.HasOutput(decerterhttp2.ServerPeer) {
		state.Errorf("Test of http2.Editor failed, nothing should follow the first frame of a header block that went on, output: %x", run.output[decerterhttp2.ServerPeer])
		return
	}

	run.feed(decerterhttp2.ServerPeer, continuation, 0, false)
	whole = bytes.Clone(run.output[decerterhttp2.ServerPeer])
	frames, err = run.read(decerterhttp2.ServerPeer, hpack.NewDecoder(4096, nil), 16384)

	if err = errors.Join(err, client.err, server.err, run.editor.Err()); (err != nil) || !bytes.HasPrefix(whole, append(bytes.Clone(headers), continuation...)) || (len(frames) != 3) || !slices.Equal(frames[0].Fields, []string{":status: 200", "x-long: " + strings.Repeat("v", 50)}) || (incrementOf(frames, 0) != 4) || (incrementOf(frames, 3) != 4) {
		state.Errorf("Test of http2.Editor failed, the WINDOW_UPDATEs should follow the whole header block, frames: %+v, error: %v", frames, err)
		return
	}
}
