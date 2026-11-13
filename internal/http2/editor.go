// SPDX-License-Identifier: AGPL-3.0-only

package http2

import (
	"bytes"
	"fmt"
	"maps"
	"slices"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// every connection window at the start, and SETTINGS_INITIAL_WINDOW_SIZE until a peer says otherwise
	defaultWindow int64 = 65535
	// the largest WINDOW_UPDATE increment
	maxIncrement int64 = 1<<31 - 1
	// the streams an editor follows at once, the frames of another stream go on as they came
	DefaultEditStreams int = 10000
)

// an editor that follows at most maxStreams streams at once, 0 or less is DefaultEditStreams
func NewEditor(maxStreams int) (editor *Editor) {
	if maxStreams <= 0 {
		maxStreams = DefaultEditStreams
	}

	framed := &bytes.Buffer{}
	editor = &Editor{
		sides:      [2]*editSide{newEditSide(ClientPeer), newEditSide(ServerPeer)},
		streams:    map[uint32]*editStream{},
		lastStream: [2]uint32{0, 0},
		maxStreams: maxStreams,
		isTouched:  false,
		isStopped:  false,
		framed:     framed,
		framer:     http2.NewFramer(framed, nil),
		err:        nil,
	}
	return
}

func newEditSide(peer Peer) (side *editSide) {
	side = &editSide{
		peer:           peer,
		buffer:         nil,
		bufferStart:    0,
		cursor:         0,
		passedEnd:      0,
		isPassingBlock: false,
		blockRaw:       nil,
		undecided:      nil,
		output:         nil,
		later:          nil,
		blocks:         0,
		sentBlocks:     0,
		encoder:        nil,
		encoded:        nil,
		maxFrameSize:   defaultMaxFrameSize,
		initialWindow:  defaultWindow,
		window:         defaultWindow,
		excess:         0,
		openings:       nil,
	}
	return
}

// whether a message was ever kept: from then on the frames of both peers go on whole, through Take
func (editor *Editor) IsTouched() (isTouched bool) {
	isTouched = editor.isTouched
	return
}

// whether the editor stopped: the conn could not read on, every byte goes on as it comes
func (editor *Editor) IsStopped() (isStopped bool) {
	isStopped = editor.isStopped
	return
}

// whether the bytes of a peer may go on as they come (Pass): nothing of its frames is waiting in the editor
func (editor *Editor) IsClean(peer Peer) (isClean bool) {
	side := editor.sides[peer]
	isClean = (len(side.buffer) == 0) && (len(side.blockRaw) == 0) && (side.undecided == nil)
	return
}

// whether something waits to go on towards the receiver of the peer's frames
func (editor *Editor) HasOutput(peer Peer) (hasOutput bool) {
	hasOutput = len(editor.sides[peer].output) > 0
	return
}

// what goes on next in the frames of the peer, taken out of the editor
func (editor *Editor) Output(peer Peer) (output []byte) {
	side := editor.sides[peer]
	output = side.output
	side.output = nil
	return
}

// the first thing the editor could not do right, nil when there is none
func (editor *Editor) Err() (err error) {
	err = editor.err
	return
}

// the next bytes of a peer, they go on once the frame events say what they are
func (editor *Editor) Take(peer Peer, data []byte) {
	side := editor.sides[peer]

	if editor.isStopped {
		side.output = append(side.output, data...)
		return
	}

	side.buffer = append(side.buffer, data...)
}

// the next bytes of a peer went on as they came: their frame events only keep the windows and the header blocks in step
func (editor *Editor) Pass(peer Peer, data []byte) {
	side := editor.sides[peer]

	if editor.isStopped {
		return
	}

	// bytes taken before can't go on behind these any more
	if len(side.buffer) > 0 {
		editor.fail(fmt.Errorf("%w: %d bytes kept back before bytes that went on", ErrEditOrder, len(side.buffer)))
		side.output = append(side.output, side.buffer...)
	}

	side.bufferStart += int64(len(side.buffer) + len(data))
	side.buffer = nil
	side.passedEnd = side.bufferStart
}

// one frame event of the peer's conn, in order
func (editor *Editor) Frame(peer Peer, event Event) {
	side := editor.sides[peer]
	frame := event.Frame

	if editor.isStopped || (frame == nil) {
		return
	}

	editor.commitUndecided(side)

	// the bytes before the first frame: the client preface
	if event.Start > side.cursor {
		side.output = append(side.output, side.cut(side.cursor, event.Start)...)
	}

	raw := side.cut(event.Start, event.End)
	side.cursor = event.End

	switch {
	case event.Start < side.passedEnd:
		// the frame went on, all of it or its start: what is left of it follows as it came
		side.output = append(side.output, raw...)
		editor.passed(side, frame)
	case side.isPassingBlock:
		side.output = append(side.output, raw...)

		if frame.Block != nil {
			editor.blockPassed(side, frame.Block)
		}
	default:
		editor.take(side, frame, raw)
	}

	editor.openNext(side)
	side.flushLater()
}

// the head of a whole header block of the peer was asked for: the block and the rest of its message stay in the editor until Release, Replace or Drop
// isKept is false when the block is not the one waiting, the block went on already or it opens no message
func (editor *Editor) Keep(peer Peer, streamID uint32) (isKept bool) {
	side := editor.sides[peer]
	waiting := side.undecided
	stream := editor.streams[streamID]

	if editor.isStopped || (waiting == nil) || (waiting.streamID != streamID) || waiting.block.IsPush || (stream == nil) {
		return
	}

	side.undecided = nil
	stream.sides[peer].message = &keptMessage{units: []unit{*waiting}, isComplete: waiting.endStream}
	editor.isTouched = true
	isKept = true
	return
}

// the kept message goes on as it came, and the frames behind it
func (editor *Editor) Release(peer Peer, streamID uint32) {
	stream, message := editor.kept(peer, streamID)

	if message == nil {
		return
	}

	editor.resume(editor.sides[peer], stream, message.units)
}

// the kept message goes on as the edit has it: a head that changed is encoded again, a body that changed goes on in new DATA frames without padding, trailers as they came
// END_STREAM goes on the trailers, or the last DATA frame, or the head of a message without body
func (editor *Editor) Replace(peer Peer, streamID uint32, edit Edit) {
	stream, message := editor.kept(peer, streamID)

	if message == nil {
		return
	}

	head := message.units[0]
	trailers := (*unit)(nil)
	data := []unit{}

	for index, current := range message.units[1:] {
		if current.kind == blockUnit {
			trailers = &message.units[1+index]
			continue
		}

		data = append(data, current)
	}

	endOnHead := head.endStream

	if edit.IsBodyChanged {
		endOnHead = (len(edit.Body) == 0) && (trailers == nil)
	}

	units := []unit{head}

	if edit.IsHeadChanged || (endOnHead != head.endStream) {
		block := *head.block
		block.Fields = edit.Fields
		block.EndStream = endOnHead
		block.IsCut = false
		units[0] = unit{kind: blockUnit, streamID: streamID, raw: nil, payload: nil, need: 0, endStream: endOnHead, block: &block, seq: -1, isPart: true}
	}

	switch {
	case !edit.IsBodyChanged:
		units = append(units, data...)
	case len(edit.Body) > 0:
		units = append(units, unit{kind: dataUnit, streamID: streamID, raw: nil, payload: bytes.Clone(edit.Body), need: int64(len(edit.Body)), endStream: trailers == nil, block: nil, seq: -1, isPart: true})
	default:
	}

	if trailers != nil {
		units = append(units, *trailers)
	}

	editor.resume(editor.sides[peer], stream, units)
}

// the kept message does not go on: the stream ends for both peers, each one that knows it gets RST_STREAM with CANCEL
func (editor *Editor) Drop(peer Peer, streamID uint32) {
	stream, message := editor.kept(peer, streamID)

	if message == nil {
		return
	}

	knows := [2]bool{stream.sides[ClientPeer].isOpened, stream.sides[ServerPeer].isOpened}
	editor.reset(stream)

	for _, side := range editor.sides {
		if knows[side.peer] {
			side.write(editor.build(func(framer *http2.Framer) error {
				return framer.WriteRSTStream(streamID, http2.ErrCodeCancel)
			}))
		}
	}

	for _, side := range editor.sides {
		editor.openNext(side)
	}
}

// the end of a feed or a decision: blocks nobody kept go on, senders get back the window of what they sent and the receiver did not count, DATA that waited goes on as far as the windows allow
func (editor *Editor) Settle() {
	if editor.isStopped {
		return
	}

	for _, side := range editor.sides {
		editor.commitUndecided(side)
		editor.openNext(side)
	}

	for _, side := range editor.sides {
		editor.topUp(side)
	}

	for _, side := range editor.sides {
		editor.flushQueues(side)
		side.flushLater()
	}

	editor.forget()
}

// the conn can't read on: everything the editor keeps goes on as it is now, without windows or order, and every later byte as it comes
func (editor *Editor) Stop() {
	if editor.isStopped {
		return
	}

	for _, side := range editor.sides {
		editor.commitUndecided(side)
		side.openings = nil
		side.window = maxIncrement

		for _, id := range slices.Sorted(maps.Keys(editor.streams)) {
			stream := editor.streams[id]
			current := stream.sides[side.peer]
			current.window = maxIncrement

			if current.message != nil {
				current.held = append(current.message.units, current.held...)
				current.message = nil
			}

			editor.drain(side, stream)
		}

		editor.flushQueues(side)
		side.output = append(side.output, side.later...)
		side.output = append(side.output, side.blockRaw...)
		side.output = append(side.output, side.buffer...)
		side.later, side.blockRaw, side.buffer = nil, nil, nil
	}

	editor.isStopped = true
}

// the stream and its kept message of a peer, nil without one
func (editor *Editor) kept(peer Peer, streamID uint32) (stream *editStream, message *keptMessage) {
	stream = editor.streams[streamID]

	if editor.isStopped || (stream == nil) {
		return
	}

	current := stream.sides[peer]
	message = current.message
	current.message = nil
	return
}

// the units of a message that is no longer kept go first, before the frames that waited behind it
func (editor *Editor) resume(side *editSide, stream *editStream, units []unit) {
	current := stream.sides[side.peer]
	current.held = append(units, current.held...)
	editor.drain(side, stream)
	editor.openNext(side)
}

// a frame that went on before it was taken: the windows, the settings and the order of the header blocks follow it
func (editor *Editor) passed(side *editSide, frame *Frame) {
	switch frame.Type {
	case http2.FrameData:
		side.window -= int64(frame.Length)

		if stream := editor.streams[frame.StreamID]; stream != nil {
			current := stream.sides[side.peer]
			current.window -= int64(frame.Length)
			current.isEnded = current.isEnded || frame.Flags.Has(http2.FlagDataEndStream)
		}
	case
		http2.FrameHeaders,
		http2.FramePushPromise,
		http2.FrameContinuation:
		if frame.Block == nil {
			side.isPassingBlock = true
			return
		}

		editor.blockPassed(side, frame.Block)
	case http2.FrameWindowUpdate:
		other := editor.sides[otherPeer(side.peer)]

		if frame.StreamID == 0 {
			other.window += int64(frame.Increment)
		} else if stream := editor.streams[frame.StreamID]; stream != nil {
			stream.sides[other.peer].window += int64(frame.Increment)
		}
	case http2.FrameRSTStream:
		if stream := editor.streams[frame.StreamID]; stream != nil {
			editor.reset(stream)
		}
	case http2.FrameSettings:
		if frame.Flags.Has(http2.FlagSettingsAck) {
			editor.apply(side, frame.Settings)
		}
	default:
	}
}

// a header block went on as it came, in its order
func (editor *Editor) blockPassed(side *editSide, block *Block) {
	side.isPassingBlock = false
	side.blocks++

	if side.encoder != nil {
		editor.fail(fmt.Errorf("%w: a header block went on as it came after decerter encoded one", ErrEditOrder))
	} else {
		side.sentBlocks = side.blocks
	}

	stream := editor.streams[block.StreamID]

	if block.IsPush {
		stream = editor.open(ServerPeer, block.PromiseID)
	} else if stream == nil {
		stream = editor.open(side.peer, block.StreamID)
	}

	if stream == nil {
		return
	}

	if !block.IsPush {
		stream.sides[side.peer].isEnded = stream.sides[side.peer].isEnded || block.EndStream
	}

	editor.opened(side, stream)
}

// a frame in frame mode
func (editor *Editor) take(side *editSide, frame *Frame, raw []byte) {
	switch frame.Type {
	case http2.FrameData:
		length := int64(frame.Length)
		taken := unit{kind: dataUnit, streamID: frame.StreamID, raw: raw, payload: frame.Data, need: length, endStream: frame.Flags.Has(http2.FlagDataEndStream), block: nil, seq: -1, isPart: true}
		side.excess += length
		stream := editor.streams[frame.StreamID]

		if stream == nil {
			editor.commit(side, nil, taken)
			return
		}

		current := stream.sides[side.peer]
		current.excess += length
		current.isEnded = current.isEnded || taken.endStream
		editor.route(side, stream, taken)
	case
		http2.FrameHeaders,
		http2.FramePushPromise,
		http2.FrameContinuation:
		side.blockRaw = append(side.blockRaw, raw...)

		if frame.Block == nil {
			return
		}

		taken := unit{kind: blockUnit, streamID: frame.Block.StreamID, raw: side.blockRaw, payload: nil, need: 0, endStream: frame.Block.EndStream, block: frame.Block, seq: side.blocks, isPart: true}
		side.blockRaw = nil
		side.blocks++
		editor.takeBlock(side, taken)
	case http2.FrameWindowUpdate:
		editor.takeWindowUpdate(side, frame, raw)
	case http2.FrameRSTStream:
		stream := editor.streams[frame.StreamID]

		if stream == nil {
			side.write(raw)
			return
		}

		// a stream the receiver never heard of needs no reset
		isKnown := stream.sides[side.peer].isOpened
		editor.reset(stream)

		if isKnown {
			side.write(raw)
		}
	case http2.FrameSettings:
		side.write(raw)

		if frame.Flags.Has(http2.FlagSettingsAck) {
			editor.apply(side, frame.Settings)
		}
	default:
		// PING, GOAWAY, PRIORITY and the rest go on at once
		side.write(raw)
	}
}

// a whole header block: a PUSH_PROMISE goes on at once, a HEADERS block that may open a message waits for Keep until the next frame or Settle
func (editor *Editor) takeBlock(side *editSide, taken unit) {
	block := taken.block

	if block.IsPush {
		editor.open(ServerPeer, block.PromiseID)
		editor.commit(side, nil, taken)
		return
	}

	stream := editor.streams[block.StreamID]

	if stream == nil {
		stream = editor.open(side.peer, block.StreamID)
	}

	if stream == nil {
		editor.commit(side, nil, taken)
		return
	}

	current := stream.sides[side.peer]
	current.isEnded = current.isEnded || block.EndStream

	if (current.message == nil) && (len(current.held) == 0) {
		side.undecided = &taken
		return
	}

	editor.route(side, stream, taken)
}

// a WINDOW_UPDATE of the peer grants the other side's data: the window grows by all of it, the other peer gets what is left after the excess decerter sent is paid back
func (editor *Editor) takeWindowUpdate(side *editSide, frame *Frame, raw []byte) {
	other := editor.sides[otherPeer(side.peer)]
	increment := int64(frame.Increment)
	forward := increment
	stream := (*editStream)(nil)

	if frame.StreamID == 0 {
		other.window += increment
		forward = swallow(&other.excess, increment)
	} else if stream = editor.streams[frame.StreamID]; stream != nil {
		current := stream.sides[other.peer]
		current.window += increment
		forward = swallow(&current.excess, increment)
	}

	if forward < increment {
		raw = nil

		if forward > 0 {
			raw = editor.windowUpdate(frame.StreamID, forward)
		}
	}

	if len(raw) > 0 {
		forwarded := unit{kind: frameUnit, streamID: frame.StreamID, raw: raw, payload: nil, need: 0, endStream: false, block: nil, seq: -1, isPart: false}

		if stream == nil {
			editor.commit(side, nil, forwarded)
		} else {
			editor.route(side, stream, forwarded)
		}
	}

	editor.flushQueues(other)
}

// a frame of a stream: into the kept message, behind what waits on the stream, or on its way
func (editor *Editor) route(side *editSide, stream *editStream, taken unit) {
	current := stream.sides[side.peer]

	switch {
	case (current.message != nil) && !current.message.isComplete && taken.isPart:
		current.message.units = append(current.message.units, taken)
		current.message.isComplete = taken.endStream
	case (current.message != nil) || (len(current.held) > 0) || editor.isGated(side, stream):
		current.held = append(current.held, taken)
	default:
		editor.commit(side, stream, taken)
	}
}

// a unit is on its way: DATA counts against the excess now, it goes on as far as the windows allow and the rest waits in the stream's queue
func (editor *Editor) commit(side *editSide, stream *editStream, taken unit) {
	current := (*streamSide)(nil)

	if stream != nil {
		current = stream.sides[side.peer]
	}

	if taken.kind == dataUnit {
		side.excess -= taken.need

		if current != nil {
			current.excess -= taken.need
		}
	}

	if (current != nil) && (len(current.queue) > 0) {
		current.queue = append(current.queue, taken)
		return
	}

	if rest := editor.send(side, stream, taken); rest != nil {
		current.queue = append(current.queue, *rest)
	}
}

// write a unit; rest is what of DATA has to wait for the windows
func (editor *Editor) send(side *editSide, stream *editStream, taken unit) (rest *unit) {
	switch taken.kind {
	case dataUnit:
		rest = editor.sendData(side, stream, taken)
	case blockUnit:
		editor.sendBlock(side, stream, taken)
	case frameUnit:
		side.write(taken.raw)
	}

	return
}

// DATA within the windows of the receiver: a frame that fits goes on as it came, otherwise its body goes on without padding in frames of the receiver's max frame size
// a stream the editor does not follow has only the connection window counted
func (editor *Editor) sendData(side *editSide, stream *editStream, taken unit) (rest *unit) {
	if stream == nil {
		side.window -= taken.need

		if (taken.raw != nil) && (len(taken.raw)-frameHeaderLength <= int(side.maxFrameSize)) {
			side.write(taken.raw)
		} else {
			editor.writeData(side, taken.streamID, taken.payload, taken.endStream)
		}

		return
	}

	current := stream.sides[side.peer]
	available := min(side.window, current.window)

	if (taken.raw != nil) && (taken.need <= available) && (len(taken.raw)-frameHeaderLength <= int(side.maxFrameSize)) {
		side.window -= taken.need
		current.window -= taken.need
		side.write(taken.raw)
		return
	}

	// a frame that waits or is split goes on without its padding, the sender gets it back
	if dropped := taken.need - int64(len(taken.payload)); dropped > 0 {
		side.excess += dropped
		current.excess += dropped
	}

	taken.raw = nil
	taken.need = int64(len(taken.payload))

	if taken.need <= available {
		side.window -= taken.need
		current.window -= taken.need

		if (taken.need > 0) || taken.endStream {
			editor.writeData(side, taken.streamID, taken.payload, taken.endStream)
		}

		return
	}

	if available <= 0 {
		rest = &taken
		return
	}

	side.window -= available
	current.window -= available
	editor.writeData(side, taken.streamID, taken.payload[:available], false)
	rest = &unit{kind: dataUnit, streamID: taken.streamID, raw: nil, payload: taken.payload[available:], need: taken.need - available, endStream: taken.endStream, block: nil, seq: -1, isPart: true}
	return
}

// a header block goes on as it came while every block before it did, in order; after that every block is encoded again
func (editor *Editor) sendBlock(side *editSide, stream *editStream, taken unit) {
	block := taken.block

	if (taken.raw != nil) && (side.encoder == nil) && (taken.seq == side.sentBlocks) {
		side.write(taken.raw)
		side.sentBlocks++
	} else {
		editor.encodeBlock(side, taken)
	}

	if block.IsPush {
		stream = editor.streams[block.PromiseID]
	}

	if stream != nil {
		editor.opened(side, stream)
	}
}

// the fields of a block with the side's own encoder, in HEADERS (or PUSH_PROMISE) and CONTINUATION frames of the receiver's max frame size
// the encoder's table size is 0: its first block starts with a dynamic table size update to 0, every field is a literal without indexing, the receiver's table stays empty
func (editor *Editor) encodeBlock(side *editSide, taken unit) {
	block := taken.block

	if side.encoder == nil {
		side.encoded = &bytes.Buffer{}
		side.encoder = hpack.NewEncoder(side.encoded)
		side.encoder.SetMaxDynamicTableSizeLimit(0)
	}

	if block.IsCut {
		editor.fail(fmt.Errorf("%w: stream %d", ErrHeaderListTooLarge, block.StreamID))
	}

	side.encoded.Reset()

	for _, field := range block.Fields {
		if err := side.encoder.WriteField(hpack.HeaderField{Name: field.Name, Value: field.Value, Sensitive: false}); err != nil {
			editor.fail(err)
		}
	}

	fragment := bytes.Clone(side.encoded.Bytes())
	first := int(side.maxFrameSize)

	if block.IsPush {
		first -= 4
	}

	if block.HasPriority {
		first -= 5
	}

	piece := fragment[:min(first, len(fragment))]
	fragment = fragment[len(piece):]
	side.write(editor.build(func(framer *http2.Framer) (err error) {
		if block.IsPush {
			err = framer.WritePushPromise(http2.PushPromiseParam{StreamID: block.StreamID, PromiseID: block.PromiseID, BlockFragment: piece, EndHeaders: len(fragment) == 0, PadLength: 0})
			return
		}

		priority := http2.PriorityParam{}

		if block.HasPriority {
			priority = block.Priority
		}

		err = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: block.StreamID, BlockFragment: piece, EndStream: taken.endStream, EndHeaders: len(fragment) == 0, PadLength: 0, Priority: priority})
		return
	}))

	for len(fragment) > 0 {
		piece = fragment[:min(int(side.maxFrameSize), len(fragment))]
		fragment = fragment[len(piece):]
		side.write(editor.build(func(framer *http2.Framer) error {
			return framer.WriteContinuation(block.StreamID, len(fragment) == 0, piece)
		}))
	}
}

// body bytes in DATA frames of the receiver's max frame size, END_STREAM on the last
func (editor *Editor) writeData(side *editSide, streamID uint32, payload []byte, endStream bool) {
	for {
		piece := payload[:min(int(side.maxFrameSize), len(payload))]
		payload = payload[len(piece):]
		side.write(editor.build(func(framer *http2.Framer) error {
			return framer.WriteData(streamID, endStream && (len(payload) == 0), piece)
		}))

		if len(payload) == 0 {
			return
		}
	}
}

func (editor *Editor) windowUpdate(streamID uint32, increment int64) (data []byte) {
	for increment > 0 {
		piece := min(increment, maxIncrement)
		increment -= piece
		data = append(data, editor.build(func(framer *http2.Framer) error {
			return framer.WriteWindowUpdate(streamID, uint32(piece))
		})...)
	}

	return
}

// the frames the write makes
func (editor *Editor) build(write func(framer *http2.Framer) error) (data []byte) {
	editor.framed.Reset()

	if err := write(editor.framer); err != nil {
		editor.fail(err)
	}

	data = bytes.Clone(editor.framed.Bytes())
	return
}

// the sender of a side gets back the window of what it sent and the receiver did not count: on the connection, and on each stream it still sends on that does not only wait to open
func (editor *Editor) topUp(side *editSide) {
	other := editor.sides[otherPeer(side.peer)]

	if side.excess > 0 {
		other.write(editor.windowUpdate(0, side.excess))
		side.excess = 0
	}

	for _, id := range slices.Sorted(maps.Keys(editor.streams)) {
		current := editor.streams[id].sides[side.peer]

		// a stream that only waits to open gets nothing: its sender stops at its window, so the frames that wait stay few
		if (current.excess <= 0) || ((current.message == nil) && (len(current.held) > 0) && !current.isEnded) {
			continue
		}

		if !current.isEnded {
			other.write(editor.windowUpdate(id, current.excess))
		}

		current.excess = 0
	}
}

// the DATA that waits for the windows goes on as far as they allow now, with what waits behind it on its stream
func (editor *Editor) flushQueues(side *editSide) {
	for _, id := range slices.Sorted(maps.Keys(editor.streams)) {
		stream := editor.streams[id]
		current := stream.sides[side.peer]

		for len(current.queue) > 0 {
			waiting := current.queue[0]

			if rest := editor.send(side, stream, waiting); rest != nil {
				current.queue[0] = *rest
				break
			}

			current.queue = current.queue[1:]
		}

		if len(current.queue) == 0 {
			current.queue = nil
		}
	}
}

// the frames held on a stream go on while nothing is kept on it and it may open
func (editor *Editor) drain(side *editSide, stream *editStream) {
	current := stream.sides[side.peer]

	for (current.message == nil) && (len(current.held) > 0) && !editor.isGated(side, stream) {
		next := current.held[0]
		current.held = current.held[1:]
		editor.commit(side, stream, next)
	}

	if len(current.held) == 0 {
		current.held = nil
	}
}

// the streams of a peer open in the order of their ids: a stream waits while an earlier one of the peer is not open yet at the receiver
func (editor *Editor) isGated(side *editSide, stream *editStream) (isGated bool) {
	isGated = !stream.sides[side.peer].isOpened && (len(side.openings) > 0) && (side.openings[0] != stream.id)
	return
}

// the first stream that waits to open may go on now, and the next one after it
func (editor *Editor) openNext(side *editSide) {
	for len(side.openings) > 0 {
		stream := editor.streams[side.openings[0]]

		if (stream == nil) || stream.sides[side.peer].isOpened {
			side.openings = side.openings[1:]
			continue
		}

		editor.drain(side, stream)

		if !stream.sides[side.peer].isOpened {
			return
		}
	}
}

// the receiver of a side knows the stream now
func (editor *Editor) opened(side *editSide, stream *editStream) {
	stream.sides[side.peer].isOpened = true
	side.openings = slices.DeleteFunc(side.openings, func(id uint32) bool {
		return id == stream.id
	})
}

// a new stream the initiator opens, nil when it is no new stream of the initiator or over the max streams
// the initiator's side waits to be known by the receiver, the other side's receiver opened it; a stream of the client waits in the openings of its side
func (editor *Editor) open(initiator Peer, id uint32) (stream *editStream) {
	isClientStream := id%2 == 1

	if (id == 0) || (id <= editor.lastStream[initiator]) || (isClientStream != (initiator == ClientPeer)) || (len(editor.streams) >= editor.maxStreams) {
		return
	}

	editor.lastStream[initiator] = id
	stream = &editStream{id: id, sides: [2]*streamSide{}}

	for _, side := range editor.sides {
		stream.sides[side.peer] = &streamSide{isOpened: side.peer != initiator, isEnded: false, window: side.initialWindow, excess: 0, message: nil, held: nil, queue: nil}
	}

	editor.streams[id] = stream

	if initiator == ClientPeer {
		side := editor.sides[ClientPeer]
		side.openings = append(side.openings, id)
	}

	return
}

// the stream ends for both peers: nothing of it waits any more, DATA that waited for the windows is given back to its sender
func (editor *Editor) reset(stream *editStream) {
	for _, side := range editor.sides {
		current := stream.sides[side.peer]

		for _, waiting := range current.queue {
			if waiting.kind == dataUnit {
				side.excess += waiting.need
			}
		}

		current.message, current.held, current.queue = nil, nil, nil
		current.isEnded = true
		current.excess = 0
		side.openings = slices.DeleteFunc(side.openings, func(id uint32) bool {
			return id == stream.id
		})
	}
}

// the receiver's settings the sender acknowledged: its max frame size, and its initial window, which moves the window of every stream by the change
func (editor *Editor) apply(side *editSide, settings Settings) {
	side.maxFrameSize = defaultMaxFrameSize

	if size, found := settings[http2.SettingMaxFrameSize]; found {
		side.maxFrameSize = size
	}

	window := defaultWindow

	if initial, found := settings[http2.SettingInitialWindowSize]; found {
		window = int64(initial)
	}

	change := window - side.initialWindow
	side.initialWindow = window

	if change == 0 {
		return
	}

	for _, stream := range editor.streams {
		stream.sides[side.peer].window += change
	}
}

// a block nobody kept goes on
func (editor *Editor) commitUndecided(side *editSide) {
	waiting := side.undecided

	if waiting == nil {
		return
	}

	side.undecided = nil
	stream := editor.streams[waiting.streamID]

	if stream == nil {
		editor.commit(side, nil, *waiting)
		return
	}

	editor.route(side, stream, *waiting)
}

// streams both peers ended and nothing waits on any more
func (editor *Editor) forget() {
	for id, stream := range editor.streams {
		isDone := true

		for _, current := range stream.sides {
			isDone = isDone && current.isEnded && (current.message == nil) && (len(current.held) == 0) && (len(current.queue) == 0)
		}

		for _, side := range editor.sides {
			isDone = isDone && ((side.undecided == nil) || (side.undecided.streamID != id))
		}

		if isDone {
			delete(editor.streams, id)
		}
	}
}

func (editor *Editor) fail(err error) {
	if editor.err == nil {
		editor.err = err
	}
}

// the bytes of the stream offsets from start to end that are still in the buffer, taken out of it with everything before end
func (side *editSide) cut(start int64, end int64) (data []byte) {
	from := max(start, side.bufferStart)

	if end > from {
		data = bytes.Clone(side.buffer[from-side.bufferStart : end-side.bufferStart])
	}

	if end > side.bufferStart {
		side.buffer = side.buffer[end-side.bufferStart:]
		side.bufferStart = end
	}

	if len(side.buffer) == 0 {
		side.buffer = nil
	}

	return
}

// frames decerter adds go on at once only between whole frames and outside of a header block, which a frame that went on half may not be
func (side *editSide) write(data []byte) {
	if (side.passedEnd <= side.cursor) && !side.isPassingBlock {
		side.output = append(side.output, data...)
		return
	}

	side.later = append(side.later, data...)
}

func (side *editSide) flushLater() {
	if (len(side.later) == 0) || (side.passedEnd > side.cursor) || side.isPassingBlock {
		return
	}

	side.output = append(side.output, side.later...)
	side.later = nil
}

// what is left of an increment after the excess below 0 took its part back
func swallow(excess *int64, increment int64) (forward int64) {
	forward = increment

	if *excess < 0 {
		taken := min(increment, -*excess)
		*excess += taken
		forward = increment - taken
	}

	return
}
