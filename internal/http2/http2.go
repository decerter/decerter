// SPDX-License-Identifier: AGPL-3.0-only

package http2

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// the largest frame the protocol can express, the settings of the receiver decide below it
	maxFrameLength uint32 = 1<<24 - 1
	// SETTINGS a peer may send before the other acknowledges them, older ones are taken as acknowledged
	maxPendingSettings int = 64
)

// a conn that follows at most maxStreams open streams at once, 0 or less is DefaultMaxStreams
func New(maxStreams int) (conn *Conn) {
	if maxStreams <= 0 {
		maxStreams = DefaultMaxStreams
	}

	conn = &Conn{
		isFraming:  false,
		readers:    [2]*reader{newReader(ClientPeer), newReader(ServerPeer)},
		streams:    map[uint32]*stream{},
		lastStream: [2]uint32{0, 0},
		maxStreams: maxStreams,
		isSkipped:  false,
		err:        nil,
	}
	return
}

func newReader(peer Peer) (newReader *reader) {
	source := &frameSource{data: nil}
	framer := http2.NewFramer(nil, source)
	// the order of header blocks is checked by the conn, the framer's check does not know CONTINUATION after PUSH_PROMISE
	framer.AllowIllegalReads = true
	// the reader checks the size against the settings before the framer sees the frame
	framer.SetMaxReadFrameSize(maxFrameLength)
	newReader = &reader{
		peer:          peer,
		buffer:        nil,
		offset:        0,
		isPrefaceRead: peer == ServerPeer,
		source:        source,
		framer:        framer,
		decoder:       hpack.NewDecoder(defaultHeaderTableSize, nil),
		block:         nil,
		acknowledged:  Settings{},
		pending:       nil,
		isFraming:     false,
	}
	newReader.decoder.SetMaxStringLength(maxStringBytes)
	newReader.decoder.SetEmitFunc(newReader.emit)
	return
}

// the next bytes a peer sent, in order; events are what they complete, nothing once the conn stopped
func (conn *Conn) Feed(peer Peer, data []byte) (events []Event) {
	if conn.err != nil {
		return
	}

	reader := conn.readers[peer]
	reader.buffer = append(reader.buffer, data...)
	var err error
	events, err = conn.read(reader)

	if err != nil {
		events = append(events, conn.stop(err)...)
	}

	return
}

// the stream of a peer ended: the messages it was sending are incomplete; after the server's no response can come, so every stream closes
func (conn *Conn) Close(peer Peer) (events []Event) {
	if conn.err != nil {
		return
	}

	side := sideOf(peer)
	offset := conn.readers[peer].offset

	for _, id := range slices.Sorted(maps.Keys(conn.streams)) {
		current := conn.streams[id]
		base := Event{Type: EndEventType, StreamID: id, PromisedBy: current.promisedBy, Side: side, Start: offset, End: offset}

		if peer == ServerPeer {
			events = append(events, conn.abort(current, base, "the connection ended before the stream")...)
			continue
		}

		if current.messages[side].state == bodyState {
			events = append(events, conn.end(current, side, base, false, nil, "the connection ended before the message")...)
		}
	}

	return
}

// every whole frame gets a frame event from now on, before the events it makes, and header blocks keep all their fields for it
func (conn *Conn) EmitFrames() {
	conn.isFraming = true

	for _, reader := range conn.readers {
		reader.isFraming = true
	}
}

// the stream ends now, as by a reset nobody sent: its open messages end incomplete with the note, it closes; nothing for a stream that is not open
func (conn *Conn) Abort(id uint32, note string) (events []Event) {
	current := conn.streams[id]

	if (conn.err != nil) || (current == nil) {
		return
	}

	events = conn.abort(current, Event{Type: EndEventType, StreamID: id, PromisedBy: current.promisedBy, Side: RequestSide, Start: 0, End: 0}, note)
	return
}

// the settings a peer sent that the other peer acknowledged: the frames and header blocks the other peer sends keep to them
func (conn *Conn) Settings(peer Peer) (settings Settings) {
	settings = maps.Clone(conn.readers[otherPeer(peer)].acknowledged)
	return
}

// why the conn stopped parsing, nil while it reads
func (conn *Conn) Err() (err error) {
	err = conn.err
	return
}

// the whole frames in the buffer of a reader, after the preface of the client
func (conn *Conn) read(reader *reader) (events []Event, err error) {
	if !reader.isPrefaceRead {
		length := min(len(reader.buffer), len(Preface))

		if !bytes.Equal(reader.buffer[:length], []byte(Preface[:length])) {
			err = fmt.Errorf("%w: %q", ErrPreface, reader.buffer[:length])
			return
		}

		if length < len(Preface) {
			return
		}

		reader.consume(len(Preface))
		reader.isPrefaceRead = true
	}

	for len(reader.buffer) >= frameHeaderLength {
		length := uint32(reader.buffer[0])<<16 | uint32(reader.buffer[1])<<8 | uint32(reader.buffer[2])
		maxLength := reader.limit(http2.SettingMaxFrameSize, defaultMaxFrameSize)

		if length > maxLength {
			err = fmt.Errorf("%w: %d bytes, at most %d", ErrFrameTooLarge, length, maxLength)
			return
		}

		size := frameHeaderLength + int(length)

		if len(reader.buffer) < size {
			return
		}

		start := reader.offset
		reader.source.data = reader.buffer[:size]
		frame, readErr := reader.framer.ReadFrame()
		reader.consume(size)

		if readErr != nil {
			err = fmt.Errorf("%w: %w", ErrFrame, readErr)
			return
		}

		frameEvents, frameErr := conn.frame(reader, frame, start)
		events = append(events, frameEvents...)

		if err = frameErr; err != nil {
			return
		}
	}

	return
}

// one whole frame of a reader from stream offset start; the frame is only valid until the next one is read
func (conn *Conn) frame(reader *reader, frame http2.Frame, start int64) (events []Event, err error) {
	header := frame.Header()
	end := reader.offset

	// a header block goes on only in CONTINUATION frames of its own stream
	if ((reader.block != nil) != (header.Type == http2.FrameContinuation)) || ((reader.block != nil) && (header.StreamID != reader.block.streamID)) {
		err = fmt.Errorf("%w: %s on stream %d", ErrFrameOrder, header.Type, header.StreamID)
		return
	}

	described := &Frame{Type: header.Type, Flags: header.Flags, StreamID: header.StreamID, Length: header.Length, Data: nil, Increment: 0, ErrCode: 0, Priority: http2.PriorityParam{}, HasPriority: false, PromiseID: 0, Settings: nil, Block: nil}
	block := (*headerBlock)(nil)

	switch typed := frame.(type) {
	case *http2.DataFrame:
		described.Data = bytes.Clone(typed.Data())
		events = conn.data(reader.peer, typed, start, end)
	case *http2.HeadersFrame:
		reader.block = &headerBlock{streamID: header.StreamID, isPush: false, promised: 0, endStream: typed.StreamEnded(), priority: typed.Priority, hasPriority: typed.HasPriority(), fields: nil, size: 0, isCut: false, start: start, all: nil, allSize: 0, isAllCut: false}
		block = reader.block
		events, err = conn.fragment(reader, typed.HeaderBlockFragment(), typed.HeadersEnded(), end)
	case *http2.PushPromiseFrame:
		described.PromiseID = typed.PromiseID
		reader.block = &headerBlock{streamID: header.StreamID, isPush: true, promised: typed.PromiseID, endStream: false, priority: http2.PriorityParam{}, hasPriority: false, fields: nil, size: 0, isCut: false, start: start, all: nil, allSize: 0, isAllCut: false}
		block = reader.block
		events, err = conn.fragment(reader, typed.HeaderBlockFragment(), typed.HeadersEnded(), end)
	case *http2.ContinuationFrame:
		block = reader.block
		events, err = conn.fragment(reader, typed.HeaderBlockFragment(), typed.HeadersEnded(), end)
	case *http2.RSTStreamFrame:
		described.ErrCode = typed.ErrCode
		events = conn.reset(reader.peer, header.StreamID, typed.ErrCode, start, end)
	case *http2.GoAwayFrame:
		events = conn.goAway(reader.peer, typed.LastStreamID, typed.ErrCode, start, end)
	case *http2.SettingsFrame:
		conn.settings(reader.peer, typed)

		if typed.IsAck() {
			described.Settings = maps.Clone(reader.acknowledged)
		}
	case *http2.WindowUpdateFrame:
		described.Increment = typed.Increment
	default:
		// PING, PRIORITY, PRIORITY_UPDATE and unknown frames change nothing that is shown
	}

	if !conn.isFraming || (err != nil) {
		return
	}

	// the block is whole once the reader let go of it
	if (block != nil) && (reader.block == nil) {
		described.Block = &Block{StreamID: block.streamID, IsPush: block.isPush, PromiseID: block.promised, EndStream: block.endStream, Priority: block.priority, HasPriority: block.hasPriority, Fields: block.all, IsCut: block.isAllCut}
	}

	events = append([]Event{{Type: FrameEventType, StreamID: header.StreamID, Side: sideOf(reader.peer), Start: start, End: end, Frame: described}}, events...)
	return
}

// a piece of a header block: decoded at once, so the dynamic table stays in step even for a stream that is not shown
func (conn *Conn) fragment(reader *reader, fragment []byte, isEnd bool, end int64) (events []Event, err error) {
	_, err = reader.decoder.Write(fragment)

	if (err == nil) && isEnd {
		err = reader.decoder.Close()
	}

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrHPACK, err)
		return
	}

	if !isEnd {
		return
	}

	block := reader.block
	reader.block = nil
	events = conn.headers(reader.peer, block, end)
	return
}

// a whole header block of a HEADERS frame: a head, a 1xx head or the trailers of a message; a PUSH_PROMISE opens its stream with the request
func (conn *Conn) headers(peer Peer, block *headerBlock, end int64) (events []Event) {
	head := HeadOf(block.fields, block.isCut)

	if block.isPush {
		events = conn.promise(block, head, end)
		return
	}

	current := conn.streams[block.streamID]

	if current == nil {
		current, events = conn.open(peer, block.streamID, 0)

		if current == nil {
			return
		}
	}

	side := sideOf(peer)
	message := &current.messages[side]
	base := Event{Type: HeadEventType, StreamID: current.id, PromisedBy: current.promisedBy, Side: side, Start: block.start, End: end}

	switch message.state {
	case waitingState:
		event := base
		event.Head = head
		event.IsInterim = (side == ResponseSide) && (head.Status >= 100) && (head.Status < 200) && !block.endStream
		event.EndsMessage = block.endStream
		events = append(events, event)

		if event.IsInterim {
			return
		}

		message.state = bodyState
		current.hasResponse = current.hasResponse || (side == ResponseSide)
		contentType, _ := head.Get("content-type")
		message.isGRPC = isGRPC(contentType)

		if block.endStream {
			events = append(events, conn.end(current, side, base, true, nil, "")...)
		}
	case bodyState:
		// a header block after the head is the trailer section, it ends the message
		events = append(events, conn.end(current, side, base, true, head.Fields, "")...)
	default:
	}

	return
}

// a PUSH_PROMISE: the promised stream opens with the request the server made up for it, whole at once; the response comes in HEADERS on that stream
func (conn *Conn) promise(block *headerBlock, head Head, end int64) (events []Event) {
	if (block.promised == 0) || (block.promised%2 != 0) {
		return
	}

	pushed, events := conn.open(ServerPeer, block.promised, block.streamID)

	if pushed == nil {
		return
	}

	base := Event{Type: HeadEventType, StreamID: pushed.id, PromisedBy: pushed.promisedBy, Side: RequestSide, Start: block.start, End: end}
	event := base
	event.Head = head
	event.EndsMessage = true
	events = append(events, event)
	pushed.messages[RequestSide].state = bodyState
	events = append(events, conn.end(pushed, RequestSide, base, true, nil, "")...)
	return
}

// a stream the client opens with HEADERS or the server with PUSH_PROMISE; nil when it is no new stream of that peer or over the max streams
func (conn *Conn) open(initiator Peer, id uint32, promisedBy uint32) (opened *stream, events []Event) {
	isClientStream := id%2 == 1

	if (id <= conn.lastStream[initiator]) || (isClientStream != (initiator == ClientPeer)) {
		return
	}

	conn.lastStream[initiator] = id

	if len(conn.streams) >= conn.maxStreams {
		if !conn.isSkipped {
			conn.isSkipped = true
			events = append(events, Event{Type: SkipEventType, StreamID: id, Note: fmt.Sprintf("more than %d streams open at once, stream %d and others over the limit are not shown", conn.maxStreams, id)})
		}

		return
	}

	opened = &stream{id: id, promisedBy: promisedBy, messages: [2]message{}, hasResponse: false}
	conn.streams[id] = opened
	return
}

// a DATA frame: body bytes of its stream's message without the padding, with the gRPC messages that start in them
func (conn *Conn) data(peer Peer, frame *http2.DataFrame, start int64, end int64) (events []Event) {
	current := conn.streams[frame.StreamID]

	if current == nil {
		return
	}

	side := sideOf(peer)
	message := &current.messages[side]

	if message.state != bodyState {
		return
	}

	base := Event{Type: BodyEventType, StreamID: current.id, PromisedBy: current.promisedBy, Side: side, Start: start, End: end}

	if data := frame.Data(); len(data) > 0 {
		event := base
		event.Data = bytes.Clone(data)

		if message.isGRPC {
			event.GRPC = message.splitter.split(message.bodyLength, event.Data)
		}

		message.bodyLength += int64(len(data))
		events = append(events, event)
	}

	if frame.StreamEnded() {
		events = append(events, conn.end(current, side, base, true, nil, "")...)
	}

	return
}

// a message is over, the stream closes once both are; a message without its head has no end event
func (conn *Conn) end(current *stream, side Side, base Event, isComplete bool, trailers []Field, note string) (events []Event) {
	message := &current.messages[side]

	if message.state == endedState {
		return
	}

	wasOpen := message.state == bodyState
	message.state = endedState

	if wasOpen {
		event := base
		event.Type = EndEventType
		event.Side = side
		event.Head = Head{}
		event.Data = nil
		event.IsComplete = isComplete
		event.Trailers = trailers
		event.Note = joinNotes(note, message.splitter.note(message.isGRPC))
		events = append(events, event)
	}

	if (current.messages[RequestSide].state == endedState) && (current.messages[ResponseSide].state == endedState) {
		events = append(events, conn.close(current, base, ""))
	}

	return
}

// a stream ends before its messages did: the open ones end incomplete with the note, and the stream closes with it
func (conn *Conn) abort(current *stream, base Event, note string) (events []Event) {
	for _, side := range []Side{RequestSide, ResponseSide} {
		message := &current.messages[side]

		if message.state == bodyState {
			event := base
			event.Type = EndEventType
			event.Side = side
			event.IsComplete = false
			event.Note = joinNotes(note, message.splitter.note(message.isGRPC))
			events = append(events, event)
		}

		message.state = endedState
	}

	events = append(events, conn.close(current, base, note))
	return
}

// the stream is done; the note matters when no response came
func (conn *Conn) close(current *stream, base Event, note string) (event Event) {
	delete(conn.streams, current.id)
	event = Event{Type: CloseEventType, StreamID: current.id, PromisedBy: current.promisedBy, Side: base.Side, Start: base.Start, End: base.End, HasResponse: current.hasResponse, Note: note}
	return
}

// RST_STREAM from a peer ends the stream at once
func (conn *Conn) reset(peer Peer, id uint32, code http2.ErrCode, start int64, end int64) (events []Event) {
	current := conn.streams[id]

	if current == nil {
		return
	}

	note := fmt.Sprintf("the %s reset the stream: %s", peerName(peer), code)
	events = conn.abort(current, Event{Type: EndEventType, StreamID: id, PromisedBy: current.promisedBy, Side: sideOf(peer), Start: start, End: end}, note)
	return
}

// GOAWAY from a peer: the streams the other peer opened above the last stream were not processed and end now, the ones up to it go on
func (conn *Conn) goAway(peer Peer, last uint32, code http2.ErrCode, start int64, end int64) (events []Event) {
	initiator := otherPeer(peer)
	note := fmt.Sprintf("not processed: the %s sent GOAWAY (%s) with last stream %d", peerName(peer), code, last)

	for _, id := range slices.Sorted(maps.Keys(conn.streams)) {
		current := conn.streams[id]

		if (id <= last) || ((id%2 == 1) != (initiator == ClientPeer)) {
			continue
		}

		events = append(events, conn.abort(current, Event{Type: EndEventType, StreamID: id, PromisedBy: current.promisedBy, Side: sideOf(peer), Start: start, End: end}, note)...)
	}

	return
}

// SETTINGS of a peer are pending for the other peer's frames until it acknowledges them, in order; its ACK puts the oldest in effect
func (conn *Conn) settings(peer Peer, frame *http2.SettingsFrame) {
	sender := conn.readers[peer]

	if frame.IsAck() {
		if len(sender.pending) > 0 {
			maps.Copy(sender.acknowledged, sender.pending[0])
			sender.pending = sender.pending[1:]
		}

		sender.apply()
		return
	}

	settings := Settings{}

	for index := range frame.NumSettings() {
		setting := frame.Setting(index)
		settings[setting.ID] = setting.Val
	}

	receiver := conn.readers[otherPeer(peer)]
	receiver.pending = append(receiver.pending, settings)

	// a peer that never acknowledges does not grow the list
	if len(receiver.pending) > maxPendingSettings {
		maps.Copy(receiver.acknowledged, receiver.pending[0])
		receiver.pending = receiver.pending[1:]
	}

	receiver.apply()
}

// the conn stops: every open stream ends with the reason, nothing more is read
func (conn *Conn) stop(err error) (events []Event) {
	conn.err = err
	note := fmt.Sprintf("http/2 parsing stopped: %v", err)

	for _, id := range slices.Sorted(maps.Keys(conn.streams)) {
		current := conn.streams[id]
		events = append(events, conn.abort(current, Event{Type: EndEventType, StreamID: id, PromisedBy: current.promisedBy, Side: RequestSide, Start: 0, End: 0}, note)...)
	}

	for _, reader := range conn.readers {
		reader.buffer = nil
		reader.block = nil
	}

	events = append(events, Event{Type: StopEventType, Err: err})
	return
}

// the decoder of the reader, with the table size the other peer allows
func (reader *reader) apply() {
	reader.decoder.SetAllowedMaxDynamicTableSize(reader.limit(http2.SettingHeaderTableSize, defaultHeaderTableSize))
}

// what the reader's frames may use of a setting of the other peer: the acknowledged value, or a larger one it announced and the reader may already have seen
func (reader *reader) limit(id http2.SettingID, initial uint32) (value uint32) {
	value = initial

	if acknowledged, found := reader.acknowledged[id]; found {
		value = acknowledged
	}

	for _, settings := range reader.pending {
		if pending, found := settings[id]; found {
			value = max(value, pending)
		}
	}

	return
}

func (reader *reader) consume(size int) {
	reader.buffer = reader.buffer[size:]
	reader.offset += int64(size)

	if len(reader.buffer) == 0 {
		reader.buffer = nil
	}
}

// a decoded field of the open header block, kept while the head is under MaxHeadBytes (the size HPACK gives a field)
func (reader *reader) emit(field hpack.HeaderField) {
	block := reader.block

	if block == nil {
		return
	}

	size := int(field.Size())

	if reader.isFraming && !block.isAllCut {
		if block.allSize+size > maxEditHeadBytes {
			block.isAllCut = true
		} else {
			block.allSize += size
			block.all = append(block.all, Field{Name: field.Name, Value: field.Value})
		}
	}

	if block.isCut {
		return
	}

	if block.size+size > MaxHeadBytes {
		block.isCut = true
		return
	}

	block.size += size
	block.fields = append(block.fields, Field{Name: field.Name, Value: field.Value})
}

// the head of the fields of a header block
func HeadOf(fields []Field, isCut bool) (head Head) {
	head = Head{Method: "", Scheme: "", Authority: "", Path: "", Protocol: "", Status: 0, Fields: fields, IsCut: isCut}

	for _, field := range fields {
		switch field.Name {
		case ":method":
			head.Method = field.Value
		case ":scheme":
			head.Scheme = field.Value
		case ":authority":
			head.Authority = field.Value
		case ":path":
			head.Path = field.Value
		case ":protocol":
			head.Protocol = field.Value
		case ":status":
			status, statusErr := strconv.Atoi(field.Value)

			if statusErr == nil {
				head.Status = status
			}
		default:
		}
	}

	return
}

func sideOf(peer Peer) (side Side) {
	side = RequestSide

	if peer == ServerPeer {
		side = ResponseSide
	}

	return
}

func otherPeer(peer Peer) (other Peer) {
	other = ServerPeer

	if peer == ServerPeer {
		other = ClientPeer
	}

	return
}

func peerName(peer Peer) (name string) {
	name = "client"

	if peer == ServerPeer {
		name = "server"
	}

	return
}

func joinNotes(first string, second string) (note string) {
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

// the media type is application/grpc or one of its subtypes (application/grpc+proto), parameters may follow; grpc-web (application/grpc-web,
// application/grpc-web-text in base64) has a framing of its own and is not split
func isGRPC(contentType string) (isGRPC bool) {
	rest, isPrefix := strings.CutPrefix(strings.ToLower(strings.TrimSpace(contentType)), grpcContentType)
	rest = strings.TrimLeft(rest, " \t")
	isGRPC = isPrefix && ((rest == "") || (rest[0] == '+') || (rest[0] == ';'))
	return
}
