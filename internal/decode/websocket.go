// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/output"
)

// WebSocket frames from RFC 6455 after an HTTP/1.1 Upgrade, or in the body of an HTTP/2 extended CONNECT (RFC 8441), permessage-deflate from RFC 7692
// a message is frames in order: a client masks every frame, a server none; a text or binary message can go on in continuation frames, control frames
// (close, ping, pong) come between them; a message compressed with permessage-deflate has RSV1 set on its first frame and is inflated alone, which fails
// when its compressor used the window of earlier messages (context takeover)
const (
	websocketProtocol string = "websocket"
	websocketTitle    string = "WebSocket"
	// the bits of the first two bytes of a frame
	finBit        byte = 0x80
	rsv1Bit       byte = 0x40
	rsv2Bit       byte = 0x20
	rsv3Bit       byte = 0x10
	opcodeBits    byte = 0x0f
	maskBit       byte = 0x80
	lengthBits    byte = 0x7f
	maxControlLen int  = 125
	// the opcodes
	continuationOpcode byte = 0
	textOpcode         byte = 1
	binaryOpcode       byte = 2
	closeOpcode        byte = 8
	pingOpcode         byte = 9
	pongOpcode         byte = 10
	// sniffing alone never takes WebSocket, the Upgrade of the flow does
	websocketSniffScore int = 40
	// the frames the summary names one by one
	maxSummaryFrames int = 8
	// the bytes of a text frame the summary shows
	maxSummaryText int    = 40
	deflateName    string = "permessage-deflate"
)

var (
	websocketOpcodes = nameTable{names: map[uint16]string{0: "Continuation", 1: "Text", 2: "Binary", 8: "Close", 9: "Ping", 10: "Pong"}, unknown: "Opcode %d"}
	websocketCloses  = nameTable{names: map[uint16]string{
		1000: "Normal Closure", 1001: "Going Away", 1002: "Protocol Error", 1003: "Unsupported Data", 1005: "No Status Received", 1006: "Abnormal Closure",
		1007: "Invalid Payload Data", 1008: "Policy Violation", 1009: "Message Too Big", 1010: "Mandatory Extension", 1011: "Internal Error",
		1012: "Service Restart", 1013: "Try Again Later", 1014: "Bad Gateway", 1015: "TLS Handshake",
	}, unknown: "Code %d"}
	// the empty stored block a sender of permessage-deflate takes off the end of a message (RFC 7692 7.2.1)
	deflateTail = []byte{0x00, 0x00, 0xff, 0xff}
)

func init() {
	register(decoder{
		Protocol:   websocketProtocol,
		Title:      websocketTitle,
		Ports:      nil,
		hint:       websocketHint,
		sniff:      websocketSniff,
		decode:     websocketDecode,
		fromTarget: nil,
	})
}

func websocketHint(context Context) (reason string) {
	if !strings.EqualFold(strings.TrimSpace(context.Upgrade), websocketProtocol) {
		return
	}

	reason = "the flow switched to WebSocket with an HTTP Upgrade"

	if context.Transport == BodyTransport {
		reason = "the :protocol websocket of the HTTP/2 extended CONNECT"
	}

	return
}

// frames that read to the end of the data, each masked when the client sent it and not when the server did; the head of the 101 or of the upgrade
// request in front of them is skipped; a frame that goes on in the next read counts too; frames RFC 6455 forbids or a header cut short get a little, so
// the Upgrade of the flow still takes them and the tree shows what is wrong
func websocketSniff(data []byte, context Context) (score int) {
	offset := httpHeadEnd(data)

	if offset == len(data) {
		return
	}

	isDeflate := hasDeflate(context.Extensions)

	for offset < len(data) {
		frame, isFrame := readFrameHeader(data, offset)

		if !isFrame || (frame.opcode > pongOpcode) || ((frame.opcode > binaryOpcode) && (frame.opcode < closeOpcode)) || (frame.rsv&(rsv2Bit|rsv3Bit) != 0) ||
			((frame.rsv&rsv1Bit != 0) && !isDeflate) || ((frame.opcode >= closeOpcode) && ((frame.length > uint64(maxControlLen)) || !frame.isFin)) || isWrongMask(frame, context) {
			score = protobufPartialScore
			return
		}

		score = websocketSniffScore

		if frame.length > uint64(len(data)-frame.payloadStart) {
			return
		}

		offset = frame.payloadStart + int(frame.length)
	}

	return
}

// a client frame without a mask or a server frame with one (RFC 6455 5.1)
func isWrongMask(frame websocketFrame, context Context) (isWrong bool) {
	isWrong = ((context.Direction == v1.UpDirection) && !frame.isMasked) || ((context.Direction == v1.DownDirection) && frame.isMasked)
	return
}

// the end of an HTTP/1 head the data starts with (a 101 whose read carried the first frames), 0 for none
func httpHeadEnd(data []byte) (end int) {
	if !bytes.HasPrefix(data, []byte("HTTP/1.")) && !bytes.HasPrefix(data, []byte("GET ")) {
		return
	}

	index := bytes.Index(data, []byte("\r\n\r\n"))

	if index < 0 {
		end = len(data)
		return
	}

	end = index + 4
	return
}

// whether the Sec-WebSocket-Extensions the server answered has permessage-deflate
func hasDeflate(extensions string) (isDeflate bool) {
	for extension := range strings.SplitSeq(extensions, ",") {
		name, _, _ := strings.Cut(extension, ";")

		if strings.EqualFold(strings.TrimSpace(name), deflateName) {
			isDeflate = true
			return
		}
	}

	return
}

// the header of the frame at offset, isFrame is false when it is cut short
func readFrameHeader(data []byte, offset int) (frame websocketFrame, isFrame bool) {
	if len(data)-offset < 2 {
		return
	}

	first, second := data[offset], data[offset+1]
	frame = websocketFrame{
		start:        offset,
		isFin:        first&finBit != 0,
		rsv:          first & (rsv1Bit | rsv2Bit | rsv3Bit),
		opcode:       first & opcodeBits,
		isMasked:     second&maskBit != 0,
		length:       uint64(second & lengthBits),
		lengthBytes:  0,
		key:          [4]byte{},
		payloadStart: offset + 2,
	}

	switch frame.length {
	case 126:
		frame.lengthBytes = 2
	case 127:
		frame.lengthBytes = 8
	}

	if len(data)-frame.payloadStart < frame.lengthBytes {
		return
	}

	switch frame.lengthBytes {
	case 2:
		frame.length = uint64(binary.BigEndian.Uint16(data[frame.payloadStart:]))
	case 8:
		frame.length = binary.BigEndian.Uint64(data[frame.payloadStart:])
	}

	frame.payloadStart += frame.lengthBytes

	if frame.isMasked {
		if len(data)-frame.payloadStart < 4 {
			return
		}

		copy(frame.key[:], data[frame.payloadStart:])
		frame.payloadStart += 4
	}

	isFrame = true
	return
}

func websocketDecode(tree *Tree, data []byte, context Context) {
	state := &websocketState{isDeflate: hasDeflate(context.Extensions), opcode: 0, isCompressed: false, parts: nil, joined: nil, firstStart: 0, frames: 0, summary: nil, context: context}
	offset := httpHeadEnd(data)

	if offset > 0 {
		tree.add(nil, "websocket.http_head", "HTTP head (see the exchange)", fmt.Sprintf("%d bytes", offset), 0, offset)
	}

	for (offset < len(data)) && !tree.isFull {
		frame, isFrame := readFrameHeader(data, offset)

		if !isFrame {
			root := tree.add(nil, websocketProtocol, "WebSocket frame", "", offset, len(data)-offset)
			tree.fail(root, fmt.Sprintf("the frame header is cut short, %d bytes are here; the frame goes on in the next read", len(data)-offset))
			state.addSummary("header cut short")
			break
		}

		offset = websocketFrameNodes(tree, data, frame, state)
	}

	summary := fmt.Sprintf("WebSocket, %d frame%s", state.frames, map[bool]string{false: "s", true: ""}[state.frames == 1])

	if len(state.summary) > 0 {
		summary += ": " + strings.Join(state.summary, ", ")
	}

	tree.addSummary(summary)
}

func (state *websocketState) addSummary(line string) {
	switch {
	case len(state.summary) < maxSummaryFrames:
		state.summary = append(state.summary, line)
	case len(state.summary) == maxSummaryFrames:
		state.summary = append(state.summary, "...")
	}
}

// one frame as a root; next is the byte after it
func websocketFrameNodes(tree *Tree, data []byte, frame websocketFrame, state *websocketState) (next int) {
	available := min(frame.length, uint64(len(data)-frame.payloadStart))
	next = frame.payloadStart + int(available)
	state.frames++
	opcodeName := shortName(websocketOpcodes, uint16(frame.opcode))
	labels := []string{opcodeName}

	if frame.isFin {
		labels = append(labels, "FIN")
	}

	if frame.isMasked {
		labels = append(labels, "masked")
	}

	root := tree.add(nil, websocketProtocol, "WebSocket "+strings.Join(labels, ", ")+fmt.Sprintf(", %d bytes", frame.length), "", frame.start, next-frame.start)
	start := frame.start
	tree.addBits(root, "websocket.fin", "Fin", yesNo(frame.isFin), start, 1, uint32(finBit))
	tree.addBits(root, "websocket.rsv1", map[bool]string{false: "Reserved 1", true: "Reserved 1 (compressed)"}[state.isDeflate], yesNo(frame.rsv&rsv1Bit != 0), start, 1, uint32(rsv1Bit))
	tree.addBits(root, "websocket.rsv2", "Reserved 2", yesNo(frame.rsv&rsv2Bit != 0), start, 1, uint32(rsv2Bit))
	tree.addBits(root, "websocket.rsv3", "Reserved 3", yesNo(frame.rsv&rsv3Bit != 0), start, 1, uint32(rsv3Bit))
	tree.addBits(root, "websocket.opcode", "Opcode", nameOf(websocketOpcodes, uint16(frame.opcode)), start, 1, uint32(opcodeBits))
	tree.addBits(root, "websocket.mask", "Mask", yesNo(frame.isMasked), start+1, 1, uint32(maskBit))

	if frame.lengthBytes == 0 {
		tree.addBits(root, "websocket.payload_length", "Payload length", strconv.FormatUint(frame.length, 10), start+1, 1, uint32(lengthBits))
	} else {
		tree.addBits(root, "websocket.payload_length", "Payload length", fmt.Sprintf("%d bytes follow", frame.lengthBytes), start+1, 1, uint32(lengthBits))
		tree.add(root, "websocket.payload_length_ext", "Extended payload length", strconv.FormatUint(frame.length, 10), start+2, frame.lengthBytes)
	}

	if frame.isMasked {
		tree.add(root, "websocket.masking_key", "Masking key", fmt.Sprintf("%x", frame.key), frame.payloadStart-4, 4)
	}

	websocketFrameChecks(tree, root, frame, state)
	payload := unmask(data[frame.payloadStart:next], frame)

	if available < frame.length {
		tree.fail(root, fmt.Sprintf("the frame goes on in the next read: %d of its %d payload bytes are here", available, frame.length))
	}

	switch frame.opcode {
	case closeOpcode:
		websocketClose(tree, root, payload, frame.payloadStart, state)
	case
		pingOpcode,
		pongOpcode:
		websocketPayload(tree, root, payload, frame.payloadStart, isText(payload))
		state.addSummary(opcodeName)
	case
		textOpcode,
		binaryOpcode,
		continuationOpcode:
		websocketData(tree, root, payload, frame, available == frame.length, state)
	default:
		websocketPayload(tree, root, payload, frame.payloadStart, false)
		state.addSummary(opcodeName)
	}

	return
}

// what RFC 6455 5 forbids: masking the wrong way, reserved bits without an extension, an unknown opcode, a fragmented or long control frame, a continuation
// without a message
func websocketFrameChecks(tree *Tree, root *node, frame websocketFrame, state *websocketState) {
	if (frame.rsv&(rsv2Bit|rsv3Bit) != 0) || ((frame.rsv&rsv1Bit != 0) && !state.isDeflate) {
		tree.fail(root, "reserved bits are set without an extension that uses them")
	}

	if isWrongMask(frame, state.context) {
		tree.fail(root, map[bool]string{false: "a frame of the server is masked", true: "a frame of the client is not masked"}[state.context.Direction == v1.UpDirection])
	}

	switch {
	case (frame.opcode > binaryOpcode) && (frame.opcode < closeOpcode), frame.opcode > pongOpcode:
		tree.fail(root, fmt.Sprintf("opcode %d is reserved", frame.opcode))
	case (frame.opcode >= closeOpcode) && (!frame.isFin || (frame.length > uint64(maxControlLen))):
		tree.fail(root, "a control frame is not fragmented and has at most 125 bytes")
	case (frame.opcode == continuationOpcode) && (state.opcode == 0):
		tree.fail(root, "a continuation frame without the start of a message in this read")
	case ((frame.opcode == textOpcode) || (frame.opcode == binaryOpcode)) && (state.opcode != 0):
		tree.fail(root, "a new message before the end of the one before it")
	}
}

// the payload of a frame unmasked, a copy when it was masked
func unmask(payload []byte, frame websocketFrame) (plain []byte) {
	if !frame.isMasked {
		plain = payload
		return
	}

	plain = make([]byte, len(payload))

	for index, value := range payload {
		plain[index] = value ^ frame.key[index%4]
	}

	return
}

// a close frame: the status code and the reason, both optional
func websocketClose(tree *Tree, root *node, payload []byte, start int, state *websocketState) {
	if len(payload) == 0 {
		state.addSummary("Close")
		return
	}

	if len(payload) == 1 {
		tree.fail(root, "a close payload of 1 byte, the status code has 2")
		state.addSummary("Close")
		return
	}

	code := binary.BigEndian.Uint16(payload)
	tree.add(root, "websocket.close.code", "Status code", nameOf(websocketCloses, code), start, 2)
	text := shortName(websocketCloses, code)

	if len(payload) > 2 {
		tree.add(root, "websocket.close.reason", "Reason", textValue(payload[2:]), start+2, len(payload)-2)
	}

	state.addSummary(fmt.Sprintf("Close %d %s", code, text))
}

// a payload as text or hex, every node over the frame's payload bytes
func websocketPayload(tree *Tree, root *node, payload []byte, start int, isTextual bool) {
	if len(payload) == 0 {
		return
	}

	if isTextual {
		tree.add(root, "websocket.payload.text", "Payload (unmasked)", textValue(payload), start, len(payload))
		return
	}

	tree.add(root, "websocket.payload.data", "Payload (unmasked)", hexValue(payload), start, len(payload))
}

// a frame of a text or binary message: alone it is shown at once, a fragmented message is shown frame by frame and put together after its last frame
func websocketData(tree *Tree, root *node, payload []byte, frame websocketFrame, isWhole bool, state *websocketState) {
	if frame.opcode != continuationOpcode {
		state.opcode, state.isCompressed, state.parts, state.firstStart = frame.opcode, state.isDeflate && (frame.rsv&rsv1Bit != 0), nil, frame.start
	}

	opcode := state.opcode

	if opcode == 0 {
		opcode = binaryOpcode
	}

	isMessage := frame.isFin && (frame.opcode != continuationOpcode) && isWhole

	if isMessage {
		websocketMessage(tree, root, payload, fixedOrAt(state.isCompressed, frame.payloadStart, len(payload)), opcode, state)
		state.opcode = 0
		return
	}

	// a fragment: its own bytes now, the message once its last frame is here
	if state.isCompressed {
		tree.add(root, "websocket.payload.compressed", "Payload (unmasked, compressed)", hexValue(payload), frame.payloadStart, len(payload))
	} else {
		websocketPayload(tree, root, payload, frame.payloadStart, (opcode == textOpcode) && utf8.Valid(payload))
	}

	state.parts = append(state.parts, segment{from: len(state.joined), at: frame.payloadStart, length: len(payload)})
	state.joined = append(state.joined, payload...)

	if !frame.isFin || !isWhole || (state.opcode == 0) {
		state.addSummary(shortName(websocketOpcodes, uint16(frame.opcode)) + " fragment")

		if !isWhole {
			state.opcode = 0
		}

		return
	}

	// the last frame: the message is a root of its own over its frames
	end := frame.payloadStart + len(payload)
	message := tree.add(nil, "websocket.message", fmt.Sprintf("Reassembled %s message (%d frames)", shortName(websocketOpcodes, uint16(opcode)), len(state.parts)), fmt.Sprintf("%d bytes", len(state.joined)), state.firstStart, end-state.firstStart)
	place := fixed(state.firstStart, end-state.firstStart)

	if !state.isCompressed {
		place = pieces(state.parts)
	}

	websocketMessage(tree, message, state.joined, place, opcode, state)
	state.opcode, state.parts, state.joined = 0, nil, nil
}

// the place of a payload: the source bytes as they are, or fixed over them when the payload is inflated
func fixedOrAt(isFixed bool, start int, length int) (place placement) {
	place = at(start)

	if isFixed {
		place = fixed(start, length)
	}

	return
}

// a whole message: inflated when it is compressed, then text, or binary through the decoder its bytes sniff as, or hex
func websocketMessage(tree *Tree, parent *node, payload []byte, place placement, opcode byte, state *websocketState) {
	data := payload
	kind := shortName(websocketOpcodes, uint16(opcode))

	if state.isCompressed {
		inflated, err := inflateMessage(payload)
		inflatedNode := tree.addAt(parent, place, "websocket.payload.inflated", "Payload (inflated, "+deflateName+")", fmt.Sprintf("%d bytes from %d", len(inflated), len(payload)), 0, len(payload))

		if err != nil {
			tree.fail(inflatedNode, "could not inflate the message alone: "+err.Error()+"; it may use the window of earlier messages (context takeover)")
			state.addSummary(kind + " (compressed)")
			return
		}

		data, parent = inflated, inflatedNode
	}

	if len(data) == 0 {
		state.addSummary(kind + " (empty)")
		return
	}

	if (opcode == textOpcode) || isText(data) {
		tree.addAt(parent, place, "websocket.payload.text", "Text", textValue(data), 0, len(data))
		shown := data[:min(len(data), maxSummaryText)]
		text := `"` + output.Escape(shown) + `"`

		if len(data) > maxSummaryText {
			text += "..."
		}

		state.addSummary(kind + " " + text)

		if opcode != textOpcode {
			return
		}

		if !utf8.Valid(data) {
			tree.fail(parent, "a text message is not UTF-8")
		}

		return
	}

	// the binary payload as another protocol when its bytes sniff as one, protobuf counts from its clean score
	protocol, _ := decodeNested(tree, parent, data, place, state.context, websocketProtocol, protobufCleanScore)

	if protocol != "" {
		state.addSummary(fmt.Sprintf("%s %d bytes (%s)", kind, len(data), protocol))
		return
	}

	tree.addAt(parent, place, "websocket.payload.data", "Binary data", hexValue(data), 0, len(data))
	state.addSummary(fmt.Sprintf("%s %d bytes", kind, len(data)))
}

// a permessage-deflate message: raw DEFLATE with the empty stored block put back at its end, at most maxInflatedBytes
func inflateMessage(payload []byte) (inflated []byte, err error) {
	reader := flate.NewReader(io.MultiReader(bytes.NewReader(payload), bytes.NewReader(deflateTail)))
	inflated, err = io.ReadAll(io.LimitReader(reader, int64(maxInflatedBytes)+1))
	closeErr := reader.Close()

	// the stream ends with the empty block, without a final block: the end of the bytes is the end of the message (Close gives the same error again)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err, closeErr = nil, nil
	}

	if (err == nil) && (len(inflated) > maxInflatedBytes) {
		inflated = inflated[:maxInflatedBytes]
		err = fmt.Errorf("it inflates to more than %d bytes", maxInflatedBytes)
	}

	err = errors.Join(err, closeErr)
	return
}
