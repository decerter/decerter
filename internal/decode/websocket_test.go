// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"testing"

	v1 "github.com/decerter/decerter/api"
)

// the contexts of a flow an HTTP Upgrade switched to WebSocket, each way, with permessage-deflate, and the body of an HTTP/2 extended CONNECT
var (
	websocketUp      = Context{Transport: StreamTransport, Layer: v1.TCPLayer, Direction: v1.UpDirection, ServerPort: 8080, ALPN: "", ContentType: "", Upgrade: "websocket", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	websocketDown    = Context{Transport: StreamTransport, Layer: v1.TCPLayer, Direction: v1.DownDirection, ServerPort: 8080, ALPN: "", ContentType: "", Upgrade: "websocket", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	websocketDeflate = Context{Transport: StreamTransport, Layer: v1.TLSLayer, Direction: v1.DownDirection, ServerPort: 443, ALPN: "http/1.1", ContentType: "", Upgrade: "WebSocket", Method: "", Target: "", Encoding: "", Extensions: "permessage-deflate; client_max_window_bits=15", Handshake: false, Joined: false}
	websocketBody    = Context{Transport: BodyTransport, Layer: "", Direction: v1.UpDirection, ServerPort: 443, ALPN: "h2", ContentType: "", Upgrade: "websocket", Method: "CONNECT", Target: "/chat", Encoding: "", Extensions: "", Handshake: false, Joined: false}
)

var testMask = []byte{0x37, 0xfa, 0x21, 0x3d}

// a frame: a 7-bit, 16-bit or 64-bit length by the payload's size, masked with key when there is one
func websocketFrameOf(isFin bool, rsv byte, opcode byte, key []byte, payload []byte) (data []byte) {
	first := rsv | opcode

	if isFin {
		first |= finBit
	}

	maskFlag := byte(0)

	if key != nil {
		maskFlag = maskBit
	}

	switch {
	case len(payload) <= 125:
		data = []byte{first, maskFlag | byte(len(payload))}
	case len(payload) <= 0xffff:
		data = join([]byte{first, maskFlag | 126}, be16(uint16(len(payload))))
	default:
		data = binary.BigEndian.AppendUint64([]byte{first, maskFlag | 127}, uint64(len(payload)))
	}

	data = append(data, key...)

	for index, value := range payload {
		if key != nil {
			value ^= key[index%4]
		}

		data = append(data, value)
	}

	return
}

// a message compressed for permessage-deflate: DEFLATE with a sync flush, its empty stored block taken off
func deflated(state testing.TB, data []byte) (compressed []byte) {
	buffer := bytes.Buffer{}
	writer, err := flate.NewWriter(&buffer, flate.BestCompression)

	if err == nil {
		_, err = writer.Write(data)
	}

	if err == nil {
		err = writer.Flush()
	}

	if err != nil {
		state.Fatalf("Could not deflate the message, error: %s", err.Error())
	}

	compressed = bytes.TrimSuffix(buffer.Bytes(), deflateTail)
	return
}

// Test if decode.Decode returns with the expected output for WebSocket: a masked text frame of the client, the read of the 101 with the server's first frames,
// ping, pong and close, a text message in fragments with a ping between them, extended lengths, a binary protobuf message, a permessage-deflate message and
// the frames of an HTTP/2 extended CONNECT.
func TestWebSocketPositive(state *testing.T) {
	result := mustDecode(state, websocketFrameOf(true, 0, textOpcode, testMask, []byte("hello")), websocketUp, "")

	if (result.Protocol != websocketProtocol) || (result.Summary != `WebSocket, 1 frame: Text "hello"`) || (result.Candidates[0].Reason != "the flow switched to WebSocket with an HTTP Upgrade") || (len(errorsOf(result.Tree)) > 0) {
		state.Fatalf("Test of decode.Decode failed, the masked text frame should decode, result: %+v", result)
	}

	checkValues(state, "decode.Decode", result, map[string]string{"websocket.fin": "yes", "websocket.opcode": "Text (1)", "websocket.mask": "yes", "websocket.payload_length": "5", "websocket.masking_key": "37fa213d", "websocket.payload.text": `"hello"`})

	if text := findNode(result.Tree, "websocket.payload.text"); (text.Offset != 6) || (text.Length != 5) {
		state.Errorf("Test of decode.Decode failed, the text should be over the masked payload bytes, node: %+v", text)
	}

	head := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	down := join(head, websocketFrameOf(true, 0, textOpcode, nil, []byte("welcome")), websocketFrameOf(true, 0, pingOpcode, nil, []byte("p")), websocketFrameOf(true, 0, pongOpcode, nil, nil),
		websocketFrameOf(true, 0, closeOpcode, nil, join(be16(1001), []byte("bye"))))
	result = mustDecode(state, down, websocketDown, "")

	if (result.Summary != `WebSocket, 4 frames: Text "welcome", Ping, Pong, Close 1001 Going Away`) || (len(errorsOf(result.Tree)) > 0) || (result.Tree[0].Name != "websocket.http_head") || (result.Tree[0].Length != len(head)) {
		state.Errorf("Test of decode.Decode failed, the 101 head and the server frames should decode, summary: %q, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	checkValues(state, "decode.Decode", result, map[string]string{"websocket.close.code": "Going Away (1001)", "websocket.close.reason": `"bye"`, "websocket.mask#0": "no"})

	fragments := join(websocketFrameOf(false, 0, textOpcode, testMask, []byte("hel")), websocketFrameOf(true, 0, pingOpcode, testMask, nil), websocketFrameOf(true, 0, continuationOpcode, testMask, []byte("lo")))
	result = mustDecode(state, fragments, websocketUp, "")
	message := findNode(result.Tree, "websocket.message")

	if (result.Summary != `WebSocket, 3 frames: Text fragment, Ping, Text "hello"`) || (message == nil) || (message.Label != "Reassembled Text message (2 frames)") || (len(errorsOf(result.Tree)) > 0) ||
		(message.Children[0].Value != `"hello"`) || (message.Children[0].Offset != 6) || (message.Children[0].Offset+message.Children[0].Length != len(fragments)) {
		state.Errorf("Test of decode.Decode failed, the fragments should be put together, summary: %q, message: %+v", result.Summary, message)
	}

	long := bytes.Repeat([]byte{0xff}, 300)
	huge := bytes.Repeat([]byte("a"), 70000)
	result = mustDecode(state, join(websocketFrameOf(true, 0, binaryOpcode, testMask, long), websocketFrameOf(true, 0, textOpcode, testMask, huge)), websocketUp, "")
	checkValues(state, "decode.Decode", result, map[string]string{"websocket.payload_length#0": "2 bytes follow", "websocket.payload_length_ext#0": "300", "websocket.payload_length#1": "8 bytes follow", "websocket.payload_length_ext#1": "70000"})

	if result.Summary != `WebSocket, 2 frames: Binary 300 bytes, Text "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"...` {
		state.Errorf("Test of decode.Decode failed, the long frames should decode, summary: %q", result.Summary)
	}

	result = mustDecode(state, websocketFrameOf(true, 0, binaryOpcode, nil, protobufSample()), websocketDown, "")

	if (result.Summary != "WebSocket, 1 frame: Binary 52 bytes (protobuf)") || (findNode(result.Tree, "protobuf.field.string") == nil) || (findNode(result.Tree, "protobuf.field.string").Offset != 2+5) {
		state.Errorf("Test of decode.Decode failed, the binary message should be protobuf at the payload's offsets, result: %+v", result)
	}

	compressed := deflated(state, []byte("hello hello hello hello"))
	result = mustDecode(state, websocketFrameOf(true, rsv1Bit, textOpcode, nil, compressed), websocketDeflate, "")
	inflated := findNode(result.Tree, "websocket.payload.inflated")

	if (result.Summary != `WebSocket, 1 frame: Text "hello hello hello hello"`) || (inflated == nil) || (inflated.Offset != 2) || (inflated.Length != len(compressed)) || (len(errorsOf(result.Tree)) > 0) ||
		(findNode(result.Tree, "websocket.rsv1").Label != "Reserved 1 (compressed)") {
		state.Errorf("Test of decode.Decode failed, the deflate message should be inflated, result: %+v", result)
	}

	// a deflate message in two fragments
	split := join(websocketFrameOf(false, rsv1Bit, textOpcode, nil, compressed[:3]), websocketFrameOf(true, 0, continuationOpcode, nil, compressed[3:]))

	if result = mustDecode(state, split, websocketDeflate, ""); (result.Summary != `WebSocket, 2 frames: Text fragment, Text "hello hello hello hello"`) || (len(errorsOf(result.Tree)) > 0) {
		state.Errorf("Test of decode.Decode failed, the fragmented deflate message should be inflated, summary: %q, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	result = mustDecode(state, websocketFrameOf(true, 0, textOpcode, testMask, []byte("over h2")), websocketBody, "")

	if (result.Protocol != websocketProtocol) || (result.Candidates[0].Reason != "the :protocol websocket of the HTTP/2 extended CONNECT") {
		state.Errorf("Test of decode.Decode failed, the extended CONNECT body should be WebSocket, result: %+v", result)
	}

	// without the Upgrade a frame alone is never taken by sniffing
	if result = mustDecode(state, websocketFrameOf(true, 0, textOpcode, testMask, []byte("hello")), tcpContext, ""); result.Protocol == websocketProtocol {
		state.Errorf("Test of decode.Decode failed, a frame without the Upgrade should not be WebSocket, result: %+v", result)
	}
}

// Test if decode.Decode returns with the expected errors for WebSocket: a header or a payload cut short, the frames RFC 6455 forbids, a close of 1 byte, text that
// is not UTF-8, and a deflate message that does not inflate alone or inflates past the cap; each is a tree with the error on its frame.
func TestWebSocketNegative(state *testing.T) {
	bomb := deflated(state, make([]byte, maxInflatedBytes+10))
	testCases := map[string]struct {
		data     []byte
		context  Context
		expected string
	}{
		"short header":     {data: join(websocketFrameOf(true, 0, pingOpcode, nil, nil), []byte{0x81, 0x85, 1}), context: websocketDown, expected: "websocket: the frame header is cut short, 3 bytes are here; the frame goes on in the next read"},
		"short payload":    {data: websocketFrameOf(true, 0, textOpcode, nil, []byte("0123456789"))[:5], context: websocketDown, expected: "websocket: the frame goes on in the next read: 3 of its 10 payload bytes are here"},
		"reserved bits":    {data: websocketFrameOf(true, rsv1Bit, textOpcode, nil, []byte("x")), context: websocketDown, expected: "websocket: reserved bits are set without an extension that uses them"},
		"reserved opcode":  {data: websocketFrameOf(true, 0, 3, nil, []byte("x")), context: websocketDown, expected: "websocket: opcode 3 is reserved"},
		"fragmented ping":  {data: websocketFrameOf(false, 0, pingOpcode, nil, nil), context: websocketDown, expected: "websocket: a control frame is not fragmented and has at most 125 bytes"},
		"lone continue":    {data: websocketFrameOf(true, 0, continuationOpcode, nil, []byte("x")), context: websocketDown, expected: "websocket: a continuation frame without the start of a message in this read"},
		"message in a row": {data: join(websocketFrameOf(false, 0, textOpcode, nil, []byte("a")), websocketFrameOf(true, 0, textOpcode, nil, []byte("b"))), context: websocketDown, expected: "websocket: a new message before the end of the one before it"},
		"short close":      {data: websocketFrameOf(true, 0, closeOpcode, nil, []byte{3}), context: websocketDown, expected: "websocket: a close payload of 1 byte, the status code has 2"},
		"not UTF-8":        {data: websocketFrameOf(true, 0, textOpcode, nil, []byte{'a', 0xff}), context: websocketDown, expected: "websocket: a text message is not UTF-8"},
		"unmasked client":  {data: websocketFrameOf(true, 0, textOpcode, nil, []byte("x")), context: websocketUp, expected: "websocket: a frame of the client is not masked"},
		"masked server":    {data: websocketFrameOf(true, 0, textOpcode, testMask, []byte("x")), context: websocketDown, expected: "websocket: a frame of the server is masked"},
		"no inflate":       {data: websocketFrameOf(true, rsv1Bit, textOpcode, nil, []byte{0xff, 0xff, 0xff}), context: websocketDeflate, expected: ""},
		"bomb":             {data: websocketFrameOf(true, rsv1Bit, binaryOpcode, nil, bomb), context: websocketDeflate, expected: "websocket.payload.inflated: could not inflate the message alone: it inflates to more than 1048576 bytes; it may use the window of earlier messages (context takeover)"},
	}

	for name, testCase := range testCases {
		result := mustDecode(state, testCase.data, testCase.context, "")
		errors := errorsOf(result.Tree)

		if (result.Protocol != websocketProtocol) || (result.Error != "") || (len(errors) == 0) || ((testCase.expected != "") && (errors[0] != testCase.expected)) {
			state.Errorf("Test of decode.Decode failed, %s should fail with %q, protocol: %s, errors: %v", name, testCase.expected, result.Protocol, errors)
		}
	}
}

// Fuzz if decode.Decode never fails on any bytes as WebSocket each way, with permessage-deflate and as an HTTP/2 body: no error and a tree inside the bytes
// with printable strings only.
func FuzzWebSocket(fuzz *testing.F) {
	fuzz.Add(websocketFrameOf(true, 0, textOpcode, testMask, []byte("hello")))
	fuzz.Add(join([]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"), websocketFrameOf(true, 0, closeOpcode, nil, join(be16(1000), []byte("bye")))))
	fuzz.Add(join(websocketFrameOf(false, 0, textOpcode, testMask, []byte("hel")), websocketFrameOf(true, 0, pingOpcode, testMask, nil), websocketFrameOf(true, 0, continuationOpcode, testMask, []byte("lo"))))
	fuzz.Add(websocketFrameOf(true, rsv1Bit, textOpcode, nil, deflated(fuzz, []byte("hello hello hello"))))
	fuzz.Add(websocketFrameOf(true, 0, binaryOpcode, nil, protobufSample()))
	fuzz.Add(websocketFrameOf(true, 0, binaryOpcode, testMask, bytes.Repeat([]byte{1}, 300)))

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		for _, context := range []Context{websocketUp, websocketDown, websocketDeflate, websocketBody} {
			result, err := Decode(data, context, "")

			if err != nil {
				state.Fatalf("Fuzz of decode.Decode failed, it should take any bytes, error: %s", err.Error())
			}

			if problems := shapeErrors(result.Tree, 0, result.Length); (len(problems) > 0) || (result.Error != "") {
				state.Fatalf("Fuzz of decode.Decode failed, the tree should fit its bytes, problems: %v, error: %s", problems, result.Error)
			}
		}
	})
}
