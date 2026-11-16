// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"bytes"
	"compress/gzip"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	v1 "github.com/decerter/decerter/api"
)

// a length-prefixed message of gRPC with these flags
func grpcFrame(flags byte, message []byte) (data []byte) {
	data = join([]byte{flags}, be32(uint32(len(message))), message)
	return
}

// a protobuf message with field 1 the text
func echoMessage(text string) (data []byte) {
	data = protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), text)
	return
}

func gzipped(state testing.TB, data []byte) (compressed []byte) {
	buffer := bytes.Buffer{}
	writer := gzip.NewWriter(&buffer)
	_, err := writer.Write(data)

	if err == nil {
		err = writer.Close()
	}

	if err != nil {
		state.Fatalf("Could not gzip the message, error: %s", err.Error())
	}

	compressed = buffer.Bytes()
	return
}

// Test if decode.Decode returns with the expected output for gRPC: several messages of one body with their protobuf fields at body offsets, an empty message, a
// gzip message by its grpc-encoding, a response, gRPC-Web with trailers, a +json codec, and a body without a content type sniffed as gRPC.
func TestGRPCPositive(state *testing.T) {
	body := join(grpcFrame(0, echoMessage("hello")), grpcFrame(0, nil), grpcFrame(0, echoMessage("world")))
	result := mustDecode(state, body, bodyContext("application/grpc"), "")
	texts := findAll(result.Tree, "protobuf.field.string")

	if (result.Protocol != grpcProtocol) || (len(result.Tree) != 3) || (result.Summary != "gRPC request /decerter.Echo/Say, 3 messages") || (result.Candidates[0].Reason != "content type application/grpc is gRPC") ||
		(len(texts) != 2) || (texts[1].Value != `"world"`) || (texts[1].Offset != 24) || (len(errorsOf(result.Tree)) > 0) {
		state.Fatalf("Test of decode.Decode failed, the body should be three gRPC messages, result: %+v", result)
	}

	checkValues(state, "decode.Decode", result, map[string]string{"grpc.compressed#0": "no", "grpc.length#0": "7", "grpc.length#1": "0", "protobuf.field.string#0": `"hello"`})

	context := bodyContext("application/grpc+proto")
	context.Direction, context.Encoding = v1.DownDirection, "gzip"
	result = mustDecode(state, grpcFrame(1, gzipped(state, echoMessage("packed"))), context, "")
	text := findNode(result.Tree, "protobuf.field.string")

	if (result.Protocol != grpcProtocol) || (result.Summary != "gRPC response, 1 message") || (text == nil) || (text.Value != `"packed"`) || (text.Offset != 5) || (findNode(result.Tree, "grpc.compressed").Value != "yes") {
		state.Errorf("Test of decode.Decode failed, the gzip message should be inflated with its fields over the compressed bytes, result: %+v", result)
	}

	web := join(grpcFrame(0, echoMessage("hi")), grpcFrame(0x80, []byte("grpc-status: 0\r\ngrpc-message: OK\r\n")))
	context = bodyContext("application/grpc-web+proto")
	context.Direction = v1.DownDirection
	result = mustDecode(state, web, context, "")
	trailers := findAll(result.Tree, "grpc.trailer")

	if (result.Summary != "gRPC-Web response, 1 message and trailers") || (len(trailers) != 2) || (trailers[0].Label != "grpc-status") || (trailers[0].Value != "0") || (trailers[1].Value != "OK") || (result.Tree[1].Label != "gRPC-Web trailers") {
		state.Errorf("Test of decode.Decode failed, gRPC-Web should have its trailers, result: %+v", result)
	}

	result = mustDecode(state, grpcFrame(0, []byte(`{"text":"hi"}`)), bodyContext("application/grpc+json"), "")

	if data := findNode(result.Tree, "grpc.message_data"); (data == nil) || (data.Label != "Message (json)") || (data.Value != `"{"text":"hi"}"`) {
		state.Errorf("Test of decode.Decode failed, a +json message should be text, result: %+v", result)
	}

	sniffed := bodyContext("")
	sniffed.Target = ""

	if result = mustDecode(state, body, sniffed, ""); (result.Protocol != grpcProtocol) || (result.Candidates[0].Basis != v1.SniffDecodeBasis) || (result.Summary != "gRPC request, 3 messages") {
		state.Errorf("Test of decode.Decode failed, prefixed messages without a content type should sniff as gRPC, result: %+v", result)
	}

	if result = mustDecode(state, body, bodyContext("application/grpc-web-text"), ""); result.Protocol == grpcProtocol && (result.Candidates[0].Basis == v1.ContextDecodeBasis) {
		state.Errorf("Test of decode.Decode failed, grpc-web-text is base64 and its content type should not take gRPC, result: %+v", result)
	}
}

// Test if decode.Decode returns with the expected errors for gRPC: a prefix or a message cut short, reserved flag bits, a compression decerter does not inflate and gzip
// that does not inflate are trees with errors on the message, not failed decodes.
func TestGRPCNegative(state *testing.T) {
	gzipContext := bodyContext("application/grpc")
	gzipContext.Encoding = "gzip"
	testCases := map[string]struct {
		data     []byte
		context  Context
		expected string
	}{
		"short prefix":  {data: join(grpcFrame(0, nil), []byte{0, 0}), context: bodyContext("application/grpc"), expected: "grpc: the 5-byte prefix of a message is cut short, 2 bytes are here"},
		"short message": {data: join([]byte{0}, be32(10), []byte("abc")), context: bodyContext("application/grpc"), expected: "grpc: the message runs past the end of the body: 3 of its 10 bytes are here"},
		"reserved bits": {data: grpcFrame(0x04, nil), context: bodyContext("application/grpc"), expected: "grpc: reserved flag bits 0x04 are set"},
		"snappy":        {data: grpcFrame(1, []byte{1, 2}), context: bodyContext("application/grpc"), expected: `grpc.message_data: compressed with grpc-encoding "", decerter inflates gzip only`},
		"broken gzip":   {data: grpcFrame(1, []byte{0x1f, 0x8b, 8, 0, 0}), context: gzipContext, expected: "grpc.message_data: could not inflate it: unexpected EOF"},
	}

	for name, testCase := range testCases {
		result := mustDecode(state, testCase.data, testCase.context, "")
		errors := errorsOf(result.Tree)

		if (result.Protocol != grpcProtocol) || (result.Error != "") || (len(errors) == 0) || (errors[0] != testCase.expected) {
			state.Errorf("Test of decode.Decode failed, %s should fail with %q, errors: %v, tree: %+v", name, testCase.expected, errors, result.Tree)
		}
	}

	// gzip that inflates past the cap
	bomb := gzipped(state, make([]byte, maxInflatedBytes+1))

	if errors := errorsOf(mustDecode(state, grpcFrame(1, bomb), gzipContext, "").Tree); (len(errors) == 0) || (errors[0] != "grpc.message_data: could not inflate it: it inflates to more than 1048576 bytes") {
		state.Errorf("Test of decode.Decode failed, gzip should inflate at most %d bytes, errors: %v", maxInflatedBytes, errors)
	}

	// not a body: never gRPC by sniffing
	if result := mustDecode(state, grpcFrame(0, echoMessage("x")), tcpContext, ""); result.Protocol == grpcProtocol {
		state.Errorf("Test of decode.Decode failed, a tcp payload should not sniff as gRPC, result: %+v", result)
	}
}

// Fuzz if decode.Decode never fails on any bytes as gRPC and gRPC-Web, gzip or not: no error and a tree inside the bytes with printable strings; the messages a
// body splits into cover it to its end.
func FuzzGRPC(fuzz *testing.F) {
	fuzz.Add(join(grpcFrame(0, echoMessage("hello")), grpcFrame(0, nil)))
	fuzz.Add(grpcFrame(1, gzipped(fuzz, echoMessage("packed"))))
	fuzz.Add(join(grpcFrame(0, echoMessage("hi")), grpcFrame(0x80, []byte("grpc-status: 0\r\n"))))
	fuzz.Add(join([]byte{0}, be32(10), []byte("abc")))
	fuzz.Add(bytes.Repeat(grpcFrame(1, gzipped(fuzz, make([]byte, 1<<16))), 3))
	gzipContext := bodyContext("application/grpc")
	gzipContext.Encoding = "gzip"
	contexts := []Context{bodyContext("application/grpc"), bodyContext("application/grpc-web"), bodyContext("application/grpc+json"), gzipContext}

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		for _, context := range contexts {
			result, err := Decode(data, context, grpcProtocol)

			if err != nil {
				state.Fatalf("Fuzz of decode.Decode failed, it should take any bytes, error: %s", err.Error())
			}

			if problems := resultProblems(result); len(problems) > 0 {
				state.Fatalf("Fuzz of decode.Decode failed, the tree should fit its bytes, problems: %v", problems)
			}

			if result.Truncated || (len(data) == 0) {
				continue
			}

			end := 0

			for _, message := range result.Tree {
				if message.Offset != end {
					state.Fatalf("Fuzz of decode.Decode failed, message at %d should start at %d", message.Offset, end)
				}

				end = message.Offset + message.Length
			}

			if end != len(data) {
				state.Fatalf("Fuzz of decode.Decode failed, the messages end at %d of %d bytes", end, len(data))
			}
		}
	})
}
