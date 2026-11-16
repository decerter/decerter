// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"math"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	v1 "github.com/decerter/decerter/api"
)

// the context of a body with that content type
func bodyContext(contentType string) (context Context) {
	context = Context{Transport: BodyTransport, Layer: "", Direction: v1.UpDirection, ServerPort: 443, ALPN: "h2", ContentType: contentType, Upgrade: "", Method: "POST", Target: "/decerter.Echo/Say", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	return
}

// a message with every wire type: a varint, a string, a nested message, a double, a float, a negative int64, a zigzag value, a group and bytes
func protobufSample() (data []byte) {
	data = protowire.AppendTag(data, 1, protowire.VarintType)
	data = protowire.AppendVarint(data, 150)
	data = protowire.AppendTag(data, 2, protowire.BytesType)
	data = protowire.AppendString(data, "testing")
	data = protowire.AppendTag(data, 3, protowire.BytesType)
	data = protowire.AppendBytes(data, protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 1))
	data = protowire.AppendTag(data, 4, protowire.Fixed64Type)
	data = protowire.AppendFixed64(data, math.Float64bits(1.5))
	data = protowire.AppendTag(data, 5, protowire.Fixed32Type)
	data = protowire.AppendFixed32(data, math.Float32bits(2.5))
	data = protowire.AppendTag(data, 6, protowire.VarintType)
	data = protowire.AppendVarint(data, math.MaxUint64)
	data = protowire.AppendTag(data, 7, protowire.VarintType)
	data = protowire.AppendVarint(data, protowire.EncodeZigZag(-2))
	data = protowire.AppendTag(data, 8, protowire.StartGroupType)
	data = protowire.AppendTag(data, 1, protowire.VarintType)
	data = protowire.AppendVarint(data, 5)
	data = protowire.AppendTag(data, 8, protowire.EndGroupType)
	data = protowire.AppendTag(data, 9, protowire.BytesType)
	data = protowire.AppendBytes(data, []byte{0, 0xff, 0xfe})
	return
}

// Test if decode.Decode returns with the expected output for Protocol Buffers: each wire type with its readings, a nested message, a group, bytes, a field
// number of 5 tag bytes, taken by its content type and by as=protobuf, and a payload without a hint left raw since sniffing alone does not take protobuf.
func TestProtobufPositive(state *testing.T) {
	data := protobufSample()
	result := mustDecode(state, data, bodyContext("application/x-protobuf"), "")

	if (result.Protocol != protobufProtocol) || (result.Candidates[0].Basis != v1.ContextDecodeBasis) || (result.Summary != "Protocol Buffers message, 9 fields, 52 bytes") || (len(result.Tree[0].Children) != 9) || (len(errorsOf(result.Tree)) > 0) {
		state.Fatalf("Test of decode.Decode failed, the message should be protobuf by its content type, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "decode.Decode", result, map[string]string{
		"protobuf.field.number#0":   "1",
		"protobuf.field.wiretype#0": "VARINT (0)",
		"protobuf.field.varint#0":   "150",
		"protobuf.field.string#0":   `"testing"`,
		"protobuf.field.bool#0":     "true",
		"protobuf.field.double#0":   "1.5",
		"protobuf.field.float#0":    "2.5",
		"protobuf.field.varint#2":   "18446744073709551615",
		"protobuf.field.int64#0":    "-1",
		"protobuf.field.sint#3":     "-2",
		"protobuf.field.varint#4":   "5",
		"protobuf.field.bytes#0":    "00fffe",
	})
	nested := findNode(result.Tree, "protobuf.message")

	if (nested == nil) || (nested.Value != "1 field") || (nested.Offset != 14) || (nested.Length != 2) {
		state.Errorf("Test of decode.Decode failed, field 3 should be a nested message at byte 14, node: %+v", nested)
	}

	group := result.Tree[0].Children[7]

	if (group.Label != "Field 8 (SGROUP)") || (group.Value != "1 field") || (group.Length != 4) || (group.Children[len(group.Children)-1].Label != "End of group 8") {
		state.Errorf("Test of decode.Decode failed, field 8 should be a group of one field with its end, node: %+v", group)
	}

	wireType := findNode(result.Tree, "protobuf.field.wiretype")

	if (wireType.Mask != 0x07) || (wireType.Length != 1) {
		state.Errorf("Test of decode.Decode failed, the wire type should be the low 3 bits of the tag, node: %+v", wireType)
	}

	// a 5-byte tag has no mask, its wire type spans the tag
	large := protowire.AppendVarint(protowire.AppendTag(nil, protowire.MaxValidNumber, protowire.VarintType), 1)
	result = mustDecode(state, large, tcpContext, protobufProtocol)
	wireType = findNode(result.Tree, "protobuf.field.wiretype")

	if (result.Protocol != protobufProtocol) || (wireType == nil) || (wireType.Mask != 0) || (wireType.Length != 5) || (findNode(result.Tree, "protobuf.field.number").Value != "536870911") {
		state.Errorf("Test of decode.Decode failed, the largest field number should read with a 5-byte tag, result: %+v", result)
	}

	for _, contentType := range []string{"application/protobuf", "application/x-google-protobuf", "application/vnd.google.protobuf; proto=decerter.Echo"} {
		if result = mustDecode(state, data, bodyContext(contentType), ""); result.Protocol != protobufProtocol {
			state.Errorf("Test of decode.Decode failed, content type %s should be protobuf, result: %+v", contentType, result)
		}
	}

	// sniffing scores protobuf below the threshold
	if result = mustDecode(state, data, otherUDP, ""); (result.Protocol != RawProtocol) || (protobufSniff(data, otherUDP) != protobufCleanScore) {
		state.Errorf("Test of decode.Decode failed, a message without a hint should be raw, sniffed below the threshold, result: %+v", result)
	}

	// text that starts readable is a string even when it reads as a message
	text := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "hello")

	if result = mustDecode(state, text, otherUDP, protobufProtocol); findNode(result.Tree, "protobuf.field.string") == nil {
		state.Errorf("Test of decode.Decode failed, hello should be a string, tree: %+v", result.Tree)
	}
}

// Test if decode.Decode returns with the expected errors for Protocol Buffers: a broken message is a tree with an error on the field that broke, not a failed
// decode; a content type with bytes that are no message is raw; nested messages deeper than the cap are bytes.
func TestProtobufNegative(state *testing.T) {
	testCases := map[string]struct {
		data     []byte
		expected string
	}{
		"truncated varint":     {data: []byte{0x08, 0x96}, expected: "protobuf.field: the varint runs past the end of the message or is longer than 10 bytes"},
		"bad tag":              {data: []byte{0x08, 0x01, 0xff}, expected: "protobuf: a tag at byte 2 does not read as a varint"},
		"field zero":           {data: []byte{0x00, 0x01}, expected: "protobuf.field: field number 0 is outside 1 to 536870911"},
		"short fixed64":        {data: []byte{0x09, 1, 2, 3}, expected: "protobuf.field: an I64 value has 8 bytes, 3 are left"},
		"short fixed32":        {data: []byte{0x0d, 1}, expected: "protobuf.field: an I32 value has 4 bytes, 1 are left"},
		"long length":          {data: []byte{0x0a, 0x05, 'a'}, expected: "protobuf.field: the value of 5 bytes runs past the end of the message, 1 are left"},
		"bad length":           {data: []byte{0x0a, 0xff}, expected: "protobuf.field: the length runs past the end of the message or is longer than 10 bytes"},
		"wire type 6":          {data: []byte{0x0e, 0x01}, expected: "protobuf.field: wire type 6 is not one of protobuf's"},
		"open group":           {data: []byte{0x0b, 0x08, 0x01}, expected: "protobuf.field: group 1 has no end"},
		"stray end":            {data: []byte{0x0c}, expected: "protobuf.field: the end of group 1 where none is open"},
		"group end of another": {data: []byte{0x0b, 0x14}, expected: "protobuf.field: the end of group 2 where none is open"},
	}

	for name, testCase := range testCases {
		result := mustDecode(state, testCase.data, otherUDP, protobufProtocol)
		errors := errorsOf(result.Tree)

		if (result.Protocol != protobufProtocol) || (result.Error != "") || (len(errors) == 0) || (errors[len(errors)-1] != testCase.expected) {
			state.Errorf("Test of decode.Decode failed, %s should fail with %q, errors: %v, tree: %+v", name, testCase.expected, errors, result.Tree)
		}
	}

	if result := mustDecode(state, []byte{0xff, 0xff}, bodyContext("application/x-protobuf"), ""); result.Protocol != RawProtocol {
		state.Errorf("Test of decode.Decode failed, bytes that are no message should be raw despite the content type, result: %+v", result)
	}

	// 12 nested messages: the 11th level is bytes
	nested := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 1)

	for range 11 {
		nested = protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), nested)
	}

	result := mustDecode(state, nested, otherUDP, protobufProtocol)

	if messages := findAll(result.Tree, "protobuf.message"); (len(messages) != maxProtobufDepth) || (findNode(result.Tree, "protobuf.field.bytes") == nil) {
		state.Errorf("Test of decode.Decode failed, messages should nest %d levels, then be bytes, messages: %d", maxProtobufDepth, len(messages))
	}

	groups := []byte{}

	for range maxProtobufDepth + 1 {
		groups = protowire.AppendTag(groups, 1, protowire.StartGroupType)
	}

	if errors := errorsOf(mustDecode(state, groups, otherUDP, protobufProtocol).Tree); (len(errors) == 0) || (errors[len(errors)-1] != "protobuf.field: groups and messages nest deeper than 10 levels") {
		state.Errorf("Test of decode.Decode failed, groups should nest %d levels at most, errors: %v", maxProtobufDepth, errors)
	}
}

// Fuzz if decode.Decode never fails on any bytes as protobuf: no error, a tree inside the bytes with printable strings, and bytes protobuf's scan reads
// to their end are read the same by google.golang.org/protobuf/encoding/protowire (a test-only oracle): the same fields at the top, one node each.
func FuzzProtobuf(fuzz *testing.F) {
	fuzz.Add(protobufSample())
	fuzz.Add([]byte{0x0b, 0x08, 0x01, 0x0c})
	fuzz.Add([]byte{0x0a, 0x02, 0x08, 0x01, 0x12, 0x01, 'x'})
	fuzz.Add([]byte{0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01})
	fuzz.Add([]byte{0x0e})
	fuzz.Add(protowire.AppendVarint(protowire.AppendTag(nil, protowire.MaxValidNumber, protowire.VarintType), 1))

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		for _, context := range []Context{bodyContext("application/x-protobuf"), otherUDP} {
			result, err := Decode(data, context, protobufProtocol)

			if err != nil {
				state.Fatalf("Fuzz of decode.Decode failed, it should take any bytes, error: %s", err.Error())
			}

			if problems := shapeErrors(result.Tree, 0, result.Length); (len(problems) > 0) || (result.Error != "") {
				state.Fatalf("Fuzz of decode.Decode failed, the tree should fit its bytes, problems: %v, error: %s", problems, result.Error)
			}
		}

		fields, isClean := protobufScan(data, 0)

		if !isClean {
			return
		}

		count := 0

		for rest := data; len(rest) > 0; count++ {
			_, _, length := protowire.ConsumeField(rest)

			if length < 0 {
				state.Fatalf("Fuzz of protobufScan failed, protowire cannot read field %d: %v, data: %x", count, protowire.ParseError(length), data)
			}

			rest = rest[length:]
		}

		result, _ := Decode(data, otherUDP, protobufProtocol)

		if (count != fields) || (!result.Truncated && (len(findAll(result.Tree[:1], "protobuf")[0].Children) != fields)) {
			state.Fatalf("Fuzz of protobufScan failed, protowire reads %d fields, the scan %d, data: %x", count, fields, data)
		}
	})
}
