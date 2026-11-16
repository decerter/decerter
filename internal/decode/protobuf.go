// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"encoding/binary"
	"fmt"
	"math"
	"mime"
	"strconv"
)

// Protocol Buffers without a schema, like protoc --decode_raw, from the encoding guide (protobuf.dev/programming-guides/encoding): each field is a varint tag
// (field number << 3 | wire type) and a value: a varint, 8 or 4 bytes, a varint length and that many bytes, or the start and end of a group
// a length-delimited value is a nested message when it reads as one to its end, a string when it is text, bytes otherwise; text that starts with a
// printable byte is taken as a string before it is tried as a message, a message's first tag byte is mostly a control character
const (
	protobufProtocol string = "protobuf"
	protobufTitle    string = "Protocol Buffers"
	// the nested messages and groups one decode follows, deeper ones are shown as bytes
	maxProtobufDepth int = 10
	// the largest field number (2^29 - 1)
	maxFieldNumber uint64 = 1<<29 - 1
	// sniffing alone never takes protobuf: bytes that read cleanly score below the threshold, a content type or as= takes them
	protobufCleanScore   int = 30
	protobufPartialScore int = 5
)

// the wire types of a tag
const (
	varintWireType     uint64 = 0
	fixed64WireType    uint64 = 1
	lengthWireType     uint64 = 2
	startGroupWireType uint64 = 3
	endGroupWireType   uint64 = 4
	fixed32WireType    uint64 = 5
)

var (
	protobufMediaTypes = []string{"application/x-protobuf", "application/protobuf", "application/x-google-protobuf", "application/vnd.google.protobuf"}
	wireTypeNames      = map[uint64]string{varintWireType: "VARINT", fixed64WireType: "I64", lengthWireType: "LEN", startGroupWireType: "SGROUP", endGroupWireType: "EGROUP", fixed32WireType: "I32"}
)

func init() {
	register(decoder{
		Protocol:   protobufProtocol,
		Title:      protobufTitle,
		Ports:      nil,
		hint:       protobufHint,
		sniff:      protobufSniff,
		decode:     protobufDecode,
		fromTarget: nil,
	})
}

func protobufHint(context Context) (reason string) {
	if context.Transport != BodyTransport {
		return
	}

	mediaType, _, parseErr := mime.ParseMediaType(context.ContentType)

	for _, known := range protobufMediaTypes {
		if (parseErr == nil) && (mediaType == known) {
			reason = "content type " + known + " is Protocol Buffers"
			return
		}
	}

	return
}

// bytes that read as a message to their end, at least one field; a message that breaks after its first field gets a little, so a content type still takes it
func protobufSniff(data []byte, context Context) (score int) {
	fields, isClean := protobufScan(data, 0)

	switch {
	case isClean && (fields > 0):
		score = protobufCleanScore
	case fields > 0:
		score = protobufPartialScore
	}

	return
}

func protobufDecode(tree *Tree, data []byte, context Context) {
	root := tree.add(nil, protobufProtocol, protobufTitle, "", 0, len(data))
	count := protobufMessage(tree, root, data, at(0), 0)
	root.value = fieldCount(count)
	tree.addSummary(fmt.Sprintf("Protocol Buffers message, %s, %d bytes", fieldCount(count), len(data)))
}

func fieldCount(count int) (text string) {
	text = strconv.Itoa(count) + " fields"

	if count == 1 {
		text = "1 field"
	}

	return
}

// the fields of a message to its end under parent; count is how many were read, an error on parent says where it broke
func protobufMessage(tree *Tree, parent *node, data []byte, place placement, depth int) (count int) {
	_, count = protobufFields(tree, parent, data, 0, place, depth, 0)
	return
}

// fields from offset on until the end of data, or until the end of the group of field number group (0 for none); next is after the last field read
func protobufFields(tree *Tree, parent *node, data []byte, offset int, place placement, depth int, group uint64) (next int, count int) {
	next = offset

	for (next < len(data)) && !tree.isFull {
		start := next
		tag, tagLength := binary.Uvarint(data[next:])

		if tagLength <= 0 {
			tree.fail(parent, fmt.Sprintf("a tag at byte %d does not read as a varint", start))
			return
		}

		number, wireType := tag>>3, tag&7
		next += tagLength

		if wireType == endGroupWireType {
			field := tree.addAt(parent, place, "protobuf.field", fmt.Sprintf("End of group %d", number), "", start, tagLength)
			protobufTag(tree, field, place, start, tagLength, number, wireType)

			if number != group {
				tree.fail(field, fmt.Sprintf("the end of group %d where none is open", number))
			}

			return
		}

		field := tree.addAt(parent, place, "protobuf.field", fmt.Sprintf("Field %d (%s)", number, wireTypeName(wireType)), "", start, tagLength)
		protobufTag(tree, field, place, start, tagLength, number, wireType)
		count++

		if (number == 0) || (number > maxFieldNumber) {
			tree.fail(field, fmt.Sprintf("field number %d is outside 1 to %d", number, maxFieldNumber))
			return
		}

		isRead := false
		next, isRead = protobufValue(tree, field, data, next, place, depth, number, wireType)
		fieldStart, fieldLength := place.span(start, next-start)

		if field != tree.sink {
			field.offset, field.length = fieldStart, fieldLength
		}

		if !isRead {
			return
		}
	}

	if group != 0 {
		tree.fail(parent, fmt.Sprintf("group %d has no end", group))
	}

	return
}

// the field number and the wire type of a tag, the wire type is the low 3 bits of its first byte
func protobufTag(tree *Tree, field *node, place placement, start int, length int, number uint64, wireType uint64) {
	tree.addAt(field, place, "protobuf.field.number", "Field number", strconv.FormatUint(number, 10), start, length)

	if length <= 4 {
		tree.addBitsAt(field, place, "protobuf.field.wiretype", "Wire type", fmt.Sprintf("%s (%d)", wireTypeName(wireType), wireType), start, length, 0x07<<(8*(length-1)))
		return
	}

	tree.addAt(field, place, "protobuf.field.wiretype", "Wire type", fmt.Sprintf("%s (%d)", wireTypeName(wireType), wireType), start, length)
}

func wireTypeName(wireType uint64) (name string) {
	name, isKnown := wireTypeNames[wireType]

	if !isKnown {
		name = "invalid"
	}

	return
}

// the value after a tag; isRead is false when the field broke, the error is on field
func protobufValue(tree *Tree, field *node, data []byte, offset int, place placement, depth int, number uint64, wireType uint64) (next int, isRead bool) {
	next = offset

	switch wireType {
	case varintWireType:
		value, length := binary.Uvarint(data[offset:])

		if length <= 0 {
			tree.fail(field, "the varint runs past the end of the message or is longer than 10 bytes")
			return
		}

		field.value = strconv.FormatUint(value, 10)
		tree.addAt(field, place, "protobuf.field.varint", "Value", field.value, offset, length)

		if int64(value) < 0 {
			tree.addAt(field, place, "protobuf.field.int64", "As int64", strconv.FormatInt(int64(value), 10), offset, length)
		}

		tree.addAt(field, place, "protobuf.field.sint", "As sint (zigzag)", strconv.FormatInt(int64(value>>1)^-int64(value&1), 10), offset, length)

		if value <= 1 {
			tree.addAt(field, place, "protobuf.field.bool", "As bool", strconv.FormatBool(value == 1), offset, length)
		}

		next = offset + length
	case fixed64WireType:
		if len(data)-offset < 8 {
			tree.fail(field, fmt.Sprintf("an I64 value has 8 bytes, %d are left", len(data)-offset))
			return
		}

		value := binary.LittleEndian.Uint64(data[offset:])
		field.value = strconv.FormatUint(value, 10)
		tree.addAt(field, place, "protobuf.field.fixed64", "Value", field.value, offset, 8)

		if int64(value) < 0 {
			tree.addAt(field, place, "protobuf.field.sfixed64", "As sfixed64", strconv.FormatInt(int64(value), 10), offset, 8)
		}

		tree.addAt(field, place, "protobuf.field.double", "As double", strconv.FormatFloat(math.Float64frombits(value), 'g', -1, 64), offset, 8)
		next = offset + 8
	case fixed32WireType:
		if len(data)-offset < 4 {
			tree.fail(field, fmt.Sprintf("an I32 value has 4 bytes, %d are left", len(data)-offset))
			return
		}

		value := binary.LittleEndian.Uint32(data[offset:])
		field.value = strconv.FormatUint(uint64(value), 10)
		tree.addAt(field, place, "protobuf.field.fixed32", "Value", field.value, offset, 4)

		if int32(value) < 0 {
			tree.addAt(field, place, "protobuf.field.sfixed32", "As sfixed32", strconv.FormatInt(int64(int32(value)), 10), offset, 4)
		}

		tree.addAt(field, place, "protobuf.field.float", "As float", strconv.FormatFloat(float64(math.Float32frombits(value)), 'g', -1, 32), offset, 4)
		next = offset + 4
	case lengthWireType:
		length, lengthSize := binary.Uvarint(data[offset:])

		if lengthSize <= 0 {
			tree.fail(field, "the length runs past the end of the message or is longer than 10 bytes")
			return
		}

		tree.addAt(field, place, "protobuf.field.length", "Length", strconv.FormatUint(length, 10), offset, lengthSize)
		start := offset + lengthSize

		if length > uint64(len(data)-start) {
			next = start
			tree.fail(field, fmt.Sprintf("the value of %d bytes runs past the end of the message, %d are left", length, len(data)-start))
			return
		}

		protobufBytes(tree, field, data[start:start+int(length)], place.from(start), depth)
		next = start + int(length)
	case startGroupWireType:
		if depth >= maxProtobufDepth {
			tree.fail(field, fmt.Sprintf("groups and messages nest deeper than %d levels", maxProtobufDepth))
			return
		}

		count := 0
		next, count = protobufFields(tree, field, data, offset, place, depth+1, number)
		field.value = fieldCount(count)
	default:
		tree.fail(field, fmt.Sprintf("wire type %d is not one of protobuf's", wireType))
		return
	}

	isRead = true
	return
}

// a length-delimited value: text first when it starts readable, then a message when it reads as one to its end, then text, else bytes
func protobufBytes(tree *Tree, field *node, data []byte, place placement, depth int) {
	isReadable := isText(data)
	isStringFirst := isReadable && (len(data) > 0) && (data[0] >= ' ')

	if !isStringFirst && (len(data) > 0) && (depth < maxProtobufDepth) {
		if fields, isClean := protobufScan(data, depth+1); isClean && (fields > 0) {
			message := tree.addAt(field, place, "protobuf.message", "Message", fieldCount(fields), 0, len(data))
			protobufMessage(tree, message, data, place, depth+1)
			field.value = "message, " + fieldCount(fields)
			return
		}
	}

	if isReadable {
		field.value = textValue(data)
		tree.addAt(field, place, "protobuf.field.string", "String", field.value, 0, len(data))
		return
	}

	field.value = hexValue(data)
	tree.addAt(field, place, "protobuf.field.bytes", "Bytes", field.value, 0, len(data))
}

// whether data is a message to its end without building nodes: fields counts its top-level fields, groups closed in order; depth is that of data
func protobufScan(data []byte, depth int) (fields int, isClean bool) {
	open := []uint64{}

	for offset := 0; offset < len(data); {
		tag, tagLength := binary.Uvarint(data[offset:])

		if tagLength <= 0 {
			return
		}

		number, wireType := tag>>3, tag&7
		offset += tagLength

		if (number == 0) || (number > maxFieldNumber) {
			return
		}

		if len(open) == 0 {
			fields++
		}

		switch wireType {
		case varintWireType:
			_, length := binary.Uvarint(data[offset:])

			if length <= 0 {
				return
			}

			offset += length
		case fixed64WireType, fixed32WireType:
			size := map[uint64]int{fixed64WireType: 8, fixed32WireType: 4}[wireType]

			if len(data)-offset < size {
				return
			}

			offset += size
		case lengthWireType:
			length, lengthSize := binary.Uvarint(data[offset:])

			if (lengthSize <= 0) || (length > uint64(len(data)-offset-lengthSize)) {
				return
			}

			offset += lengthSize + int(length)
		case startGroupWireType:
			if depth+len(open) >= maxProtobufDepth {
				return
			}

			open = append(open, number)
		case endGroupWireType:
			if (len(open) == 0) || (open[len(open)-1] != number) {
				return
			}

			open = open[:len(open)-1]
		default:
			return
		}
	}

	isClean = len(open) == 0
	return
}
