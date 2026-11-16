// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"fmt"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/decerter/decerter/internal/output"
)

// the bytes are the source's own from base on
func at(base int) (place placement) {
	place = placement{base: base, segments: nil, isFixed: false, fixedOffset: 0, fixedLength: 0}
	return
}

// every node spans these source bytes: the bytes a decoder reads are not in the source, they were inflated from these
func fixed(offset int, length int) (place placement) {
	place = placement{base: 0, segments: nil, isFixed: true, fixedOffset: offset, fixedLength: length}
	return
}

// the bytes are pieces of the source put together, in the order of segments
func pieces(segments []segment) (place placement) {
	place = placement{base: 0, segments: segments, isFixed: false, fixedOffset: 0, fixedLength: 0}
	return
}

// the place of the bytes from offset on, for a decoder that reads data[offset:]
func (place placement) from(offset int) (moved placement) {
	moved = place

	switch {
	case place.isFixed:
	case place.segments == nil:
		moved.base += offset
	default:
		moved.segments = make([]segment, len(place.segments))

		for index, piece := range place.segments {
			moved.segments[index] = segment{from: piece.from - offset, at: piece.at, length: piece.length}
		}
	}

	return
}

// the source bytes of the bytes offset..offset+length: a range over pieces runs from the first byte's place to the last's, the bytes between them included
func (place placement) span(offset int, length int) (start int, size int) {
	switch {
	case place.isFixed:
		start, size = place.fixedOffset, place.fixedLength
	case place.segments == nil:
		start, size = place.base+offset, length
	default:
		start = place.sourceOf(offset)
		size = 0

		if length > 0 {
			size = place.sourceOf(offset+length-1) + 1 - start
		}
	}

	return
}

// the source offset of one byte of pieces; a byte past the last piece is where the last piece ends
func (place placement) sourceOf(offset int) (source int) {
	index, _ := slices.BinarySearchFunc(place.segments, offset, func(piece segment, target int) int {
		if target < piece.from {
			return 1
		}

		if target >= piece.from+piece.length {
			return -1
		}

		return 0
	})

	switch {
	case index < len(place.segments):
		piece := place.segments[index]
		source = piece.at + max(0, offset-piece.from)
	case len(place.segments) > 0:
		last := place.segments[len(place.segments)-1]
		source = last.at + last.length
	}

	return
}

// a node of bytes a decoder reads, placed into the source
func (tree *Tree) addAt(parent *node, place placement, name string, label string, value string, offset int, length int) (child *node) {
	start, size := place.span(offset, length)
	child = tree.add(parent, name, label, value, start, size)
	return
}

// addAt for a field smaller than its bytes; a fixed place has no bits of its own
func (tree *Tree) addBitsAt(parent *node, place placement, name string, label string, value string, offset int, length int, mask uint32) (child *node) {
	if place.isFixed {
		child = tree.addAt(parent, place, name, label, value, offset, length)
		return
	}

	start, size := place.span(offset, length)
	child = tree.addBits(parent, name, label, value, start, size, mask)
	return
}

// the fields of data from offset to end under parent
func newCursor(tree *Tree, parent *node, data []byte, offset int, end int, place placement) (reader *cursor) {
	reader = &cursor{tree: tree, parent: parent, data: data, offset: offset, end: min(end, len(data)), place: place, isShort: false}
	return
}

// the fields of count bytes from the next one on under parent, as a cursor of their own; the bytes are taken from this one
func (reader *cursor) vector(parent *node, label string, count int) (inner *cursor) {
	_, start, ok := reader.take(label, count)

	if !ok {
		start, count = reader.offset, 0
	}

	inner = newCursor(reader.tree, parent, reader.data, start, start+count, reader.place)
	return
}

// count bytes from the next one on; when they do not fit the parent gets an error, once
func (reader *cursor) take(label string, count int) (data []byte, start int, ok bool) {
	start = reader.offset

	if reader.isShort {
		return
	}

	if (count < 0) || (reader.offset+count > reader.end) {
		reader.isShort = true
		reader.tree.fail(reader.parent, fmt.Sprintf("%s: %s, %d bytes of %d", label, errFieldShort.Error(), max(0, reader.end-reader.offset), count))
		return
	}

	data = reader.data[reader.offset : reader.offset+count]
	reader.offset += count
	ok = true
	return
}

func (reader *cursor) left() (count int) {
	count = max(0, reader.end-reader.offset)
	return
}

func (reader *cursor) add(name string, label string, value string, start int, length int) (child *node) {
	child = reader.tree.addAt(reader.parent, reader.place, name, label, value, start, length)
	return
}

// an unsigned big-endian integer of size bytes (1 to 4), its node shows it by format, in decimal for nil
func (reader *cursor) number(name string, label string, size int, format func(value uint32) (text string)) (value uint32, ok bool) {
	data, start, ok := reader.take(label, size)

	if !ok {
		return
	}

	for _, part := range data {
		value = value<<8 | uint32(part)
	}

	reader.add(name, label, formatted(value, format), start, size)
	return
}

func formatted(value uint32, format func(value uint32) (text string)) (text string) {
	if format == nil {
		text = strconv.FormatUint(uint64(value), 10)
		return
	}

	text = format(value)
	return
}

// a value by its name in table with the number: A (1)
func named(table nameTable) (format func(value uint32) (text string)) {
	format = func(value uint32) (text string) {
		text = nameOf(table, uint16(value))
		return
	}
	return
}

// a value by its name in table with the number in hex: TLS_AES_128_GCM_SHA256 (0x1301)
func hexNamed(table nameTable) (format func(value uint32) (text string)) {
	format = func(value uint32) (text string) {
		text = hexNameOf(table, uint16(value))
		return
	}
	return
}

// a vector of itemSize-byte values with a length of lengthSize bytes, each value a node shown by format; values are the values in order
func (reader *cursor) list(name string, label string, itemName string, itemLabel string, lengthSize int, itemSize int, format func(value uint32) (text string)) (values []uint32, listNode *node) {
	length, lengthStart, ok := reader.lengthOf(label, lengthSize)

	if !ok {
		listNode = reader.tree.sink
		return
	}

	// a length past the end fails the list in vector, the node keeps to the bytes that are there
	listNode = reader.add(name, label, strconv.Itoa(length/itemSize), lengthStart, lengthSize+min(length, reader.left()))
	inner := reader.vector(listNode, label, length)

	if length%itemSize != 0 {
		reader.tree.fail(listNode, fmt.Sprintf("a list of %d-byte values of %d bytes", itemSize, length))
	}

	for inner.left() >= itemSize {
		value, _ := inner.number(itemName, itemLabel, itemSize, format)
		values = append(values, value)
	}

	return
}

// the length field of a vector, lengthSize bytes, not a node of its own
func (reader *cursor) lengthOf(label string, lengthSize int) (length int, start int, ok bool) {
	data, start, ok := reader.take(label+" length", lengthSize)

	for _, part := range data {
		length = length<<8 | int(part)
	}

	return
}

// a vector of bytes with a length of lengthSize bytes as one node, its bytes as hex; the node spans the length too
func (reader *cursor) opaque(name string, label string, lengthSize int) (data []byte, ok bool) {
	length, start, ok := reader.lengthOf(label, lengthSize)

	if !ok {
		return
	}

	data, _, ok = reader.take(label, length)

	if !ok {
		return
	}

	reader.add(name, label, hexValue(data), start, lengthSize+length)
	return
}

// bytes the fields do not use
func (reader *cursor) finish() {
	if !reader.isShort && (reader.offset < reader.end) {
		reader.tree.fail(reader.parent, fmt.Sprintf("%d bytes after the last field", reader.end-reader.offset))
	}
}

// text from the traffic as a quoted value, escaped, at most maxTextBytes of it
func textValue(data []byte) (value string) {
	value = `"` + output.Escape(data[:min(len(data), maxTextBytes)]) + `"`

	if len(data) > maxTextBytes {
		value += fmt.Sprintf("... (%d bytes)", len(data))
	}

	return
}

// text a person would read: UTF-8 without control characters but tab, line feed and carriage return
func isText(data []byte) (isReadable bool) {
	if !utf8.Valid(data) {
		return
	}

	for _, value := range data {
		if ((value < ' ') && (value != '\t') && (value != '\n') && (value != '\r')) || (value == 0x7f) {
			return
		}
	}

	isReadable = true
	return
}

// the decoder of data among the registry but except by its sniff score from minimum on, the best one; its roots go under parent placed by place
// protocol is empty when none scores enough; the nested context is a datagram of the outer one's direction
func decodeNested(tree *Tree, parent *node, data []byte, place placement, context Context, except string, minimum int) (protocol string, summary []string) {
	nested := Context{Transport: DatagramTransport, Layer: "", Direction: context.Direction, ServerPort: 0, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	best, bestScore := decoder{}, 0

	for _, known := range registry {
		if (known.Protocol == except) || (known.Protocol == websocketProtocol) {
			continue
		}

		if score := known.sniff(data, nested); (score >= minimum) && (score > bestScore) {
			best, bestScore = known, score
		}
	}

	if bestScore == 0 {
		return
	}

	inner := tree.nested()
	best.decode(inner, data, nested)
	graft(tree, parent, inner.roots, place)
	tree.adopt(inner)
	protocol, summary = best.Protocol, inner.summary
	return
}

// nodes of another tree under parent, their offsets placed by place; the limits of this tree hold
func graft(tree *Tree, parent *node, nodes []*node, place placement) {
	for _, current := range nodes {
		start, size := place.span(current.offset, current.length)
		child := tree.add(parent, current.name, current.label, current.value, start, size)

		if child == tree.sink {
			return
		}

		if current.err != "" {
			tree.fail(child, current.err)
		}

		if !place.isFixed {
			child.mask = current.mask
		}

		graft(tree, child, current.children, place)
	}
}
