// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
)

// the fields the decoders of stage 50 share on top of the cursor: wide numbers, addresses, bytes and text of a fixed size

// a cursor over data[start:end] whose offsets are the source's own
func fieldsOf(tree *Tree, parent *node, data []byte, start int, end int) (reader *cursor) {
	reader = newCursor(tree, parent, data, start, end, at(0))
	return
}

// a big-endian number of 8 bytes, shown by format or in decimal
func (reader *cursor) number64(name string, label string, format func(value uint64) (text string)) (value uint64, ok bool) {
	data, start, ok := reader.take(label, 8)

	if !ok {
		return
	}

	value = binary.BigEndian.Uint64(data)
	text := strconv.FormatUint(value, 10)

	if format != nil {
		text = format(value)
	}

	reader.add(name, label, text, start, 8)
	return
}

// an IPv4 (4 bytes) or IPv6 (16 bytes) address
func (reader *cursor) address(name string, label string, size int) (address netip.Addr, ok bool) {
	data, start, ok := reader.take(label, size)

	if !ok {
		return
	}

	address, _ = netip.AddrFromSlice(data)
	reader.add(name, label, address.String(), start, size)
	return
}

// count bytes as hex
func (reader *cursor) bytesField(name string, label string, count int) (data []byte, ok bool) {
	data, start, ok := reader.take(label, count)

	if ok {
		reader.add(name, label, hexValue(data), start, count)
	}

	return
}

// count bytes of text from the traffic, quoted and escaped
func (reader *cursor) textField(name string, label string, count int) (data []byte, ok bool) {
	data, start, ok := reader.take(label, count)

	if ok {
		reader.add(name, label, textValue(data), start, count)
	}

	return
}

// the bytes left as one node: text when they read as text, else hex
func (reader *cursor) restField(name string, label string) (data []byte) {
	count := reader.left()

	if count == 0 {
		return
	}

	data, start, _ := reader.take(label, count)

	if isText(data) {
		reader.add(name, label, textValue(data), start, count)
		return
	}

	reader.add(name, label, hexValue(data), start, count)
	return
}

// a number shown with its name: Binding Request (0x0001)
func hexNumber(table nameTable, width int) (format func(value uint32) (text string)) {
	format = func(value uint32) (text string) {
		text = fmt.Sprintf("%s (0x%0*x)", shortName(table, uint16(value)), width, value)
		return
	}
	return
}

// text up to a zero byte, the zero byte with it; without one the cursor is short
func (reader *cursor) cString(name string, label string) (text []byte, ok bool) {
	end := bytes.IndexByte(reader.data[reader.offset:max(reader.offset, reader.end)], 0)

	if end < 0 {
		_, _, _ = reader.take(label+" (no zero byte ends it)", reader.left()+1)
		return
	}

	text, start, ok := reader.take(label, end+1)

	if ok {
		text = text[:end]
		reader.add(name, label, textValue(text), start, end+1)
	}

	return
}

// an unsigned little-endian integer of size bytes (1 to 8), its node shows it by format, in decimal for nil
func (reader *cursor) little(name string, label string, size int, format func(value uint64) (text string)) (value uint64, ok bool) {
	data, start, ok := reader.take(label, size)

	if !ok {
		return
	}

	for index := len(data) - 1; index >= 0; index-- {
		value = value<<8 | uint64(data[index])
	}

	text := strconv.FormatUint(value, 10)

	if format != nil {
		text = format(value)
	}

	reader.add(name, label, text, start, size)
	return
}
