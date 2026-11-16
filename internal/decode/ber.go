// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// a walker for ASN.1 BER and DER from ITU-T X.690: the identifier with its class, constructed bit and tag number (high tag numbers too), the definite
// and the indefinite length, and the contents, nested; it reads the elements first and makes nodes of them after, so LDAP and Kerberos can name
// the elements by where they are; the "ber" decoder shows any bytes as the generic TLV tree
const (
	berProtocol string = "ber"
	berTitle    string = "ASN.1 BER"
	// the classes of the identifier's top two bits
	universalClass   byte = 0
	applicationClass byte = 1
	contextClass     byte = 2
	privateClass     byte = 3
	// the elements one decode reads at most, and their depth (below the tree's own limit, with room for the nodes above them)
	berMaxElements int = 10000
	berMaxDepth    int = 24
	// a length of more than 4 bytes is no length of anything real
	berMaxLengthBytes int = 4
)

var (
	berUniversal = map[int]string{
		0: "END OF CONTENTS", 1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING", 4: "OCTET STRING", 5: "NULL", 6: "OBJECT IDENTIFIER", 7: "ObjectDescriptor",
		8: "EXTERNAL", 9: "REAL", 10: "ENUMERATED", 11: "EMBEDDED PDV", 12: "UTF8String", 13: "RELATIVE-OID", 16: "SEQUENCE", 17: "SET",
		18: "NumericString", 19: "PrintableString", 20: "TeletexString", 21: "VideotexString", 22: "IA5String", 23: "UTCTime", 24: "GeneralizedTime",
		25: "GraphicString", 26: "VisibleString", 27: "GeneralString", 28: "UniversalString", 30: "BMPString",
	}
	berClasses = []string{"universal", "application", "context", "private"}
)

// one element as far as it was read; end is past its contents (and past the end-of-contents octets of an indefinite length)
type berElement struct {
	class         byte
	tag           int
	isConstructed bool
	isIndefinite  bool
	start         int
	contentStart  int
	contentEnd    int
	end           int
	children      []*berElement
	err           string
}

// the reading of a tree of elements: the elements so far, against berMaxElements
type berReader struct {
	data     []byte
	elements int
}

func init() {
	register(decoder{
		Protocol:   berProtocol,
		Title:      berTitle,
		Ports:      nil,
		hint:       noHint,
		sniff:      berSniff,
		decode:     framedDecode(berProtocol),
		fromTarget: nil,
		frame:      berFrame,
		pdu:        berPDU,
		unit:       "element",
	})
}

// a constructed element that spans the bytes exactly and reads without an error; never more than possible, BER is too general to be sure of
func berSniff(data []byte, context Context) (score int) {
	if (len(data) < 2) || (data[0]&0x20 == 0) {
		return
	}

	reader := &berReader{data: data, elements: 0}

	if element := reader.read(0, len(data), 0); (element.end == len(data)) && !element.hasError() {
		score = 25
	}

	return
}

// the identifier and length of an element at data[offset:end]: its tag, its contents' start and their length, -1 for an indefinite length; ok is false
// when they are cut short or wrong, with the reason
func berHeader(data []byte, offset int, end int) (class byte, tag int, isConstructed bool, contentStart int, length int, reason string) {
	if offset >= end {
		reason = "the identifier is cut short"
		return
	}

	first := data[offset]
	class, isConstructed, tag = first>>6, first&0x20 != 0, int(first&0x1f)
	next := offset + 1

	// a high tag number: base-128 digits, the last without its top bit
	if tag == 0x1f {
		tag = 0

		for {
			if next >= end {
				reason = "the tag number is cut short"
				return
			}

			if tag > 1<<24 {
				reason = "the tag number is too large"
				return
			}

			digit := data[next]
			tag = tag<<7 | int(digit&0x7f)
			next++

			if digit&0x80 == 0 {
				break
			}
		}
	}

	if next >= end {
		reason = "the length is cut short"
		return
	}

	lengthByte := data[next]
	next++

	switch {
	case lengthByte < 0x80:
		length = int(lengthByte)
	case lengthByte == 0x80:
		length = -1

		if !isConstructed {
			reason = "a primitive element has an indefinite length"
			return
		}
	case int(lengthByte&0x7f) > berMaxLengthBytes:
		reason = fmt.Sprintf("a length of %d bytes", lengthByte&0x7f)
		return
	default:
		size := int(lengthByte & 0x7f)

		if next+size > end {
			reason = "the length is cut short"
			return
		}

		for _, part := range data[next : next+size] {
			length = length<<8 | int(part)
		}

		next += size
	}

	contentStart = next
	return
}

// the whole length of the element at the start of data, 0 while it is cut short, -1 when the bytes are no element; an indefinite length is read
// through its contents
func berFrame(data []byte, state *streamState) (length int) {
	_, _, _, contentStart, contentLength, reason := berHeader(data, 0, len(data))

	switch {
	case reason != "":
		length = map[bool]int{true: 0, false: -1}[strings.Contains(reason, "cut short")]
	case contentLength < 0:
		reader := &berReader{data: data, elements: 0}
		element := reader.read(0, len(data), 0)

		// an error of a child counts too: a child cut short leaves its parent without an error and the end at the end of the bytes
		switch reason := element.firstError(); {
		case reason == "":
			length = element.end
		case strings.Contains(reason, "cut short") || strings.Contains(reason, "past") || strings.Contains(reason, "end-of-contents"):
			length = 0
		default:
			length = -1
		}
	default:
		length = contentStart + contentLength
	}

	return
}

// the element at offset within end, its children read too while it is constructed
func (reader *berReader) read(offset int, end int, depth int) (element *berElement) {
	element = &berElement{class: 0, tag: 0, isConstructed: false, isIndefinite: false, start: offset, contentStart: offset, contentEnd: end, end: end, children: nil, err: ""}
	reader.elements++

	// an element without its header has no contents of its own: they are empty at its start, never the bytes before it
	if reader.elements > berMaxElements {
		element.err, element.contentEnd = fmt.Sprintf("more than %d elements", berMaxElements), offset
		return
	}

	class, tag, isConstructed, contentStart, length, reason := berHeader(reader.data, offset, end)
	element.class, element.tag, element.isConstructed = class, tag, isConstructed

	if reason != "" {
		element.err, element.contentEnd = reason, offset
		return
	}

	element.contentStart = contentStart

	switch {
	case length < 0:
		element.isIndefinite = true
	case contentStart+length > end:
		element.err = fmt.Sprintf("the contents run past their parent: %d of their %d bytes are there", end-contentStart, length)
		element.contentEnd = end
		return
	default:
		element.contentEnd, element.end = contentStart+length, contentStart+length
	}

	if !isConstructed {
		return
	}

	if depth >= berMaxDepth {
		element.err = fmt.Sprintf("the elements nest more than %d deep", berMaxDepth)
		return
	}

	next := contentStart

	for next < element.contentEnd {
		// an indefinite length ends with two zero bytes
		if element.isIndefinite && (next+2 <= end) && (reader.data[next] == 0) && (reader.data[next+1] == 0) {
			element.contentEnd, element.end = next, next+2
			return
		}

		child := reader.read(next, element.contentEnd, depth+1)
		element.children = append(element.children, child)

		if child.err != "" {
			return
		}

		next = child.end
	}

	if element.isIndefinite {
		element.err = "the end-of-contents octets are missing"
	}

	return
}

// whether the element or one below it has an error
func (element *berElement) hasError() (hasError bool) {
	hasError = element.firstError() != ""
	return
}

// the error of the element, else the first one below it, depth first
func (element *berElement) firstError() (reason string) {
	reason = element.err

	for _, child := range element.children {
		if reason != "" {
			return
		}

		reason = child.firstError()
	}

	return
}

// the child of a constructed element with that context tag, nil without one
func (element *berElement) context(tag int) (child *berElement) {
	for _, candidate := range element.children {
		if (candidate.class == contextClass) && (candidate.tag == tag) {
			child = candidate
			return
		}
	}

	return
}

// the first child, nil without one
func (element *berElement) first() (child *berElement) {
	if (element != nil) && (len(element.children) > 0) {
		child = element.children[0]
	}

	return
}

// the contents of a primitive element
func (element *berElement) contents(data []byte) (contents []byte) {
	if element != nil {
		contents = data[element.contentStart:min(element.contentEnd, len(data))]
	}

	return
}

// an INTEGER or ENUMERATED of at most 8 bytes, two's complement
func (element *berElement) integer(data []byte) (value int64, ok bool) {
	contents := element.contents(data)

	if (element == nil) || element.isConstructed || (len(contents) == 0) || (len(contents) > 8) {
		return
	}

	value = int64(int8(contents[0]))

	for _, part := range contents[1:] {
		value = value<<8 | int64(part)
	}

	ok = true
	return
}

// the text of a string element, quoted and escaped, or its hex
func (element *berElement) text(data []byte) (text string) {
	contents := element.contents(data)

	if isText(contents) {
		text = textValue(contents)
		return
	}

	text = hexValue(contents)
	return
}

// the class and tag as X.690 writes them: INTEGER, [APPLICATION 3], [0]
func (element *berElement) tagText() (text string) {
	switch element.class {
	case universalClass:
		text = berUniversal[element.tag]

		if text == "" {
			text = fmt.Sprintf("[UNIVERSAL %d]", element.tag)
		}
	case applicationClass:
		text = fmt.Sprintf("[APPLICATION %d]", element.tag)
	case contextClass:
		text = fmt.Sprintf("[%d]", element.tag)
	default:
		text = fmt.Sprintf("[PRIVATE %d]", element.tag)
	}

	return
}

// the value of a primitive element by its universal type; the contents of any other one as text or hex
func (element *berElement) valueText(data []byte) (text string) {
	contents := element.contents(data)

	if element.class != universalClass {
		text = element.text(data)
		return
	}

	switch element.tag {
	case 1:
		text = map[bool]string{true: "TRUE", false: "FALSE"}[(len(contents) > 0) && (contents[0] != 0)]
	case 2, 10:
		if value, ok := element.integer(data); ok {
			text = strconv.FormatInt(value, 10)
			return
		}

		text = new(big.Int).SetBytes(contents).String()

		if (len(contents) > 0) && (contents[0]&0x80 != 0) {
			text = hexValue(contents)
		}
	case 3:
		if len(contents) > 0 {
			text = fmt.Sprintf("%d unused bits, %s", contents[0], hexValue(contents[1:]))
		}
	case 5:
		text = "NULL"
	case 6, 13:
		text = oidText(contents, element.tag == 6)
	default:
		text = element.text(data)
	}

	return
}

// an OBJECT IDENTIFIER (the first arc pair in one number) or a RELATIVE-OID in dotted form
func oidText(contents []byte, isAbsolute bool) (text string) {
	arcs := []string{}
	value := uint64(0)

	for index, part := range contents {
		if value > 1<<56 {
			text = hexValue(contents)
			return
		}

		value = value<<7 | uint64(part&0x7f)

		if part&0x80 != 0 {
			if index == len(contents)-1 {
				text = hexValue(contents)
				return
			}

			continue
		}

		if isAbsolute && (len(arcs) == 0) {
			first := min(value/40, 2)
			arcs = append(arcs, strconv.FormatUint(first, 10), strconv.FormatUint(value-40*first, 10))
		} else {
			arcs = append(arcs, strconv.FormatUint(value, 10))
		}

		value = 0
	}

	text = strings.Join(arcs, ".")
	return
}

// the nodes of an element and its children under parent; label names an element by its place (empty keeps the generic name), the node gets its
// value from valueText for a primitive and from value of a constructed one
func berNodes(tree *Tree, parent *node, data []byte, element *berElement, label func(element *berElement, parent *berElement) (name string, text string), container *berElement) (elementNode *node) {
	name, text := "", ""

	if label != nil {
		name, text = label(element, container)
	}

	if name == "" {
		name = "ber." + berClasses[element.class]

		if element.class == universalClass {
			name = "ber." + strings.ToLower(strings.ReplaceAll(element.tagText(), " ", "_"))
		}
	}

	if text == "" {
		text = element.tagText()
	} else {
		text += " " + element.tagText()
	}

	value := ""

	if !element.isConstructed && (element.err == "") {
		value = element.valueText(data)
	}

	if element.isConstructed {
		value = fmt.Sprintf("%d elements", len(element.children))
	}

	elementNode = tree.add(parent, name, text, value, element.start, max(0, min(element.end, len(data))-element.start))

	if element.err != "" {
		tree.fail(elementNode, element.err)
	}

	for _, child := range element.children {
		if tree.isFull {
			return
		}

		berNodes(tree, elementNode, data, child, label, element)
	}

	return
}

func berPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	reader := &berReader{data: data, elements: 0}
	element := reader.read(start, len(data), 0)
	root = berNodes(tree, nil, data, element, nil, nil)
	tree.addSummary(fmt.Sprintf("BER %s, %d bytes", element.tagText(), element.end-element.start))
	return
}
