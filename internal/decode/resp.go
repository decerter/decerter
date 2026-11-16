// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/output"
)

// the Redis serialization protocol from the Redis protocol specification (RESP2 and RESP3: simple strings, errors, integers, bulk strings, arrays, and
// RESP3's null, boolean, double, big number, bulk error, verbatim string, map, set, push and attribute), and inline commands; a value nests at most
// respMaxDepth levels, a deeper one is an error
const (
	respProtocol string = "resp"
	respTitle    string = "Redis Serialization Protocol"
	respMaxDepth int    = 24
	// the elements of an aggregate the summary shows of a command
	respSummaryArguments int = 3
	// the bytes of an argument the summary shows
	respSummaryBytes int = 48
)

var (
	respTypes = map[byte]string{
		'+': "Simple string", '-': "Error", ':': "Integer", '$': "Bulk string", '*': "Array", '_': "Null", '#': "Boolean", ',': "Double", '(': "Big number",
		'!': "Bulk error", '=': "Verbatim string", '%': "Map", '~': "Set", '>': "Push", '|': "Attribute",
	}
	// the commands an inline command line starts with that make it likely
	respCommands = []string{"PING", "SET", "GET", "DEL", "AUTH", "HELLO", "INFO", "SELECT", "KEYS", "SCAN", "QUIT", "EXISTS", "INCR", "EXPIRE", "MULTI", "EXEC", "SUBSCRIBE", "PUBLISH", "CLIENT", "COMMAND", "CONFIG", "MONITOR"}
)

func init() {
	register(decoder{
		Protocol:   respProtocol,
		Title:      respTitle,
		Ports:      []Port{{Layer: v1.TCPLayer, Number: 6379}, {Layer: v1.TLSLayer, Number: 6379}, {Layer: v1.TLSLayer, Number: 6380}},
		hint:       noHint,
		sniff:      respSniff,
		decode:     framedDecode(respProtocol),
		fromTarget: nil,
		frame:      respFrame,
		pdu:        respPDU,
		unit:       "value",
	})
}

// a value that frames cleanly to its end: an array of bulk strings is a client's command, certain; a simple string, error or integer is likely;
// an inline command by its first word
func respSniff(data []byte, context Context) (score int) {
	if (context.Transport != StreamTransport) || (len(data) < 3) {
		return
	}

	if _, isType := respTypes[data[0]]; !isType {
		word, _, _ := strings.Cut(string(trimLine(data[:min(len(data), 64)])), " ")

		if (lineLength(data) > 0) && slices.Contains(respCommands, asciiUpper(word)) {
			score = 40
		}

		return
	}

	length := respFrame(data, &streamState{context: context, index: 0, isTLS: false, mode: "", waiting: 0, columns: 0, sequence: 0, command: 0})

	switch {
	case length < 0:
	case (data[0] == '*') && (len(data) > 4) && bytes.Contains(data[:min(len(data), 24)], []byte("\r\n$")):
		score = 90
	case length == 0:
		score = 20
	case data[0] == '+' || data[0] == '-' || data[0] == ':' || data[0] == '$':
		score = 60
	default:
		score = 50
	}

	return
}

// the length of the value at the start of data with everything it nests, 0 while it is cut short, -1 when the bytes are no value
func respFrame(data []byte, state *streamState) (length int) {
	if _, isType := respTypes[data[0]]; !isType {
		// an inline command is one line
		length = lineLength(data)
		return
	}

	length = respValueLength(data, 0, 0)
	return
}

func respValueLength(data []byte, offset int, depth int) (length int) {
	if offset >= len(data) {
		return
	}

	if depth > respMaxDepth {
		length = -1
		return
	}

	kind := data[offset]
	line := lineLength(data[offset:])

	if line == 0 {
		return
	}

	header := string(trimLine(data[offset+1 : offset+line]))

	switch kind {
	case '+', '-', ':', '_', '#', ',', '(':
		length = line
	case '$', '!', '=':
		size, err := strconv.Atoi(header)

		// a size from the traffic is checked against the bytes left before it is added to an offset
		switch {
		case err != nil:
			length = -1
		case size < 0:
			length = line
		case size > len(data)-offset-line-2:
			length = 0
		default:
			length = line + size + 2
		}
	case '*', '%', '~', '>', '|':
		count, err := strconv.Atoi(header)

		if (err != nil) || (count > len(data)) {
			length = -1
			return
		}

		if (kind == '%') || (kind == '|') {
			count *= 2
		}

		next := offset + line

		for range max(0, count) {
			element := respValueLength(data, next, depth+1)

			if element <= 0 {
				length = element
				return
			}

			next += element
		}

		length = next - offset
	default:
		length = -1
	}

	return
}

func respPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	if _, isType := respTypes[data[start]]; !isType {
		line := data[start:]

		if length := lineLength(line); length > 0 {
			line = line[:length]
		}

		root = tree.add(nil, respProtocol, respTitle+" (inline command)", textValue(trimLine(line)), start, len(line))
		words := strings.Fields(string(trimLine(line)))

		if len(words) > 0 {
			tree.addSummary("Redis inline " + output.Escape([]byte(asciiUpper(words[0]))))
		}

		return
	}

	root = tree.add(nil, respProtocol, respTitle, "", start, len(data)-start)
	_, words, _ := respValue(tree, root, data, start, 0)
	child := root

	if len(root.children) > 0 {
		child = root.children[0]
		root.length = child.length
		tree.setLabel(root, respTitle+" ("+child.label+")")
	}

	// a client sends commands as arrays of bulk strings
	switch {
	case (state.context.Direction == v1.UpDirection) && (len(words) > 0):
		command := asciiUpper(strings.Trim(words[0], `"`))
		arguments := words[1:min(len(words), 1+respSummaryArguments)]
		summary := "Redis " + output.Escape([]byte(command))

		if len(arguments) > 0 {
			summary += " " + strings.Join(arguments, " ")
		}

		if len(words) > 1+respSummaryArguments {
			summary += fmt.Sprintf(" ... (%d arguments)", len(words)-1)
		}

		tree.setValue(child, summary)
		tree.addSummary(summary)
	default:
		tree.addSummary("Redis " + strings.ToLower(child.label) + " " + child.value)
	}

	return
}

// one value at offset under parent and its end; words are the texts of an array of bulk strings (a command), quoted, escaped and cut to respSummaryBytes
func respValue(tree *Tree, parent *node, data []byte, offset int, depth int) (end int, words []string, ok bool) {
	end = len(data)
	kind := data[offset]
	line := lineLength(data[offset:])
	label := respTypes[kind]

	if line == 0 {
		valueNode := tree.add(parent, "resp.value", label, "", offset, len(data)-offset)
		tree.fail(valueNode, "the line has no CRLF")
		return
	}

	header := trimLine(data[offset+1 : offset+line])
	length := respValueLength(data, offset, depth)

	if length <= 0 {
		length = len(data) - offset
	}

	valueNode := tree.add(parent, respName(kind), label, "", offset, length)
	end = offset + length

	switch kind {
	case '+', '-', ':', ',', '(':
		tree.setValue(valueNode, textValue(header))
		ok = true
	case '_':
		tree.setValue(valueNode, "null")
		ok = true
	case '#':
		tree.setValue(valueNode, map[string]string{"t": "true", "f": "false"}[string(header)])

		if valueNode.value == "" {
			tree.fail(valueNode, "a boolean is t or f")
		}

		ok = true
	case '$', '!', '=':
		size, _ := strconv.Atoi(string(header))
		tree.add(valueNode, "resp.length", "Length", strconv.Itoa(size), offset+1, line-1)

		if size < 0 {
			tree.setValue(valueNode, "null")
			ok = true
			return
		}

		body := data[offset+line : offset+line+min(size, len(data)-offset-line)]

		if len(body) < size {
			tree.fail(valueNode, fmt.Sprintf("the string goes on past the bytes: %d of its %d bytes are there", len(body), size))
		}

		tree.setValue(valueNode, fmt.Sprintf("%d bytes", size))
		text := textValue(body)

		if !isText(body) {
			text = hexValue(body)
		}

		dataNode := tree.add(valueNode, "resp.data", "Data", text, offset+line, len(body))

		if (kind == '=') && (len(body) >= 4) {
			tree.setLabel(dataNode, "Data ("+output.Escape(body[:3])+")")
		}

		if (size <= len(data)-offset-line-2) && !bytes.Equal(data[offset+line+size:offset+line+size+2], []byte("\r\n")) {
			tree.fail(valueNode, "the string does not end with CRLF")
		}

		// the summary keeps a long argument short
		word := textValue(body[:min(len(body), respSummaryBytes)])

		if !isText(body) {
			word = hexValue(body[:min(len(body), respSummaryBytes)])
		}

		if len(body) > respSummaryBytes {
			word += "..."
		}

		words = []string{word}
		ok = len(body) == size
	default:
		count, _ := strconv.Atoi(string(header))
		elements := count

		if (kind == '%') || (kind == '|') {
			elements *= 2
		}

		tree.setValue(valueNode, fmt.Sprintf("%d elements", count))

		if count < 0 {
			tree.setValue(valueNode, "null")
			ok = true
			return
		}

		next := offset + line
		isCommand := kind == '*'

		for index := 0; (index < elements) && (next < len(data)) && !tree.isFull; index++ {
			elementEnd, elementWords, elementOK := respValue(tree, valueNode, data, next, depth+1)

			if !elementOK {
				return
			}

			if data[next] != '$' {
				isCommand = false
			}

			if isCommand && (len(elementWords) == 1) {
				words = append(words, elementWords[0])
			}

			next = elementEnd
		}

		if !isCommand {
			words = nil
		}

		ok = true
	}

	return
}

// the field name of a value by its type
func respName(kind byte) (name string) {
	name = map[byte]string{
		'+': "resp.simple_string", '-': "resp.error", ':': "resp.integer", '$': "resp.bulk_string", '*': "resp.array", '_': "resp.null", '#': "resp.boolean",
		',': "resp.double", '(': "resp.big_number", '!': "resp.bulk_error", '=': "resp.verbatim_string", '%': "resp.map", '~': "resp.set", '>': "resp.push",
		'|': "resp.attribute",
	}[kind]
	return
}
