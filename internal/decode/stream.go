// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"fmt"
	"strconv"
)

// the PDUs of a stream: frame cuts them, pdu decodes each one; a read that starts with a whole PDU and one direction of a flow joined from its first
// byte (Context.Joined) are both walked here, so a PDU split over reads decodes as one in the joined stream
func decodeFramed(tree *Tree, data []byte, context Context, protocol decoder) {
	state := &streamState{context: context, index: 0, isTLS: false, mode: "", waiting: 0, columns: 0, sequence: 0, command: 0}
	offset := 0

	for (offset < len(data)) && !tree.isFull {
		rest := data[offset:]

		// after STARTTLS or an SSLRequest the server took, the bytes are TLS records
		if (state.mode == starttlsMode) && isTLSStart(rest) {
			state.isTLS = true
		}

		if state.isTLS {
			root := tree.add(nil, protocol.Protocol+".tls", "TLS after "+protocol.Title+" switched to it", strconv.Itoa(len(rest))+" bytes", offset, len(rest))
			nested := context
			nested.Transport, nested.Joined = StreamTransport, context.Joined
			inner := newTree()
			tlsDecode(inner, rest, nested)
			graft(tree, root, inner.roots, at(offset))
			tree.addSummary("TLS")
			return
		}

		length := protocol.frame(rest, state)

		switch {
		case length < 0:
			root := tree.add(nil, protocol.Protocol, protocol.Title, strconv.Itoa(len(rest))+" bytes", offset, len(rest))
			tree.fail(root, fmt.Sprintf("the bytes are no %s %s", protocol.Title, protocol.unit))
			tree.addSummary(fmt.Sprintf("%d bytes that are no %s", len(rest), protocol.Title))
			return
		case (length == 0) || (length > len(rest)):
			root := protocol.pdu(tree, data, offset, state)
			tree.fail(root, continued(context, protocol.unit, len(rest), length))
			return
		}

		protocol.pdu(tree, data[:offset+length], offset, state)
		state.index++
		offset += length
	}
}

// what a PDU cut short at the end of the bytes says: a read goes on in the next one, a joined stream ends where the history's bytes end
func continued(context Context, unit string, have int, length int) (message string) {
	switch {
	case context.Joined && (length == 0):
		message = fmt.Sprintf("the stream ends inside the %s, %d bytes of it are kept", unit, have)
	case context.Joined:
		message = fmt.Sprintf("the stream ends inside the %s: %d of its %d bytes are kept", unit, have, length)
	case length == 0:
		message = fmt.Sprintf("the %s continues in the next read, %d bytes of it are here", unit, have)
	default:
		message = fmt.Sprintf("the %s continues in the next read: %d of its %d bytes are here", unit, have, length)
	}

	return
}

// the decode of a protocol with a frame function: its PDUs over any transport (a datagram or a body holds whole ones)
func framedDecode(name string) (decode func(tree *Tree, data []byte, context Context)) {
	decode = func(tree *Tree, data []byte, context Context) {
		protocol, _ := lookup(name)
		decodeFramed(tree, data, context, protocol)
	}
	return
}

// the length of a line from the start of data with its CRLF (a lone LF ends it too), 0 when no line end is there
func lineLength(data []byte) (length int) {
	for index, value := range data {
		if value == '\n' {
			length = index + 1
			return
		}
	}

	return
}

// a line without its line end
func trimLine(line []byte) (text []byte) {
	text = line

	if (len(text) > 0) && (text[len(text)-1] == '\n') {
		text = text[:len(text)-1]
	}

	if (len(text) > 0) && (text[len(text)-1] == '\r') {
		text = text[:len(text)-1]
	}

	return
}

// the hint of a protocol no context names
func noHint(context Context) (reason string) {
	return
}

// a TLS handshake record header: what a stream that switched to TLS goes on with
func isTLSStart(data []byte) (isTLS bool) {
	isTLS = (len(data) >= 3) && (data[0] == 22) && (data[1] == 3) && (data[2] <= 4)
	return
}
