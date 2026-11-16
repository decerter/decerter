// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"bytes"
	"strings"
	"testing"

	v1 "github.com/decerter/decerter/api"
)

// the context of one direction of a tcp flow to port 53 joined from its messages
var joinedContext = Context{Transport: StreamTransport, Layer: v1.TCPLayer, Direction: v1.DownDirection, ServerPort: 53, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: true}

// Test if decode.Decode returns with the expected output for a joined stream: messages over 64 KiB of reads decode whole, the input limit is MaxStreamBytes,
// a message cut at the end says the stream ends there, and a summary of many PDUs counts the lines past maxSummaryLines.
func TestJoinedPositive(state *testing.T) {
	// an answer of 300 TXT records of 200 bytes: 61 KiB in one message
	records := []byte{}

	for range 300 {
		records = append(records, resource([]byte{0xc0, 0x0c}, 16, 1, 60, characters(strings.Repeat("t", 199)))...)
	}

	answer := dnsPacket(7, 0x8180, [4]uint16{1, 300, 0, 0}, question(wireName("example.com"), 16, 1), records)
	stream := join(be16(uint16(len(answer))), answer)
	result := mustDecode(state, stream, joinedContext, "")

	if (result.Protocol != dnsProtocol) || (len(result.Tree) != 1) || (len(findAll(result.Tree, "dns.txt")) != 300) || (len(errorsOf(result.Tree)) != 0) || result.Truncated {
		state.Errorf("Test of a joined stream failed, the large answer should be one whole message, errors: %v, truncated: %t", errorsOf(result.Tree), result.Truncated)
	}

	// the same bytes as one read of a tcp flow: the message continues in the next read
	result = mustDecode(state, stream[:1000], tcpContext, "")

	if errors := errorsOf(result.Tree); (len(errors) == 0) || !strings.Contains(strings.Join(errors, "; "), "the message continues in the next read: 1000 of its ") {
		state.Errorf("Test of a read failed, the message should continue in the next read, errors: %v", errors)
	}

	result = mustDecode(state, stream[:1000], joinedContext, "")

	if errors := errorsOf(result.Tree); !strings.Contains(strings.Join(errors, "; "), "the stream ends inside the message: 1000 of its ") {
		state.Errorf("Test of a joined stream failed, the cut message should say the stream ends, errors: %v", errors)
	}

	// 40 queries: 32 summary lines and a count
	query := dnsPacket(1, 0x0100, [4]uint16{1, 0, 0, 0}, question(wireName("example.com"), 1, 1))
	queries := bytes.Repeat(join(be16(uint16(len(query))), query), 40)
	result = mustDecode(state, queries, joinedContext, "")

	if (len(result.Tree) != 40) || !strings.HasSuffix(result.Summary, "; 8 more") || (strings.Count(result.Summary, "Standard query") != maxSummaryLines) {
		state.Errorf("Test of the summary limit failed, it should have %d lines and count the rest, summary: %s", maxSummaryLines, result.Summary)
	}

	// the input limit of a joined stream
	large := make([]byte, MaxStreamBytes+10)
	result = mustDecode(state, large, joinedContext, RawProtocol)

	if !result.Truncated || (result.Length != MaxStreamBytes) {
		state.Errorf("Test of the stream input limit failed, MaxStreamBytes should be decoded, length: %d", result.Length)
	}
}

// Test if decode.decodeFramed returns with the expected errors: bytes a frame function refuses are one node with an error.
func TestFramedNegative(state *testing.T) {
	tree := newTree()
	protocol := decoder{Protocol: "zframe", Title: "Frames", Ports: nil, hint: nil, sniff: nil, decode: nil, fromTarget: nil,
		frame: func(data []byte, state *streamState) (length int) { length = -1; return }, pdu: nil, unit: "frame"}
	decodeFramed(tree, []byte("abc"), joinedContext, protocol)
	nodes := tree.view()

	if (len(nodes) != 1) || (nodes[0].Error != "the bytes are no Frames frame") || (nodes[0].Length != 3) || (tree.summaryText() != "3 bytes that are no Frames") {
		state.Errorf("Test of decodeFramed failed, refused bytes should be one node with an error, nodes: %+v", nodes)
	}
}
