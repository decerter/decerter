// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"slices"
	"strings"
	"testing"

	v1 "github.com/decerter/decerter/api"
)

// Test if decode.Decode returns with the expected output at its limits: a tree that reaches the node limit stops with a truncated node, an input over
// MaxInputBytes is cut, nodes past the depth and size limits go to the sink and a decoder's panic gives the raw tree with the error.
func TestLimitsPositive(state *testing.T) {
	// 2000 records of 16 bytes are more than MaxNodes nodes
	records := []byte{}

	for range 2000 {
		records = append(records, resource([]byte{0xc0, 0x0c}, 1, 1, 1, []byte{1, 2, 3, 4})...)
	}

	packet := dnsPacket(1, 0x8000, [4]uint16{1, 2000, 0, 0}, question(wireName("example.com"), 1, 1), records)
	result := mustDecode(state, packet, udpContext, "")
	last := result.Tree[len(result.Tree)-1]

	if !result.Truncated || (last.Name != "decode.truncated") || !strings.Contains(last.Error, "10000 nodes") || (len(findAll(result.Tree, "dns.rr")) >= 2000) {
		state.Errorf("Test of the node limit failed, the tree should stop at it and say so, truncated: %t, last: %+v", result.Truncated, last)
	}

	// the input limit
	large := make([]byte, MaxInputBytes+10)
	result = mustDecode(state, large, otherUDP, "")

	if !result.Truncated || (result.Length != MaxInputBytes) || (result.Total != MaxInputBytes+10) || (result.Tree[0].Length != MaxInputBytes) {
		state.Errorf("Test of the input limit failed, only MaxInputBytes should be decoded, result: length %d total %d truncated %t", result.Length, result.Total, result.Truncated)
	}

	// depth: a chain of nodes stops at MaxDepth
	tree := newTree()
	parent := (*node)(nil)

	for range MaxDepth + 5 {
		parent = tree.add(parent, "chain", "Chain", "", 0, 0)
	}

	if !tree.isFull || (tree.count != MaxDepth) || (parent != tree.sink) || (len(tree.sink.children) != 0) {
		state.Errorf("Test of the depth limit failed, the chain should stop at %d nodes, count: %d, full: %t", MaxDepth, tree.count, tree.isFull)
	}

	// size: values of 1 MiB stop before MaxOutputBytes
	tree = newTree()
	value := strings.Repeat("x", 1<<20)

	for range 8 {
		tree.add(nil, "big", "Big", value, 0, 0)
	}

	if !tree.isFull || (tree.size > MaxOutputBytes) || (len(tree.roots) != 3) {
		state.Errorf("Test of the size limit failed, the tree should keep 3 values of 1 MiB, roots: %d, size: %d", len(tree.roots), tree.size)
	}

	// the sink takes errors and bits without keeping them
	tree.fail(tree.sink, "lost")
	tree.addBits(tree.sink, "bits", "Bits", "", 0, 1, 1)

	if (tree.sink.err != "") || (tree.sink.mask != 0) || (tree.errors != 1) {
		state.Errorf("Test of the sink failed, it should keep nothing, sink: %+v", tree.sink)
	}

	// a decoder that panics
	register(decoder{
		Protocol:   "zpanic",
		Title:      "Panic",
		Ports:      nil,
		hint:       func(context Context) (reason string) { return },
		sniff:      func(data []byte, context Context) (score int) { score = 100; return },
		decode:     func(tree *Tree, data []byte, context Context) { panic("broken \x1b decoder") },
		fromTarget: nil,
	})
	state.Cleanup(func() {
		registry = slices.DeleteFunc(registry, func(protocol decoder) bool { return protocol.Protocol == "zpanic" })
	})
	result = mustDecode(state, []byte("hello"), otherUDP, "zpanic")

	if (result.Protocol != RawProtocol) || (result.Error != `the zpanic decoder failed: broken \x1b decoder`) || (len(result.Tree) != 1) || (result.Summary != "5 bytes, the decoder failed") {
		state.Errorf("Test of the panic recovery failed, the result should be raw with the error, result: %+v", result)
	}
}

// Test if decode.sanitize returns with the expected output: printable ASCII stays as it is (an escape's backslash too), every other byte is \xNN.
func TestSanitizePositive(state *testing.T) {
	positiveCases := map[string]string{
		"":                 "",
		"example.com":      "example.com",
		`a\x00b\\`:         `a\x00b\\`,
		"a\x00b":           `a\x00b`,
		"caf\xc3\xa9\x1b[": `caf\xc3\xa9\x1b[`,
		"\n\x7f":           `\x0a\x7f`,
	}

	for text, expected := range positiveCases {
		if clean := sanitize(text); clean != expected {
			state.Errorf("Test of decode.sanitize failed, text: %q, result should be %q, result: %q", text, expected, clean)
		}
	}
}

// Test if decode.FromTarget returns with the expected errors: no query, no dns parameter, bad base64, too short a message and another as find nothing.
func TestFromTargetNegative(state *testing.T) {
	negativeCases := map[string]string{
		"no query":     "/dns-query",
		"no parameter": "/dns-query?name=example.com",
		"bad base64":   "/dns-query?dns=***",
		"short":        "/dns-query?dns=AAAA",
		"bad query":    "/dns-query?dns=%zz",
	}

	for name, target := range negativeCases {
		if data, found := FromTarget(Context{Transport: BodyTransport, Layer: "", Direction: v1.UpDirection, ServerPort: 0, ALPN: "", ContentType: "", Upgrade: "", Method: "GET", Target: target, Encoding: "", Extensions: "", Handshake: false}, ""); found {
			state.Errorf("Test of decode.FromTarget failed, %s should find nothing, data: %x", name, data)
		}
	}

	if _, found := FromTarget(Context{Transport: BodyTransport, Layer: "", Direction: v1.UpDirection, ServerPort: 0, ALPN: "", ContentType: "", Upgrade: "", Method: "GET", Target: "/q?dns=AAABAAABAAAAAAAAAAABAAEB", Encoding: "", Extensions: "", Handshake: false}, RawProtocol); found {
		state.Errorf("Test of decode.FromTarget failed, as=raw should find nothing in a dns parameter")
	}
}
