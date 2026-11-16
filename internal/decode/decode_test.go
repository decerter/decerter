// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"bytes"
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

	// size: values of 1 MiB are cut to maxStringBytes, and the nodes stop before MaxOutputBytes
	tree = newTree()
	value := strings.Repeat("x", 1<<20)

	for range 1000 {
		tree.add(nil, "big", "Big", value, 0, 0)
	}

	if !tree.isFull || (tree.size > MaxOutputBytes) || (len(tree.roots) != MaxOutputBytes/(maxStringBytes+6+nodeOverheadBytes)) || (len(tree.roots[0].value) != maxStringBytes) || !strings.HasSuffix(tree.roots[0].value, "x...") {
		state.Errorf("Test of the size limit failed, the tree should keep %d values cut to %d bytes, roots: %d, size: %d", MaxOutputBytes/(maxStringBytes+6+nodeOverheadBytes), maxStringBytes, len(tree.roots), tree.size)
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
		if data, found := FromTarget(Context{Transport: BodyTransport, Layer: "", Direction: v1.UpDirection, ServerPort: 0, ALPN: "", ContentType: "", Upgrade: "", Method: "GET", Target: target, Encoding: "", Extensions: "", Handshake: false, Joined: false}, ""); found {
			state.Errorf("Test of decode.FromTarget failed, %s should find nothing, data: %x", name, data)
		}
	}

	if _, found := FromTarget(Context{Transport: BodyTransport, Layer: "", Direction: v1.UpDirection, ServerPort: 0, ALPN: "", ContentType: "", Upgrade: "", Method: "GET", Target: "/q?dns=AAABAAABAAAAAAAAAAABAAEB", Encoding: "", Extensions: "", Handshake: false, Joined: false}, RawProtocol); found {
		state.Errorf("Test of decode.FromTarget failed, as=raw should find nothing in a dns parameter")
	}
}

// text capText cut at limit: at most limit bytes, an escape it would split left out, "..." at the end
func isCut(text string, limit int) (isCapped bool) {
	isCapped = (len(text) <= limit) && (len(text) >= limit-len(`\x00`)) && strings.HasSuffix(text, "...")
	return
}

// Test if the tree's bounds return with the expected output: capText cuts before an escape it would split, a label or value written after add is charged
// and cut, the sink keeps none, a summary line is cut to maxSummaryBytes, and inflating draws from one budget per decode that nested trees share.
func TestTreeBoundsPositive(state *testing.T) {
	positiveCases := map[string]struct {
		text     string
		limit    int
		expected string
	}{
		"short":          {text: "abc", limit: 10, expected: "abc"},
		"cut":            {text: strings.Repeat("a", 20), limit: 10, expected: "aaaaaaa..."},
		"hex escape":     {text: `aaaaa\x41bbbb`, limit: 10, expected: "aaaaa..."},
		"short escape":   {text: `aaaaaa\nbbbb`, limit: 10, expected: "aaaaaa..."},
		"whole escape":   {text: `aaaaa\\bbbbbb`, limit: 10, expected: `aaaaa\\...`},
		"escaped escape": {text: `aaaa\\\x41bbbb`, limit: 11, expected: `aaaa\\...`},
	}

	for name, testCase := range positiveCases {
		if capped := capText(testCase.text, testCase.limit); (capped != testCase.expected) || (len(capped) > testCase.limit) {
			state.Errorf("Test of decode.capText failed, %s: %q should be %q, result: %q", name, testCase.text, testCase.expected, capped)
		}
	}

	// a value written after add counts and is cut; one past MaxOutputBytes leaves the old value and fills the tree; the sink keeps nothing
	tree := newTree()
	target := tree.add(nil, "field", "Field", "old", 0, 0)
	size := tree.size
	tree.setValue(target, strings.Repeat("\x01", 1<<20))

	if !isCut(target.value, maxStringBytes) || !strings.HasSuffix(target.value, `\x01...`) || (tree.size != size-3+len(target.value)) || tree.isFull {
		state.Errorf("Test of Tree.setValue failed, the value should be cut and charged, length: %d, size: %d", len(target.value), tree.size)
	}

	tree.size = MaxOutputBytes - 10
	tree.setLabel(target, strings.Repeat("y", 100))
	tree.setValue(tree.sink, "lost")
	tree.fail(tree.sink, "lost")

	if !tree.isFull || (target.label != "Field") || (tree.sink.value != "") || (tree.sink.err != "") || (tree.errors != 1) {
		state.Errorf("Test of Tree.setLabel failed, past the limit the label should stay and the tree be full, label: %q, full: %t, sink: %+v", target.label, tree.isFull, tree.sink)
	}

	// a summary line is cut and sanitized
	tree = newTree()
	tree.addSummary(strings.Repeat("z", 2000))
	tree.addSummary("a\x01b")

	if (len(tree.summary[0]) != maxSummaryBytes) || !strings.HasSuffix(tree.summary[0], "z...") || (tree.summary[1] != `a\x01b`) {
		state.Errorf("Test of Tree.addSummary failed, the line should be cut to %d bytes and sanitized, summary: %q", maxSummaryBytes, tree.summaryText()[:40])
	}

	// four payloads of 1 MiB spend the budget, the fifth inflates nothing and fills the tree; a nested tree draws from the same budget
	tree = newTree()
	inner := tree.nested()

	for index := range 4 {
		source := tree

		if index == 3 {
			source = inner
		}

		if inflated, err := source.inflate(bytes.NewReader(make([]byte, maxInflatedBytes))); (err != nil) || (len(inflated) != maxInflatedBytes) {
			state.Fatalf("Test of Tree.inflate failed, payload %d should inflate whole, length: %d, error: %v", index, len(inflated), err)
		}
	}

	inflated, err := inner.inflate(bytes.NewReader([]byte("more")))
	tree.adopt(inner)

	if (err == nil) || !strings.Contains(err.Error(), "the decode inflated 4194304 bytes already") || (len(inflated) != 0) || !inner.isFull || !tree.isFull || (*tree.inflated != maxDecodeInflatedBytes) {
		state.Errorf("Test of Tree.inflate failed, the budget should be spent, length: %d, error: %v, full: %t", len(inflated), err, tree.isFull)
	}

	// one payload past what is left: cut to the budget, the tree full
	tree = newTree()
	*tree.inflated = maxDecodeInflatedBytes - 10

	if inflated, err = tree.inflate(bytes.NewReader(make([]byte, 100))); (err == nil) || (len(inflated) != 10) || !tree.isFull {
		state.Errorf("Test of Tree.inflate failed, the payload should stop at the budget, length: %d, error: %v", len(inflated), err)
	}
}

// Test if decode.Decode returns with the expected output at the bounds the second review found broken: a joined DNS stream of 64 KB NSID options, a ClientHello
// of 255 ALPN names of 255 bytes, a record of 32767 alerts, gRPC and WebSocket messages that inflate to 1 MiB each, and the handshake records of a flow
// whose ALPN names another protocol.
func TestDecodeBoundsPositive(state *testing.T) {
	// the strings of the NSID options were not charged: 20 MB of JSON from a tree of 4 MiB
	option := join(be16(3), be16(65000), bytes.Repeat([]byte{0xff}, 65000))
	message := dnsPacket(1, 0x8000, [4]uint16{0, 0, 0, 1}, resource(wireName(""), 41, 4096, 0, option))
	stream := []byte{}

	for range 60 {
		stream = append(stream, join(be16(uint16(len(message))), message)...)
	}

	context := tcpContext
	context.Direction, context.Joined = v1.DownDirection, true
	result := mustDecode(state, stream, context, "")

	if (result.Protocol != dnsProtocol) || (len(findAll(result.Tree, "dns.opt")) != 60) || !strings.HasSuffix(findNode(result.Tree, "dns.opt").Value, "...") {
		state.Errorf("Test of the output bound failed, the NSID values should be cut, protocol: %s, options: %d, bytes: %d", result.Protocol, len(findAll(result.Tree, "dns.opt")), outputBytes(result.Tree))
	}

	// 255 ALPN names of 255 bytes that are no text: the extension's value and the summary
	names := bytes.Repeat(join([]byte{255}, bytes.Repeat([]byte{1}, 255)), 255)
	hello := handshakeMessage(1, join(be16(0x0303), make([]byte, 32), []byte{0}, be16(2), be16(0x1301), []byte{1, 0}, vector16(extension(16, vector16(names)))))
	result = mustDecode(state, tlsRecord(22, 0x0301, hello), tlsTCPContext, tlsProtocol)
	alpn := findNode(result.Tree, "tls.handshake.extension")

	if (result.Protocol != tlsProtocol) || !isCut(result.Summary, maxSummaryBytes) || (alpn == nil) || !isCut(alpn.Value, maxStringBytes) {
		state.Errorf("Test of the summary bound failed, the ALPN list should be cut, summary: %d bytes, extension found: %t", len(result.Summary), alpn != nil)
	}

	// a record of 32767 alerts: the loop stops when the tree is full, the summary line stays short
	result = mustDecode(state, tlsRecord(21, 0x0303, bytes.Repeat([]byte{2, 40}, 32767)), tlsTCPContext, tlsProtocol)

	if !result.Truncated || !isCut(result.Summary, maxSummaryBytes) || (len(findAll(result.Tree, "tls.alert_message")) >= 32767) {
		state.Errorf("Test of the summary bound failed, the alerts should stop at the tree's limit, truncated: %t, summary: %d bytes", result.Truncated, len(result.Summary))
	}

	// gzip messages of 1 MiB each: the fifth finds the budget spent
	zeros := gzipped(state, make([]byte, maxInflatedBytes))
	body := bytes.Repeat(grpcFrame(1, zeros), 6)
	grpcContext := bodyContext("application/grpc")
	grpcContext.Encoding = "gzip"
	result = mustDecode(state, body, grpcContext, "")
	errors := errorsOf(result.Tree)
	last := result.Tree[len(result.Tree)-1]

	if !result.Truncated || !slices.ContainsFunc(errors, func(text string) bool {
		return strings.Contains(text, "the decode inflated 4194304 bytes already, its limit")
	}) || (len(result.Tree) != 6) ||
		(last.Name != "decode.truncated") || !strings.Contains(last.Error, "4194304 inflated bytes") {
		state.Errorf("Test of the inflate budget failed, the gRPC body should stop after 4 MiB, roots: %d, errors: %v", len(result.Tree), errors)
	}

	// the same over permessage-deflate
	frames := bytes.Repeat(websocketFrameOf(true, rsv1Bit, binaryOpcode, nil, deflated(state, make([]byte, maxInflatedBytes))), 6)
	result = mustDecode(state, frames, websocketDeflate, "")
	errors = errorsOf(result.Tree)

	if !result.Truncated || !slices.ContainsFunc(errors, func(text string) bool {
		return strings.Contains(text, "could not inflate the message: the decode inflated 4194304 bytes already")
	}) {
		state.Errorf("Test of the inflate budget failed, the WebSocket messages should stop after 4 MiB, errors: %v", errors)
	}

	// the handshake records of a flow with the ALPN mqtt or dot (and its port) are TLS, the ALPN names what comes after them
	record := tlsRecord(22, 0x0301, handshakeMessage(1, join(be16(0x0303), make([]byte, 32), []byte{0}, be16(2), be16(0x1301), []byte{1, 0})))

	for _, flow := range []struct {
		alpn string
		port uint16
	}{{alpn: "mqtt", port: 8883}, {alpn: "dot", port: 853}, {alpn: "imap", port: 993}} {
		kept := keptContext
		kept.ALPN, kept.ServerPort = flow.alpn, flow.port
		result = mustDecode(state, record, kept, "")

		if (result.Protocol != tlsProtocol) || (len(result.Candidates) != 2) || (result.Candidates[0].Protocol != tlsProtocol) || (result.Candidates[0].Basis != v1.ContextDecodeBasis) {
			state.Errorf("Test of the hint order failed, the kept handshake of an %s flow should be tls, candidates: %+v", flow.alpn, result.Candidates)
		}
	}
}

// Test if the decoders that add bits under a field take the field's own node at every fill level of the tree: none fails, and every bit node of an MQTT
// CONNECT, a DHCP message and a STUN message is under its field, never under another node (the sink has no children to take one from).
func TestSinkFieldsPositive(state *testing.T) {
	connect := mqttPacket(0x10, join(mqttText("MQTT"), []byte{4, 0xc2}, be16(60), mqttText("client"), mqttText("user"), mqttText("pass")))
	dhcp := dhcpPacket(1, [4]byte{}, []byte{53, 1, 1, 255})
	stun := join(be16(0x0001), be16(0), be32(stunCookie), bytes.Repeat([]byte{7}, 12))
	parents := map[string]string{"mqtt.conflag.uname": "mqtt.conflags", "mqtt.conflag.qos": "mqtt.conflags", "dhcp.flags.bc": "dhcp.flags", "stun.type.method": "stun.type", "stun.type.class": "stun.type"}

	for left := range 40 {
		for name, decode := range map[string]func(tree *Tree){
			"mqtt": func(tree *Tree) {
				mqttPDU(tree, connect, 0, &streamState{context: streamContext(1883, v1.UpDirection, false), index: 0, isTLS: false, mode: "", waiting: 0, columns: 0, sequence: 0, command: 0})
			},
			"dhcp": func(tree *Tree) { dhcpDecode(tree, dhcp, dhcpUDP) },
			"stun": func(tree *Tree) {
				stunPDU(tree, stun, 0, &streamState{context: otherUDP, index: 0, isTLS: false, mode: "", waiting: 0, columns: 0, sequence: 0, command: 0})
			},
		} {
			tree := newTree()
			tree.count = MaxNodes - left
			decode(tree)

			for _, root := range tree.view() {
				for child, parent := range parents {
					if found := findNode([]v1.DecodeNode{root}, child); (found != nil) && (findNode(findAll([]v1.DecodeNode{root}, parent), child) == nil) {
						state.Errorf("Test of the %s fields failed, %d nodes left: %s should be under %s", name, left, child, parent)
					}
				}
			}
		}
	}
}
