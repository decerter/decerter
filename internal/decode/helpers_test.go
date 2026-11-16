// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	v1 "github.com/decerter/decerter/api"
)

// the contexts of the transports the tests use
var (
	udpContext  = Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 53, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false}
	tcpContext  = Context{Transport: StreamTransport, Layer: v1.TCPLayer, Direction: v1.UpDirection, ServerPort: 53, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false}
	dotContext  = Context{Transport: StreamTransport, Layer: v1.TLSLayer, Direction: v1.DownDirection, ServerPort: 853, ALPN: "dot", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false}
	mdnsContext = Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 5353, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false}
	otherUDP    = Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 9999, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false}
)

func be16(value uint16) (data []byte) {
	data = binary.BigEndian.AppendUint16(nil, value)
	return
}

func be32(value uint32) (data []byte) {
	data = binary.BigEndian.AppendUint32(nil, value)
	return
}

func join(parts ...[]byte) (data []byte) {
	for _, part := range parts {
		data = append(data, part...)
	}

	return
}

// the wire form of a name without compression, "" is the root
func wireName(name string) (data []byte) {
	for label := range strings.SplitSeq(strings.TrimSuffix(name, "."), ".") {
		if label != "" {
			data = append(data, byte(len(label)))
			data = append(data, label...)
		}
	}

	data = append(data, 0)
	return
}

// a header with the counts of the sections, then the sections as they are
func dnsPacket(id uint16, flags uint16, counts [4]uint16, sections ...[]byte) (data []byte) {
	data = join(be16(id), be16(flags), be16(counts[0]), be16(counts[1]), be16(counts[2]), be16(counts[3]))
	data = append(data, join(sections...)...)
	return
}

func question(name []byte, qType uint16, class uint16) (data []byte) {
	data = join(name, be16(qType), be16(class))
	return
}

func resource(name []byte, rrType uint16, class uint16, ttl uint32, rdata []byte) (data []byte) {
	data = join(name, be16(rrType), be16(class), be32(ttl), be16(uint16(len(rdata))), rdata)
	return
}

// a character-string
func characters(text string) (data []byte) {
	data = append([]byte{byte(len(text))}, text...)
	return
}

// a response with one answer record of type rrType for example.com
func answerPacket(rrType uint16, rdata []byte) (data []byte) {
	data = dnsPacket(0x4242, 0x8180, [4]uint16{0, 1, 0, 0}, resource(wireName("example.com"), rrType, 1, 300, rdata))
	return
}

// the first node of that name, depth first
func findNode(nodes []v1.DecodeNode, name string) (found *v1.DecodeNode) {
	for index := range nodes {
		if nodes[index].Name == name {
			found = &nodes[index]
			return
		}

		if found = findNode(nodes[index].Children, name); found != nil {
			return
		}
	}

	return
}

// every node of that name, depth first
func findAll(nodes []v1.DecodeNode, name string) (found []v1.DecodeNode) {
	for _, current := range nodes {
		if current.Name == name {
			found = append(found, current)
		}

		found = append(found, findAll(current.Children, name)...)
	}

	return
}

// the errors of the tree with the names of their nodes
func errorsOf(nodes []v1.DecodeNode) (errors []string) {
	for _, current := range nodes {
		if current.Error != "" {
			errors = append(errors, current.Name+": "+current.Error)
		}

		errors = append(errors, errorsOf(current.Children)...)
	}

	return
}

// what is wrong with the tree's shape: a node outside the decoded bytes, a child outside its parent, a byte outside printable ASCII
func shapeErrors(nodes []v1.DecodeNode, start int, end int) (problems []string) {
	for _, current := range nodes {
		if (current.Offset < start) || (current.Length < 0) || (current.Offset+current.Length > end) {
			problems = append(problems, fmt.Sprintf("%s at %d+%d is outside %d to %d", current.Name, current.Offset, current.Length, start, end))
		}

		for _, text := range []string{current.Name, current.Label, current.Value, current.Error} {
			for index := range len(text) {
				if (text[index] < ' ') || (text[index] > '~') {
					problems = append(problems, fmt.Sprintf("%s has byte 0x%02x in %q", current.Name, text[index], text))
					break
				}
			}
		}

		problems = append(problems, shapeErrors(current.Children, current.Offset, current.Offset+current.Length)...)
	}

	return
}

// a decode that must not fail
func mustDecode(state *testing.T, data []byte, context Context, as string) (result v1.Decode) {
	result, err := Decode(data, context, as)

	if err != nil {
		state.Fatalf("Could not decode %x, error: %s", data, err.Error())
	}

	if problems := shapeErrors(result.Tree, 0, result.Length); len(problems) > 0 {
		state.Fatalf("Test of decode.Decode failed, the tree should fit its bytes, problems: %v", problems)
	}

	return
}

// the values the nodes of these names should have, a name with #n is its n-th node
func checkValues(state *testing.T, name string, result v1.Decode, expected map[string]string) {
	for field, value := range expected {
		fieldName, index := field, 0

		if before, after, isIndexed := strings.Cut(field, "#"); isIndexed {
			fieldName = before
			_, scanErr := fmt.Sscanf(after, "%d", &index)

			if scanErr != nil {
				state.Fatalf("Could not read the index of %q, error: %s", field, scanErr.Error())
			}
		}

		found := findAll(result.Tree, fieldName)

		if index >= len(found) {
			state.Errorf("Test of %s failed, the tree should have %s, tree: %+v", name, field, result.Tree)
			continue
		}

		if found[index].Value != value {
			state.Errorf("Test of %s failed, %s should be %q, value: %q", name, field, value, found[index].Value)
		}
	}
}
