// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net/netip"
	"strconv"

	v1 "github.com/decerter/decerter/api"
)

// STUN from RFC 8489 (message, attributes, FINGERPRINT), TURN from RFC 8656 (methods, attributes, ChannelData), ICE attributes from RFC 8445, the NAT
// behaviour attributes of RFC 5780; RFC 7983 tells STUN (first byte 0-3) from DTLS (20-63), TURN channels (64-79) and RTP/RTCP (128-191) on one port
const (
	stunProtocol    string = "stun"
	stunTitle       string = "Session Traversal Utilities for NAT"
	stunHeaderBytes int    = 20
	stunCookie      uint32 = 0x2112a442
	// FINGERPRINT is the CRC-32 of the message before it XOR this
	stunFingerprintXOR uint32 = 0x5354554e
	stunFingerprint    uint16 = 0x8028
	// a TURN ChannelData message starts with a channel number 0x4000-0x4fff
	turnChannelFirst byte = 0x40
	turnChannelLast  byte = 0x4f
	stunSniffMessage int  = 100
	stunSniffChannel int  = 30
)

var (
	stunMethods = nameTable{names: map[uint16]string{
		0x001: "Binding", 0x002: "Shared Secret", 0x003: "Allocate", 0x004: "Refresh", 0x006: "Send", 0x007: "Data", 0x008: "CreatePermission",
		0x009: "ChannelBind", 0x00a: "Connect", 0x00b: "ConnectionBind", 0x00c: "ConnectionAttempt",
	}, unknown: "Method 0x%03x"}
	stunClasses    = nameTable{names: map[uint16]string{0: "Request", 1: "Indication", 2: "Success Response", 3: "Error Response"}, unknown: "Class %d"}
	stunAttributes = nameTable{names: map[uint16]string{
		0x0001: "MAPPED-ADDRESS", 0x0002: "RESPONSE-ADDRESS", 0x0003: "CHANGE-REQUEST", 0x0004: "SOURCE-ADDRESS", 0x0005: "CHANGED-ADDRESS", 0x0006: "USERNAME",
		0x0007: "PASSWORD", 0x0008: "MESSAGE-INTEGRITY", 0x0009: "ERROR-CODE", 0x000a: "UNKNOWN-ATTRIBUTES", 0x000b: "REFLECTED-FROM", 0x000c: "CHANNEL-NUMBER",
		0x000d: "LIFETIME", 0x0012: "XOR-PEER-ADDRESS", 0x0013: "DATA", 0x0014: "REALM", 0x0015: "NONCE", 0x0016: "XOR-RELAYED-ADDRESS",
		0x0017: "REQUESTED-ADDRESS-FAMILY", 0x0018: "EVEN-PORT", 0x0019: "REQUESTED-TRANSPORT", 0x001a: "DONT-FRAGMENT", 0x001c: "MESSAGE-INTEGRITY-SHA256",
		0x001d: "PASSWORD-ALGORITHM", 0x001e: "USERHASH", 0x0020: "XOR-MAPPED-ADDRESS", 0x0022: "RESERVATION-TOKEN", 0x0024: "PRIORITY", 0x0025: "USE-CANDIDATE",
		0x0026: "PADDING", 0x0027: "RESPONSE-PORT", 0x002a: "CONNECTION-ID", 0x8000: "ADDITIONAL-ADDRESS-FAMILY", 0x8001: "ADDRESS-ERROR-CODE",
		0x8002: "PASSWORD-ALGORITHMS", 0x8003: "ALTERNATE-DOMAIN", 0x8004: "ICMP", 0x8022: "SOFTWARE", 0x8023: "ALTERNATE-SERVER", 0x8027: "CACHE-TIMEOUT",
		0x8028: "FINGERPRINT", 0x8029: "ICE-CONTROLLED", 0x802a: "ICE-CONTROLLING", 0x802b: "RESPONSE-ORIGIN", 0x802c: "OTHER-ADDRESS",
	}, unknown: "Attribute 0x%04x"}
	stunFamilies   = nameTable{names: map[uint16]string{1: "IPv4", 2: "IPv6"}, unknown: "Family %d"}
	stunTransports = nameTable{names: map[uint16]string{6: "TCP", 17: "UDP"}, unknown: "Protocol %d"}
)

func init() {
	register(decoder{
		Protocol: stunProtocol,
		Title:    stunTitle,
		Ports: []Port{
			{Layer: v1.UDPLayer, Number: 3478},
			{Layer: v1.TCPLayer, Number: 3478},
			{Layer: v1.TLSLayer, Number: 5349},
			{Layer: v1.DTLSLayer, Number: 5349},
		},
		hint:       noHint,
		sniff:      stunSniff,
		decode:     framedDecode(stunProtocol),
		fromTarget: nil,
		frame:      stunFrame,
		pdu:        stunPDU,
		unit:       "message",
	})
}

// the magic cookie and a length that is a multiple of 4 make a STUN message certain; a TURN ChannelData message of the right length is only likely
func stunSniff(data []byte, context Context) (score int) {
	if len(data) < 4 {
		return
	}

	if (data[0] >= turnChannelFirst) && (data[0] <= turnChannelLast) {
		length := 4 + int(binary.BigEndian.Uint16(data[2:]))

		if (length == len(data)) || ((context.Transport == StreamTransport) && (length <= len(data))) {
			score = stunSniffChannel
		}

		return
	}

	if (len(data) < stunHeaderBytes) || (data[0]&0xc0 != 0) || (binary.BigEndian.Uint32(data[4:]) != stunCookie) {
		return
	}

	length := int(binary.BigEndian.Uint16(data[2:]))

	if (length%4 == 0) && ((stunHeaderBytes+length == len(data)) || ((context.Transport == StreamTransport) && (stunHeaderBytes+length <= len(data)))) {
		score = stunSniffMessage
		return
	}

	score = 20
	return
}

// a message is its header and its length, a ChannelData message its 4 bytes and its length (over a stream padded to 4, RFC 8656 12.5)
func stunFrame(data []byte, state *streamState) (length int) {
	if len(data) < 4 {
		return
	}

	switch {
	case (data[0] >= turnChannelFirst) && (data[0] <= turnChannelLast):
		length = 4 + int(binary.BigEndian.Uint16(data[2:]))

		if state.context.Transport == StreamTransport {
			length = (length + 3) &^ 3
		}
	case data[0]&0xc0 == 0:
		length = stunHeaderBytes + int(binary.BigEndian.Uint16(data[2:]))
	default:
		length = -1
	}

	return
}

func stunPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	if len(data)-start < 4 {
		root = tree.add(nil, stunProtocol, stunTitle, "", start, len(data)-start)
		tree.addSummary("STUN header cut short")
		return
	}

	if (data[start] >= turnChannelFirst) && (data[start] <= turnChannelLast) {
		root = turnChannelData(tree, data, start, state)
		return
	}

	length := int(binary.BigEndian.Uint16(data[start+2:]))
	end := min(len(data), start+stunHeaderBytes+length)
	root = tree.add(nil, stunProtocol, stunTitle, "", start, end-start)
	reader := fieldsOf(tree, root, data, start, end)
	messageType, isType := reader.number("stun.type", "Message Type", 2, func(value uint32) (text string) { text = fmt.Sprintf("0x%04x", value); return })
	method := (messageType & 0x000f) | ((messageType >> 1) & 0x0070) | ((messageType >> 2) & 0x0f80)
	class := ((messageType >> 7) & 2) | ((messageType >> 4) & 1)

	if isType {
		typeNode := reader.last
		tree.setValue(typeNode, typeNode.value+" "+shortName(stunMethods, uint16(method))+" "+shortName(stunClasses, uint16(class)))
		tree.addBits(typeNode, "stun.type.method", "Method", hexNameOf(stunMethods, uint16(method)), start, 2, 0x3eef)
		tree.addBits(typeNode, "stun.type.class", "Class", nameOf(stunClasses, uint16(class)), start, 2, 0x0110)
	}

	reader.number("stun.length", "Message Length", 2, nil)
	cookie, isCookie := reader.number("stun.cookie", "Magic Cookie", 4, func(value uint32) (text string) { text = fmt.Sprintf("0x%08x", value); return })
	cookieNode := reader.last
	transaction, _ := reader.bytesField("stun.id", "Transaction ID", 12)
	summary := fmt.Sprintf("%s %s", shortName(stunMethods, uint16(method)), shortName(stunClasses, uint16(class)))
	tree.setLabel(root, stunTitle+" "+summary)

	if isCookie && (cookie != stunCookie) {
		tree.fail(cookieNode, fmt.Sprintf("the magic cookie of RFC 8489 is 0x%08x, so this is a classic RFC 3489 message", stunCookie))
	}

	if length%4 != 0 {
		tree.fail(root, fmt.Sprintf("the message length %d is no multiple of 4", length))
	}

	if reader.isShort {
		tree.addSummary("STUN " + summary)
		return
	}

	attributes := tree.add(root, "stun.attributes", "Attributes", "", start+stunHeaderBytes, end-start-stunHeaderBytes)
	count := 0

	for (reader.left() >= 4) && !tree.isFull {
		value := stunAttribute(tree, attributes, data, reader, start, cookie, transaction)

		if value != "" {
			summary += " " + value
		}

		count++
	}

	tree.setValue(attributes, strconv.Itoa(count))

	if reader.left() > 0 {
		tree.fail(attributes, fmt.Sprintf("%d bytes after the last attribute", reader.left()))
	}

	tree.addSummary("STUN " + summary)
	return
}

// one attribute, its value padded to 4 bytes; summary is what the summary shows of it (a mapped address, an error)
func stunAttribute(tree *Tree, parent *node, data []byte, reader *cursor, messageStart int, cookie uint32, transaction []byte) (summary string) {
	start := reader.offset
	attributeType := binary.BigEndian.Uint16(data[start:])
	length := int(binary.BigEndian.Uint16(data[start+2:]))
	padded := (length + 3) &^ 3
	end := min(reader.end, start+4+length)
	attribute := tree.add(parent, "stun.attribute", shortName(stunAttributes, attributeType), "", start, min(reader.end, start+4+padded)-start)
	inner := fieldsOf(tree, attribute, data, start, end)
	inner.number("stun.attribute.type", "Type", 2, hexNumber(stunAttributes, 4))
	inner.number("stun.attribute.length", "Length", 2, nil)
	reader.offset = min(reader.end, start+4+padded)

	if start+4+length > reader.end {
		tree.fail(attribute, fmt.Sprintf("the value runs past the message: %d of its %d bytes are there", reader.end-start-4, length))
		reader.offset = reader.end
		return
	}

	switch attributeType {
	case 0x0001, 0x0002, 0x0004, 0x0005, 0x000b, 0x8023, 0x802b, 0x802c:
		tree.setValue(attribute, stunAddress(inner, nil, nil))
	case 0x0020, 0x0012, 0x0016:
		tree.setValue(attribute, stunAddress(inner, binary.BigEndian.AppendUint32(nil, cookie), transaction))

		if attributeType == 0x0020 {
			summary = attribute.value
		}
	case 0x0006, 0x0014, 0x0015, 0x8022, 0x8003:
		text, _ := inner.textField("stun.attribute.text", shortName(stunAttributes, attributeType), length)
		tree.setValue(attribute, textValue(text))
	case 0x0009:
		inner.number("stun.error.reserved", "Reserved", 2, nil)
		class, _ := inner.number("stun.error.class", "Class", 1, func(value uint32) (text string) { text = strconv.Itoa(int(value & 7)); return })
		number, _ := inner.number("stun.error.number", "Number", 1, nil)
		reason, _ := inner.textField("stun.error.reason", "Reason", inner.left())
		tree.setValue(attribute, fmt.Sprintf("%d %s", (class&7)*100+number, textValue(reason)))
		summary = "error " + attribute.value
	case 0x000a:
		for inner.left() >= 2 {
			inner.number("stun.unknown_attribute", "Attribute", 2, hexNumber(stunAttributes, 4))
		}
	case 0x000c:
		channel, _ := inner.number("stun.channel", "Channel Number", 2, func(value uint32) (text string) { text = fmt.Sprintf("0x%04x", value); return })
		inner.number("stun.channel.reserved", "Reserved", 2, nil)
		tree.setValue(attribute, fmt.Sprintf("0x%04x", channel))
	case 0x000d, 0x8027:
		lifetime, _ := inner.number("stun.lifetime", "Lifetime", 4, func(value uint32) (text string) { text = ttlText(value); return })
		tree.setValue(attribute, ttlText(lifetime))
	case 0x0019:
		transport, _ := inner.number("stun.transport", "Protocol", 1, named(stunTransports))
		inner.bytesField("stun.transport.reserved", "Reserved", 3)
		tree.setValue(attribute, shortName(stunTransports, uint16(transport)))
	case 0x0017, 0x8000:
		family, _ := inner.number("stun.family", "Family", 1, named(stunFamilies))
		inner.bytesField("stun.family.reserved", "Reserved", 3)
		tree.setValue(attribute, shortName(stunFamilies, uint16(family)))
	case 0x0024:
		priority, _ := inner.number("stun.priority", "Priority", 4, nil)
		tree.setValue(attribute, strconv.FormatUint(uint64(priority), 10))
	case 0x8029, 0x802a:
		tieBreaker, _ := inner.number64("stun.tie_breaker", "Tie breaker", func(value uint64) (text string) { text = fmt.Sprintf("0x%016x", value); return })
		tree.setValue(attribute, fmt.Sprintf("0x%016x", tieBreaker))
	case 0x0003:
		flags, _ := inner.number("stun.change", "Change", 4, func(value uint32) (text string) { text = fmt.Sprintf("0x%08x", value); return })
		tree.setValue(attribute, fmt.Sprintf("change IP %s, change port %s", yesNo(flags&4 != 0), yesNo(flags&2 != 0)))
	case 0x0018:
		inner.number("stun.even_port", "Reserve next port", 1, func(value uint32) (text string) { text = yesNo(value&0x80 != 0); return })
	case 0x0013:
		inner.bytesField("stun.data", "Data", length)
		tree.setValue(attribute, fmt.Sprintf("%d bytes", length))
	case 0x0008, 0x001c:
		inner.bytesField("stun.integrity", "HMAC", length)
	case stunFingerprint:
		tree.setValue(attribute, stunCheckFingerprint(tree, inner, data, messageStart, start))
	default:
		if length > 0 {
			inner.restField("stun.attribute.value", "Value")
		}
	}

	inner.finish()

	if attribute.value == "" {
		tree.setValue(attribute, strconv.Itoa(length)+" bytes")
	}

	tree.setLabel(attribute, shortName(stunAttributes, attributeType))
	return
}

// a (XOR-)MAPPED-ADDRESS: reserved, family, port and address; key is the cookie the port and an IPv4 address are XORed with, transaction extends it for IPv6
func stunAddress(reader *cursor, key []byte, transaction []byte) (value string) {
	reader.number("stun.address.reserved", "Reserved", 1, nil)
	family, ok := reader.number("stun.address.family", "Family", 1, named(stunFamilies))

	if !ok {
		return
	}

	portData, portStart, ok := reader.take("Port", 2)

	if !ok {
		return
	}

	size := 4

	if family == 2 {
		size = 16
	}

	addressData, addressStart, ok := reader.take("Address", size)

	if !ok {
		return
	}

	port := binary.BigEndian.Uint16(portData)
	plain := append([]byte(nil), addressData...)

	if key != nil {
		port ^= uint16(stunCookie >> 16)
		mask := append(append([]byte(nil), key...), transaction...)

		for index := range plain {
			plain[index] ^= mask[index%len(mask)]
		}
	}

	address, _ := netip.AddrFromSlice(plain)
	reader.add("stun.address.port", "Port", strconv.Itoa(int(port)), portStart, 2)
	reader.add("stun.address.address", "Address", address.String(), addressStart, size)
	value = netip.AddrPortFrom(address, port).String()

	if (family != 1) && (family != 2) {
		value = ""
	}

	return
}

// the FINGERPRINT value and whether it matches the CRC-32 of the message before it
func stunCheckFingerprint(tree *Tree, reader *cursor, data []byte, messageStart int, attributeStart int) (value string) {
	fingerprint, ok := reader.number("stun.fingerprint", "CRC-32", 4, func(value uint32) (text string) { text = fmt.Sprintf("0x%08x", value); return })

	if !ok {
		return
	}

	// the CRC covers the header with the length up to and including this attribute
	covered := append([]byte(nil), data[messageStart:attributeStart]...)
	binary.BigEndian.PutUint16(covered[2:], uint16(attributeStart+8-messageStart-stunHeaderBytes))
	expected := crc32.ChecksumIEEE(covered) ^ stunFingerprintXOR
	value = fmt.Sprintf("0x%08x correct", fingerprint)

	if fingerprint != expected {
		value = fmt.Sprintf("0x%08x wrong", fingerprint)
		tree.fail(reader.parent, fmt.Sprintf("the CRC-32 of the message is 0x%08x", expected))
	}

	return
}

// a TURN ChannelData message: channel number, length and the application data, as the protocol it sniffs as (DTLS, RTP)
func turnChannelData(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	length := int(binary.BigEndian.Uint16(data[start+2:]))
	end := min(len(data), start+4+length)
	root = tree.add(nil, "turn.channel", "TURN ChannelData", "", start, end-start)
	reader := fieldsOf(tree, root, data, start, end)
	channel, _ := reader.number("turn.channel.number", "Channel Number", 2, func(value uint32) (text string) { text = fmt.Sprintf("0x%04x", value); return })
	reader.number("turn.channel.length", "Length", 2, nil)
	payload, payloadStart, ok := reader.take("Data", reader.left())
	summary := fmt.Sprintf("TURN ChannelData 0x%04x, %d bytes", channel, length)

	if ok && (len(payload) > 0) {
		dataNode := tree.add(root, "turn.channel.data", "Data", strconv.Itoa(len(payload))+" bytes", payloadStart, len(payload))

		if protocol, _ := decodeNested(tree, dataNode, payload, at(payloadStart), state.context, stunProtocol, sniffThreshold); protocol != "" {
			summary += " (" + protocol + ")"
		}
	}

	tree.addSummary(summary)
	return
}
