// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"encoding/binary"
	"fmt"
	"strconv"

	v1 "github.com/decerter/decerter/api"
)

// MQTT from the OASIS standards MQTT 3.1.1 and MQTT 5.0: the fixed header, the variable headers and payloads of the control packets, and the properties
// and reason codes of 5.0; a stream learns the version from CONNECT (the client) or CONNACK (the server), a read alone takes 3.1.1 unless the bytes say 5
const (
	mqttProtocol string = "mqtt"
	mqttTitle    string = "MQ Telemetry Transport Protocol"
	// state.mode once the stream said which version it speaks
	mqttVersion5 string = "5"
	mqttVersion4 string = "4"
	// the remaining length has at most 4 bytes of 7 bits
	mqttMaxLengthBytes int = 4
)

var (
	mqttTypes = nameTable{names: map[uint16]string{
		1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE",
		11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT", 15: "AUTH",
	}, unknown: "Reserved %d"}
	mqttReasons = nameTable{names: map[uint16]string{
		0x00: "Success", 0x01: "Granted QoS 1", 0x02: "Granted QoS 2", 0x04: "Disconnect with Will Message", 0x10: "No matching subscribers", 0x11: "No subscription existed",
		0x18: "Continue authentication", 0x19: "Re-authenticate", 0x80: "Unspecified error", 0x81: "Malformed Packet", 0x82: "Protocol Error",
		0x83: "Implementation specific error", 0x84: "Unsupported Protocol Version", 0x85: "Client Identifier not valid", 0x86: "Bad User Name or Password",
		0x87: "Not authorized", 0x88: "Server unavailable", 0x89: "Server busy", 0x8a: "Banned", 0x8b: "Server shutting down", 0x8c: "Bad authentication method",
		0x8d: "Keep Alive timeout", 0x8e: "Session taken over", 0x8f: "Topic Filter invalid", 0x90: "Topic Name invalid", 0x91: "Packet Identifier in use",
		0x92: "Packet Identifier not found", 0x93: "Receive Maximum exceeded", 0x94: "Topic Alias invalid", 0x95: "Packet too large", 0x96: "Message rate too high",
		0x97: "Quota exceeded", 0x98: "Administrative action", 0x99: "Payload format invalid", 0x9a: "Retain not supported", 0x9b: "QoS not supported",
		0x9c: "Use another server", 0x9d: "Server moved", 0x9e: "Shared Subscriptions not supported", 0x9f: "Connection rate exceeded", 0xa0: "Maximum connect time",
		0xa1: "Subscription Identifiers not supported", 0xa2: "Wildcard Subscriptions not supported",
	}, unknown: "Reason 0x%02x"}
	// the CONNACK return codes of 3.1.1
	mqttReturnCodes = nameTable{names: map[uint16]string{0: "Connection Accepted", 1: "unacceptable protocol version", 2: "identifier rejected", 3: "Server unavailable", 4: "bad user name or password", 5: "not authorized"}, unknown: "Return code %d"}
	mqttProperties  = nameTable{names: map[uint16]string{
		0x01: "Payload Format Indicator", 0x02: "Message Expiry Interval", 0x03: "Content Type", 0x08: "Response Topic", 0x09: "Correlation Data",
		0x0b: "Subscription Identifier", 0x11: "Session Expiry Interval", 0x12: "Assigned Client Identifier", 0x13: "Server Keep Alive", 0x15: "Authentication Method",
		0x16: "Authentication Data", 0x17: "Request Problem Information", 0x18: "Will Delay Interval", 0x19: "Request Response Information",
		0x1a: "Response Information", 0x1c: "Server Reference", 0x1f: "Reason String", 0x21: "Receive Maximum", 0x22: "Topic Alias Maximum", 0x23: "Topic Alias",
		0x24: "Maximum QoS", 0x25: "Retain Available", 0x26: "User Property", 0x27: "Maximum Packet Size", 0x28: "Wildcard Subscription Available",
		0x29: "Subscription Identifier Available", 0x2a: "Shared Subscription Available",
	}, unknown: "Property 0x%02x"}
	// how each property's value is written: b byte, 2 two-byte, 4 four-byte, v variable byte integer, s UTF-8 string, d binary data, p string pair
	mqttPropertyKinds = map[byte]byte{
		0x01: 'b', 0x02: '4', 0x03: 's', 0x08: 's', 0x09: 'd', 0x0b: 'v', 0x11: '4', 0x12: 's', 0x13: '2', 0x15: 's', 0x16: 'd', 0x17: 'b', 0x18: '4', 0x19: 'b',
		0x1a: 's', 0x1c: 's', 0x1f: 's', 0x21: '2', 0x22: '2', 0x23: '2', 0x24: 'b', 0x25: 'b', 0x26: 'p', 0x27: '4', 0x28: 'b', 0x29: 'b', 0x2a: 'b',
	}
)

func init() {
	register(decoder{
		Protocol:   mqttProtocol,
		Title:      mqttTitle,
		Ports:      []Port{{Layer: v1.TCPLayer, Number: 1883}, {Layer: v1.TLSLayer, Number: 8883}},
		hint:       mqttHint,
		sniff:      mqttSniff,
		decode:     framedDecode(mqttProtocol),
		fromTarget: nil,
		frame:      mqttFrame,
		pdu:        mqttPDU,
		unit:       "packet",
	})
}

// MQTT over TLS names itself with the ALPN mqtt (AWS IoT and others), and MQTT over WebSocket with the subprotocol
func mqttHint(context Context) (reason string) {
	if (context.Layer == v1.TLSLayer) && (context.ALPN == "mqtt") {
		reason = "TLS ALPN mqtt is MQTT"
	}

	return
}

// a CONNECT with the protocol name MQTT (or MQIsdp of 3.1) is certain; another packet whose remaining length is all there only possible
func mqttSniff(data []byte, context Context) (score int) {
	if (context.Transport != StreamTransport) || (len(data) < 2) {
		return
	}

	length, lengthBytes := mqttRemaining(data[1:])

	if lengthBytes <= 0 {
		return
	}

	header := 1 + lengthBytes

	if (data[0]>>4 == 1) && (len(data) >= header+8) {
		nameLength := int(binary.BigEndian.Uint16(data[header:]))

		if name := string(data[header+2 : min(len(data), header+2+nameLength)]); (name == "MQTT") || (name == "MQIsdp") {
			score = 100
			return
		}
	}

	if (data[0]>>4 == 0) || (header+length > len(data)) {
		return
	}

	score = 15
	return
}

// the remaining length, a variable byte integer, and its bytes; 0 bytes while it is cut short, -1 when it has more than 4 bytes
func mqttRemaining(data []byte) (value int, size int) {
	shift := 0

	for index, part := range data {
		if index >= mqttMaxLengthBytes {
			size = -1
			return
		}

		value |= int(part&0x7f) << shift
		shift += 7

		if part&0x80 == 0 {
			size = index + 1
			return
		}
	}

	return
}

func mqttFrame(data []byte, state *streamState) (length int) {
	if len(data) < 2 {
		return
	}

	remaining, size := mqttRemaining(data[1:])

	switch {
	case size < 0:
		length = -1
	case size > 0:
		length = 1 + size + remaining
	}

	return
}

func mqttPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	first := data[start]
	packetType := first >> 4
	name := shortName(mqttTypes, uint16(packetType))
	root = tree.add(nil, mqttProtocol, mqttTitle+" ("+name+")", "", start, len(data)-start)
	header := tree.add(root, "mqtt.hdrflags", "Header Flags", fmt.Sprintf("0x%02x", first), start, 1)
	tree.addBits(header, "mqtt.msgtype", "Message Type", nameOf(mqttTypes, uint16(packetType)), start, 1, 0xf0)

	if packetType == 3 {
		tree.addBits(header, "mqtt.dupflag", "DUP Flag", yesNo(first&0x08 != 0), start, 1, 0x08)
		tree.addBits(header, "mqtt.qos", "QoS Level", strconv.Itoa(int(first>>1&3)), start, 1, 0x06)
		tree.addBits(header, "mqtt.retain", "Retain", yesNo(first&0x01 != 0), start, 1, 0x01)
	} else {
		tree.addBits(header, "mqtt.flags", "Reserved flags", fmt.Sprintf("0x%x", first&0x0f), start, 1, 0x0f)
	}

	remaining, size := mqttRemaining(data[start+1:])

	if size <= 0 {
		tree.fail(root, "the remaining length is cut short")
		tree.addSummary("MQTT " + name + " header cut short")
		return
	}

	tree.add(root, "mqtt.len", "Msg Len", strconv.Itoa(remaining), start+1, size)
	end := min(len(data), start+1+size+remaining)
	root.length = end - start
	reader := fieldsOf(tree, root, data, start+1+size, end)
	summary := "MQTT " + name

	// the version of the stream: a CONNECT says it, a CONNACK of 5.0 has properties after its two bytes
	isV5 := state.mode == mqttVersion5

	switch packetType {
	case 1:
		summary += mqttConnect(tree, root, reader, state)
	case 2:
		if (state.mode == "") && (remaining > 2) {
			state.mode, isV5 = mqttVersion5, true
		}

		reader.number("mqtt.conack.flags", "Acknowledge Flags", 1, func(value uint32) (text string) {
			text = fmt.Sprintf("0x%02x session present %s", value, yesNo(value&1 != 0))
			return
		})

		if isV5 {
			code, _ := reader.number("mqtt.conack.reason", "Reason Code", 1, hexNumber(mqttReasons, 2))
			summary += " " + shortName(mqttReasons, uint16(code))
			mqttPropertyList(tree, root, data, reader)
		} else {
			code, _ := reader.number("mqtt.conack.val", "Return Code", 1, named(mqttReturnCodes))
			summary += " " + shortName(mqttReturnCodes, uint16(code))
		}
	case 3:
		topic := mqttString(reader, "mqtt.topic", "Topic")
		summary += " " + topic

		if first>>1&3 > 0 {
			identifier, _ := reader.number("mqtt.msgid", "Message Identifier", 2, nil)
			summary += fmt.Sprintf(" id=%d", identifier)
		}

		if isV5 {
			mqttPropertyList(tree, root, data, reader)
		}

		reader.restField("mqtt.msg", "Message")
	case 4, 5, 6, 7, 11:
		identifier, _ := reader.number("mqtt.msgid", "Message Identifier", 2, nil)
		summary += fmt.Sprintf(" id=%d", identifier)

		if isV5 && (packetType != 11) && (reader.left() > 0) {
			code, _ := reader.number("mqtt.reason_code", "Reason Code", 1, hexNumber(mqttReasons, 2))
			summary += " " + shortName(mqttReasons, uint16(code))
		}

		if isV5 && (reader.left() > 0) {
			mqttPropertyList(tree, root, data, reader)
		}

		for (reader.left() > 0) && !reader.isShort && !tree.isFull {
			reader.number("mqtt.unsuback.reason_code", "Reason Code", 1, hexNumber(mqttReasons, 2))
		}
	case 8, 9, 10:
		identifier, _ := reader.number("mqtt.msgid", "Message Identifier", 2, nil)
		summary += fmt.Sprintf(" id=%d", identifier)

		if isV5 {
			mqttPropertyList(tree, root, data, reader)
		}

		for (reader.left() > 0) && !reader.isShort && !tree.isFull {
			switch packetType {
			case 8:
				summary += " " + mqttString(reader, "mqtt.topic", "Topic Filter")
				reader.number("mqtt.sub.qos", "Subscription Options", 1, func(value uint32) (text string) { text = fmt.Sprintf("0x%02x QoS %d", value, value&3); return })
			case 9:
				code, _ := reader.number("mqtt.suback.qos", "Return Code", 1, hexNumber(mqttReasons, 2))
				summary += " " + shortName(mqttReasons, uint16(code))
			default:
				summary += " " + mqttString(reader, "mqtt.topic", "Topic Filter")
			}
		}
	case 14, 15:
		if reader.left() > 0 {
			code, _ := reader.number("mqtt.reason_code", "Reason Code", 1, hexNumber(mqttReasons, 2))
			summary += " " + shortName(mqttReasons, uint16(code))
		}

		if reader.left() > 0 {
			mqttPropertyList(tree, root, data, reader)
		}
	}

	reader.finish()
	tree.addSummary(summary)
	return
}

// a CONNECT: protocol name and level, flags, keep alive, properties of 5.0, then the client id, the will, the user name and the password (not shown)
func mqttConnect(tree *Tree, root *node, reader *cursor, state *streamState) (summary string) {
	name := mqttString(reader, "mqtt.protoname", "Protocol Name")
	level, _ := reader.number("mqtt.ver", "Version", 1, func(value uint32) (text string) {
		text = map[uint32]string{3: "MQTT v3.1 (3)", 4: "MQTT v3.1.1 (4)", 5: "MQTT v5.0 (5)"}[value]

		if text == "" {
			text = fmt.Sprintf("Unknown (%d)", value)
		}

		return
	})
	state.mode = mqttVersion4

	if level == 5 {
		state.mode = mqttVersion5
	}

	flags, ok := reader.number("mqtt.conflags", "Connect Flags", 1, func(value uint32) (text string) { text = fmt.Sprintf("0x%02x", value); return })

	if ok {
		flagsNode := reader.last
		start := flagsNode.offset

		for _, flag := range []struct {
			name  string
			label string
			mask  uint32
		}{{"mqtt.conflag.uname", "User Name Flag", 0x80}, {"mqtt.conflag.passwd", "Password Flag", 0x40}, {"mqtt.conflag.retain", "Will Retain", 0x20}, {"mqtt.conflag.willflag", "Will Flag", 0x04}, {"mqtt.conflag.cleansess", "Clean Session Flag", 0x02}} {
			tree.addBits(flagsNode, flag.name, flag.label, yesNo(flags&flag.mask != 0), start, 1, flag.mask)
		}

		tree.addBits(flagsNode, "mqtt.conflag.qos", "QoS Level", strconv.Itoa(int(flags>>3&3)), start, 1, 0x18)
	}

	reader.number("mqtt.kalive", "Keep Alive", 2, nil)

	if level == 5 {
		mqttPropertyList(tree, root, reader.data, reader)
	}

	client := mqttString(reader, "mqtt.clientid", "Client ID")

	if flags&0x04 != 0 {
		if level == 5 {
			mqttPropertyList(tree, root, reader.data, reader)
		}

		mqttString(reader, "mqtt.willtopic", "Will Topic")
		mqttBinary(reader, "mqtt.willmsg", "Will Message")
	}

	if flags&0x80 != 0 {
		mqttString(reader, "mqtt.username", "User Name")
	}

	if flags&0x40 != 0 {
		mqttBinary(reader, "mqtt.passwd", "Password")
	}

	summary = fmt.Sprintf(" %s level %d client %s", name, level, client)
	return
}

// a UTF-8 string with a 2-byte length, quoted and escaped
func mqttString(reader *cursor, name string, label string) (value string) {
	length, start, ok := reader.lengthOf(label, 2)

	if !ok {
		return
	}

	text, _, ok := reader.take(label, length)

	if ok {
		value = textValue(text)
		reader.add(name, label, value, start, 2+length)
	}

	return
}

// binary data with a 2-byte length
func mqttBinary(reader *cursor, name string, label string) {
	length, start, ok := reader.lengthOf(label, 2)

	if !ok {
		return
	}

	data, _, ok := reader.take(label, length)

	if ok {
		reader.add(name, label, hexValue(data), start, 2+length)
	}
}

// the properties of 5.0: a variable byte integer length, then each property's identifier and value
func mqttPropertyList(tree *Tree, root *node, data []byte, reader *cursor) {
	if reader.left() == 0 {
		return
	}

	start := reader.offset
	length, size := mqttRemaining(data[start:reader.end])

	if size <= 0 {
		tree.fail(root, "the properties length is cut short")
		reader.offset = reader.end
		return
	}

	properties := tree.add(root, "mqtt.properties", "Properties", strconv.Itoa(length)+" bytes", start, min(size+length, reader.end-start))
	reader.offset += size
	inner := reader.vector(properties, "Properties", length)

	for (inner.left() > 0) && !inner.isShort && !tree.isFull {
		identifier := data[inner.offset]
		propertyStart := inner.offset
		property := tree.add(properties, "mqtt.property", shortName(mqttProperties, uint16(identifier)), "", propertyStart, 0)
		values := fieldsOf(tree, property, data, propertyStart+1, inner.end)

		switch mqttPropertyKinds[identifier] {
		case 'b':
			value, _ := values.number("mqtt.property.byte", "Value", 1, nil)
			tree.setValue(property, strconv.Itoa(int(value)))
		case '2':
			value, _ := values.number("mqtt.property.uint16", "Value", 2, nil)
			tree.setValue(property, strconv.Itoa(int(value)))
		case '4':
			value, _ := values.number("mqtt.property.uint32", "Value", 4, nil)
			tree.setValue(property, strconv.FormatUint(uint64(value), 10))
		case 'v':
			value, valueSize := mqttRemaining(data[values.offset:values.end])

			if valueSize <= 0 {
				values.isShort = true
				tree.fail(property, "the value is cut short")
				break
			}

			values.add("mqtt.property.varint", "Value", strconv.Itoa(value), values.offset, valueSize)
			values.offset += valueSize
			tree.setValue(property, strconv.Itoa(value))
		case 's':
			tree.setValue(property, mqttString(values, "mqtt.property.string", "Value"))
		case 'd':
			mqttBinary(values, "mqtt.property.binary", "Value")
		case 'p':
			key := mqttString(values, "mqtt.property.key", "Key")
			value := mqttString(values, "mqtt.property.value", "Value")
			tree.setValue(property, key+"="+value)
		default:
			tree.fail(property, "an unknown property, the properties after it can't be read")
			values.offset = values.end
		}

		property.length = values.offset - propertyStart
		inner.offset = values.offset

		if values.isShort {
			break
		}
	}

	reader.offset = inner.end
}
