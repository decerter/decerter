// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	v1 "github.com/decerter/decerter/api"
)

// DHCPv4 from RFC 2131 (the BOOTP message of RFC 951) and RFC 2132 (options), with RFC 3046 (relay agent), RFC 3442 (classless routes) and RFC 4702
// (client FQDN) by name; DHCPv6 from RFC 8415 (messages, relay messages, options, DUIDs, IAs) with RFC 3646 (DNS servers) and RFC 4704 (client FQDN)
const (
	dhcpProtocol     string = "dhcp"
	dhcpTitle        string = "Dynamic Host Configuration Protocol"
	dhcpv6Protocol   string = "dhcpv6"
	dhcpv6Title      string = "DHCPv6"
	dhcpFixedBytes   int    = 236
	dhcpCookie       uint32 = 0x63825363
	dhcpv6RelayBytes int    = 34
)

var (
	dhcpMessageTypes = nameTable{names: map[uint16]string{
		1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform", 9: "Force Renew", 10: "Lease query",
		11: "Lease Unassigned", 12: "Lease Unknown", 13: "Lease Active", 14: "Bulk Lease Query", 15: "Lease Query Done", 16: "Active LeaseQuery",
		17: "Lease Query Status", 18: "TLS",
	}, unknown: "Type %d"}
	dhcpOptions = nameTable{names: map[uint16]string{
		0: "Padding", 1: "Subnet Mask", 2: "Time Offset", 3: "Router", 4: "Time Server", 5: "Name Server", 6: "Domain Name Server", 7: "Log Server",
		9: "LPR Server", 12: "Host Name", 13: "Boot File Size", 15: "Domain Name", 17: "Root Path", 19: "IP Forwarding", 23: "Default IP TTL",
		26: "Interface MTU", 28: "Broadcast Address", 31: "Perform Router Discover", 33: "Static Route", 35: "ARP Cache Timeout", 40: "NIS Domain",
		41: "NIS Servers", 42: "NTP Servers", 43: "Vendor-Specific Information", 44: "NetBIOS Name Server", 45: "NetBIOS Datagram Distribution Server",
		46: "NetBIOS Node Type", 47: "NetBIOS Scope", 50: "Requested IP Address", 51: "IP Address Lease Time", 52: "Option Overload",
		53: "DHCP Message Type", 54: "DHCP Server Identifier", 55: "Parameter Request List", 56: "Message", 57: "Maximum DHCP Message Size",
		58: "Renewal Time Value", 59: "Rebinding Time Value", 60: "Vendor class identifier", 61: "Client identifier", 66: "TFTP Server Name",
		67: "Bootfile name", 69: "SMTP Server", 77: "User Class Information", 80: "Rapid Commit", 81: "Client Fully Qualified Domain Name",
		82: "Agent Information Option", 93: "Client System Architecture", 94: "Client Network Device Interface", 97: "UUID/GUID-based Client Identifier",
		100: "PCode", 101: "TCode", 108: "IPv6-Only Preferred", 114: "Captive-Portal", 116: "Auto-Config", 118: "Subnet Selection", 119: "Domain Search",
		121: "Classless Static Route", 125: "V-I Vendor-Specific Information", 150: "TFTP server address", 249: "Private/Classless Static Route (Microsoft)",
		252: "Private/Proxy autodiscovery", 255: "End",
	}, unknown: "Option %d"}
	dhcpHardwareTypes = nameTable{names: map[uint16]string{1: "Ethernet", 6: "IEEE 802", 32: "InfiniBand"}, unknown: "Type %d"}
	dhcpv6Types       = nameTable{names: map[uint16]string{
		1: "Solicit", 2: "Advertise", 3: "Request", 4: "Confirm", 5: "Renew", 6: "Rebind", 7: "Reply", 8: "Release", 9: "Decline", 10: "Reconfigure",
		11: "Information-request", 12: "Relay-forw", 13: "Relay-repl", 14: "Leasequery", 15: "Leasequery-reply", 16: "Leasequery-done", 17: "Leasequery-data",
	}, unknown: "Type %d"}
	dhcpv6Options = nameTable{names: map[uint16]string{
		1: "Client Identifier", 2: "Server Identifier", 3: "Identity Association for Non-temporary Address", 4: "Identity Association for Temporary Address",
		5: "IA Address", 6: "Option Request", 7: "Preference", 8: "Elapsed time", 9: "Relay Message", 11: "Authentication", 12: "Server unicast",
		13: "Status code", 14: "Rapid Commit", 15: "User Class", 16: "Vendor Class", 17: "Vendor-specific Information", 18: "Interface-Id",
		19: "Reconfigure Message", 20: "Reconfigure Accept", 21: "SIP Server Domain Name List", 22: "SIP Servers IPv6 Address List", 23: "DNS recursive name server",
		24: "Domain Search List", 25: "Identity Association for Prefix Delegation", 26: "IA Prefix", 27: "NIS Servers", 29: "NIS Domain Name",
		31: "Simple Network Time Protocol Server", 32: "Information Refresh Time", 39: "Fully Qualified Domain Name", 56: "NTP Server", 82: "SOL_MAX_RT",
		83: "INF_MAX_RT", 103: "Captive-Portal",
	}, unknown: "Option %d"}
	dhcpv6Statuses = nameTable{names: map[uint16]string{0: "Success", 1: "UnspecFail", 2: "NoAddrsAvail", 3: "NoBinding", 4: "NotOnLink", 5: "UseMulticast", 6: "NoPrefixAvail"}, unknown: "Status %d"}
	duidTypes      = nameTable{names: map[uint16]string{1: "link-layer address plus time", 2: "assigned by vendor based on Enterprise number", 3: "link-layer address", 4: "UUID"}, unknown: "Type %d"}
)

func init() {
	register(decoder{
		Protocol:   dhcpProtocol,
		Title:      dhcpTitle,
		Ports:      []Port{{Layer: v1.UDPLayer, Number: 67}, {Layer: v1.UDPLayer, Number: 68}},
		hint:       noHint,
		sniff:      dhcpSniff,
		decode:     dhcpDecode,
		fromTarget: nil,
	})
	register(decoder{
		Protocol:   dhcpv6Protocol,
		Title:      dhcpv6Title,
		Ports:      []Port{{Layer: v1.UDPLayer, Number: 546}, {Layer: v1.UDPLayer, Number: 547}},
		hint:       noHint,
		sniff:      dhcpv6Sniff,
		decode:     dhcpv6Decode,
		fromTarget: nil,
	})
}

// the magic cookie after the fixed fields
func dhcpSniff(data []byte, context Context) (score int) {
	if (context.Transport != DatagramTransport) || (len(data) < dhcpFixedBytes+4) || (data[0] < 1) || (data[0] > 2) || (binary.BigEndian.Uint32(data[dhcpFixedBytes:]) != dhcpCookie) {
		return
	}

	score = 100
	return
}

func dhcpDecode(tree *Tree, data []byte, context Context) {
	root := tree.add(nil, dhcpProtocol, dhcpTitle, "", 0, len(data))
	reader := fieldsOf(tree, root, data, 0, len(data))
	operation, _ := reader.number("dhcp.type", "Message type", 1, func(value uint32) (text string) {
		text = map[uint32]string{1: "Boot Request (1)", 2: "Boot Reply (2)"}[value]

		if text == "" {
			text = fmt.Sprintf("Unknown (%d)", value)
		}

		return
	})
	reader.number("dhcp.hw.type", "Hardware type", 1, named(dhcpHardwareTypes))
	hardwareLength, _ := reader.number("dhcp.hw.len", "Hardware address length", 1, nil)
	reader.number("dhcp.hops", "Hops", 1, nil)
	transaction, _ := reader.number("dhcp.id", "Transaction ID", 4, hexWord)
	reader.number("dhcp.secs", "Seconds elapsed", 2, nil)
	flags, ok := reader.number("dhcp.flags", "Bootp flags", 2, func(value uint32) (text string) { text = fmt.Sprintf("0x%04x", value); return })

	if ok {
		flagsNode := root.children[len(root.children)-1]
		tree.addBits(flagsNode, "dhcp.flags.bc", "Broadcast flag", yesNo(flags&0x8000 != 0), 10, 2, 0x8000)
	}

	reader.address("dhcp.ip.client", "Client IP address", 4)
	yours, _ := reader.address("dhcp.ip.your", "Your (client) IP address", 4)
	reader.address("dhcp.ip.server", "Next server IP address", 4)
	reader.address("dhcp.ip.relay", "Relay agent IP address", 4)

	if hardware, start, ok := reader.take("Client hardware address", 16); ok {
		length := min(int(hardwareLength), 16)
		reader.add("dhcp.hw.mac_addr", "Client hardware address", macText(hardware[:length]), start, 16)
	}

	reader.textField("dhcp.server", "Server host name", 64)
	reader.textField("dhcp.file", "Boot file name", 128)

	if reader.isShort {
		tree.addSummary("DHCP message cut short")
		return
	}

	if reader.left() < 4 {
		tree.addSummary("BOOTP")
		return
	}

	cookie, _ := reader.number("dhcp.cookie", "Magic cookie", 4, func(value uint32) (text string) {
		text = fmt.Sprintf("0x%08x", value)

		if value == dhcpCookie {
			text += " DHCP"
		}

		return
	})

	if cookie != dhcpCookie {
		tree.fail(root, fmt.Sprintf("the magic cookie of DHCP is 0x%08x", dhcpCookie))
	}

	messageType := dhcpOptionList(tree, root, data, reader)
	name := "BOOTP"

	if messageType != 0 {
		name = "DHCP " + shortName(dhcpMessageTypes, uint16(messageType))
		root.label = dhcpTitle + " (" + shortName(dhcpMessageTypes, uint16(messageType)) + ")"
	}

	summary := fmt.Sprintf("%s - Transaction ID 0x%08x", name, transaction)

	if (operation == 2) && yours.IsValid() && !yours.IsUnspecified() {
		summary += ", your address " + yours.String()
	}

	tree.addSummary(summary)
}

// the options up to End; messageType is the DHCP message type of option 53, 0 without one
func dhcpOptionList(tree *Tree, root *node, data []byte, reader *cursor) (messageType byte) {
	for (reader.left() > 0) && !reader.isShort && !tree.isFull {
		start := reader.offset
		code := data[start]

		if code == 0 {
			reader.offset++
			continue
		}

		if code == 255 {
			reader.add("dhcp.option.end", "Option (255) End", "", start, 1)
			reader.offset++

			if rest := reader.left(); rest > 0 {
				reader.add("dhcp.option.padding", "Padding", strconv.Itoa(rest)+" bytes", reader.offset, rest)
				reader.offset = reader.end
			}

			return
		}

		if reader.left() < 2 {
			tree.fail(root, "an option header is cut short")
			reader.offset = reader.end
			return
		}

		length := int(data[start+1])
		option := tree.add(root, "dhcp.option", fmt.Sprintf("Option (%d) %s", code, shortName(dhcpOptions, uint16(code))), "", start, min(2+length, reader.left()))
		// an option past the end keeps to the bytes there are, and the options end there
		if 2+length > reader.left() {
			tree.fail(option, fmt.Sprintf("the option runs past its message: %d of its %d bytes are there", reader.left()-2, length))
			length = reader.left() - 2
		}

		inner := reader.vector(option, "Option", 2+length)
		inner.number("dhcp.option.type", "Option", 1, named(dhcpOptions))
		inner.number("dhcp.option.length", "Length", 1, nil)
		option.value = dhcpOptionValue(tree, option, data, inner, code, length)

		if (code == 53) && (length == 1) && !inner.isShort {
			messageType = data[start+2]
		}

		inner.finish()
	}

	tree.fail(root, "the options have no End option")
	return
}

// the value of one option by its type, its text for the option's node
func dhcpOptionValue(tree *Tree, option *node, data []byte, reader *cursor, code byte, length int) (value string) {
	switch code {
	case 1, 28, 32, 50, 54, 118:
		address, _ := reader.address("dhcp.option.ip", shortName(dhcpOptions, uint16(code)), 4)
		value = address.String()
	case 3, 4, 5, 6, 7, 9, 41, 42, 44, 45, 69, 150:
		addresses := []string{}

		for reader.left() >= 4 {
			address, _ := reader.address("dhcp.option.ip", "Address", 4)
			addresses = append(addresses, address.String())
		}

		value = strings.Join(addresses, ", ")
	case 2:
		offset, _ := reader.number("dhcp.option.time_offset", "Time offset", 4, func(value uint32) (text string) { text = fmt.Sprintf("%d s", int32(value)); return })
		value = fmt.Sprintf("%d s", int32(offset))
	case 51, 58, 59, 35:
		seconds, _ := reader.number("dhcp.option.time", shortName(dhcpOptions, uint16(code)), 4, ttlText)
		value = ttlText(seconds)
	case 13, 26, 57:
		number, _ := reader.number("dhcp.option.value", shortName(dhcpOptions, uint16(code)), 2, nil)
		value = strconv.Itoa(int(number))
	case 19, 23, 31, 46, 52, 116:
		number, _ := reader.number("dhcp.option.value", shortName(dhcpOptions, uint16(code)), 1, nil)
		value = strconv.Itoa(int(number))
	case 53:
		messageType, _ := reader.number("dhcp.option.dhcp", "DHCP", 1, named(dhcpMessageTypes))
		value = shortName(dhcpMessageTypes, uint16(messageType))
	case 55:
		names := []string{}

		for reader.left() > 0 {
			requested, _ := reader.number("dhcp.option.request_list_item", "Parameter Request List Item", 1, func(value uint32) (text string) { text = nameOf(dhcpOptions, uint16(value)); return })
			names = append(names, strconv.Itoa(int(requested)))
		}

		value = strings.Join(names, ", ")
	case 61:
		hardwareType, _ := reader.number("dhcp.hw.type", "Hardware type", 1, named(dhcpHardwareTypes))

		if identifier, start, ok := reader.take("Client identifier", reader.left()); ok {
			if (hardwareType == 1) && (len(identifier) == 6) {
				value = macText(identifier)
			} else {
				value = hexValue(identifier)
			}

			reader.add("dhcp.client_id", "Client identifier", value, start, len(identifier))
		}
	case 12, 15, 17, 40, 47, 56, 60, 66, 67, 114, 252:
		text, _ := reader.textField("dhcp.option.text", shortName(dhcpOptions, uint16(code)), length)
		value = textValue(text)
	case 121, 249:
		routes := []string{}

		for (reader.left() > 0) && !reader.isShort {
			width := int(data[reader.offset])

			if width > 32 {
				tree.fail(option, fmt.Sprintf("a route of %d bits", width))
				reader.offset = reader.end
				break
			}

			start := reader.offset
			parts, _, ok := reader.take("Route", 1+(width+7)/8+4)

			if !ok {
				break
			}

			destination := [4]byte{}
			copy(destination[:], parts[1:1+(width+7)/8])
			router := netip.AddrFrom4([4]byte(parts[len(parts)-4:]))
			route := fmt.Sprintf("%s/%d via %s", netip.AddrFrom4(destination), width, router)
			routes = append(routes, route)
			reader.add("dhcp.option.route", "Route", route, start, len(parts))
		}

		value = strings.Join(routes, ", ")
	case 80:
	default:
		if length > 0 {
			bytes, _ := reader.bytesField("dhcp.option.value", "Value", reader.left())
			value = fmt.Sprintf("%d bytes", len(bytes))
		}
	}

	return
}

// a hardware address as colon-separated hex
func macText(data []byte) (text string) {
	parts := make([]string, len(data))

	for index, value := range data {
		parts[index] = fmt.Sprintf("%02x", value)
	}

	text = strings.Join(parts, ":")
	return
}

// a known message type and options that read cleanly to the end; a relay message by its header
func dhcpv6Sniff(data []byte, context Context) (score int) {
	if (context.Transport != DatagramTransport) || (len(data) < 4) || (data[0] < 1) || (data[0] > 17) {
		return
	}

	start := 4

	if (data[0] == 12) || (data[0] == 13) {
		start = dhcpv6RelayBytes
	}

	offset, known := start, 0

	for offset+4 <= len(data) {
		code := binary.BigEndian.Uint16(data[offset:])

		if _, isKnown := dhcpv6Options.names[code]; isKnown {
			known++
		}

		offset += 4 + int(binary.BigEndian.Uint16(data[offset+2:]))
	}

	if (offset == len(data)) && (known > 0) {
		score = 60
	}

	return
}

func dhcpv6Decode(tree *Tree, data []byte, context Context) {
	root := tree.add(nil, dhcpv6Protocol, dhcpv6Title, "", 0, len(data))
	summary := dhcpv6Message(tree, root, data, 0, len(data), 0)
	tree.addSummary(summary)
}

// one message at data[start:end], a relay message nests the message it carries; depth counts the relays
func dhcpv6Message(tree *Tree, root *node, data []byte, start int, end int, depth int) (summary string) {
	reader := fieldsOf(tree, root, data, start, end)
	messageType, ok := reader.number("dhcpv6.msgtype", "Message type", 1, named(dhcpv6Types))

	if !ok {
		summary = "Malformed DHCPv6 message"
		return
	}

	root.label = dhcpv6Title + " (" + shortName(dhcpv6Types, uint16(messageType)) + ")"
	summary = shortName(dhcpv6Types, uint16(messageType))

	if (messageType == 12) || (messageType == 13) {
		reader.number("dhcpv6.hopcount", "Hop count", 1, nil)
		reader.address("dhcpv6.linkaddr", "Link address", 16)
		peer, _ := reader.address("dhcpv6.peeraddr", "Peer address", 16)
		summary += " peer " + peer.String()
	} else {
		transaction, _ := reader.number("dhcpv6.xid", "Transaction ID", 3, func(value uint32) (text string) { text = fmt.Sprintf("0x%06x", value); return })
		summary += fmt.Sprintf(" XID: 0x%06x", transaction)
	}

	if inner := dhcpv6OptionList(tree, root, data, reader, depth); inner != "" {
		summary += ": " + inner
	}

	return
}

// the options from the reader's offset to its end; relayed is the summary of a relay message the options carry
func dhcpv6OptionList(tree *Tree, parent *node, data []byte, reader *cursor, depth int) (relayed string) {
	for (reader.left() > 0) && !reader.isShort && !tree.isFull {
		start := reader.offset

		if reader.left() < 4 {
			tree.fail(parent, "an option header is cut short")
			reader.offset = reader.end
			return
		}

		code := binary.BigEndian.Uint16(data[start:])
		length := int(binary.BigEndian.Uint16(data[start+2:]))
		option := tree.add(parent, "dhcpv6.option", shortName(dhcpv6Options, code), "", start, min(4+length, reader.left()))

		// an option past the end keeps to the bytes there are
		if 4+length > reader.left() {
			tree.fail(option, fmt.Sprintf("the option runs past its message: %d of its %d bytes are there", reader.left()-4, length))
			length = reader.left() - 4
		}

		inner := reader.vector(option, "Option", 4+length)
		inner.number("dhcpv6.option.type", "Option", 2, named(dhcpv6Options))
		inner.number("dhcpv6.option.length", "Length", 2, nil)

		switch code {
		case 1, 2:
			option.value = dhcpv6DUID(inner)
		case 3, 4, 25:
			inner.number("dhcpv6.iaid", "IAID", 4, hexWord)

			if code != 4 {
				inner.number("dhcpv6.iaid.t1", "T1", 4, ttlText)
				inner.number("dhcpv6.iaid.t2", "T2", 4, ttlText)
			}

			dhcpv6OptionList(tree, option, data, inner, depth)
		case 5:
			address, _ := inner.address("dhcpv6.iaaddr.ip", "IPv6 address", 16)
			inner.number("dhcpv6.iaaddr.pref_lifetime", "Preferred lifetime", 4, ttlText)
			inner.number("dhcpv6.iaaddr.valid_lifetime", "Valid lifetime", 4, ttlText)
			option.value = address.String()
			dhcpv6OptionList(tree, option, data, inner, depth)
		case 26:
			inner.number("dhcpv6.iaprefix.pref_lifetime", "Preferred lifetime", 4, ttlText)
			inner.number("dhcpv6.iaprefix.valid_lifetime", "Valid lifetime", 4, ttlText)
			prefixLength, _ := inner.number("dhcpv6.iaprefix.pref_len", "Prefix length", 1, nil)
			prefix, _ := inner.address("dhcpv6.iaprefix.pref_addr", "Prefix address", 16)
			option.value = fmt.Sprintf("%s/%d", prefix, prefixLength)
			dhcpv6OptionList(tree, option, data, inner, depth)
		case 6:
			names := []string{}

			for inner.left() >= 2 {
				requested, _ := inner.number("dhcpv6.requested_option_code", "Requested Option code", 2, named(dhcpv6Options))
				names = append(names, strconv.Itoa(int(requested)))
			}

			option.value = strings.Join(names, ", ")
		case 7:
			preference, _ := inner.number("dhcpv6.preference", "Pref-value", 1, nil)
			option.value = strconv.Itoa(int(preference))
		case 8:
			elapsed, _ := inner.number("dhcpv6.elapsed_time", "Elapsed time", 2, func(value uint32) (text string) { text = fmt.Sprintf("%d ms", 10*value); return })
			option.value = fmt.Sprintf("%d ms", 10*elapsed)
		case 9:
			if depth >= 8 {
				tree.fail(option, "relay messages nest more than 8 deep")
				inner.offset = inner.end
				break
			}

			message := tree.add(option, dhcpv6Protocol, dhcpv6Title, "", inner.offset, inner.left())
			relayed = dhcpv6Message(tree, message, data, inner.offset, inner.end, depth+1)
			inner.offset = inner.end
		case 13:
			status, _ := inner.number("dhcpv6.status_code", "Status Code", 2, named(dhcpv6Statuses))
			text, _ := inner.textField("dhcpv6.status_message", "Status Message", inner.left())
			option.value = shortName(dhcpv6Statuses, uint16(status)) + " " + textValue(text)
		case 12:
			address, _ := inner.address("dhcpv6.unicast", "Server Address", 16)
			option.value = address.String()
		case 21, 23, 31, 22, 27, 56:
			addresses := []string{}

			for inner.left() >= 16 {
				address, _ := inner.address("dhcpv6.address", "Address", 16)
				addresses = append(addresses, address.String())
			}

			option.value = strings.Join(addresses, ", ")
		case 32, 82, 83:
			seconds, _ := inner.number("dhcpv6.time", shortName(dhcpv6Options, code), 4, ttlText)
			option.value = ttlText(seconds)
		case 14, 20:
		default:
			if inner.left() > 0 {
				inner.restField("dhcpv6.option.value", "Value")
			}
		}

		inner.finish()
	}

	return
}

// a DUID: its type, then the hardware type, time and address, the enterprise number and identifier, or the UUID
func dhcpv6DUID(reader *cursor) (value string) {
	duidType, ok := reader.number("dhcpv6.duid.type", "DUID Type", 2, named(duidTypes))

	if !ok {
		return
	}

	switch duidType {
	case 1, 3:
		reader.number("dhcpv6.duid.hwtype", "Hardware type", 2, named(dhcpHardwareTypes))

		if duidType == 1 {
			reader.number("dhcpv6.duid.time", "Time", 4, nil)
		}

		if address, start, ok := reader.take("Link-layer address", reader.left()); ok {
			value = macText(address)
			reader.add("dhcpv6.duid.linklayer", "Link-layer address", value, start, len(address))
		}
	case 2:
		reader.number("dhcpv6.duid.enterprise", "Enterprise number", 4, nil)
		identifier, _ := reader.bytesField("dhcpv6.duid.identifier", "Identifier", reader.left())
		value = hexValue(identifier)
	default:
		identifier, _ := reader.bytesField("dhcpv6.duid.bytes", "Identifier", reader.left())
		value = hexValue(identifier)
	}

	return
}
