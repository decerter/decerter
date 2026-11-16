// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"mime"
	"net/url"
	"strconv"
	"strings"

	v1 "github.com/decerter/decerter/api"
)

// DNS from RFC 1035 (message format, names and compression), RFC 7766 (TCP framing), RFC 7858 (DNS over TLS), RFC 8484 (DoH), RFC 6762 (mDNS),
// RFC 6891 (EDNS), the record types of the files dns_rdata.go and dns_tables.go
const (
	dnsProtocol      string = "dns"
	dnsTitle         string = "Domain Name System"
	mdnsTitle        string = "Multicast Domain Name System"
	dnsHeaderBytes   int    = 12
	dnsMediaType     string = "application/dns-message"
	dnsALPN          string = "dot"
	dnsTargetKey     string = "dns"
	mdnsPort         uint16 = 5353
	maxNameBytes     int    = 255
	maxPointerJumps  int    = 32
	maxSummaryBytes  int    = 512
	maxSummaryValues int    = 4
	// the type of an EDNS OPT record, it has no class and TTL of its own
	optType uint16 = 41
	// the bits of the header flags
	responseFlag      uint16 = 0x8000
	opcodeMask        uint16 = 0x7800
	authoritativeFlag uint16 = 0x0400
	truncatedFlag     uint16 = 0x0200
	recursionFlag     uint16 = 0x0100
	availableFlag     uint16 = 0x0080
	zFlag             uint16 = 0x0040
	authenticFlag     uint16 = 0x0020
	checkingFlag      uint16 = 0x0010
	rcodeMask         uint16 = 0x000f
	// mDNS: the top bit of a question's class asks for a unicast answer, of a record's class flushes the cache
	multicastClassFlag uint16 = 0x8000
)

func init() {
	register(decoder{
		Protocol: dnsProtocol,
		Title:    dnsTitle,
		Ports: []Port{
			{Layer: v1.UDPLayer, Number: 53},
			{Layer: v1.TCPLayer, Number: 53},
			{Layer: v1.UDPLayer, Number: mdnsPort},
			{Layer: v1.UDPLayer, Number: 5355},
			{Layer: v1.TLSLayer, Number: 853},
			{Layer: v1.DTLSLayer, Number: 853},
		},
		hint:       dnsHint,
		sniff:      dnsSniff,
		decode:     dnsDecode,
		fromTarget: dnsFromTarget,
		frame:      dnsFrame,
		pdu:        dnsPDU,
		unit:       "message",
	})
}

// DoH by its media type or the dns parameter of a GET, DNS over TLS by its ALPN
func dnsHint(context Context) (reason string) {
	if context.Transport == BodyTransport {
		mediaType, _, parseErr := mime.ParseMediaType(context.ContentType)

		if (parseErr == nil) && (mediaType == dnsMediaType) {
			reason = "content type " + dnsMediaType + " is DNS over HTTPS"
			return
		}

		if _, found := dnsFromTarget(context.Target); found && (context.Direction == v1.UpDirection) && strings.EqualFold(context.Method, "GET") {
			reason = "the dns parameter of the GET is DNS over HTTPS"
		}

		return
	}

	if (context.Layer == v1.TLSLayer) && (context.ALPN == dnsALPN) {
		reason = "TLS ALPN " + dnsALPN + " is DNS over TLS"
	}

	return
}

// the message of a DoH GET: the dns query parameter in base64url (RFC 8484 4.1, without padding; padding is taken too)
func dnsFromTarget(target string) (data []byte, found bool) {
	_, query, hasQuery := strings.Cut(target, "?")

	if !hasQuery {
		return
	}

	values, parseErr := url.ParseQuery(query)

	if (parseErr != nil) || !values.Has(dnsTargetKey) {
		return
	}

	decoded, decodeErr := base64.RawURLEncoding.DecodeString(strings.TrimRight(values.Get(dnsTargetKey), "="))

	if (decodeErr != nil) || (len(decoded) < dnsHeaderBytes) {
		return
	}

	data, found = decoded, true
	return
}

// a stream starts with the 2-byte length of its first message; 5 for a message that goes on in the next read, the port or a hint still takes it
func dnsSniff(data []byte, context Context) (score int) {
	if context.Transport != StreamTransport {
		score = dnsMessageScore(data)
		return
	}

	if len(data) < 2 {
		return
	}

	length := int(binary.BigEndian.Uint16(data))

	switch {
	case length < dnsHeaderBytes:
	case 2+length > len(data):
		score = 5
	default:
		score = dnsMessageScore(data[2 : 2+length])
	}

	return
}

// how much one message looks like DNS: it has to read without an error to reach the threshold, a known opcode and one question make it likely
func dnsMessageScore(data []byte) (score int) {
	if len(data) < dnsHeaderBytes {
		return
	}

	flags := binary.BigEndian.Uint16(data[2:])
	records := 0

	for index := range 4 {
		records += int(binary.BigEndian.Uint16(data[4+2*index:]))
	}

	if _, isKnown := dnsOpcodes.names[(flags&opcodeMask)>>11]; !isKnown {
		score = 5
		return
	}

	tree := newTree()
	dnsFields(tree, tree.add(nil, dnsProtocol, dnsTitle, "", 0, len(data)), dnsMessage{data: data, base: 0, isMulticast: false, rcode: 0})

	switch {
	case tree.errors > 0:
		score = 10
	case records == 0:
		score = 10
	default:
		score = 70

		if binary.BigEndian.Uint16(data[4:]) == 1 {
			score += 20
		}

		if flags&zFlag == 0 {
			score += 10
		}
	}

	return
}

// one message per datagram or body; a stream is 2-byte lengths each followed by its message (RFC 7766 8), several in one read or the start of one
func dnsDecode(tree *Tree, data []byte, context Context) {
	isMulticast := (context.ServerPort == mdnsPort) && (context.Layer == v1.UDPLayer)

	if context.Transport != StreamTransport {
		root := tree.add(nil, dnsProtocol, titleOf(isMulticast), "", 0, len(data))
		dnsFields(tree, root, dnsMessage{data: data, base: 0, isMulticast: isMulticast, rcode: 0})
		return
	}

	protocol, _ := lookup(dnsProtocol)
	decodeFramed(tree, data, context, protocol)
}

// a message over tcp: its 2-byte length, then the message
func dnsFrame(data []byte, state *streamState) (length int) {
	if len(data) >= 2 {
		length = 2 + int(binary.BigEndian.Uint16(data))
	}

	return
}

func dnsPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	if len(data)-start < 2 {
		root = tree.add(nil, dnsProtocol, dnsTitle, "", start, len(data)-start)
		tree.addSummary("DNS length cut short")
		return
	}

	length := int(binary.BigEndian.Uint16(data[start:]))
	end := min(start+2+length, len(data))
	root = tree.add(nil, dnsProtocol, dnsTitle, "", start, end-start)
	tree.add(root, "dns.length", "Length", strconv.Itoa(length), start, 2)
	dnsFields(tree, root, dnsMessage{data: data[start+2 : end], base: start + 2, isMulticast: false, rcode: 0})
	return
}

func titleOf(isMulticast bool) (title string) {
	title = dnsTitle

	if isMulticast {
		title = mdnsTitle
	}

	return
}

// the header, the four sections and the summary line of one message under root
func dnsFields(tree *Tree, root *node, message dnsMessage) {
	if len(message.data) < dnsHeaderBytes {
		tree.fail(root, fmt.Sprintf("a DNS header has %d bytes, the message %d", dnsHeaderBytes, len(message.data)))
		tree.addSummary("Malformed DNS message")
		return
	}

	base := message.base
	id := binary.BigEndian.Uint16(message.data)
	flags := binary.BigEndian.Uint16(message.data[2:])
	isResponse := flags&responseFlag != 0
	opcode := (flags & opcodeMask) >> 11
	rcode := flags & rcodeMask
	counts := [4]int{}

	for index := range counts {
		counts[index] = int(binary.BigEndian.Uint16(message.data[4+2*index:]))
	}

	kind := "query"

	if isResponse {
		kind = "response"
	}

	root.label = titleOf(message.isMulticast) + " (" + kind + ")"
	tree.add(root, "dns.id", "Transaction ID", fmt.Sprintf("0x%04x", id), base, 2)
	flagsNode := tree.add(root, "dns.flags", "Flags", fmt.Sprintf("0x%04x %s", flags, flagsText(flags)), base+2, 2)
	tree.addBits(flagsNode, "dns.flags.response", "Response", map[bool]string{false: "Message is a query", true: "Message is a response"}[isResponse], base+2, 2, uint32(responseFlag))
	tree.addBits(flagsNode, "dns.flags.opcode", "Opcode", nameOf(dnsOpcodes, opcode), base+2, 2, uint32(opcodeMask))

	if isResponse {
		tree.addBits(flagsNode, "dns.flags.authoritative", "Authoritative", yesNo(flags&authoritativeFlag != 0), base+2, 2, uint32(authoritativeFlag))
	}

	tree.addBits(flagsNode, "dns.flags.truncated", "Truncated", yesNo(flags&truncatedFlag != 0), base+2, 2, uint32(truncatedFlag))
	tree.addBits(flagsNode, "dns.flags.recdesired", "Recursion desired", yesNo(flags&recursionFlag != 0), base+2, 2, uint32(recursionFlag))

	if isResponse {
		tree.addBits(flagsNode, "dns.flags.recavail", "Recursion available", yesNo(flags&availableFlag != 0), base+2, 2, uint32(availableFlag))
	}

	tree.addBits(flagsNode, "dns.flags.z", "Z (reserved)", strconv.Itoa(int((flags&zFlag)>>6)), base+2, 2, uint32(zFlag))
	tree.addBits(flagsNode, "dns.flags.authenticated", "Authentic data", yesNo(flags&authenticFlag != 0), base+2, 2, uint32(authenticFlag))
	tree.addBits(flagsNode, "dns.flags.checkdisable", "Checking disabled", yesNo(flags&checkingFlag != 0), base+2, 2, uint32(checkingFlag))

	if isResponse {
		tree.addBits(flagsNode, "dns.flags.rcode", "Reply code", nameOf(dnsRcodes, rcode), base+2, 2, uint32(rcodeMask))
	}

	countNames := [4][2]string{{"dns.count.queries", "Questions"}, {"dns.count.answers", "Answer RRs"}, {"dns.count.auth_rr", "Authority RRs"}, {"dns.count.add_rr", "Additional RRs"}}

	for index, count := range counts {
		tree.add(root, countNames[index][0], countNames[index][1], strconv.Itoa(count), base+4+2*index, 2)
	}

	// the summary: opcode, id, reply code of a response, the questions and the first answers
	summary := []string{}
	operation := "Standard query"

	if opcode != 0 {
		operation = shortName(dnsOpcodes, opcode)
	}

	if isResponse {
		operation += " response"
	}

	summary = append(summary, fmt.Sprintf("%s 0x%04x", operation, id))

	if isResponse && (rcode != 0) {
		summary = append(summary, nameOf(dnsRcodes, rcode))
	}

	message.rcode = uint8(rcode)
	offset := dnsHeaderBytes
	offset, isRead := dnsQuestions(tree, root, message, offset, counts[0], &summary)
	sections := [3][3]string{{"dns.answers", "Answers", "dns.answer"}, {"dns.authority", "Authoritative nameservers", "dns.authority"}, {"dns.additional", "Additional records", "dns.additional"}}

	for index, section := range sections {
		if !isRead || (counts[index+1] == 0) {
			continue
		}

		var values *[]string

		if index == 0 {
			values = &summary
		}

		offset, isRead = dnsRecords(tree, root, message, offset, counts[index+1], section[0], section[1], values)
	}

	if isRead && !tree.isFull && (offset < len(message.data)) {
		tree.fail(root, fmt.Sprintf("%d bytes after the last record", len(message.data)-offset))
	}

	line := strings.Join(summary, " ")

	if len(line) > maxSummaryBytes {
		line = line[:maxSummaryBytes] + "..."
	}

	tree.addSummary(line)
}

// the question section from offset; isRead is false when a question did not fit, the sections after it can't be found then
func dnsQuestions(tree *Tree, root *node, message dnsMessage, offset int, count int, summary *[]string) (next int, isRead bool) {
	next, isRead = offset, true

	if count == 0 {
		return
	}

	section := tree.add(root, "dns.queries", "Queries", strconv.Itoa(count), message.base+offset, 0)

	for index := 0; (index < count) && !tree.isFull; index++ {
		start := next
		question := tree.add(section, "dns.qry", "Query", "", message.base+start, 0)
		name, nameLength, nameErr := message.name(next)

		if nameErr != nil {
			tree.fail(question, nameErr.Error())
			question.length = len(message.data) - start
			next, isRead = len(message.data), false
			break
		}

		tree.add(question, "dns.qry.name", "Name", name, message.base+next, nameLength)
		next += nameLength

		if next+4 > len(message.data) {
			tree.fail(question, "the question runs past the end of the message")
			question.length = len(message.data) - start
			next, isRead = len(message.data), false
			break
		}

		qType := binary.BigEndian.Uint16(message.data[next:])
		class := binary.BigEndian.Uint16(message.data[next+2:])
		tree.add(question, "dns.qry.type", "Type", nameOf(dnsTypes, qType), message.base+next, 2)

		if message.isMulticast {
			tree.addBits(question, "dns.qry.unicast_response", "Unicast response (QU)", yesNo(class&multicastClassFlag != 0), message.base+next+2, 2, uint32(multicastClassFlag))
			class &^= multicastClassFlag
		}

		tree.add(question, "dns.qry.class", "Class", nameOf(dnsClasses, class), message.base+next+2, 2)
		next += 4
		question.label = fmt.Sprintf("%s: type %s, class %s", name, shortName(dnsTypes, qType), shortName(dnsClasses, class))
		question.length = next - start

		if index < maxSummaryValues {
			*summary = append(*summary, shortName(dnsTypes, qType)+" "+name)
		}
	}

	section.length = next - offset
	return
}

// one section of records from offset under a node of its own; values gets a short form of the first records (the answers for the summary)
func dnsRecords(tree *Tree, root *node, message dnsMessage, offset int, count int, name string, label string, values *[]string) (next int, isRead bool) {
	next, isRead = offset, true
	section := tree.add(root, name, label, strconv.Itoa(count), message.base+offset, 0)

	for index := 0; (index < count) && !tree.isFull; index++ {
		record := tree.add(section, "dns.rr", "Record", "", message.base+next, 0)
		var short string
		next, short, isRead = dnsRecord(tree, record, message, next)

		if !isRead {
			break
		}

		if (values != nil) && (index < maxSummaryValues) {
			*values = append(*values, short)
		}
	}

	section.length = next - offset
	return
}

// one resource record at offset: name, type, class, TTL, rdata length and the typed rdata fields; short is its type and value for the summary
func dnsRecord(tree *Tree, recordNode *node, message dnsMessage, offset int) (next int, short string, isRead bool) {
	base := message.base
	name, nameLength, nameErr := message.name(offset)

	if nameErr != nil {
		tree.fail(recordNode, nameErr.Error())
		recordNode.length = len(message.data) - offset
		next = len(message.data)
		return
	}

	fixed := offset + nameLength

	if fixed+10 > len(message.data) {
		tree.fail(recordNode, errRecordShort.Error())
		recordNode.length = len(message.data) - offset
		next = len(message.data)
		return
	}

	record := dnsResource{
		name:     name,
		rrType:   binary.BigEndian.Uint16(message.data[fixed:]),
		class:    binary.BigEndian.Uint16(message.data[fixed+2:]),
		ttl:      binary.BigEndian.Uint32(message.data[fixed+4:]),
		rdata:    fixed + 10,
		rdLength: int(binary.BigEndian.Uint16(message.data[fixed+8:])),
		end:      fixed + 10 + int(binary.BigEndian.Uint16(message.data[fixed+8:])),
	}
	tree.add(recordNode, "dns.rr.name", "Name", name, base+offset, nameLength)
	tree.add(recordNode, "dns.rr.type", "Type", nameOf(dnsTypes, record.rrType), base+fixed, 2)
	class := record.class

	if record.rrType == optType {
		dnsOPTHeader(tree, recordNode, message, record, fixed)
	} else {
		if message.isMulticast {
			tree.addBits(recordNode, "dns.rr.cache_flush", "Cache flush", yesNo(class&multicastClassFlag != 0), base+fixed+2, 2, uint32(multicastClassFlag))
			class &^= multicastClassFlag
		}

		tree.add(recordNode, "dns.rr.class", "Class", nameOf(dnsClasses, class), base+fixed+2, 2)
		tree.add(recordNode, "dns.rr.ttl", "Time to live", ttlText(record.ttl), base+fixed+4, 4)
	}

	tree.add(recordNode, "dns.rr.rdlength", "Data length", strconv.Itoa(record.rdLength), base+fixed+8, 2)

	if record.end > len(message.data) {
		tree.fail(recordNode, fmt.Sprintf("the rdata runs past the end of the message: %d bytes, %d are left", record.rdLength, len(message.data)-record.rdata))
		recordNode.length = len(message.data) - offset
		next = len(message.data)
		return
	}

	value := dnsRdata(tree, recordNode, message, record)
	short = shortName(dnsTypes, record.rrType)

	if value != "" {
		short += " " + value
	}

	if record.rrType == optType {
		recordNode.label = fmt.Sprintf("%s: type OPT, UDP payload size %d", name, record.class)
	} else {
		recordNode.label = fmt.Sprintf("%s: type %s, class %s", name, shortName(dnsTypes, record.rrType), shortName(dnsClasses, class))

		if value != "" {
			recordNode.label += ", " + value
		}
	}

	recordNode.length = record.end - offset
	next, isRead = record.end, true
	return
}

// the name at offset: its text, the bytes it takes where it is (up to and with its first compression pointer) and an error for a name that is not whole
// a label byte that is no printable ASCII, a dot or a backslash in a label is escaped (\xNN, \\), so the text reads back as the labels
func (message dnsMessage) name(offset int) (name string, length int, err error) {
	builder := strings.Builder{}
	position, jumps, wireLength := offset, 0, 0

	for {
		if position >= len(message.data) {
			err = errNameShort
			return
		}

		labelLength := int(message.data[position])

		switch labelLength >> 6 {
		case 0:
		case 3:
			if position+1 >= len(message.data) {
				err = errNameShort
				return
			}

			if length == 0 {
				length = position + 2 - offset
			}

			jumps++

			if jumps > maxPointerJumps {
				err = errNameLoop
				return
			}

			position = int(binary.BigEndian.Uint16(message.data[position:]) & 0x3fff)
			continue
		default:
			err = fmt.Errorf("%w 0x%02x", errLabelType, labelLength&0xc0)
			return
		}

		wireLength += labelLength + 1

		if wireLength > maxNameBytes {
			err = errNameLong
			return
		}

		if labelLength == 0 {
			if length == 0 {
				length = position + 1 - offset
			}

			break
		}

		if position+1+labelLength > len(message.data) {
			err = errNameShort
			return
		}

		labelText(&builder, message.data[position+1:position+1+labelLength])
		builder.WriteByte('.')
		position += 1 + labelLength
	}

	name = strings.TrimSuffix(builder.String(), ".")

	if name == "" {
		name = "<Root>"
	}

	return
}

// the bytes of one label: printable ASCII as it is, a dot \x2e, a backslash \\, every other byte \xNN
func labelText(builder *strings.Builder, label []byte) {
	for _, value := range label {
		switch {
		case value == '\\':
			builder.WriteString(`\\`)
		case (value > ' ') && (value <= '~') && (value != '.'):
			builder.WriteByte(value)
		default:
			builder.WriteString(`\x`)
			builder.WriteByte(hexDigits[value>>4])
			builder.WriteByte(hexDigits[value&0x0f])
		}
	}
}

// the flags of the header in a few words: query or response, the opcode, and the reply code of a response
func flagsText(flags uint16) (text string) {
	text = shortName(dnsOpcodes, (flags&opcodeMask)>>11) + " query"

	if flags&responseFlag != 0 {
		text = shortName(dnsOpcodes, (flags&opcodeMask)>>11) + " response, " + shortName(dnsRcodes, flags&rcodeMask)
	}

	return
}

func yesNo(isSet bool) (text string) {
	text = "no"

	if isSet {
		text = "yes"
	}

	return
}

func ttlText(ttl uint32) (text string) {
	text = strconv.FormatUint(uint64(ttl), 10)

	if ttl >= 60 {
		text += " (" + durationText(ttl) + ")"
	}

	return
}

// seconds as days, hours, minutes and seconds, the zero parts left out
func durationText(seconds uint32) (text string) {
	parts := []string{}

	for _, unit := range []struct {
		seconds uint32
		name    string
	}{{seconds: 86400, name: "d"}, {seconds: 3600, name: "h"}, {seconds: 60, name: "m"}, {seconds: 1, name: "s"}} {
		if seconds >= unit.seconds {
			parts = append(parts, strconv.FormatUint(uint64(seconds/unit.seconds), 10)+unit.name)
			seconds %= unit.seconds
		}
	}

	text = strings.Join(parts, " ")
	return
}
