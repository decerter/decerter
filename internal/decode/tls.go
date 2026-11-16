// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	v1 "github.com/decerter/decerter/api"
)

// TLS records and the handshake from RFC 5246 (TLS 1.2) and RFC 8446 (TLS 1.3), DTLS from RFC 6347 and RFC 9147, the extensions of tls_extensions.go
// a payload is records in order: the handshake records decerter kept of a flow (their plaintext, a decrypted record with its inner content type), or records
// as they went over a tcp stream or a udp datagram; a handshake message over several TLS records is put together, a DTLS fragment is shown as it is
const (
	tlsProtocol              string = "tls"
	tlsTitle                 string = "Transport Layer Security"
	dtlsProtocol             string = "dtls"
	dtlsTitle                string = "Datagram Transport Layer Security"
	tlsRecordHeaderBytes     int    = 5
	dtlsRecordHeaderBytes    int    = 13
	tlsHandshakeHeaderBytes  int    = 4
	dtlsHandshakeHeaderBytes int    = 12
	// the largest record a peer may send: 2^14 bytes and the expansion of the protection
	maxRecordBytes int = 1<<14 + 2048
	// the content types
	changeCipherSpecType uint8 = 20
	alertType            uint8 = 21
	handshakeType        uint8 = 22
	applicationDataType  uint8 = 23
	heartbeatType        uint8 = 24
	// the handshake types decerter reads the fields of
	helloRequestType        uint8  = 0
	clientHelloType         uint8  = 1
	serverHelloType         uint8  = 2
	helloVerifyRequestType  uint8  = 3
	newSessionTicketType    uint8  = 4
	endOfEarlyDataType      uint8  = 5
	encryptedExtensionsType uint8  = 8
	certificateType         uint8  = 11
	serverKeyExchangeType   uint8  = 12
	certificateRequestType  uint8  = 13
	serverHelloDoneType     uint8  = 14
	certificateVerifyType   uint8  = 15
	clientKeyExchangeType   uint8  = 16
	finishedType            uint8  = 20
	certificateStatusType   uint8  = 22
	keyUpdateType           uint8  = 24
	tls13Version            uint16 = 0x0304
	dtls13Version           uint16 = 0xfefc
	tlsSniffHello           int    = 90
	tlsSniffRecord          int    = 60
	tlsSniffPartial         int    = 30
)

// the random of a ServerHello that is a HelloRetryRequest, SHA-256 of "HelloRetryRequest" (RFC 8446 4.1.3)
var helloRetryRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

func init() {
	register(decoder{
		Protocol:   tlsProtocol,
		Title:      tlsTitle,
		Ports:      []Port{{Layer: v1.TCPLayer, Number: 443}},
		hint:       tlsHint,
		sniff:      tlsSniff,
		decode:     tlsDecode,
		fromTarget: nil,
	})
	register(decoder{
		Protocol:   dtlsProtocol,
		Title:      dtlsTitle,
		Ports:      nil,
		hint:       dtlsHint,
		sniff:      dtlsSniff,
		decode:     dtlsDecode,
		fromTarget: nil,
	})
}

func tlsHint(context Context) (reason string) {
	if context.Handshake && (context.Layer == v1.TLSLayer) {
		reason = "the handshake records decerter kept of the TLS flow"
	}

	return
}

func dtlsHint(context Context) (reason string) {
	if context.Handshake && (context.Layer == v1.DTLSLayer) {
		reason = "the handshake records decerter kept of the DTLS flow"
	}

	return
}

// a record header of a known content type and version 3.x; a ClientHello or ServerHello makes it certain
func tlsSniff(data []byte, context Context) (score int) {
	if (context.Transport != StreamTransport) || (len(data) < tlsRecordHeaderBytes) {
		return
	}

	contentType, length := data[0], int(binary.BigEndian.Uint16(data[3:]))

	if (contentType < changeCipherSpecType) || (contentType > heartbeatType) || (data[1] != 3) || (data[2] > 4) || (length > maxRecordBytes) {
		return
	}

	switch {
	case (contentType == handshakeType) && (len(data) > tlsRecordHeaderBytes) && ((data[5] == clientHelloType) || (data[5] == serverHelloType)):
		score = tlsSniffHello
	case tlsRecordHeaderBytes+length <= len(data):
		score = tlsSniffRecord
	default:
		score = tlsSniffPartial
	}

	return
}

// a DTLS record header of a known content type and version, or the unified header of an encrypted DTLS 1.3 record
func dtlsSniff(data []byte, context Context) (score int) {
	if context.Transport != DatagramTransport {
		return
	}

	if (len(data) > 0) && (data[0]&0xe0 == 0x20) {
		score = protobufPartialScore
		return
	}

	if len(data) < dtlsRecordHeaderBytes {
		return
	}

	contentType, length := data[0], int(binary.BigEndian.Uint16(data[11:]))

	if (contentType < changeCipherSpecType) || (contentType > 26) || (data[1] != 0xfe) || ((data[2] != 0xff) && (data[2] != 0xfd) && (data[2] != 0xfc)) || (length > maxRecordBytes) {
		return
	}

	switch {
	case (contentType == handshakeType) && (len(data) > dtlsRecordHeaderBytes) && (data[13] <= helloVerifyRequestType):
		score = tlsSniffHello
	case dtlsRecordHeaderBytes+length <= len(data):
		score = tlsSniffRecord
	default:
		score = tlsSniffPartial
	}

	return
}

func tlsDecode(tree *Tree, data []byte, context Context) {
	state := &tlsState{isDTLS: false, isKept: context.Handshake, version: 0, cipherSuite: 0, isEncrypted: false, pending: nil, pendingTotal: 0, segments: nil, summary: nil}
	tlsRecords(tree, data, state)
}

func dtlsDecode(tree *Tree, data []byte, context Context) {
	state := &tlsState{isDTLS: true, isKept: context.Handshake, version: 0, cipherSuite: 0, isEncrypted: false, pending: nil, pendingTotal: 0, segments: nil, summary: nil}
	tlsRecords(tree, data, state)
}

// the records of data in order, each a root; the summary lists the messages
func tlsRecords(tree *Tree, data []byte, state *tlsState) {
	headerBytes, title := tlsRecordHeaderBytes, "TLS"

	if state.isDTLS {
		headerBytes, title = dtlsRecordHeaderBytes, "DTLS"
	}

	offset := 0
	var last *node

	for (offset < len(data)) && !tree.isFull {
		if state.isDTLS && (data[offset]&0xe0 == 0x20) {
			offset = dtlsUnifiedRecord(tree, data, offset, state)
			continue
		}

		if len(data)-offset < headerBytes {
			root := tree.add(nil, "tls.record", title+" record", "", offset, len(data)-offset)
			tree.fail(root, fmt.Sprintf("the %d-byte record header is cut short, %d bytes are here", headerBytes, len(data)-offset))
			state.summary = append(state.summary, "record header cut short")
			break
		}

		contentType := data[offset]
		length := int(binary.BigEndian.Uint16(data[offset+headerBytes-2:]))
		available := min(length, len(data)-offset-headerBytes)
		root := tree.add(nil, "tls.record", title+" record: "+tlsShortName(tlsContentTypes, uint16(contentType)), "", offset, headerBytes+available)
		last = root
		reader := newCursor(tree, root, data, offset, offset+headerBytes, at(0))
		reader.number("tls.record.content_type", "Content type", 1, named(tlsContentTypes))
		reader.number("tls.record.version", "Version", 2, hexNamed(tlsVersions))

		if state.isDTLS {
			epoch, _ := reader.number("dtls.record.epoch", "Epoch", 2, nil)
			// a record of an epoch after 0 is protected on the wire; the handshake decerter kept has its plaintext
			state.isEncrypted = !state.isKept && (epoch != 0)
			sequence, start, _ := reader.take("Sequence number", 6)
			reader.add("dtls.record.sequence_number", "Sequence number", fmt.Sprintf("%d", uint64(binary.BigEndian.Uint16(sequence))<<32|uint64(binary.BigEndian.Uint32(sequence[2:]))), start, 6)
		}

		reader.number("tls.record.length", "Length", 2, nil)
		bodyStart := offset + headerBytes
		offset = bodyStart + available

		if available < length {
			tree.fail(root, fmt.Sprintf("the record goes on past the end of the data: %d of its %d bytes are here", available, length))
		}

		names := tlsRecordBody(tree, root, data, bodyStart, offset, contentType, state)

		if len(names) > 0 {
			root.label += ": " + strings.Join(names, ", ")
		}
	}

	if (state.pending != nil) && (last != nil) {
		tree.fail(last, fmt.Sprintf("a handshake message goes on past the end of the data: %d of its %d bytes are here", len(state.pending), state.pendingTotal))
	}

	tree.addSummary(strings.Join(state.summary, ", "))
}

// the content of one record from start to end; names are what it holds, for its label
func tlsRecordBody(tree *Tree, root *node, data []byte, start int, end int, contentType uint8, state *tlsState) (names []string) {
	switch {
	case contentType == changeCipherSpecType:
		reader := newCursor(tree, root, data, start, end, at(0))
		reader.number("tls.change_cipher_spec", "Change Cipher Spec message", 1, named(tlsChangeCipherSpecs))
		reader.finish()
		state.summary = append(state.summary, "Change Cipher Spec")

		// what a peer sends after it before TLS 1.3 is protected; the handshake decerter kept has its plaintext
		if !state.isKept && (state.version != tls13Version) {
			state.isEncrypted = true
		}
	case (contentType == alertType) && (state.isEncrypted || ((end-start)%2 != 0)):
		tree.add(root, "tls.alert_message", "Encrypted alert", hexValue(data[start:end]), start, end-start)
		state.summary = append(state.summary, "Encrypted Alert")
	case contentType == alertType:
		for offset := start; offset+2 <= end; offset += 2 {
			level, description := uint16(data[offset]), uint16(data[offset+1])
			text := tlsShortName(tlsAlertLevels, level) + " " + tlsShortName(tlsAlertDescriptions, description)
			alert := tree.add(root, "tls.alert_message", "Alert: "+text, "", offset, 2)
			tree.add(alert, "tls.alert_message.level", "Level", nameOf(tlsAlertLevels, level), offset, 1)
			tree.add(alert, "tls.alert_message.desc", "Description", nameOf(tlsAlertDescriptions, description), offset+1, 1)
			names = append(names, text)
			state.summary = append(state.summary, "Alert "+text)
		}
	case (contentType == handshakeType) && state.isEncrypted:
		tree.add(root, "tls.handshake", "Encrypted handshake message", hexValue(data[start:end]), start, end-start)
		state.summary = append(state.summary, "Encrypted Handshake Message")
	case (contentType == handshakeType) && state.isDTLS:
		names = dtlsHandshakes(tree, root, data, start, end, state)
	case contentType == handshakeType:
		names = tlsHandshakes(tree, root, data, start, end, state)
	case contentType == applicationDataType:
		tree.add(root, "tls.app_data", "Encrypted application data", hexValue(data[start:end]), start, end-start)
		state.summary = append(state.summary, "Application Data")
	default:
		tree.add(root, "tls.record.data", "Data", hexValue(data[start:end]), start, end-start)
		state.summary = append(state.summary, tlsShortName(tlsContentTypes, uint16(contentType)))
	}

	return
}

// the handshake messages of one TLS record; a message that goes on in the next record is kept in state until it is whole, then decoded as a root
func tlsHandshakes(tree *Tree, root *node, data []byte, start int, end int, state *tlsState) (names []string) {
	offset := start

	for offset < end {
		if state.pending != nil {
			need := state.pendingTotal - len(state.pending)

			// the 4-byte header itself was cut, its length is known once it is whole
			if state.pendingTotal == 0 {
				need = tlsHandshakeHeaderBytes - len(state.pending)
			}

			taken := min(need, end-offset)
			tree.add(root, "tls.handshake.fragment", "Handshake message fragment", fmt.Sprintf("%d bytes", taken), offset, taken)
			state.segments = append(state.segments, segment{from: len(state.pending), at: offset, length: taken})
			state.pending = append(state.pending, data[offset:offset+taken]...)
			offset += taken

			if (state.pendingTotal == 0) && (len(state.pending) == tlsHandshakeHeaderBytes) {
				state.pendingTotal = tlsHandshakeHeaderBytes + int(uint32(state.pending[1])<<16|uint32(state.pending[2])<<8|uint32(state.pending[3]))
			}

			if (state.pendingTotal != 0) && (len(state.pending) == state.pendingTotal) {
				first, last := state.segments[0], state.segments[len(state.segments)-1]
				reassembled := tree.add(nil, "tls.handshake.reassembled", fmt.Sprintf("Reassembled handshake message (%d fragments)", len(state.segments)), "", first.at, last.at+last.length-first.at)
				names = append(names, "fragment")
				tlsMessage(tree, reassembled, state.pending, pieces(state.segments), state)
				state.pending, state.pendingTotal, state.segments = nil, 0, nil
			}

			continue
		}

		if end-offset < tlsHandshakeHeaderBytes {
			state.pending, state.pendingTotal = bytes.Clone(data[offset:end]), 0
			state.segments = []segment{{from: 0, at: offset, length: end - offset}}
			tree.add(root, "tls.handshake.fragment", "Handshake message fragment", fmt.Sprintf("%d bytes of a message header", end-offset), offset, end-offset)
			return
		}

		length := int(uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
		total := tlsHandshakeHeaderBytes + length

		if end-offset < total {
			state.pending, state.pendingTotal = bytes.Clone(data[offset:end]), total
			state.segments = []segment{{from: 0, at: offset, length: end - offset}}
			name := tlsShortName(tlsHandshakeTypes, uint16(data[offset]))
			tree.add(root, "tls.handshake.fragment", "Handshake message fragment", fmt.Sprintf("%d bytes of a %d-byte %s", end-offset, total, name), offset, end-offset)
			names = append(names, name+" (fragment)")
			return
		}

		names = append(names, tlsMessage(tree, root, data[offset:offset+total], at(offset), state))
		offset += total
	}

	return
}

// the handshake messages of one DTLS record, each with its 12-byte header; a fragment of a message is shown, not put together
func dtlsHandshakes(tree *Tree, root *node, data []byte, start int, end int, state *tlsState) (names []string) {
	offset := start

	for offset < end {
		if end-offset < dtlsHandshakeHeaderBytes {
			fragment := tree.add(root, "dtls.handshake.fragment", "Handshake data", hexValue(data[offset:end]), offset, end-offset)
			tree.fail(fragment, fmt.Sprintf("the %d-byte handshake header is cut short, %d bytes are here", dtlsHandshakeHeaderBytes, end-offset))
			return
		}

		length := int(uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
		fragmentOffset := int(uint32(data[offset+6])<<16 | uint32(data[offset+7])<<8 | uint32(data[offset+8]))
		fragmentLength := int(uint32(data[offset+9])<<16 | uint32(data[offset+10])<<8 | uint32(data[offset+11]))
		total := min(dtlsHandshakeHeaderBytes+fragmentLength, end-offset)
		name := tlsShortName(tlsHandshakeTypes, uint16(data[offset]))

		if (fragmentOffset == 0) && (fragmentLength == length) && (dtlsHandshakeHeaderBytes+length <= end-offset) {
			names = append(names, tlsMessage(tree, root, data[offset:offset+total], at(offset), state))
			offset += total
			continue
		}

		message := tree.add(root, "tls.handshake", "Handshake: "+name+" (fragment)", fmt.Sprintf("bytes %d to %d of %d", fragmentOffset, fragmentOffset+fragmentLength, length), offset, total)
		reader := newCursor(tree, message, data, offset, offset+total, at(0))
		dtlsHandshakeHeader(reader)
		reader.add("dtls.handshake.fragment", "Fragment data", hexValue(data[reader.offset:offset+total]), reader.offset, offset+total-reader.offset)

		if dtlsHandshakeHeaderBytes+fragmentLength > end-offset {
			tree.fail(message, fmt.Sprintf("the fragment runs past the end of the record: %d of its %d bytes are here", total-dtlsHandshakeHeaderBytes, fragmentLength))
		}

		names = append(names, name+" (fragment)")
		state.summary = append(state.summary, name+" (fragment)")
		offset += total
	}

	return
}

// an encrypted DTLS 1.3 record with the unified header (RFC 9147 4): flags, a connection id decerter can't tell the length of, the sequence number and the length
func dtlsUnifiedRecord(tree *Tree, data []byte, offset int, state *tlsState) (next int) {
	flags := data[offset]
	root := tree.add(nil, "dtls.record", "DTLS 1.3 encrypted record", "", offset, len(data)-offset)
	tree.addBits(root, "dtls.unified.cid", "Connection ID present", yesNo(flags&0x10 != 0), offset, 1, 0x10)
	tree.addBits(root, "dtls.unified.s", "16-bit sequence number", yesNo(flags&0x08 != 0), offset, 1, 0x08)
	tree.addBits(root, "dtls.unified.l", "Length present", yesNo(flags&0x04 != 0), offset, 1, 0x04)
	tree.addBits(root, "dtls.unified.epoch", "Epoch (low bits)", fmt.Sprintf("%d", flags&0x03), offset, 1, 0x03)
	state.summary = append(state.summary, "Encrypted Record")
	next = len(data)

	if flags&0x10 != 0 {
		tree.fail(root, "a connection id of a length decerter does not know, the rest of the datagram is shown as one record")
		tree.add(root, "dtls.record.data", "Data", hexValue(data[offset+1:]), offset+1, len(data)-offset-1)
		return
	}

	reader := newCursor(tree, root, data, offset+1, len(data), at(0))
	reader.number("dtls.record.sequence_number", "Sequence number (low bits)", map[bool]int{false: 1, true: 2}[flags&0x08 != 0], nil)
	length := reader.left()

	if flags&0x04 != 0 {
		value, _ := reader.number("dtls.record.length", "Length", 2, nil)
		length = int(value)
	}

	encrypted, _, ok := reader.take("Encrypted record", length)

	if ok {
		reader.add("dtls.record.data", "Encrypted record", hexValue(encrypted), reader.offset-length, length)
		next = reader.offset
		root.length = next - offset
	}

	return
}

// the header of a DTLS handshake message after its type and length
func dtlsHandshakeHeader(reader *cursor) {
	reader.number("tls.handshake.type", "Handshake type", 1, named(tlsHandshakeTypes))
	reader.number("tls.handshake.length", "Length", 3, nil)
	reader.number("dtls.handshake.message_seq", "Message sequence", 2, nil)
	reader.number("dtls.handshake.fragment_offset", "Fragment offset", 3, nil)
	reader.number("dtls.handshake.fragment_length", "Fragment length", 3, nil)
}

// one whole handshake message under parent, its header included; name is its type for the label of its record
func tlsMessage(tree *Tree, parent *node, message []byte, place placement, state *tlsState) (name string) {
	messageType := message[0]
	name = tlsShortName(tlsHandshakeTypes, uint16(messageType))

	if (messageType == serverHelloType) && (len(message) >= 4+2+32) && bytes.Equal(message[6:38], helloRetryRandom) && !state.isDTLS {
		name = "Hello Retry Request"
	}

	messageNode := tree.addAt(parent, place, "tls.handshake", "Handshake: "+name, "", 0, len(message))
	reader := newCursor(tree, messageNode, message, 0, len(message), place)
	summary := name

	if state.isDTLS {
		dtlsHandshakeHeader(reader)
	} else {
		reader.number("tls.handshake.type", "Handshake type", 1, named(tlsHandshakeTypes))
		reader.number("tls.handshake.length", "Length", 3, nil)
	}

	switch messageType {
	case clientHelloType:
		hello := tlsClientHello(reader, state)
		summary = tlsClientSummary(hello)
		tlsClientFingerprints(tree, messageNode, place, len(message), hello, state.isDTLS)
	case serverHelloType:
		hello := tlsServerHello(reader, state, name == "Hello Retry Request")
		summary = tlsServerSummary(name, hello)
		tlsServerFingerprints(tree, messageNode, place, len(message), hello)
	case helloVerifyRequestType:
		reader.number("tls.handshake.version", "Server version", 2, hexNamed(tlsVersions))
		reader.opaque("dtls.handshake.cookie", "Cookie", 1)
	case newSessionTicketType:
		tlsNewSessionTicket(reader, state)
	case encryptedExtensionsType:
		tlsExtensions(reader, encryptedExtensionsKind, nil, state)
	case certificateType:
		summary = tlsCertificates(reader, state)
	case serverKeyExchangeType:
		tlsServerKeyExchange(reader)
	case certificateRequestType:
		tlsCertificateRequest(reader, state)
	case certificateVerifyType:
		reader.number("tls.handshake.sig_hash_alg", "Signature algorithm", 2, hexNamed(tlsSignatureSchemes))
		reader.opaque("tls.handshake.sig", "Signature", 2)
	case clientKeyExchangeType:
		tlsClientKeyExchange(reader)
	case finishedType:
		reader.add("tls.handshake.verify_data", "Verify data", hexValue(message[reader.offset:]), reader.offset, reader.left())
		reader.offset = reader.end
	case certificateStatusType:
		reader.number("tls.handshake.status_type", "Status type", 1, named(tlsStatusTypes))
		reader.opaque("tls.handshake.ocsp_response", "OCSP response", 3)
	case keyUpdateType:
		reader.number("tls.handshake.key_update", "Request update", 1, named(tlsKeyUpdates))
	case
		helloRequestType,
		endOfEarlyDataType,
		serverHelloDoneType:
	default:
		if reader.left() > 0 {
			reader.add("tls.handshake.data", "Message data", hexValue(message[reader.offset:]), reader.offset, reader.left())
			reader.offset = reader.end
		}
	}

	reader.finish()
	state.summary = append(state.summary, summary)
	return
}

// a ClientHello: version, random, session id, the DTLS cookie, the cipher suites, the compression methods and the extensions
func tlsClientHello(reader *cursor, state *tlsState) (hello helloInfo) {
	version, _ := reader.number("tls.handshake.version", "Version", 2, hexNamed(tlsVersions))
	hello.version = uint16(version)
	tlsRandom(reader)
	reader.opaque("tls.handshake.session_id", "Session ID", 1)

	if state.isDTLS {
		reader.opaque("dtls.handshake.cookie", "Cookie", 1)
	}

	suites, _ := reader.list("tls.handshake.ciphersuites", "Cipher suites", "tls.handshake.ciphersuite", "Cipher suite", 2, 2, hexNamed(tlsCipherSuites))

	for _, suite := range suites {
		hello.ciphers = append(hello.ciphers, uint16(suite))
	}

	reader.list("tls.handshake.comp_methods", "Compression methods", "tls.handshake.comp_method", "Compression method", 1, 1, named(tlsCompressions))

	if reader.left() > 0 {
		tlsExtensions(reader, clientHelloKind, &hello, state)
	}

	return
}

// a ServerHello or a HelloRetryRequest: version, random, session id, the cipher suite, the compression method and the extensions; the version and the
// suite it selects tell how later messages of the decode read
func tlsServerHello(reader *cursor, state *tlsState, isRetry bool) (hello helloInfo) {
	version, _ := reader.number("tls.handshake.version", "Version", 2, hexNamed(tlsVersions))
	hello.version = uint16(version)
	tlsRandom(reader)
	reader.opaque("tls.handshake.session_id", "Session ID", 1)
	suite, _ := reader.number("tls.handshake.ciphersuite", "Cipher suite", 2, hexNamed(tlsCipherSuites))
	hello.ciphers = []uint16{uint16(suite)}
	reader.number("tls.handshake.comp_method", "Compression method", 1, named(tlsCompressions))
	kind := serverHelloKind

	if isRetry {
		kind = helloRetryKind
	}

	if reader.left() > 0 {
		tlsExtensions(reader, kind, &hello, state)
	}

	hello.selected = hello.version

	if hello.selectedVersion != 0 {
		hello.selected = hello.selectedVersion
	}

	if !isRetry {
		state.version, state.cipherSuite = hello.selected, uint16(suite)
	}

	return
}

func tlsRandom(reader *cursor) {
	random, start, ok := reader.take("Random", 32)

	if ok {
		reader.add("tls.handshake.random", "Random", hexValue(random), start, 32)
	}
}

// TLS 1.3: lifetime, age add, nonce, ticket and extensions; TLS 1.2: lifetime hint and ticket; without a ServerHello in the decode the fields that fit tell
func tlsNewSessionTicket(reader *cursor, state *tlsState) {
	isTLS13 := (state.version == tls13Version) || (state.version == dtls13Version)

	if state.version == 0 {
		rest := reader.data[reader.offset:reader.end]
		isTLS13 = (len(rest) < 6) || (int(binary.BigEndian.Uint16(rest[4:])) != len(rest)-6)
	}

	reader.number("tls.handshake.session_ticket_lifetime_hint", "Ticket lifetime (seconds)", 4, nil)

	if !isTLS13 {
		reader.opaque("tls.handshake.session_ticket", "Session ticket", 2)
		return
	}

	reader.number("tls.handshake.session_ticket_age_add", "Ticket age add", 4, nil)
	reader.opaque("tls.handshake.session_ticket_nonce", "Ticket nonce", 1)
	reader.opaque("tls.handshake.session_ticket", "Session ticket", 2)
	tlsExtensions(reader, newSessionTicketKind, nil, state)
}

// ECDHE parameters with a named curve, the public key and the signature; other key exchanges as bytes
func tlsServerKeyExchange(reader *cursor) {
	if (reader.left() == 0) || (reader.data[reader.offset] != 3) {
		reader.add("tls.handshake.server_params", "Server parameters", hexValue(reader.data[reader.offset:reader.end]), reader.offset, reader.left())
		reader.offset = reader.end
		return
	}

	reader.number("tls.handshake.server_curve_type", "Curve type", 1, named(tlsCurveTypes))
	reader.number("tls.handshake.server_named_curve", "Named curve", 2, hexNamed(tlsGroups))
	reader.opaque("tls.handshake.server_point", "Public key", 1)

	if reader.left() > 0 {
		reader.number("tls.handshake.sig_hash_alg", "Signature algorithm", 2, hexNamed(tlsSignatureSchemes))
		reader.opaque("tls.handshake.sig", "Signature", 2)
	}
}

// TLS 1.3: the request context and extensions; TLS 1.2: the certificate types, the signature algorithms and the certificate authorities
func tlsCertificateRequest(reader *cursor, state *tlsState) {
	if (state.version == tls13Version) || (state.version == dtls13Version) {
		reader.opaque("tls.handshake.certificate_request_context", "Request context", 1)
		tlsExtensions(reader, certificateRequestKind, nil, state)
		return
	}

	reader.list("tls.handshake.cert_types", "Certificate types", "tls.handshake.cert_type", "Certificate type", 1, 1, nil)
	reader.list("tls.handshake.sig_hash_algs", "Signature algorithms", "tls.handshake.sig_hash_alg", "Signature algorithm", 2, 2, hexNamed(tlsSignatureSchemes))
	reader.opaque("tls.handshake.dnames", "Certificate authorities", 2)
}

// an ECDHE public key has a 1-byte length, an RSA-encrypted secret or a DH value a 2-byte one
func tlsClientKeyExchange(reader *cursor) {
	rest := reader.data[reader.offset:reader.end]

	switch {
	case (len(rest) > 1) && (int(rest[0]) == len(rest)-1):
		reader.opaque("tls.handshake.client_point", "Public key", 1)
	case (len(rest) > 2) && (int(binary.BigEndian.Uint16(rest)) == len(rest)-2):
		reader.opaque("tls.handshake.epms", "Encrypted secret or public value", 2)
	default:
		reader.add("tls.handshake.client_params", "Client parameters", hexValue(rest), reader.offset, len(rest))
		reader.offset = reader.end
	}
}

// the summary of a ClientHello: its server name and ALPN protocols
func tlsClientSummary(hello helloInfo) (summary string) {
	summary = "Client Hello"

	if hello.serverName != "" {
		summary += " SNI " + hello.serverName
	}

	if len(hello.alpn) > 0 {
		summary += " ALPN " + strings.Join(hello.alpn, ",")
	}

	return
}

// the summary of a ServerHello: the version and the cipher suite it selects
func tlsServerSummary(name string, hello helloInfo) (summary string) {
	summary = name + " " + tlsShortName(tlsVersions, hello.selected)

	if len(hello.ciphers) > 0 {
		summary += " " + tlsShortName(tlsCipherSuites, hello.ciphers[0])
	}

	if len(hello.alpn) > 0 {
		summary += " ALPN " + hello.alpn[0]
	}

	return
}
