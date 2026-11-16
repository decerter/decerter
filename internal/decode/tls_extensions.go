// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/decerter/decerter/internal/output"
)

// the extensions of the hellos and of the TLS 1.3 messages that carry them, from the IANA registry and the RFCs of each (6066, 7301, 7366, 7627, 8422,
// 8446, 8449, 8879, the ECH draft); an extension decerter has no fields for is shown as hex
const (
	serverNameExtension          uint16 = 0
	maxFragmentLengthExtension   uint16 = 1
	statusRequestExtension       uint16 = 5
	supportedGroupsExtension     uint16 = 10
	pointFormatsExtension        uint16 = 11
	signatureAlgorithmsExtension uint16 = 13
	alpnExtension                uint16 = 16
	paddingExtension             uint16 = 21
	compressCertificateExtension uint16 = 27
	recordSizeLimitExtension     uint16 = 28
	preSharedKeyExtension        uint16 = 41
	earlyDataExtension           uint16 = 42
	supportedVersionsExtension   uint16 = 43
	cookieExtension              uint16 = 44
	pskModesExtension            uint16 = 45
	signatureCertExtension       uint16 = 50
	keyShareExtension            uint16 = 51
	alpsOldExtension             uint16 = 17513
	alpsExtension                uint16 = 17613
	echExtension                 uint16 = 65037
	renegotiationExtension       uint16 = 65281
	// the fields of a certificate decerter shows, the names of each kind at most
	maxCertificateNames int = 64
)

// the extensions vector of a message; hello gets what the fingerprints and the summary need, nil for a message without one
func tlsExtensions(reader *cursor, kind helloKind, hello *helloInfo, state *tlsState) {
	length, start, ok := reader.lengthOf("Extensions", 2)

	if !ok {
		return
	}

	listNode := reader.add("tls.handshake.extensions", "Extensions", "", start, 2+min(length, reader.left()))
	inner := reader.vector(listNode, "Extensions", length)
	count := 0

	for (inner.left() > 0) && !inner.isShort && !reader.tree.isFull {
		header, extensionStart, isHeader := inner.take("Extension", 4)

		if !isHeader {
			break
		}

		extensionType, extensionLength := binary.BigEndian.Uint16(header), int(binary.BigEndian.Uint16(header[2:]))
		count++

		if hello != nil {
			hello.extensions = append(hello.extensions, extensionType)
		}

		extensionNode := inner.add("tls.handshake.extension", "Extension: "+tlsShortName(tlsExtensionTypes, extensionType), "", extensionStart, 4+min(extensionLength, inner.left()))
		reader.tree.addAt(extensionNode, reader.place, "tls.handshake.extension.type", "Type", hexNameOf(tlsExtensionTypes, extensionType), extensionStart, 2)
		reader.tree.addAt(extensionNode, reader.place, "tls.handshake.extension.len", "Length", fmt.Sprintf("%d", extensionLength), extensionStart+2, 2)
		body := inner.vector(extensionNode, "Extension data", extensionLength)

		if body.isShort || inner.isShort {
			break
		}

		body.parent = extensionNode
		tlsExtension(body, extensionNode, extensionType, kind, hello, state)
		body.finish()
	}

	reader.tree.setValue(listNode, fmt.Sprintf("%d", count))
}

// the data of one extension
func tlsExtension(reader *cursor, extensionNode *node, extensionType uint16, kind helloKind, hello *helloInfo, state *tlsState) {
	if hello == nil {
		hello = &helloInfo{}
	}

	isClient := kind == clientHelloKind

	switch {
	case reader.left() == 0:
		reader.tree.setValue(extensionNode, "(empty)")

		if (extensionType == serverNameExtension) && isClient {
			hello.hasServerName = true
		}
	case extensionType == serverNameExtension:
		hello.hasServerName = true
		tlsServerNames(reader, extensionNode, hello)
	case extensionType == maxFragmentLengthExtension:
		reader.number("tls.handshake.max_fragment_length", "Maximum fragment length", 1, named(tlsMaxFragments))
	case (extensionType == statusRequestExtension) && isClient:
		value, _ := reader.number("tls.handshake.extensions_status_request_type", "Status type", 1, named(tlsStatusTypes))
		reader.tree.setValue(extensionNode, tlsShortName(tlsStatusTypes, uint16(value)))
		reader.opaque("tls.handshake.extensions_status_request_responder_ids", "Responder ID list", 2)
		reader.opaque("tls.handshake.extensions_status_request_exts", "Request extensions", 2)
	case extensionType == statusRequestExtension:
		reader.number("tls.handshake.status_type", "Status type", 1, named(tlsStatusTypes))
		reader.opaque("tls.handshake.ocsp_response", "OCSP response", 3)
	case extensionType == supportedGroupsExtension:
		values, _ := reader.list("tls.handshake.extensions_supported_groups", "Supported groups", "tls.handshake.extensions_supported_group", "Group", 2, 2, hexNamed(tlsGroups))
		hello.groups = asUint16(values)
		reader.tree.setValue(extensionNode, shortNames(tlsGroups, hello.groups))
	case extensionType == pointFormatsExtension:
		values, _ := reader.list("tls.handshake.extensions_ec_point_formats", "EC point formats", "tls.handshake.extensions_ec_point_format", "EC point format", 1, 1, named(tlsPointFormats))
		hello.pointFormats = asUint16(values)
	case (extensionType == signatureAlgorithmsExtension) || (extensionType == signatureCertExtension):
		values, _ := reader.list("tls.handshake.sig_hash_algs", "Signature algorithms", "tls.handshake.sig_hash_alg", "Signature algorithm", 2, 2, hexNamed(tlsSignatureSchemes))

		if extensionType == signatureAlgorithmsExtension {
			hello.signatures = asUint16(values)
		}

		reader.tree.setValue(extensionNode, fmt.Sprintf("%d algorithms", len(values)))
	case extensionType == alpnExtension:
		hello.alpn, hello.firstALPN = tlsProtocolNames(reader, "tls.handshake.extensions_alpn_str", "ALPN protocol")
		reader.tree.setValue(extensionNode, strings.Join(hello.alpn, ", "))
	case (extensionType == alpsExtension) || (extensionType == alpsOldExtension):
		if isClient {
			protocols, _ := tlsProtocolNames(reader, "tls.handshake.extensions_alps_alpn_str", "Protocol")
			reader.tree.setValue(extensionNode, strings.Join(protocols, ", "))
			return
		}

		tlsRest(reader, "tls.handshake.extensions_alps_settings", "Settings")
	case extensionType == paddingExtension:
		reader.tree.setValue(extensionNode, fmt.Sprintf("%d bytes", reader.left()))
		tlsRest(reader, "tls.handshake.extensions_padding_data", "Padding")
	case extensionType == compressCertificateExtension:
		reader.list("tls.handshake.compress_certificate.algorithms", "Algorithms", "tls.handshake.compress_certificate.algorithm", "Algorithm", 1, 2, hexNamed(tlsCertCompressions))
	case extensionType == recordSizeLimitExtension:
		value, _ := reader.number("tls.handshake.record_size_limit", "Record size limit", 2, nil)
		reader.tree.setValue(extensionNode, fmt.Sprintf("%d", value))
	case extensionType == preSharedKeyExtension:
		tlsPreSharedKey(reader, extensionNode, isClient)
	case extensionType == earlyDataExtension:
		reader.number("tls.handshake.max_early_data_size", "Maximum early data size", 4, nil)
	case (extensionType == supportedVersionsExtension) && isClient:
		values, _ := reader.list("tls.handshake.extensions.supported_versions", "Supported versions", "tls.handshake.extensions.supported_version", "Supported version", 1, 2, hexNamed(tlsVersions))
		hello.versions = asUint16(values)
		reader.tree.setValue(extensionNode, shortNames(tlsVersions, hello.versions))
	case extensionType == supportedVersionsExtension:
		value, _ := reader.number("tls.handshake.extensions.supported_version", "Selected version", 2, hexNamed(tlsVersions))
		hello.selectedVersion = uint16(value)
		reader.tree.setValue(extensionNode, tlsShortName(tlsVersions, uint16(value)))
	case extensionType == cookieExtension:
		reader.opaque("tls.handshake.extensions.cookie", "Cookie", 2)
	case extensionType == pskModesExtension:
		reader.list("tls.extension.psk_ke_modes", "PSK key exchange modes", "tls.extension.psk_ke_mode", "Mode", 1, 1, named(tlsPSKModes))
	case extensionType == keyShareExtension:
		tlsKeyShare(reader, extensionNode, kind)
	case extensionType == echExtension:
		tlsECH(reader, extensionNode, kind)
	case extensionType == renegotiationExtension:
		reader.opaque("tls.handshake.extensions_reneg_info", "Renegotiated connection", 1)
	default:
		tlsRest(reader, "tls.handshake.extension.data", "Data")
	}
}

// the rest of an extension's data as hex
func tlsRest(reader *cursor, name string, label string) {
	data := reader.data[reader.offset:reader.end]
	reader.add(name, label, hexValue(data), reader.offset, len(data))
	reader.offset = reader.end
}

func asUint16(values []uint32) (converted []uint16) {
	for _, value := range values {
		converted = append(converted, uint16(value))
	}

	return
}

// the names of values joined, at most 8 of them
func shortNames(table nameTable, values []uint16) (text string) {
	names := []string{}

	for index, value := range values {
		if index == 8 {
			names = append(names, "...")
			break
		}

		names = append(names, tlsShortName(table, value))
	}

	text = strings.Join(names, ", ")
	return
}

// server_name: a list of names with their type, a host name is text from the traffic
func tlsServerNames(reader *cursor, extensionNode *node, hello *helloInfo) {
	length, start, ok := reader.lengthOf("Server name list", 2)

	if !ok {
		return
	}

	listNode := reader.add("tls.handshake.extensions_server_name_list", "Server name list", "", start, 2+min(length, reader.left()))
	inner := reader.vector(listNode, "Server name list", length)

	for (inner.left() > 0) && !inner.isShort {
		inner.number("tls.handshake.extensions_server_name_type", "Server name type", 1, named(tlsServerNameTypes))
		nameLength, nameStart, isLength := inner.lengthOf("Server name", 2)
		name, _, isName := inner.take("Server name", nameLength)

		if !isLength || !isName {
			return
		}

		escaped := output.Escape(name)
		inner.add("tls.handshake.extensions_server_name", "Server name", escaped, nameStart, 2+nameLength)

		if hello.serverName == "" {
			hello.serverName = escaped
			reader.tree.setValue(extensionNode, escaped)
		}
	}
}

// a list of protocol names with a 1-byte length each, in a vector with a 2-byte length (ALPN, ALPS)
// first is the first protocol as it came, for JA4
func tlsProtocolNames(reader *cursor, name string, label string) (protocols []string, first []byte) {
	length, start, ok := reader.lengthOf("Protocol list", 2)

	if !ok {
		return
	}

	listNode := reader.add(name+"_list", "Protocol list", "", start, 2+min(length, reader.left()))
	inner := reader.vector(listNode, "Protocol list", length)

	for (inner.left() > 0) && !inner.isShort {
		protocolLength, protocolStart, isLength := inner.lengthOf(label, 1)
		protocol, _, isProtocol := inner.take(label, protocolLength)

		if !isLength || !isProtocol {
			break
		}

		escaped := output.Escape(protocol)
		protocols = append(protocols, escaped)

		if first == nil {
			first = bytes.Clone(protocol)
		}

		inner.add(name, label, escaped, protocolStart, 1+protocolLength)
	}

	reader.tree.setValue(listNode, strings.Join(protocols, ", "))
	return
}

// pre_shared_key: the identities with their ticket age and the binders of a ClientHello, the identity a ServerHello selected
func tlsPreSharedKey(reader *cursor, extensionNode *node, isClient bool) {
	if !isClient {
		value, _ := reader.number("tls.handshake.extensions.psk.identity.selected", "Selected identity", 2, nil)
		reader.tree.setValue(extensionNode, fmt.Sprintf("identity %d", value))
		return
	}

	length, start, ok := reader.lengthOf("Identities", 2)

	if !ok {
		return
	}

	identities := reader.add("tls.handshake.extensions.psk.identities", "Identities", "", start, 2+min(length, reader.left()))
	inner := reader.vector(identities, "Identities", length)
	count := 0

	for (inner.left() > 0) && !inner.isShort {
		inner.opaque("tls.handshake.extensions.psk.identity.identity", "Identity", 2)
		inner.number("tls.handshake.extensions.psk.identity.obfuscated_ticket_age", "Obfuscated ticket age", 4, nil)
		count++
	}

	reader.tree.setValue(identities, fmt.Sprintf("%d", count))
	length, start, ok = reader.lengthOf("Binders", 2)

	if !ok {
		return
	}

	binders := reader.add("tls.handshake.extensions.psk.binders", "Binders", "", start, 2+min(length, reader.left()))
	inner = reader.vector(binders, "Binders", length)

	for (inner.left() > 0) && !inner.isShort {
		inner.opaque("tls.handshake.extensions.psk.binder", "Binder", 1)
	}

	reader.tree.setValue(extensionNode, fmt.Sprintf("%d identities", count))
}

// key_share: the groups and key lengths a ClientHello offers, the one a ServerHello answers with, the group a HelloRetryRequest asks for
func tlsKeyShare(reader *cursor, extensionNode *node, kind helloKind) {
	switch kind {
	case helloRetryKind:
		value, _ := reader.number("tls.handshake.extensions_key_share_selected_group", "Selected group", 2, hexNamed(tlsGroups))
		reader.tree.setValue(extensionNode, tlsShortName(tlsGroups, uint16(value)))
	case clientHelloKind:
		length, start, ok := reader.lengthOf("Client shares", 2)

		if !ok {
			return
		}

		shares := reader.add("tls.handshake.extensions_key_share_client_length", "Client key shares", "", start, 2+min(length, reader.left()))
		inner := reader.vector(shares, "Client key shares", length)
		groups := []string{}

		for (inner.left() > 0) && !inner.isShort {
			groups = append(groups, tlsKeyShareEntry(inner))
		}

		reader.tree.setValue(shares, strings.Join(groups, ", "))
		reader.tree.setValue(extensionNode, shares.value)
	default:
		reader.tree.setValue(extensionNode, tlsKeyShareEntry(reader))
	}
}

// one key share: a group and its key, text is the group with the key's length
func tlsKeyShareEntry(reader *cursor) (text string) {
	header, start, ok := reader.take("Key share entry", 4)

	if !ok {
		return
	}

	group, length := binary.BigEndian.Uint16(header), int(binary.BigEndian.Uint16(header[2:]))
	text = fmt.Sprintf("%s %d bytes", tlsShortName(tlsGroups, group), length)
	entry := reader.add("tls.handshake.extensions_key_share_entry", "Key share entry: "+text, "", start, 4+min(length, reader.left()))
	reader.tree.addAt(entry, reader.place, "tls.handshake.extensions_key_share_group", "Group", hexNameOf(tlsGroups, group), start, 2)
	reader.tree.addAt(entry, reader.place, "tls.handshake.extensions_key_share_key_exchange_length", "Key exchange length", fmt.Sprintf("%d", length), start+2, 2)
	key, keyStart, ok := reader.take("Key exchange", length)

	if ok {
		reader.tree.addAt(entry, reader.place, "tls.handshake.extensions_key_share_key_exchange", "Key exchange", hexValue(key), keyStart, length)
	}

	return
}

// encrypted_client_hello: an outer ClientHello's HPKE suite, config id, encapsulated key and payload, an inner one's type alone; the retry configs of
// EncryptedExtensions and the confirmation of a HelloRetryRequest as hex
func tlsECH(reader *cursor, extensionNode *node, kind helloKind) {
	if kind != clientHelloKind {
		reader.tree.setValue(extensionNode, "present")
		tlsRest(reader, "tls.handshake.extensions_ech_data", map[bool]string{false: "Retry configs", true: "Confirmation"}[kind == helloRetryKind])
		return
	}

	echType, _ := reader.number("tls.ech.client_hello_type", "Client hello type", 1, named(tlsECHTypes))
	reader.tree.setValue(extensionNode, "present ("+tlsShortName(tlsECHTypes, uint16(echType))+")")

	if echType != 0 {
		return
	}

	reader.number("tls.ech.hpke.keyschedule.kdf_id", "KDF", 2, hexNamed(tlsHPKEKDFs))
	reader.number("tls.ech.hpke.keyschedule.aead_id", "AEAD", 2, hexNamed(tlsHPKEAEADs))
	reader.number("tls.ech.config_id", "Config ID", 1, nil)
	reader.opaque("tls.ech.enc", "Encapsulated key", 2)
	reader.opaque("tls.ech.payload", "Payload", 2)
}

// the certificate list: TLS 1.3 with a request context and extensions per entry, TLS 1.2 without; each certificate read with crypto/x509
// without a ServerHello in the decode (a client's Certificate) the form that fits the bytes is taken; summary names the first subject
func tlsCertificates(reader *cursor, state *tlsState) (summary string) {
	summary = "Certificate"
	isTLS13 := (state.version == tls13Version) || (state.version == dtls13Version)

	if state.version == 0 {
		rest := reader.data[reader.offset:reader.end]
		isTLS13 = (len(rest) < 3) || (int(uint32(rest[0])<<16|uint32(rest[1])<<8|uint32(rest[2])) != len(rest)-3)
	}

	if isTLS13 {
		reader.opaque("tls.handshake.certificate_request_context", "Request context", 1)
	}

	length, start, ok := reader.lengthOf("Certificates", 3)

	if !ok {
		return
	}

	listNode := reader.add("tls.handshake.certificates", "Certificates", "", start, 3+min(length, reader.left()))
	inner := reader.vector(listNode, "Certificates", length)
	count := 0

	for (inner.left() > 0) && !inner.isShort && !reader.tree.isFull {
		certificateLength, certificateStart, isLength := inner.lengthOf("Certificate", 3)
		der, _, isCertificate := inner.take("Certificate", certificateLength)

		if !isLength || !isCertificate {
			break
		}

		count++
		subject := tlsCertificate(inner, der, certificateStart, certificateLength)

		if count == 1 && (subject != "") {
			summary += " " + subject
		}

		if isTLS13 {
			tlsExtensions(inner, certificateKind, nil, state)
		}
	}

	reader.tree.setValue(listNode, fmt.Sprintf("%d", count))
	return
}

// one certificate: its subject, issuer, validity, serial number, algorithms and subject alternative names, every node over its DER bytes
func tlsCertificate(reader *cursor, der []byte, start int, length int) (subject string) {
	certificateNode := reader.add("tls.handshake.certificate", "Certificate", fmt.Sprintf("%d bytes", length), start, 3+length)
	tree, place, derStart := reader.tree, reader.place, start+3
	certificate, parseErr := x509.ParseCertificate(der)

	if parseErr != nil {
		tree.fail(certificateNode, "crypto/x509 could not read it: "+output.Escape([]byte(parseErr.Error())))
		tree.addAt(certificateNode, place, "x509.der", "DER", hexValue(der), derStart, length)
		return
	}

	subject = cappedText(certificate.Subject.String())
	tree.setLabel(certificateNode, "Certificate: "+subject)
	add := func(name string, label string, value string) {
		tree.addAt(certificateNode, place, name, label, value, derStart, length)
	}
	add("x509.subject", "Subject", subject)
	add("x509.issuer", "Issuer", cappedText(certificate.Issuer.String()))
	add("x509.serial_number", "Serial number (hex)", cappedText(certificate.SerialNumber.Text(16)))
	add("x509.not_before", "Not before", certificate.NotBefore.UTC().Format(time.RFC3339))
	add("x509.not_after", "Not after", certificate.NotAfter.UTC().Format(time.RFC3339))
	add("x509.public_key_algorithm", "Public key algorithm", certificate.PublicKeyAlgorithm.String())
	add("x509.signature_algorithm", "Signature algorithm", certificate.SignatureAlgorithm.String())

	if certificate.IsCA {
		add("x509.ca", "CA", "yes")
	}

	names := []string{}

	for _, name := range certificate.DNSNames[:min(len(certificate.DNSNames), maxCertificateNames)] {
		names = append(names, "DNS:"+cappedText(name))
	}

	for _, address := range certificate.IPAddresses[:min(len(certificate.IPAddresses), maxCertificateNames)] {
		names = append(names, "IP:"+address.String())
	}

	for _, email := range certificate.EmailAddresses[:min(len(certificate.EmailAddresses), maxCertificateNames)] {
		names = append(names, "email:"+cappedText(email))
	}

	for _, uri := range certificate.URIs[:min(len(certificate.URIs), maxCertificateNames)] {
		names = append(names, "URI:"+cappedText(uri.String()))
	}

	if len(names) > 0 {
		sanNode := tree.addAt(certificateNode, place, "x509.san", "Subject alternative names", fmt.Sprintf("%d", len(names)), derStart, length)

		for _, name := range names {
			tree.addAt(sanNode, place, "x509.san.name", "Name", name, derStart, length)
		}
	}

	return
}

// text a certificate holds, escaped, at most maxTextBytes
func cappedText(text string) (capped string) {
	data := []byte(text)
	capped = output.Escape(data[:min(len(data), maxTextBytes)])

	if len(data) > maxTextBytes {
		capped += "..."
	}

	return
}
