// SPDX-License-Identifier: AGPL-3.0-only

package tlsrecord

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// handshake message types (RFC 8446 section 4, RFC 5246 section 7.4)
const (
	handshakeClientHello         uint8 = 1
	handshakeServerHello         uint8 = 2
	handshakeEncryptedExtensions uint8 = 8
	handshakeFinished            uint8 = 20
	handshakeKeyUpdate           uint8 = 24
	// message type and a 24 bit length
	handshakeHeaderLength int = 4
	// the messages that are read are short, a longer one is not buffered
	maxHandshake int = 65536
)

// extensions (IANA TLS ExtensionType Values registry)
const (
	extensionServerName        uint16 = 0
	extensionALPN              uint16 = 16
	extensionEncryptThenMAC    uint16 = 22
	extensionEarlyData         uint16 = 42
	extensionSupportedVersions uint16 = 43
	serverNameHostName         uint8  = 0
)

// version is the highest the client offers: from supported_versions, the legacy version without it
type clientHello struct {
	random     [randomLength]byte
	version    uint16
	serverName string
	protocols  []string
	earlyData  bool
}

// what a filter reads of a ClientHello: the highest version it offers, the first host name of server_name and the ALPN protocols, empty when it has none
// ClientRandom names the session in secrets_map, the API's key log export looks the flow's secrets up with it
type Hello struct {
	Version      uint16
	ServerName   string
	Protocols    []string
	ClientRandom [randomLength]byte
}

type serverHello struct {
	random            [randomLength]byte
	version           uint16
	cipherSuite       uint16
	protocol          string
	encryptThenMAC    bool
	helloRetryRequest bool
}

// the ServerHello.random of a HelloRetryRequest is the SHA-256 of "HelloRetryRequest" (RFC 8446 section 4.1.3)
var helloRetryRequestRandom = sha256.Sum256([]byte("HelloRetryRequest"))

// the messages the record layer needs, every other message is skipped without buffering it
func isReadHandshake(messageType uint8) (isRead bool) {
	switch messageType {
	case
		handshakeClientHello,
		handshakeServerHello,
		handshakeEncryptedExtensions,
		handshakeFinished,
		handshakeKeyUpdate:
		isRead = true
	default:
	}

	return
}

// ClientHello (RFC 8446 section 4.1.2), the layout up to the extensions is the same in TLS 1.2; DTLS has a cookie behind the session id (RFC 6347 section 4.2.1)
func parseClientHello(body []byte, hasCookie bool) (hello clientHello, err error) {
	input := cryptobyte.String(body)
	var legacyVersion uint16
	var sessionID, cookie, cipherSuites, compressionMethods cryptobyte.String

	if !input.ReadUint16(&legacyVersion) || !input.CopyBytes(hello.random[:]) || !input.ReadUint8LengthPrefixed(&sessionID) || (hasCookie && !input.ReadUint8LengthPrefixed(&cookie)) || !input.ReadUint16LengthPrefixed(&cipherSuites) || !input.ReadUint8LengthPrefixed(&compressionMethods) {
		err = fmt.Errorf("%w: client hello", ErrMalformedHandshake)
		return
	}

	hello.version = legacyVersion
	extensions, extensionsErr := parseExtensions(input)

	if err = extensionsErr; err != nil {
		err = fmt.Errorf("%w: client hello", err)
		return
	}

	for extensionType, extensionData := range extensions {
		ok := true

		switch extensionType {
		case extensionServerName:
			hello.serverName, ok = parseServerName(extensionData)
		case extensionALPN:
			hello.protocols, ok = parseProtocols(extensionData)
		case extensionEarlyData:
			hello.earlyData = true
		case extensionSupportedVersions:
			hello.version, ok = parseSupportedVersions(extensionData, legacyVersion)
		default:
		}

		if !ok {
			err = fmt.Errorf("%w: client hello extension %d", ErrMalformedHandshake, extensionType)
			return
		}
	}

	return
}

// ServerHello (RFC 8446 section 4.1.3), TLS 1.3 is selected in supported_versions, the legacy version stays TLS 1.2
func parseServerHello(body []byte) (hello serverHello, err error) {
	input := cryptobyte.String(body)
	var sessionID cryptobyte.String
	var compressionMethod uint8

	if !input.ReadUint16(&hello.version) || !input.CopyBytes(hello.random[:]) || !input.ReadUint8LengthPrefixed(&sessionID) || !input.ReadUint16(&hello.cipherSuite) || !input.ReadUint8(&compressionMethod) {
		err = fmt.Errorf("%w: server hello", ErrMalformedHandshake)
		return
	}

	hello.helloRetryRequest = hello.random == helloRetryRequestRandom
	extensions, extensionsErr := parseExtensions(input)

	if err = extensionsErr; err != nil {
		err = fmt.Errorf("%w: server hello", err)
		return
	}

	for extensionType, extensionData := range extensions {
		ok := true

		switch extensionType {
		case extensionSupportedVersions:
			ok = extensionData.ReadUint16(&hello.version) && extensionData.Empty()
		case extensionALPN:
			hello.protocol, ok = parseSelectedProtocol(extensionData)
		case extensionEncryptThenMAC:
			hello.encryptThenMAC = true
		default:
		}

		if !ok {
			err = fmt.Errorf("%w: server hello extension %d", ErrMalformedHandshake, extensionType)
			return
		}
	}

	return
}

// EncryptedExtensions (RFC 8446 section 4.3.1), only the selected ALPN protocol is read
func parseEncryptedExtensions(body []byte) (protocol string, err error) {
	extensions, extensionsErr := parseExtensions(cryptobyte.String(body))

	if err = extensionsErr; err != nil {
		err = fmt.Errorf("%w: encrypted extensions", err)
		return
	}

	extensionData, found := extensions[extensionALPN]

	if !found {
		return
	}

	protocol, ok := parseSelectedProtocol(extensionData)

	if !ok {
		err = fmt.Errorf("%w: encrypted extensions extension %d", ErrMalformedHandshake, extensionALPN)
	}

	return
}

// the extension block at the end of a hello, a TLS 1.2 hello may end without one
func parseExtensions(input cryptobyte.String) (extensions map[uint16]cryptobyte.String, err error) {
	extensions = map[uint16]cryptobyte.String{}

	if input.Empty() {
		return
	}

	var block cryptobyte.String

	if !input.ReadUint16LengthPrefixed(&block) || !input.Empty() {
		err = ErrMalformedHandshake
		return
	}

	for !block.Empty() {
		var extensionType uint16
		var extensionData cryptobyte.String

		if !block.ReadUint16(&extensionType) || !block.ReadUint16LengthPrefixed(&extensionData) {
			err = ErrMalformedHandshake
			return
		}

		extensions[extensionType] = extensionData
	}

	return
}

// server_name (RFC 6066 section 3), the first host name of the list
func parseServerName(extensionData cryptobyte.String) (serverName string, ok bool) {
	var names cryptobyte.String

	if !extensionData.ReadUint16LengthPrefixed(&names) || !extensionData.Empty() {
		return
	}

	for !names.Empty() {
		var nameType uint8
		var name cryptobyte.String

		if !names.ReadUint8(&nameType) || !names.ReadUint16LengthPrefixed(&name) {
			return
		}

		if (nameType == serverNameHostName) && (serverName == "") {
			serverName = string(name)
		}
	}

	ok = true
	return
}

// application_layer_protocol_negotiation (RFC 7301 section 3.1)
func parseProtocols(extensionData cryptobyte.String) (protocols []string, ok bool) {
	var names cryptobyte.String

	if !extensionData.ReadUint16LengthPrefixed(&names) || !extensionData.Empty() {
		return
	}

	for !names.Empty() {
		var name cryptobyte.String

		if !names.ReadUint8LengthPrefixed(&name) {
			return
		}

		protocols = append(protocols, string(name))
	}

	ok = true
	return
}

// the server answers with a list of exactly one protocol
func parseSelectedProtocol(extensionData cryptobyte.String) (protocol string, ok bool) {
	protocols, ok := parseProtocols(extensionData)

	if !ok || (len(protocols) != 1) {
		ok = false
		return
	}

	protocol = protocols[0]
	return
}

// supported_versions of a ClientHello (RFC 8446 section 4.2.1), the highest version that is no GREASE value (RFC 8701)
// DTLS counts down (0xfefd is DTLS 1.2, 0xfefc DTLS 1.3), so the lowest number of a DTLS list is its highest version
func parseSupportedVersions(extensionData cryptobyte.String, legacyVersion uint16) (version uint16, ok bool) {
	var versions cryptobyte.String

	if !extensionData.ReadUint8LengthPrefixed(&versions) || !extensionData.Empty() {
		return
	}

	isDTLS := (legacyVersion >> 8) == uint16(dtlsVersionMajor)

	for !versions.Empty() {
		var offered uint16

		if !versions.ReadUint16(&offered) {
			return
		}

		if offered&0x0F0F == 0x0A0A {
			continue
		}

		switch {
		case version == 0:
			version = offered
		case isDTLS:
			version = min(version, offered)
		default:
			version = max(version, offered)
		}
	}

	if version == 0 {
		version = legacyVersion
	}

	ok = true
	return
}

// read the ClientHello at the start of the client's TCP stream, it can take more than one record and more than one segment
// isComplete is false while more bytes are needed; data that does not start with a ClientHello, or one that can't be read, is an error
func ReadClientHello(data []byte) (hello Hello, isComplete bool, err error) {
	var message []byte
	offset := 0

	for {
		contentType, length, complete, frameErr := frameRecord(data[offset:])

		if err = frameErr; err != nil {
			return
		}

		if !complete {
			return
		}

		if contentType != HandshakeContentType {
			err = fmt.Errorf("%w: content type %d before the client hello is whole", ErrUnexpectedRecord, contentType)
			return
		}

		message = append(message, data[offset+recordHeaderLength:offset+length]...)
		offset += length

		if len(message) < handshakeHeaderLength {
			continue
		}

		if message[0] != handshakeClientHello {
			err = fmt.Errorf("%w: handshake message %d instead of a client hello", ErrUnexpectedRecord, message[0])
			return
		}

		bodyLength := int(message[1])<<16 | int(message[2])<<8 | int(message[3])

		if bodyLength > maxHandshake {
			err = fmt.Errorf("%w: client hello of %d bytes", ErrRecordOverflow, bodyLength)
			return
		}

		if len(message) < handshakeHeaderLength+bodyLength {
			continue
		}

		hello, err = toHello(message[handshakeHeaderLength:handshakeHeaderLength+bodyLength], false)
		isComplete = err == nil
		return
	}
}

// read the DTLS ClientHello of the first datagram of a client, isComplete is false when it is fragmented over more datagrams
func ReadDTLSClientHello(datagram []byte) (hello Hello, isComplete bool, err error) {
	if !IsDTLSClientHello(datagram) {
		err = fmt.Errorf("%w: no dtls client hello", ErrUnexpectedRecord)
		return
	}

	recordLength := int(binary.BigEndian.Uint16(datagram[dtlsLengthOffset:]))
	record := datagram[dtlsRecordHeaderLength:min(len(datagram), dtlsRecordHeaderLength+recordLength)]

	if len(record) < dtlsHandshakeHeaderLength {
		err = fmt.Errorf("%w: dtls client hello header", ErrMalformedHandshake)
		return
	}

	// message type, length, message sequence, fragment offset, fragment length
	bodyLength := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	fragmentOffset := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	fragmentLength := int(record[9])<<16 | int(record[10])<<8 | int(record[11])

	if (fragmentOffset != 0) || (fragmentLength != bodyLength) || (len(record) < dtlsHandshakeHeaderLength+bodyLength) {
		return
	}

	hello, err = toHello(record[dtlsHandshakeHeaderLength:dtlsHandshakeHeaderLength+bodyLength], true)
	isComplete = err == nil
	return
}

func toHello(body []byte, isDTLS bool) (hello Hello, err error) {
	parsed, parseErr := parseClientHello(body, isDTLS)

	if err = parseErr; err != nil {
		return
	}

	hello = Hello{
		Version:      parsed.version,
		ServerName:   parsed.serverName,
		Protocols:    parsed.protocols,
		ClientRandom: parsed.random,
	}
	return
}
