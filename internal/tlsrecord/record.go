// SPDX-License-Identifier: AGPL-3.0-only

package tlsrecord

import (
	"fmt"
)

// who sent a record
type Direction uint8

const (
	ClientDirection Direction = 0
	ServerDirection Direction = 1
)

// content type of a record (RFC 8446 section 5.1), for a decrypted TLS 1.3 record the one inside the protection
type ContentType uint8

const (
	ChangeCipherSpecContentType ContentType = 20
	AlertContentType            ContentType = 21
	HandshakeContentType        ContentType = 22
	ApplicationDataContentType  ContentType = 23
)

const (
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// record sizes (RFC 5246 section 6.2, RFC 8446 section 5)
const (
	recordHeaderLength int   = 5
	maxPlaintext       int   = 16384
	maxCiphertext      int   = 16384 + 2048
	maxCiphertextTLS13 int   = 16384 + 256
	recordVersionMajor uint8 = 3
	// record header and the first byte of the handshake message, enough to tell a ClientHello
	clientHelloPrefixLength int = recordHeaderLength + 1
)

// one record in the order its direction sent it, Payload is the plaintext when Decrypted and the bytes on the wire otherwise
// Sequence is the record sequence number under the keys that decrypted it
// Length is the bytes the record took in the stream of its direction, its header included, so a reader knows how far the stream is read
type Record struct {
	Direction   Direction
	ContentType ContentType
	Decrypted   bool
	Sequence    uint64
	Length      int
	Payload     []byte
}

// tell from the first bytes a client sent if they start a TLS session: a handshake record with a ClientHello
// decided is false while data is a possible but too short start, the answer needs more bytes then
func IsClientHello(data []byte) (isClientHello bool, decided bool) {
	// content type and major version of the record header, the minor version and the length can be anything, then the handshake type
	expected := [clientHelloPrefixLength]int{int(HandshakeContentType), int(recordVersionMajor), -1, -1, -1, int(handshakeClientHello)}

	for index := range min(len(data), clientHelloPrefixLength) {
		if (expected[index] >= 0) && (int(data[index]) != expected[index]) {
			decided = true
			return
		}
	}

	if len(data) < clientHelloPrefixLength {
		return
	}

	isClientHello = true
	decided = true
	return
}

// find the first record of buffer, length is the record with its header, complete is false until all of it is there
func frameRecord(buffer []byte) (contentType ContentType, length int, complete bool, err error) {
	if len(buffer) < recordHeaderLength {
		return
	}

	contentType = ContentType(buffer[0])

	switch contentType {
	case
		ChangeCipherSpecContentType,
		AlertContentType,
		HandshakeContentType,
		ApplicationDataContentType:
	default:
		err = fmt.Errorf("%w: content type %d", ErrUnexpectedRecord, contentType)
		return
	}

	if buffer[1] != recordVersionMajor {
		err = fmt.Errorf("%w: record version 0x%02x%02x", ErrUnexpectedRecord, buffer[1], buffer[2])
		return
	}

	length = recordHeaderLength + (int(buffer[3])<<8 | int(buffer[4]))

	if length > recordHeaderLength+maxCiphertext {
		err = fmt.Errorf("%w: %d bytes", ErrRecordOverflow, length-recordHeaderLength)
		return
	}

	complete = len(buffer) >= length
	return
}

func VersionName(version uint16) (name string) {
	switch version {
	case VersionTLS12:
		name = "TLS1.2"
	case VersionTLS13:
		name = "TLS1.3"
	default:
		name = fmt.Sprintf("0x%04x", version)
	}

	return
}
