// SPDX-License-Identifier: AGPL-3.0-only

package tlsrecord

import (
	"encoding/binary"
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
	VersionTLS12  uint16 = 0x0303
	VersionTLS13  uint16 = 0x0304
	VersionDTLS12 uint16 = 0xfefd
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

// what a relay in the middle does with a record of an intercepting conn, a conn that only reads gives every record with ShowAction
type Action uint8

const (
	// the bytes of the record went on already or are not the caller's to write: nothing to send, the record is only shown
	ShowAction Action = 0
	// send Raw as it came, the record is not decrypted (yet)
	ForwardAction Action = 1
	// the record was held until it was decrypted: send Payload, or what the rules made of it, sealed again with an Encrypter
	SealAction Action = 2
)

// one record in the order its direction sent it, Payload is the plaintext when Decrypted and the bytes on the wire otherwise
// Sequence is the record sequence number under the keys that decrypted it
// Length is the bytes the record took in the stream of its direction, its header included, so a reader knows how far the stream is read
// Action and Raw are only set by an intercepting conn: Raw is the record as it came, header included, for ForwardAction and SealAction
// a held record also carries what Encrypter needs: the write protection of its keys, the record header and the TLS 1.3 padding
// a DTLS record has its Epoch and Sequence from its header, Datagram counts the datagrams of its direction and tells which records came in one; header holds its type and version
// Version is the version of the record header as it came (the legacy 0x0303 of TLS 1.3, 0xfefd of DTLS 1.2)
type Record struct {
	Direction   Direction
	ContentType ContentType
	Version     uint16
	Decrypted   bool
	Epoch       uint16
	Sequence    uint64
	Datagram    uint64
	Length      int
	Payload     []byte
	Action      Action
	Raw         []byte
	sealer      *protection
	version     uint16
	header      [recordHeaderLength]byte
	padding     int
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
	case VersionDTLS12:
		name = "DTLS1.2"
	default:
		name = fmt.Sprintf("0x%04x", version)
	}

	return
}

// the record as the history keeps a handshake: a record header with the content type (the inner one of a decrypted TLS 1.3 record), the version of the
// header as it came and the length of the payload, then the payload, the plaintext of a decrypted record; a DTLS record has its 13-byte header with
// its epoch and sequence number
func AppendKept(buffer []byte, record Record, isDTLS bool) (kept []byte) {
	kept = append(buffer, byte(record.ContentType), byte(record.Version>>8), byte(record.Version))

	if isDTLS {
		kept = binary.BigEndian.AppendUint16(kept, record.Epoch)
		kept = append(kept, byte(record.Sequence>>40), byte(record.Sequence>>32), byte(record.Sequence>>24), byte(record.Sequence>>16), byte(record.Sequence>>8), byte(record.Sequence))
	}

	kept = binary.BigEndian.AppendUint16(kept, uint16(len(record.Payload)))
	kept = append(kept, record.Payload...)
	return
}
