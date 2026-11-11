// SPDX-License-Identifier: AGPL-3.0-only

package tlsrecord

import (
	"bytes"
	"fmt"
)

// which keys protect the next record of a direction
type keyPhase uint8

const (
	plaintextPhase   keyPhase = 0 // no protection yet
	handshakePhase   keyPhase = 1 // TLS 1.3 handshake traffic keys
	applicationPhase keyPhase = 2 // TLS 1.2 keys after ChangeCipherSpec, TLS 1.3 application traffic keys
)

// the secrets of one session as the NSS key log carries them: the master key for TLS 1.2, the four traffic secrets for TLS 1.3
type Secrets struct {
	Version                      uint16
	MasterKey                    []byte
	ClientHandshakeTrafficSecret []byte
	ServerHandshakeTrafficSecret []byte
	ClientTrafficSecret          []byte
	ServerTrafficSecret          []byte
}

// what the handshake told about the session, Version and CipherSuite are zero until the ServerHello, Protocol is the ALPN protocol the server selected
type Session struct {
	ClientRandom     [randomLength]byte
	ServerName       string
	OfferedProtocols []string
	Protocol         string
	Version          uint16
	CipherSuite      uint16
}

// bytes that arrived while a record waited for the secrets
type heldChunk struct {
	direction Direction
	data      []byte
}

// one direction of the record layer
// buffer holds the bytes of the stream that are not a whole record yet, or the record that waits for the secrets and what came with it
// handshake holds the start of a handshake message that goes on in the next record, handshakeSkip the rest of a message nothing is read from
// sequence is the read sequence number: the records decrypted under the current keys, it restarts with every key change
// sequenceOffset is added to it for the write sequence number once records are split or merged on the way (re-encryption), it is always zero while records are only read
type half struct {
	direction      Direction
	buffer         []byte
	handshake      []byte
	handshakeSkip  int
	phase          keyPhase
	protection     *protection
	trafficSecret  []byte
	sequence       uint64
	sequenceOffset int64
}

// the record layer of one TLS session seen from the middle: both directions are fed as they pass and come out as records, decrypted once the secrets are set
// while a protected record has no keys yet everything that follows waits in the hold queue in its order of arrival, both directions in one queue
type Conn struct {
	holdLimit      int
	halves         [2]half
	session        Session
	serverRandom   [randomLength]byte
	hasClientHello bool
	suite          *cipherSuite
	suiteTLS13     *cipherSuiteTLS13
	encryptThenMAC bool
	secrets        Secrets
	hasSecrets     bool
	waiting        bool
	held           []heldChunk
	heldBytes      int
	err            error
}

// holdLimit is the most bytes that may wait for the secrets
func New(holdLimit int) (conn Conn) {
	conn = Conn{
		holdLimit: holdLimit,
		halves: [2]half{
			{direction: ClientDirection, buffer: nil, handshake: nil, handshakeSkip: 0, phase: plaintextPhase, protection: nil, trafficSecret: nil, sequence: 0, sequenceOffset: 0},
			{direction: ServerDirection, buffer: nil, handshake: nil, handshakeSkip: 0, phase: plaintextPhase, protection: nil, trafficSecret: nil, sequence: 0, sequenceOffset: 0},
		},
		session:        Session{},
		serverRandom:   [randomLength]byte{},
		hasClientHello: false,
		suite:          nil,
		suiteTLS13:     nil,
		encryptThenMAC: false,
		secrets:        Secrets{},
		hasSecrets:     false,
		waiting:        false,
		held:           nil,
		heldBytes:      0,
		err:            nil,
	}
	return
}

// add the next bytes one direction sent, data is copied; records are the records that are complete now, in the order of the stream
// the payload of a decrypted record stays valid, nothing is written to it later
// an error is final: the stream is not TLS this package can read, every later call returns it again
func (conn *Conn) Feed(direction Direction, data []byte) (records []Record, err error) {
	if err = conn.err; err != nil {
		return
	}

	// hold queue: nothing passes a record that waits for the secrets, so the records of both directions come out in their order
	if conn.waiting {
		conn.held = append(conn.held, heldChunk{direction: direction, data: bytes.Clone(data)})
		conn.heldBytes += len(data)
	} else {
		records, err = conn.feed(direction, data, records)
	}

	if (err == nil) && (conn.heldBytes+len(conn.halves[ClientDirection].buffer)+len(conn.halves[ServerDirection].buffer) > conn.holdLimit) {
		err = fmt.Errorf("%w: limit %d", ErrHoldQueueFull, conn.holdLimit)
	}

	conn.err = err
	return
}

// set the secrets of the session, they can come before the keys are needed or while records wait for them; records are the records the hold queue gives back
func (conn *Conn) SetSecrets(secrets Secrets) (records []Record, err error) {
	if err = conn.err; err != nil {
		return
	}

	defer func() {
		conn.err = err
	}()

	conn.secrets = secrets
	conn.hasSecrets = true
	conn.waiting = false
	held := conn.held
	conn.held = nil
	conn.heldBytes = 0

	// the record that waited is in the buffer of its direction
	for index := range conn.halves {
		half := &conn.halves[index]

		if (half.phase != plaintextPhase) && (half.protection == nil) {
			err = conn.protect(half)

			if err != nil {
				return
			}
		}

		records, err = conn.process(half, records)

		if err != nil {
			return
		}
	}

	for _, chunk := range held {
		records, err = conn.feed(chunk.direction, chunk.data, records)

		if err != nil {
			return
		}
	}

	return
}

// a protected record waits for the secrets of the session, SetSecrets lets it go on
func (conn *Conn) Waiting() (waiting bool) {
	waiting = conn.waiting
	return
}

func (conn *Conn) Session() (session Session) {
	session = conn.session
	return
}

func (conn *Conn) feed(direction Direction, data []byte, records []Record) (result []Record, err error) {
	half := &conn.halves[direction]
	half.buffer = append(half.buffer, data...)
	result, err = conn.process(half, records)
	return
}

// take the whole records off the buffer of a direction until its bytes run out or a protected record has no keys yet
func (conn *Conn) process(half *half, records []Record) (result []Record, err error) {
	result = records

	for !conn.waiting {
		contentType, length, complete, frameErr := frameRecord(half.buffer)

		if err = frameErr; err != nil {
			return
		}

		if !complete {
			return
		}

		header := half.buffer[:recordHeaderLength]
		payload := half.buffer[recordHeaderLength:length]
		record := Record{
			Direction:   half.direction,
			ContentType: contentType,
			Decrypted:   false,
			Sequence:    0,
			Payload:     payload,
		}
		// TLS 1.3 sends ChangeCipherSpec only for middleboxes and never protects it (RFC 8446 appendix D.4)
		isCompatibility := (conn.session.Version == VersionTLS13) && (contentType == ChangeCipherSpecContentType)

		if (half.phase != plaintextPhase) && !isCompatibility {
			if half.protection == nil {
				conn.waiting = true
				return
			}

			record, err = conn.open(half, contentType, header, payload)

			if err != nil {
				return
			}
		}

		// the payload stays where it is, later bytes are only appended behind the buffer
		half.buffer = half.buffer[length:]
		result = append(result, record)
		err = conn.handle(half, record)

		if err != nil {
			return
		}
	}

	return
}

// decrypt one protected record with the keys of its direction and count it
func (conn *Conn) open(half *half, contentType ContentType, header []byte, payload []byte) (record Record, err error) {
	record = Record{
		Direction:   half.direction,
		ContentType: contentType,
		Decrypted:   true,
		Sequence:    half.sequence,
		Payload:     nil,
	}

	switch {
	case conn.session.Version == VersionTLS13:
		// the real content type is inside the protection
		if contentType != ApplicationDataContentType {
			err = fmt.Errorf("%w: content type %d inside the protection", ErrUnexpectedRecord, contentType)
			return
		}

		record.Payload, record.ContentType, err = openTLS13(half.protection, half.sequence, header, payload)
	case half.protection.aead != nil:
		record.Payload, err = openAEAD(half.protection, half.sequence, header, payload)
	default:
		record.Payload, err = openCBC(half.protection, half.sequence, header, payload)
	}

	if err != nil {
		err = fmt.Errorf("%w: sequence %d", err, half.sequence)
		return
	}

	half.sequence++
	return
}

// what a record changes in the session
func (conn *Conn) handle(half *half, record Record) (err error) {
	switch record.ContentType {
	case HandshakeContentType:
		err = conn.handleHandshake(half, record.Payload)
	case ChangeCipherSpecContentType:
		// before the ServerHello and in TLS 1.3 it means nothing
		if conn.session.Version != VersionTLS12 {
			return
		}

		// a second one would start the keys of a renegotiated session
		if record.Decrypted {
			err = ErrRenegotiation
			return
		}

		err = conn.startPhase(half, applicationPhase)
	case ApplicationDataContentType:
		if !record.Decrypted || (half.phase != applicationPhase) {
			err = fmt.Errorf("%w: application data before the handshake is done", ErrUnexpectedRecord)
		}
	case AlertContentType:
	default:
		err = fmt.Errorf("%w: content type %d", ErrUnexpectedRecord, record.ContentType)
	}

	return
}

// handshake messages can share a record and can span records, only the ones the record layer needs are put together
func (conn *Conn) handleHandshake(half *half, fragment []byte) (err error) {
	half.handshake = append(half.handshake, fragment...)

	for {
		skipped := min(half.handshakeSkip, len(half.handshake))
		half.handshake = half.handshake[skipped:]
		half.handshakeSkip -= skipped

		if len(half.handshake) < handshakeHeaderLength {
			return
		}

		messageType := half.handshake[0]
		length := int(half.handshake[1])<<16 | int(half.handshake[2])<<8 | int(half.handshake[3])

		if !isReadHandshake(messageType) {
			half.handshake = half.handshake[handshakeHeaderLength:]
			half.handshakeSkip = length
			continue
		}

		if length > maxHandshake {
			err = fmt.Errorf("%w: message type %d of %d bytes", ErrMalformedHandshake, messageType, length)
			return
		}

		if len(half.handshake) < handshakeHeaderLength+length {
			return
		}

		body := half.handshake[handshakeHeaderLength : handshakeHeaderLength+length]
		half.handshake = half.handshake[handshakeHeaderLength+length:]
		err = conn.handleMessage(half, messageType, body)

		if err != nil {
			return
		}
	}
}

func (conn *Conn) handleMessage(half *half, messageType uint8, body []byte) (err error) {
	isTLS13 := conn.session.Version == VersionTLS13

	switch {
	case (messageType == handshakeClientHello) && (half.direction == ClientDirection) && (half.phase == plaintextPhase):
		err = conn.handleClientHello(body)
	case (messageType == handshakeServerHello) && (half.direction == ServerDirection) && (half.phase == plaintextPhase):
		err = conn.handleServerHello(body)
	case (messageType == handshakeEncryptedExtensions) && (half.direction == ServerDirection) && isTLS13 && (half.phase == handshakePhase):
		conn.session.Protocol, err = parseEncryptedExtensions(body)
	case (messageType == handshakeFinished) && isTLS13 && (half.phase == handshakePhase):
		// the application traffic keys follow the Finished of each side (RFC 8446 section 7.1)
		err = conn.startPhase(half, applicationPhase)
	case (messageType == handshakeKeyUpdate) && isTLS13 && (half.phase == applicationPhase):
		err = conn.updateKeys(half)
	default:
	}

	return
}

func (conn *Conn) handleClientHello(body []byte) (err error) {
	// the second ClientHello after a HelloRetryRequest keeps the random
	if conn.hasClientHello {
		return
	}

	hello, parseErr := parseClientHello(body)

	if err = parseErr; err != nil {
		return
	}

	// early data is protected with a secret of the previous session that is not part of Secrets
	if hello.earlyData {
		err = ErrEarlyData
		return
	}

	conn.hasClientHello = true
	conn.session.ClientRandom = hello.random
	conn.session.ServerName = hello.serverName
	conn.session.OfferedProtocols = hello.protocols
	return
}

func (conn *Conn) handleServerHello(body []byte) (err error) {
	if !conn.hasClientHello || (conn.session.Version != 0) {
		err = fmt.Errorf("%w: server hello out of order", ErrUnexpectedRecord)
		return
	}

	hello, parseErr := parseServerHello(body)

	if err = parseErr; err != nil {
		return
	}

	// the client answers with a new ClientHello, the real ServerHello comes after it
	if hello.helloRetryRequest {
		return
	}

	switch hello.version {
	case VersionTLS13:
		conn.suiteTLS13, err = cipherSuiteTLS13ByID(hello.cipherSuite)
	case VersionTLS12:
		conn.suite, err = cipherSuiteByID(hello.cipherSuite)
	default:
		err = fmt.Errorf("%w: 0x%04x", ErrUnsupportedVersion, hello.version)
	}

	conn.session.Version = hello.version
	conn.session.CipherSuite = hello.cipherSuite
	conn.session.Protocol = hello.protocol
	conn.serverRandom = hello.random

	if err != nil {
		return
	}

	if hello.version == VersionTLS12 {
		// only CBC suites have a MAC to move behind the encryption (RFC 7366 section 3)
		conn.encryptThenMAC = hello.encryptThenMAC && (conn.suite.newAEAD == nil)
		return
	}

	// everything after the ServerHello is protected with the handshake traffic keys (RFC 8446 section 7.1)
	for index := range conn.halves {
		err = conn.startPhase(&conn.halves[index], handshakePhase)

		if err != nil {
			return
		}
	}

	return
}

// the next record of the direction is protected with the keys of phase, they are set at once if the secrets are known and when they arrive otherwise
func (conn *Conn) startPhase(half *half, phase keyPhase) (err error) {
	// a handshake message does not span a key change (RFC 8446 section 5.1)
	if (len(half.handshake) != 0) || (half.handshakeSkip != 0) {
		err = fmt.Errorf("%w: message spans a key change", ErrMalformedHandshake)
		return
	}

	half.phase = phase
	half.protection = nil

	if conn.hasSecrets {
		err = conn.protect(half)
	}

	return
}

// derive the keys of the phase a direction is in from the secrets, the sequence number starts again with new keys
func (conn *Conn) protect(half *half) (err error) {
	if conn.secrets.Version != conn.session.Version {
		err = fmt.Errorf("%w: secrets of %s for a %s session", ErrSecrets, VersionName(conn.secrets.Version), VersionName(conn.session.Version))
		return
	}

	if conn.session.Version == VersionTLS13 {
		secrets := map[keyPhase][2][]byte{
			handshakePhase:   {conn.secrets.ClientHandshakeTrafficSecret, conn.secrets.ServerHandshakeTrafficSecret},
			applicationPhase: {conn.secrets.ClientTrafficSecret, conn.secrets.ServerTrafficSecret},
		}
		err = conn.protectTLS13(half, secrets[half.phase][half.direction])
		return
	}

	if len(conn.secrets.MasterKey) != masterKeyLength {
		err = fmt.Errorf("%w: master key of %d bytes", ErrSecrets, len(conn.secrets.MasterKey))
		return
	}

	keys := keysFromMasterSecret(conn.suite, conn.secrets.MasterKey, conn.session.ClientRandom[:], conn.serverRandom[:])

	if half.direction == ClientDirection {
		half.protection, err = newProtection(conn.suite, keys.clientMAC, keys.clientKey, keys.clientIV, conn.encryptThenMAC)
	} else {
		half.protection, err = newProtection(conn.suite, keys.serverMAC, keys.serverKey, keys.serverIV, conn.encryptThenMAC)
	}

	half.sequence = 0
	half.sequenceOffset = 0
	return
}

func (conn *Conn) protectTLS13(half *half, trafficSecret []byte) (err error) {
	// a secret is as long as the hash of the suite
	if len(trafficSecret) != conn.suiteTLS13.newHash().Size() {
		err = fmt.Errorf("%w: traffic secret of %d bytes for %s", ErrSecrets, len(trafficSecret), conn.suiteTLS13.name)
		return
	}

	half.protection, err = newProtectionTLS13(conn.suiteTLS13, trafficSecret)
	half.trafficSecret = trafficSecret
	half.sequence = 0
	half.sequenceOffset = 0
	return
}

// KeyUpdate: the sender goes on with the next application traffic secret, derived here because it never reaches the secrets (RFC 8446 section 7.2)
func (conn *Conn) updateKeys(half *half) (err error) {
	if (len(half.handshake) != 0) || (half.handshakeSkip != 0) {
		err = fmt.Errorf("%w: message spans a key change", ErrMalformedHandshake)
		return
	}

	trafficSecret, secretErr := nextTrafficSecret(conn.suiteTLS13, half.trafficSecret)

	if err = secretErr; err != nil {
		return
	}

	err = conn.protectTLS13(half, trafficSecret)
	return
}
