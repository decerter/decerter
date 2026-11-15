// SPDX-License-Identifier: AGPL-3.0-only

package tlsrecord

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// DTLS 1.2 framing (RFC 6347 sections 4.1 and 4.2.2)
const (
	// content type, version, epoch, 48 bit sequence number, length
	dtlsRecordHeaderLength int = 13
	dtlsEpochOffset        int = 3
	dtlsLengthOffset       int = 11
	// message type, 24 bit length, message sequence, 24 bit fragment offset, 24 bit fragment length
	dtlsHandshakeHeaderLength int    = 12
	dtlsVersionMajor          uint8  = 0xfe
	dtlsSequenceBits          int    = 48
	dtlsMaxSequence           uint64 = 1<<dtlsSequenceBits - 1
	// the epoch of the keys after the ChangeCipherSpec of the handshake, a later one belongs to a renegotiation
	dtlsProtectedEpoch uint16 = 1
	// the records behind the newest one that still count as new (RFC 6347 section 4.1.2.6)
	replayWindowLength uint64 = 64
	// the hellos a direction may put together: the ClientHello, again after a HelloVerifyRequest, and some to spare; each takes a message sequence number
	maxDTLSMessages int = 8
	// the protected records of a direction that may fail their MAC before one passes; the keys are wrong when this many in a row fail
	maxBadRecords int = 8
	// a datagram a relay sends may grow to this or to the length it came with, whichever is more: the IPv6 minimum MTU minus the IPv6 and UDP headers fits every path
	MinDatagramLength int = 1232
)

// one handshake message the record layer reads, put together from its fragments, which can come in any order and more than once
// body and received are let go once the message is complete, the entry stays so a retransmission of it is not read again
type dtlsMessage struct {
	messageType uint8
	length      int
	body        []byte
	received    []bool
	missing     int
}

// the sequence numbers of epoch 1 a direction sent: highest is the newest, bit n of bitmap is the number n below it
type replayWindow struct {
	isStarted bool
	highest   uint64
	bitmap    uint64
}

// one direction of a DTLS session: the hellos of epoch 0 it is putting together, the keys of epoch 1 and the numbers seen in epoch 1
// holding is true once the protected records of the direction wait until they are decrypted, released once held records went on raw because the secrets were late
// badRecords counts the records that failed their MAC before one passed
type dtlsHalf struct {
	direction  Direction
	messages   map[uint16]*dtlsMessage
	protection *protection
	sealer     *protection
	window     replayWindow
	badRecords int
	holding    bool
	released   bool
}

// a protected record that waits for the secrets, isSent is true when it went on raw already
type heldRecord struct {
	record Record
	raw    []byte
	isSent bool
}

// the record layer of one DTLS 1.2 session seen from the middle: each datagram of a direction is fed as it passes and comes out as its records, decrypted once the secrets are set
// the epoch and the sequence number of a record are in its header, so a record decrypts without the ones before it: datagrams may be lost, come twice or in another order
// a protected record without keys waits in the hold queue, records of both directions in their order of arrival; a copy of a record that came already is left out
// an intercepting conn also tells the relay what to send, as Conn does: a record goes on raw at once (ForwardAction) or is held until it is decrypted (SealAction)
type DTLSConn struct {
	holdLimit      int
	intercept      bool
	halves         [2]dtlsHalf
	session        Session
	serverRandom   [randomLength]byte
	hasClientHello bool
	suite          *cipherSuite
	encryptThenMAC bool
	secrets        Secrets
	hasSecrets     bool
	held           []heldRecord
	heldBytes      int
	assemblyBytes  int
	datagrams      [2]uint64
	dropped        [2]uint64
	err            error
}

// tell from the first datagram of a client if it starts a DTLS session: a handshake record of epoch 0 with a ClientHello
func IsDTLSClientHello(datagram []byte) (isClientHello bool) {
	isClientHello = (len(datagram) > dtlsRecordHeaderLength) && (ContentType(datagram[0]) == HandshakeContentType) && (datagram[1] == dtlsVersionMajor) && (binary.BigEndian.Uint16(datagram[dtlsEpochOffset:]) == 0) && (datagram[dtlsRecordHeaderLength] == handshakeClientHello)
	return
}

// holdLimit is the most bytes that may wait for the secrets, intercept makes the conn the record layer of a relay that may change the application data
func NewDTLS(holdLimit int, intercept bool) (conn DTLSConn) {
	conn = DTLSConn{
		holdLimit: holdLimit,
		intercept: intercept,
		halves: [2]dtlsHalf{
			{direction: ClientDirection, messages: map[uint16]*dtlsMessage{}, protection: nil, sealer: nil, window: replayWindow{}, badRecords: 0, holding: false, released: false},
			{direction: ServerDirection, messages: map[uint16]*dtlsMessage{}, protection: nil, sealer: nil, window: replayWindow{}, badRecords: 0, holding: false, released: false},
		},
		session:        Session{},
		serverRandom:   [randomLength]byte{},
		hasClientHello: false,
		suite:          nil,
		encryptThenMAC: false,
		secrets:        Secrets{},
		hasSecrets:     false,
		held:           nil,
		heldBytes:      0,
		assemblyBytes:  0,
		datagrams:      [2]uint64{},
		dropped:        [2]uint64{},
		err:            nil,
	}
	return
}

// add the next datagram of a direction, it is copied; records are its records that came out now, the ones before an error included
// a record that can't be read on its own is dropped and counted (Dropped), as an endpoint drops it (RFC 6347 section 4.1.2.7): the rest of a datagram
// that does not frame, a record of an epoch above 1, a protected record before the ServerHello, one that fails its MAC; a lost, reordered or injected
// datagram does not end the session
// an error is final: the session is not DTLS 1.2 this package can read, an authenticated record breaks it or the keys are wrong (the first
// maxBadRecords protected records of a direction fail), every later call returns it again
// intercept: a record that is dropped and the part of the datagram behind an error go on as they came (ForwardAction), the receiver decides
func (conn *DTLSConn) Feed(direction Direction, datagram []byte) (records []Record, err error) {
	if err = conn.err; err != nil {
		return
	}

	half := &conn.halves[direction]
	index := conn.datagrams[direction]
	conn.datagrams[direction]++
	rest := datagram

	for len(rest) > 0 {
		contentType, epoch, sequence, length, frameErr := frameDTLSRecord(rest)

		if frameErr != nil {
			conn.dropped[direction]++
			break
		}

		record := Record{
			Direction:   direction,
			ContentType: contentType,
			Decrypted:   false,
			Epoch:       epoch,
			Sequence:    sequence,
			Datagram:    index,
			Length:      length,
			Payload:     nil,
			Action:      ShowAction,
			Raw:         nil,
		}
		raw := bytes.Clone(rest[:length])
		rest = rest[length:]
		records, err = conn.take(half, record, raw, records)

		if err != nil {
			break
		}
	}

	// intercept: what the record layer did not read goes on, so a relay that gives up still sends the whole datagram
	if conn.intercept && (len(rest) > 0) {
		records = append(records, forwardDTLSTail(direction, index, bytes.Clone(rest)))
	}

	// the hellos a peer started and never finished count too, so it can't make decerter keep more than the limit
	if (err == nil) && (conn.heldBytes+conn.assemblyBytes > conn.holdLimit) {
		err = fmt.Errorf("%w: limit %d", ErrHoldQueueFull, conn.holdLimit)
	}

	conn.err = err
	return
}

// set the secrets of the session, they can come before the keys are needed or while records wait for them; records are the records the hold queue gives back
func (conn *DTLSConn) SetSecrets(secrets Secrets) (records []Record, err error) {
	if err = conn.err; err != nil {
		return
	}

	defer func() {
		conn.err = err
	}()

	conn.secrets = secrets
	conn.hasSecrets = true

	// without the ServerHello nothing can wait, the keys are made when it comes
	if conn.session.Version == 0 {
		return
	}

	err = conn.protect()

	if err != nil {
		return
	}

	for len(conn.held) > 0 {
		current := conn.held[0]
		half := &conn.halves[current.record.Direction]

		// the window has only the records that passed their MAC, a copy of one of them is left out now
		if half.window.isNew(current.record.Sequence) {
			record, openErr := conn.open(half, current)

			switch {
			case openErr == nil:
				half.window.mark(current.record.Sequence)
				records = append(records, record)
			case errors.Is(openErr, ErrBadRecordMAC) && half.isBadRecordDropped():
				conn.dropped[current.record.Direction]++

				if conn.intercept && !current.isSent {
					records = append(records, forwardDTLSRecord(current.record, current.raw))
				}
			default:
				// the record that does not decrypt and the ones behind it stay for Unsent
				err = openErr
				return
			}
		}

		conn.held = conn.held[1:]
		conn.heldBytes -= len(current.raw)
	}

	conn.held = nil
	return
}

// a protected record waits for the secrets of the session, SetSecrets lets it go on
func (conn *DTLSConn) Waiting() (waiting bool) {
	waiting = !conn.hasSecrets && (len(conn.held) > 0)
	return
}

// intercept: held records wait for the secrets, the relay can't send them before SetSecrets or Release
func (conn *DTLSConn) Holding() (holding bool) {
	for index := range conn.halves {
		holding = holding || conn.HoldingFor(Direction(index))
	}

	return
}

// intercept: held records of the direction are not sent yet
func (conn *DTLSConn) HoldingFor(direction Direction) (holding bool) {
	for _, current := range conn.held {
		if (current.record.Direction == direction) && !current.isSent {
			holding = true
			return
		}
	}

	return
}

// intercept: the secrets are late, the held records go on as they came (ForwardAction) and both directions forward their protected records until the secrets are set
// the records are still decrypted later and come out again with ShowAction
func (conn *DTLSConn) Release() (records []Record) {
	if conn.hasSecrets {
		return
	}

	records = conn.Unsent()

	for index := range conn.halves {
		conn.halves[index].holding = false
		conn.halves[index].released = true
	}

	return
}

// intercept: the held records that did not go on yet, as they came (ForwardAction), also after an error; a relay that gives up sends them raw
func (conn *DTLSConn) Unsent() (records []Record) {
	for index := range conn.held {
		current := &conn.held[index]

		if current.isSent {
			continue
		}

		records = append(records, forwardDTLSRecord(current.record, current.raw))
		current.isSent = true
	}

	return
}

func (conn *DTLSConn) Session() (session Session) {
	session = conn.session
	return
}

// the records of each direction the record layer dropped, see Feed
func (conn *DTLSConn) Dropped() (dropped [2]uint64) {
	dropped = conn.dropped
	return
}

// what happens to one record: epoch 0 is read as it is, epoch 1 is decrypted or waits for the keys, a record that can't be read is dropped
// the replay window moves only for a record that passed its MAC (RFC 6347 section 4.1.2.6), a held one is checked against it when the keys come
func (conn *DTLSConn) take(half *dtlsHalf, record Record, raw []byte, records []Record) (result []Record, err error) {
	result = records

	switch {
	case record.Epoch == 0:
		record.Payload = raw[dtlsRecordHeaderLength:]

		if conn.intercept {
			record.Action = ForwardAction
			record.Raw = raw
		}

		result = append(result, record)
		err = conn.handle(half, record)
		return
	case (record.Epoch > dtlsProtectedEpoch) || (conn.session.Version == 0):
		// the epoch of a renegotiation, or keys that can't be there yet
		result = conn.drop(result, record, raw)
		return
	case !half.window.isNew(record.Sequence):
		// a copy of a record that passed already, the receiver would drop it too
		return
	case half.protection == nil:
		// a conn that only reads has nothing to send
		current := heldRecord{record: record, raw: raw, isSent: !conn.intercept}

		if conn.intercept && !half.holds(record.ContentType) {
			result = append(result, forwardDTLSRecord(record, raw))
			current.isSent = true
		}

		conn.held = append(conn.held, current)
		conn.heldBytes += len(raw)
		return
	}

	opened, openErr := conn.open(half, heldRecord{record: record, raw: raw, isSent: false})

	switch {
	case openErr == nil:
		half.window.mark(record.Sequence)
		result = append(result, opened)
	case errors.Is(openErr, ErrBadRecordMAC) && half.isBadRecordDropped():
		result = conn.drop(result, record, raw)
	default:
		err = openErr

		if conn.intercept {
			result = append(result, forwardDTLSRecord(record, raw))
		}
	}

	return
}

// a record that failed its MAC was changed or injected on the way and is dropped; keys that open none of the first maxBadRecords records of the
// direction are the wrong keys, that ends the session
func (half *dtlsHalf) isBadRecordDropped() (isDropped bool) {
	if half.window.isStarted {
		isDropped = true
		return
	}

	half.badRecords++
	isDropped = half.badRecords < maxBadRecords
	return
}

// a record the record layer can't read is counted, intercept lets it go on as it came
func (conn *DTLSConn) drop(records []Record, record Record, raw []byte) (result []Record) {
	result = records
	conn.dropped[record.Direction]++

	if conn.intercept {
		result = append(result, forwardDTLSRecord(record, raw))
	}

	return
}

// intercept: the protected records of a direction are held from its first application data record on, the Finished and the alerts before it go on, holding them could stop the handshake
// holding lasts for the session, unless Release lets the records go before the secrets
func (half *dtlsHalf) holds(contentType ContentType) (isHeld bool) {
	switch {
	case half.holding:
	case half.released, contentType != ApplicationDataContentType:
	default:
		half.holding = true
	}

	isHeld = half.holding
	return
}

// a record that goes on as it came
func forwardDTLSRecord(record Record, raw []byte) (forwarded Record) {
	forwarded = record
	forwarded.Payload = raw[dtlsRecordHeaderLength:]
	forwarded.Action = ForwardAction
	forwarded.Raw = raw
	return
}

// the part of a datagram behind a record that does not frame or an error goes on as it came, as one record of epoch 0 so its bytes are always free to send
func forwardDTLSTail(direction Direction, datagram uint64, tail []byte) (forwarded Record) {
	forwarded = Record{
		Direction:   direction,
		ContentType: 0,
		Decrypted:   false,
		Epoch:       0,
		Sequence:    0,
		Datagram:    datagram,
		Length:      len(tail),
		Payload:     nil,
		Action:      ForwardAction,
		Raw:         tail,
	}
	return
}

// decrypt a protected record with the keys of its direction, the additional data and the MAC take the epoch and the sequence number of its header as the 64 bit sequence number (RFC 6347 section 4.1.2.1)
// a held record is the relay's to seal and send, one that went on raw is only shown
func (conn *DTLSConn) open(half *dtlsHalf, current heldRecord) (record Record, err error) {
	record = current.record
	header := current.raw[:dtlsRecordHeaderLength]
	payload := bytes.Clone(current.raw[dtlsRecordHeaderLength:])
	sequence := uint64(record.Epoch)<<dtlsSequenceBits | record.Sequence

	if half.protection.aead != nil {
		record.Payload, err = openAEAD(half.protection, sequence, header, payload)
	} else {
		record.Payload, err = openCBC(half.protection, sequence, header, payload)
	}

	if err != nil {
		err = fmt.Errorf("%w: epoch %d sequence %d", err, record.Epoch, record.Sequence)
		return
	}

	if len(record.Payload) > maxPlaintext {
		err = fmt.Errorf("%w: %d bytes of plaintext", ErrRecordOverflow, len(record.Payload))
		return
	}

	// a ChangeCipherSpec under the keys starts the epoch of a renegotiation
	if record.ContentType == ChangeCipherSpecContentType {
		err = fmt.Errorf("%w: change cipher spec in epoch %d", ErrRenegotiation, record.Epoch)
		return
	}

	record.Decrypted = true
	record.sealer = half.sealer
	record.version = conn.session.Version
	copy(record.header[:], header)

	if conn.intercept && !current.isSent {
		record.Action = SealAction
		record.Raw = current.raw
	}

	return
}

// what a record of epoch 0 changes in the session: the hellos are read, a ChangeCipherSpec changes nothing, the epoch of every record is in its header
func (conn *DTLSConn) handle(half *dtlsHalf, record Record) (err error) {
	switch record.ContentType {
	case HandshakeContentType:
		err = conn.handleHandshake(half, record.Payload)
	case
		ChangeCipherSpecContentType,
		AlertContentType:
	default:
		err = fmt.Errorf("%w: content type %d in epoch 0", ErrUnexpectedRecord, record.ContentType)
	}

	return
}

// the handshake fragments of a record: each one names its message, its offset and its length, so a message can be put together from records of several datagrams and from retransmissions
// only the hellos are put together, every other message is skipped
func (conn *DTLSConn) handleHandshake(half *dtlsHalf, fragments []byte) (err error) {
	for len(fragments) > 0 {
		if len(fragments) < dtlsHandshakeHeaderLength {
			err = fmt.Errorf("%w: %d bytes of a fragment header", ErrMalformedHandshake, len(fragments))
			return
		}

		messageType := fragments[0]
		length := int(fragments[1])<<16 | int(fragments[2])<<8 | int(fragments[3])
		messageSequence := binary.BigEndian.Uint16(fragments[4:])
		offset := int(fragments[6])<<16 | int(fragments[7])<<8 | int(fragments[8])
		fragmentLength := int(fragments[9])<<16 | int(fragments[10])<<8 | int(fragments[11])

		if len(fragments) < dtlsHandshakeHeaderLength+fragmentLength {
			err = fmt.Errorf("%w: fragment of %d bytes in %d bytes", ErrMalformedHandshake, fragmentLength, len(fragments)-dtlsHandshakeHeaderLength)
			return
		}

		fragment := fragments[dtlsHandshakeHeaderLength : dtlsHandshakeHeaderLength+fragmentLength]
		fragments = fragments[dtlsHandshakeHeaderLength+fragmentLength:]

		if !conn.reads(half, messageType) {
			continue
		}

		if (length > maxHandshake) || (offset+fragmentLength > length) {
			err = fmt.Errorf("%w: fragment %d+%d of message type %d of %d bytes", ErrMalformedHandshake, offset, fragmentLength, messageType, length)
			return
		}

		body, isComplete, addErr := conn.addFragment(half, messageType, messageSequence, length, offset, fragment)

		if err = addErr; err != nil {
			return
		}

		if !isComplete {
			continue
		}

		err = conn.handleMessage(messageType, body)

		if err != nil {
			return
		}
	}

	return
}

// the client's hellos until the ServerHello, the last one is the one the server answers; the server's ServerHello once
func (conn *DTLSConn) reads(half *dtlsHalf, messageType uint8) (isRead bool) {
	switch {
	case conn.session.Version != 0:
	case half.direction == ClientDirection:
		isRead = messageType == handshakeClientHello
	default:
		isRead = messageType == handshakeServerHello
	}

	return
}

// put a fragment into its message, the body is there when every byte of it came; a message that is complete already is not given again
// a direction puts at most maxDTLSMessages messages together, and the bytes of the ones not complete yet count toward the hold limit
func (conn *DTLSConn) addFragment(half *dtlsHalf, messageType uint8, messageSequence uint16, length int, offset int, fragment []byte) (body []byte, isComplete bool, err error) {
	message := half.messages[messageSequence]

	if message == nil {
		if len(half.messages) >= maxDTLSMessages {
			err = fmt.Errorf("%w: more than %d hellos of one direction", ErrMalformedHandshake, maxDTLSMessages)
			return
		}

		message = &dtlsMessage{
			messageType: messageType,
			length:      length,
			body:        make([]byte, length),
			received:    make([]bool, length),
			missing:     length,
		}
		half.messages[messageSequence] = message
		conn.assemblyBytes += 2 * length
	}

	if (message.messageType != messageType) || (message.length != length) {
		err = fmt.Errorf("%w: fragments of message %d do not match", ErrMalformedHandshake, messageSequence)
		return
	}

	if message.missing == 0 {
		return
	}

	copy(message.body[offset:], fragment)

	for index := offset; index < offset+len(fragment); index++ {
		if !message.received[index] {
			message.received[index] = true
			message.missing--
		}
	}

	isComplete = message.missing == 0

	if isComplete {
		body = message.body
		message.body = nil
		message.received = nil
		conn.assemblyBytes -= 2 * length
	}

	return
}

func (conn *DTLSConn) handleMessage(messageType uint8, body []byte) (err error) {
	switch messageType {
	case handshakeClientHello:
		hello, parseErr := parseClientHello(body, true)

		if err = parseErr; err != nil {
			return
		}

		// the ClientHello sent again with the cookie of a HelloVerifyRequest keeps the random (RFC 6347 section 4.2.1)
		conn.hasClientHello = true
		conn.session.ClientRandom = hello.random
		conn.session.ServerName = hello.serverName
		conn.session.OfferedProtocols = hello.protocols
	case handshakeServerHello:
		err = conn.handleServerHello(body)
	default:
	}

	return
}

func (conn *DTLSConn) handleServerHello(body []byte) (err error) {
	if !conn.hasClientHello {
		err = fmt.Errorf("%w: server hello out of order", ErrUnexpectedRecord)
		return
	}

	hello, parseErr := parseServerHello(body)

	if err = parseErr; err != nil {
		return
	}

	if hello.version != VersionDTLS12 {
		err = fmt.Errorf("%w: 0x%04x", ErrUnsupportedVersion, hello.version)
		return
	}

	conn.suite, err = cipherSuiteByID(hello.cipherSuite)
	conn.session.Version = hello.version
	conn.session.CipherSuite = hello.cipherSuite
	conn.session.Protocol = hello.protocol
	conn.serverRandom = hello.random

	if err != nil {
		return
	}

	// only CBC suites have a MAC to move behind the encryption (RFC 7366 section 3)
	conn.encryptThenMAC = hello.encryptThenMAC && (conn.suite.newAEAD == nil)

	for index := range conn.halves {
		conn.halves[index].messages = nil
	}

	conn.assemblyBytes = 0

	if conn.hasSecrets {
		err = conn.protect()
	}

	return
}

// the keys of epoch 1 of both directions from the master key, the key block is the one of TLS 1.2
func (conn *DTLSConn) protect() (err error) {
	if conn.secrets.Version != conn.session.Version {
		err = fmt.Errorf("%w: secrets of %s for a %s session", ErrSecrets, VersionName(conn.secrets.Version), VersionName(conn.session.Version))
		return
	}

	if len(conn.secrets.MasterKey) != masterKeyLength {
		err = fmt.Errorf("%w: master key of %d bytes", ErrSecrets, len(conn.secrets.MasterKey))
		return
	}

	keys := keysFromMasterSecret(conn.suite, conn.secrets.MasterKey, conn.session.ClientRandom[:], conn.serverRandom[:])

	for index := range conn.halves {
		half := &conn.halves[index]
		macKey, key, iv := keys.serverMAC, keys.serverKey, keys.serverIV

		if half.direction == ClientDirection {
			macKey, key, iv = keys.clientMAC, keys.clientKey, keys.clientIV
		}

		half.protection, err = newProtection(conn.suite, macKey, key, iv, conn.encryptThenMAC)

		if err != nil {
			return
		}

		if conn.intercept {
			half.sealer, err = newProtection(conn.suite, macKey, key, iv, conn.encryptThenMAC)

			if err != nil {
				return
			}
		}
	}

	return
}

// a number is new when the window is empty, above the newest one or inside the window and not seen yet
func (window *replayWindow) isNew(sequence uint64) (isNew bool) {
	switch {
	case !window.isStarted:
	case sequence > window.highest:
	case window.highest-sequence >= replayWindowLength:
		return
	case window.bitmap&(1<<(window.highest-sequence)) != 0:
		return
	default:
	}

	isNew = true
	return
}

// mark a number as seen, only once its record passed the MAC; a number that is not new changes nothing
func (window *replayWindow) mark(sequence uint64) {
	switch {
	case !window.isStarted:
		window.isStarted = true
		window.highest = sequence
		window.bitmap = 1
	case sequence > window.highest:
		// a shift by the width or more leaves zero
		window.bitmap = window.bitmap<<(sequence-window.highest) | 1
		window.highest = sequence
	case window.highest-sequence >= replayWindowLength:
	default:
		window.bitmap |= 1 << (window.highest - sequence)
	}
}

// the first record of a datagram, length is the record with its header, a record has to end inside its datagram (RFC 6347 section 4.1.1)
func frameDTLSRecord(datagram []byte) (contentType ContentType, epoch uint16, sequence uint64, length int, err error) {
	if len(datagram) < dtlsRecordHeaderLength {
		err = fmt.Errorf("%w: %d bytes of a record header", ErrUnexpectedRecord, len(datagram))
		return
	}

	contentType = ContentType(datagram[0])

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

	if datagram[1] != dtlsVersionMajor {
		err = fmt.Errorf("%w: record version 0x%02x%02x", ErrUnexpectedRecord, datagram[1], datagram[2])
		return
	}

	epoch = binary.BigEndian.Uint16(datagram[dtlsEpochOffset:])
	sequence = binary.BigEndian.Uint64(datagram[dtlsEpochOffset:]) & dtlsMaxSequence
	length = dtlsRecordHeaderLength + int(binary.BigEndian.Uint16(datagram[dtlsLengthOffset:]))

	if length > dtlsRecordHeaderLength+maxCiphertext {
		err = fmt.Errorf("%w: %d bytes", ErrRecordOverflow, length-dtlsRecordHeaderLength)
		return
	}

	if length > len(datagram) {
		err = fmt.Errorf("%w: record of %d bytes in %d bytes of the datagram", ErrUnexpectedRecord, length, len(datagram))
	}

	return
}

// the write side of one direction of a DTLS relay: records of epoch 1 keep the sequence number they came with as long as no number is used twice
// next is above every number written so far; isShifted is true once a record went on with another number than its own, a record split in two or one that came after a later one in a session that was split before
// from then on every record gets the next free number, the receiver's replay window takes numbers that skip ahead (a dropped record leaves a gap) but never one it saw already
type DTLSEncrypter struct {
	next      uint64
	isShifted bool
}

func NewDTLSEncrypter() (encrypter DTLSEncrypter) {
	encrypter = DTLSEncrypter{
		next:      0,
		isShifted: false,
	}
	return
}

// a record that came with ForwardAction can go on raw while its sequence number was not given to a sealed record; only epoch 1 is sealed, a record
// of another epoch always can
func (encrypter *DTLSEncrypter) Forward(record Record) (isFree bool) {
	if record.Epoch != dtlsProtectedEpoch {
		isFree = true
		return
	}

	isFree = !encrypter.isShifted || (record.Sequence >= encrypter.next)

	if isFree {
		encrypter.next = max(encrypter.next, record.Sequence+1)
	}

	return
}

// seal a record that came with SealAction again, plaintext is its payload or what the rules made of it; each sealed record fits maxLength bytes with its header
// plaintext that doesn't fit one record is split into records with the numbers after the first one, empty plaintext is one empty record
func (encrypter *DTLSEncrypter) Seal(record Record, plaintext []byte, maxLength int) (sealed [][]byte, err error) {
	if record.sealer == nil {
		err = fmt.Errorf("%w: content type %d", ErrSeal, record.ContentType)
		return
	}

	fragmentLength := min(maxPlaintext, maxLength-dtlsRecordHeaderLength-sealOverhead(record.sealer))

	if fragmentLength <= 0 {
		err = fmt.Errorf("%w: a datagram of %d bytes holds no record", ErrSeal, maxLength)
		return
	}

	count := max(1, (len(plaintext)+fragmentLength-1)/fragmentLength)
	sequence := record.Sequence

	if (encrypter.isShifted || (count > 1)) && (sequence < encrypter.next) {
		sequence = encrypter.next
	}

	if (sequence != record.Sequence) || (count > 1) {
		encrypter.isShifted = true
	}

	version := [2]byte{record.header[1], record.header[2]}

	for start := 0; (start < len(plaintext)) || (len(sealed) == 0); start += fragmentLength {
		if sequence > dtlsMaxSequence {
			err = fmt.Errorf("%w: sequence number %d of epoch %d", ErrSeal, sequence, record.Epoch)
			return
		}

		wire, sealErr := sealDTLS(record.sealer, record.Epoch, sequence, record.ContentType, version, plaintext[start:min(start+fragmentLength, len(plaintext))])

		if err = sealErr; err != nil {
			err = fmt.Errorf("%w: %w", ErrSeal, err)
			return
		}

		sealed = append(sealed, wire)
		sequence++
	}

	encrypter.next = max(encrypter.next, sequence)
	return
}

// the most bytes sealing adds to a plaintext: the explicit nonce and the tag of an AEAD, the iv, the MAC and the longest padding of CBC
func sealOverhead(recordProtection *protection) (overhead int) {
	if recordProtection.aead != nil {
		overhead = recordProtection.aead.Overhead()

		if recordProtection.explicitNonce {
			overhead += explicitNonceLength
		}

		return
	}

	overhead = 2*recordProtection.block.BlockSize() + recordProtection.mac.Size()
	return
}

// encrypt a DTLS record: the TLS 1.2 protection with the epoch and the sequence number as the 64 bit sequence number, then the TLS header is replaced by the DTLS one
// AES-GCM carries epoch and sequence number as its explicit nonce (RFC 6347 section 4.1.2.1 leaves it to the sender), OpenSSL sends another one, so its records come out different but valid
func sealDTLS(recordProtection *protection, epoch uint16, sequence uint64, contentType ContentType, version [2]byte, plaintext []byte) (record []byte, err error) {
	fullSequence := uint64(epoch)<<dtlsSequenceBits | sequence
	var sealed []byte

	if recordProtection.aead != nil {
		sealed = sealAEAD(recordProtection, fullSequence, contentType, version, plaintext)
	} else {
		sealed, err = sealCBC(recordProtection, fullSequence, contentType, version, plaintext)

		if err != nil {
			return
		}
	}

	body := sealed[recordHeaderLength:]
	record = make([]byte, 0, dtlsRecordHeaderLength+len(body))
	record = append(record, byte(contentType), version[0], version[1])
	record = binary.BigEndian.AppendUint64(record, fullSequence)
	record = binary.BigEndian.AppendUint16(record, uint16(len(body)))
	record = append(record, body...)
	return
}
