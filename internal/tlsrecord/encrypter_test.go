// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
)

const (
	// what the relay adds to the first client record before a KeyUpdate, more than one record holds
	syntheticGrowLength int = 20000
	syntheticPadding    int = 3
)

// one TLS 1.3 session made up from random secrets: the record layer only reads the hellos, EncryptedExtensions, Finished and KeyUpdate, nothing checks the rest of a handshake
type synthetic struct {
	suite       *cipherSuiteTLS13
	secrets     Secrets
	random      [randomLength]byte
	stream      []syntheticChunk
	protections [2]*protection
	traffic     [2][]byte
	sequences   [2]uint64
}

type syntheticChunk struct {
	direction Direction
	data      []byte
}

// what the relay did and what the receiver got
type syntheticResult struct {
	sent     [2][]byte
	received [2][]byte
	offsets  map[string]int64
	split    int
	dropped  int
}

// Test if tlsrecord.Encrypter returns with the expected output across KeyUpdate in both directions.
func TestKeyUpdatePositive(state *testing.T) {
	for _, suite := range cipherSuitesTLS13 {
		session, err := newSynthetic(suite)

		if err != nil {
			state.Fatalf("Test of tlsrecord.Encrypter failed, cannot create session, error: %s", err.Error())
		}

		result, relayErr := relaySynthetic(session)

		if relayErr != nil {
			state.Errorf("Test of tlsrecord.Encrypter failed, suite: %s, error: %s", suite.name, relayErr.Error())
			return
		}

		for direction := range result.sent {
			if (len(result.sent[direction]) == 0) || !bytes.Equal(result.sent[direction], result.received[direction]) {
				state.Errorf("Test of tlsrecord.Encrypter failed, suite: %s, direction %d: the receiver got %d bytes, the relay sent %d", suite.name, direction, len(result.received[direction]), len(result.sent[direction]))
				return
			}
		}

		// the split moves the client offset up and the drop the server offset down, the KeyUpdate goes on at the moved sequence number and the next keys start again at zero
		expected := map[string]int64{"0 grow": 1, "0 keyupdate": 1, "0 next": 0, "1 drop": -1, "1 keyupdate": -1, "1 next": 0}

		if (result.split != 1) || (result.dropped != 1) || (fmt.Sprint(result.offsets) != fmt.Sprint(expected)) {
			state.Errorf("Test of tlsrecord.Encrypter failed, suite: %s, split %d, dropped %d, offsets return value was not %v instead: %v", suite.name, result.split, result.dropped, expected, result.offsets)
			return
		}
	}
}

// Test if the TLS 1.2 CBC records sealed again return with the expected output, with and without encrypt-then-MAC.
func TestSealCBCPositive(state *testing.T) {
	for _, suiteID := range []uint16{tlsECDHERSAWithAES128CBCSHA, tlsECDHERSAWithAES128CBCSHA256, tlsECDHERSAWithAES256CBCSHA, tlsECDHERSAWith3DESEDECBCSHA} {
		suite, suiteErr := cipherSuiteByID(suiteID)

		if suiteErr != nil {
			state.Fatalf("Test of tlsrecord.sealCBC failed, error: %s", suiteErr.Error())
		}

		for _, encryptThenMAC := range []bool{false, true} {
			err := testSealCBC(suite, encryptThenMAC)

			if err != nil {
				state.Errorf("Test of tlsrecord.sealCBC failed, suite: %s, encrypt-then-MAC: %v, error: %s", suite.name, encryptThenMAC, err.Error())
				return
			}
		}
	}
}

// Test if the TLS 1.2 CBC records sealed again return with the expected errors.
func TestSealCBCNegative(state *testing.T) {
	suite, err := cipherSuiteByID(tlsECDHERSAWithAES128CBCSHA256)

	if err != nil {
		state.Fatalf("Test of tlsrecord.sealCBC failed, error: %s", err.Error())
	}

	for _, encryptThenMAC := range []bool{false, true} {
		sealer, opener, protectionErr := newCBCPair(suite, encryptThenMAC)

		if protectionErr != nil {
			state.Fatalf("Test of tlsrecord.sealCBC failed, error: %s", protectionErr.Error())
		}

		record, sealErr := sealCBC(sealer, 7, ApplicationDataContentType, [2]byte{3, 3}, []byte("GET / HTTP/1.1\r\n\r\n"))

		if sealErr != nil {
			state.Fatalf("Test of tlsrecord.sealCBC failed, error: %s", sealErr.Error())
		}

		// another sequence number and a flipped bit both fail the MAC
		_, openErr := openCBC(opener, 8, record[:recordHeaderLength], bytes.Clone(record[recordHeaderLength:]))

		if !errors.Is(openErr, ErrBadRecordMAC) {
			state.Errorf("Test of tlsrecord.sealCBC failed, encrypt-then-MAC: %v, open with the wrong sequence return value was not %v instead: %v", encryptThenMAC, ErrBadRecordMAC, openErr)
			return
		}

		tampered := bytes.Clone(record[recordHeaderLength:])
		tampered[len(tampered)-1] ^= 1
		_, openErr = openCBC(opener, 7, record[:recordHeaderLength], tampered)

		if !errors.Is(openErr, ErrBadRecordMAC) {
			state.Errorf("Test of tlsrecord.sealCBC failed, encrypt-then-MAC: %v, open of a changed record return value was not %v instead: %v", encryptThenMAC, ErrBadRecordMAC, openErr)
			return
		}
	}
}

func testSealCBC(suite *cipherSuite, encryptThenMAC bool) (err error) {
	sealer, opener, protectionErr := newCBCPair(suite, encryptThenMAC)

	if err = protectionErr; err != nil {
		return
	}

	for _, length := range []int{0, 1, 7, 8, 15, 16, 17, 1000, maxPlaintext} {
		plaintext := make([]byte, length)
		_, err = rand.Read(plaintext)

		if err != nil {
			return
		}

		sequence := uint64(length)
		record, sealErr := sealCBC(sealer, sequence, ApplicationDataContentType, [2]byte{3, 3}, plaintext)

		if err = sealErr; err != nil {
			return
		}

		if int(record[3])<<8|int(record[4]) != len(record)-recordHeaderLength {
			err = fmt.Errorf("length %d: record header length does not fit the record", length)
			return
		}

		opened, openErr := openCBC(opener, sequence, record[:recordHeaderLength], record[recordHeaderLength:])

		if err = openErr; err != nil {
			err = fmt.Errorf("length %d: %w", length, err)
			return
		}

		if !bytes.Equal(opened, plaintext) {
			err = fmt.Errorf("length %d: opened plaintext return value was not the sealed one", length)
			return
		}
	}

	return
}

// a write and a read protection of the same keys, as an intercepting conn has them
func newCBCPair(suite *cipherSuite, encryptThenMAC bool) (sealer *protection, opener *protection, err error) {
	macKey := make([]byte, suite.macLength)
	key := make([]byte, suite.keyLength)
	_, err = rand.Read(macKey)

	if err != nil {
		return
	}

	_, err = rand.Read(key)

	if err != nil {
		return
	}

	sealer, err = newProtection(suite, macKey, key, nil, encryptThenMAC)

	if err != nil {
		return
	}

	opener, err = newProtection(suite, macKey, key, nil, encryptThenMAC)
	return
}

func newSynthetic(suite *cipherSuiteTLS13) (session synthetic, err error) {
	session.suite = suite
	session.secrets.Version = VersionTLS13

	for _, target := range []*[]byte{&session.secrets.ClientHandshakeTrafficSecret, &session.secrets.ServerHandshakeTrafficSecret, &session.secrets.ClientTrafficSecret, &session.secrets.ServerTrafficSecret} {
		*target = make([]byte, suite.newHash().Size())
		_, err = rand.Read(*target)

		if err != nil {
			return
		}
	}

	_, err = rand.Read(session.random[:])

	if err != nil {
		return
	}

	// ClientHello and ServerHello with supported_versions TLS 1.3
	clientHello := []byte{3, 3}
	clientHello = append(clientHello, session.random[:]...)
	clientHello = append(clientHello, 0, 0, 2, byte(suite.id>>8), byte(suite.id), 1, 0)
	serverHello := []byte{3, 3}
	serverHello = append(serverHello, bytes.Repeat([]byte{7}, randomLength)...)
	serverHello = append(serverHello, 0, byte(suite.id>>8), byte(suite.id), 0, 0, 6, 0, 43, 0, 2, 3, 4)
	session.plain(ClientDirection, HandshakeContentType, handshakeMessage(handshakeClientHello, clientHello))
	session.plain(ServerDirection, HandshakeContentType, handshakeMessage(handshakeServerHello, serverHello))

	// the handshake flights under the handshake traffic secrets, then the application traffic secrets
	finished := make([]byte, suite.newHash().Size())
	err = session.protect(ServerDirection, session.secrets.ServerHandshakeTrafficSecret)

	if err != nil {
		return
	}

	session.protected(ServerDirection, HandshakeContentType, append(handshakeMessage(handshakeEncryptedExtensions, []byte{0, 0}), handshakeMessage(handshakeFinished, finished)...))
	err = errors.Join(session.protect(ServerDirection, session.secrets.ServerTrafficSecret), session.protect(ClientDirection, session.secrets.ClientHandshakeTrafficSecret))

	if err != nil {
		return
	}

	session.protected(ClientDirection, HandshakeContentType, handshakeMessage(handshakeFinished, finished))
	err = session.protect(ClientDirection, session.secrets.ClientTrafficSecret)

	if err != nil {
		return
	}

	// client: a record that grows past the limit, KeyUpdate with update_requested, records under the next secret
	// server: four records of which the relay drops the second, KeyUpdate, records under the next secret
	for index := range 4 {
		session.protected(ClientDirection, ApplicationDataContentType, bytes.Repeat([]byte{byte('a' + index)}, 1000+index))
		session.protected(ServerDirection, ApplicationDataContentType, bytes.Repeat([]byte{byte('A' + index)}, 3000+index))
	}

	err = errors.Join(session.keyUpdate(ClientDirection, 1), session.keyUpdate(ServerDirection, 0))

	if err != nil {
		return
	}

	for index := range 3 {
		session.protected(ClientDirection, ApplicationDataContentType, bytes.Repeat([]byte{byte('k' + index)}, 500))
		session.protected(ServerDirection, ApplicationDataContentType, bytes.Repeat([]byte{byte('K' + index)}, 700))
	}

	return
}

func handshakeMessage(messageType uint8, body []byte) (message []byte) {
	message = append([]byte{messageType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return
}

func (session *synthetic) plain(direction Direction, contentType ContentType, fragment []byte) {
	record := newRecord(contentType, [2]byte{3, 3}, len(fragment))
	record = append(record, fragment...)
	setRecordLength(record, len(fragment))
	session.stream = append(session.stream, syntheticChunk{direction: direction, data: record})
}

func (session *synthetic) protect(direction Direction, trafficSecret []byte) (err error) {
	session.protections[direction], err = newProtectionTLS13(session.suite, trafficSecret)
	session.traffic[direction] = trafficSecret
	session.sequences[direction] = 0
	return
}

func (session *synthetic) protected(direction Direction, contentType ContentType, plaintext []byte) {
	record := sealTLS13(session.protections[direction], session.sequences[direction], [2]byte{3, 3}, contentType, plaintext, syntheticPadding)
	session.sequences[direction]++
	session.stream = append(session.stream, syntheticChunk{direction: direction, data: record})
}

// KeyUpdate under the current secret, the next record uses the next one (RFC 8446 section 7.2)
func (session *synthetic) keyUpdate(direction Direction, requested byte) (err error) {
	session.protected(direction, HandshakeContentType, handshakeMessage(handshakeKeyUpdate, []byte{requested}))
	next, nextErr := nextTrafficSecret(session.suite, session.traffic[direction])

	if err = nextErr; err != nil {
		return
	}

	err = session.protect(direction, next)
	return
}

// the session through an intercepting conn and two encrypters into a reading conn as the receiver, which only accepts records at the sequence numbers it expects
// the relay grows the first client application data record and drops the second server one, both before the KeyUpdate of their direction
func relaySynthetic(session synthetic) (result syntheticResult, err error) {
	relayConn := New(holdLimit(), true)
	receiver := New(holdLimit(), false)
	encrypters := [2]Encrypter{NewEncrypter(), NewEncrypter()}
	appCount := [2]int{}
	result.offsets = map[string]int64{}
	_, err = receiver.SetSecrets(session.secrets)

	if err != nil {
		return
	}

	for _, chunk := range session.stream {
		records, feedErr := relayConn.Feed(chunk.direction, chunk.data)

		if err = feedErr; err != nil {
			return
		}

		if relayConn.Waiting() {
			released, secretsErr := relayConn.SetSecrets(session.secrets)

			if err = secretsErr; err != nil {
				return
			}

			records = append(records, released...)
		}

		for _, record := range records {
			var wire []byte

			switch record.Action {
			case ShowAction:
				continue
			case ForwardAction:
				wire = record.Raw
			case SealAction:
				plaintext := record.Payload

				if record.ContentType == ApplicationDataContentType {
					index := appCount[record.Direction]
					appCount[record.Direction]++

					switch {
					case (record.Direction == ClientDirection) && (index == 0):
						plaintext = append(bytes.Clone(plaintext), bytes.Repeat([]byte{'x'}, syntheticGrowLength)...)
					case (record.Direction == ServerDirection) && (index == 1):
						encrypters[record.Direction].Drop(record)
						result.dropped++
						result.offsets[fmt.Sprintf("%d drop", record.Direction)] = encrypters[record.Direction].Offset()
						continue
					default:
					}

					result.sent[record.Direction] = append(result.sent[record.Direction], plaintext...)
				}

				sealed, count, sealErr := encrypters[record.Direction].Seal(record, plaintext)

				if err = sealErr; err != nil {
					return
				}

				if count > 1 {
					result.split++
				}

				wire = sealed
				offset := encrypters[record.Direction].Offset()

				// the offset after the grown record, the KeyUpdate and the first record under the next keys
				switch {
				case (record.ContentType == HandshakeContentType) && (record.Payload[0] == handshakeKeyUpdate):
					result.offsets[fmt.Sprintf("%d keyupdate", record.Direction)] = offset
				case (record.ContentType == ApplicationDataContentType) && (record.Direction == ClientDirection) && (appCount[record.Direction] == 1):
					result.offsets[fmt.Sprintf("%d grow", record.Direction)] = offset
				case (record.ContentType == ApplicationDataContentType) && (appCount[record.Direction] == 5):
					result.offsets[fmt.Sprintf("%d next", record.Direction)] = offset
				default:
				}
			}

			received, receiveErr := receiver.Feed(record.Direction, wire)

			if err = receiveErr; err != nil {
				err = fmt.Errorf("receiver, direction %d: %w", record.Direction, err)
				return
			}

			for _, receivedRecord := range received {
				if receivedRecord.Decrypted && (receivedRecord.ContentType == ApplicationDataContentType) {
					result.received[receivedRecord.Direction] = append(result.received[receivedRecord.Direction], receivedRecord.Payload...)
				}
			}
		}
	}

	return
}

func holdLimit() (limit int) {
	limit = 1 << 20
	return
}

// Test if tlsrecord.Encrypter.SealData returns with the expected output: records held back and dropped go on later as application data with the keys of another record,
// before the KeyUpdate that changes the keys and after a dropped record of the next keys, and the receiver reads every byte in order at the sequence numbers it expects.
func TestSealDataPositive(state *testing.T) {
	for _, suite := range cipherSuitesTLS13 {
		session, err := newSynthetic(suite)

		if err != nil {
			state.Fatalf("Test of tlsrecord.Encrypter.SealData failed, cannot create session, error: %s", err.Error())
		}

		relayConn := New(holdLimit(), true)
		receiver := New(holdLimit(), false)
		encrypters := [2]Encrypter{NewEncrypter(), NewEncrypter()}
		appCount := [2]int{}
		kept := [2][]byte{}
		sent := [2][]byte{}
		received := [2][]byte{}
		_, err = receiver.SetSecrets(session.secrets)

		for _, chunk := range session.stream {
			if err != nil {
				break
			}

			records, feedErr := relayConn.Feed(chunk.direction, chunk.data)

			if err = feedErr; (err == nil) && relayConn.Waiting() {
				released, secretsErr := relayConn.SetSecrets(session.secrets)
				records = append(records, released...)
				err = secretsErr
			}

			for _, record := range records {
				if (err != nil) || (record.Action == ShowAction) {
					continue
				}

				direction := record.Direction
				encrypter := &encrypters[direction]
				wire := record.Raw

				if record.Action == SealAction {
					wire = nil
					isApplication := record.ContentType == ApplicationDataContentType
					index := appCount[direction]

					if isApplication {
						appCount[direction]++
					}

					switch {
					// held back before the KeyUpdate, they go on in front of it with its keys
					case isApplication && ((index == 2) || (index == 3)):
						kept[direction] = append(kept[direction], record.Payload...)
						encrypter.Drop(record)
						continue
					case !isApplication && (len(kept[direction]) > 0):
						sealed, _, sealErr := encrypter.SealData(record, kept[direction])
						wire, err = sealed, sealErr
						sent[direction] = append(sent[direction], kept[direction]...)
						kept[direction] = nil
					// dropped and sealed at once after it, with its own keys
					case isApplication && (index == 5):
						encrypter.Drop(record)
						sealed, _, sealErr := encrypter.SealData(record, record.Payload)
						sent[direction] = append(sent[direction], record.Payload...)
						received, err = feedReceiver(&receiver, direction, sealed, received, sealErr)
						continue
					default:
					}

					if isApplication {
						sent[direction] = append(sent[direction], record.Payload...)
					}

					sealed, _, sealErr := encrypter.Seal(record, record.Payload)
					wire = append(wire, sealed...)
					err = errors.Join(err, sealErr)
				}

				received, err = feedReceiver(&receiver, direction, wire, received, err)
			}
		}

		if err != nil {
			state.Errorf("Test of tlsrecord.Encrypter.SealData failed, suite: %s, error: %s", suite.name, err.Error())
			return
		}

		for direction := range sent {
			if (len(sent[direction]) == 0) || !bytes.Equal(sent[direction], received[direction]) || (encrypters[direction].Offset() != 0) {
				state.Errorf("Test of tlsrecord.Encrypter.SealData failed, suite: %s, direction %d: the receiver got %d bytes, the relay sent %d, offset %d", suite.name, direction, len(received[direction]), len(sent[direction]), encrypters[direction].Offset())
				return
			}
		}
	}
}

// the receiver reads wire, its application data goes after received; an error before is passed on
func feedReceiver(receiver *Conn, direction Direction, wire []byte, received [2][]byte, before error) (result [2][]byte, err error) {
	result = received
	err = before

	if err != nil {
		return
	}

	records, err := receiver.Feed(direction, wire)

	for _, record := range records {
		if record.Decrypted && (record.ContentType == ApplicationDataContentType) {
			result[record.Direction] = append(result[record.Direction], record.Payload...)
		}
	}

	return
}
