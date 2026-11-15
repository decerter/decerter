// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// one TLS 1.2 session made up from a random master key: the record layer reads the hellos and the ChangeCipherSpec of each side, nothing checks the rest of a handshake
type synthetic12 struct {
	suite       *cipherSuite
	secrets     Secrets
	stream      []syntheticChunk
	protections [2]*protection
	sequences   [2]uint64
}

// Test if tlsrecord.Conn.Feed returns with the expected output for a ClientHello that is sent again after a HelloRetryRequest.
func TestHelloRetryRequestPositive(state *testing.T) {
	for _, suite := range cipherSuitesTLS13 {
		session, err := startSynthetic(suite)

		if err != nil {
			state.Fatalf("Test of tlsrecord.Conn.Feed failed, cannot create session, error: %s", err.Error())
		}

		clientHello, serverHello := session.stream[0], session.stream[1]
		// the second ClientHello keeps the random, another one here shows the first is the one that is read
		secondHello := bytes.Clone(clientHello.data)
		secondHello[recordHeaderLength+handshakeHeaderLength+2] ^= 0xff
		session.stream = []syntheticChunk{clientHello}
		session.plain(ServerDirection, HandshakeContentType, handshakeMessage(handshakeServerHello, serverHelloBody(VersionTLS12, helloRetryRequestRandom, suite.id, helloExtension(extensionSupportedVersions, []byte{3, 4}))))
		session.plain(ServerDirection, ChangeCipherSpecContentType, []byte{1})
		session.plain(ClientDirection, ChangeCipherSpecContentType, []byte{1})
		session.stream = append(session.stream, syntheticChunk{direction: ClientDirection, data: secondHello}, serverHello)
		err = finishSynthetic(&session)

		if err != nil {
			state.Fatalf("Test of tlsrecord.Conn.Feed failed, cannot create session, error: %s", err.Error())
		}

		session.protected(ClientDirection, ApplicationDataContentType, []byte("ping"))
		session.protected(ServerDirection, ApplicationDataContentType, []byte("pong"))

		for _, intercept := range []bool{false, true} {
			conn, records, feedErr := feedSynthetic(session.stream, session.secrets, intercept)

			if feedErr != nil {
				state.Errorf("Test of tlsrecord.Conn.Feed function failed, suite: %s, intercept: %v, error: %s", suite.name, intercept, feedErr.Error())
				return
			}

			plain := applicationData(records)
			result := conn.Session()

			if (string(plain[ClientDirection]) != "ping") || (string(plain[ServerDirection]) != "pong") || (result.Version != VersionTLS13) || (result.CipherSuite != suite.id) || (result.ClientRandom != session.random) {
				state.Errorf("Test of tlsrecord.Conn.Feed function failed, suite: %s, intercept: %v, plaintext should be ping and pong of a TLS 1.3 session with the first random, plaintext: %q, session: %+v", suite.name, intercept, plain, result)
				return
			}
		}
	}
}

// Test if tlsrecord.Conn.Feed returns with the expected output for handshake messages that are cut into records at any byte, the hellos and the protected ones.
func TestHandshakeRecordsPositive(state *testing.T) {
	suite := cipherSuitesTLS13[0]
	session, err := startSynthetic(suite)

	if err != nil {
		state.Fatalf("Test of tlsrecord.Conn.Feed failed, cannot create session, error: %s", err.Error())
	}

	clientHello := session.stream[0].data[recordHeaderLength:]
	serverHello := session.stream[1].data[recordHeaderLength:]
	finished := handshakeMessage(handshakeFinished, make([]byte, suite.newHash().Size()))
	// EncryptedExtensions with a protocol, a Certificate nothing is read from, and the Finished
	flight := slices.Concat(handshakeMessage(handshakeEncryptedExtensions, extensionBlock(helloExtension(extensionALPN, protocolsData("h2")))), handshakeMessage(11, bytes.Repeat([]byte{'c'}, 300)), finished)
	// where the messages are cut: inside a header, inside a body, inside the Certificate that is skipped, and in front of the last byte
	positiveCases := [][]int{
		{},
		{2},
		{handshakeHeaderLength, 30},
		{1, 2, 3, 4, 5},
		{20, 100, 200},
	}

	for _, positive := range positiveCases {
		session.stream = nil
		err = errors.Join(session.protect(ServerDirection, session.secrets.ServerHandshakeTrafficSecret), session.protect(ClientDirection, session.secrets.ClientHandshakeTrafficSecret))

		if err != nil {
			state.Fatalf("Test of tlsrecord.Conn.Feed failed, cannot create session, error: %s", err.Error())
		}

		for _, piece := range cutMessage(clientHello, positive) {
			session.plain(ClientDirection, HandshakeContentType, piece)
		}

		for _, piece := range cutMessage(serverHello, positive) {
			session.plain(ServerDirection, HandshakeContentType, piece)
		}

		for _, piece := range cutMessage(flight, append(slices.Clone(positive), len(flight)-1)) {
			session.protected(ServerDirection, HandshakeContentType, piece)
		}

		session.protected(ClientDirection, HandshakeContentType, finished)
		err = errors.Join(session.protect(ServerDirection, session.secrets.ServerTrafficSecret), session.protect(ClientDirection, session.secrets.ClientTrafficSecret))

		if err != nil {
			state.Fatalf("Test of tlsrecord.Conn.Feed failed, cannot create session, error: %s", err.Error())
		}

		session.protected(ClientDirection, ApplicationDataContentType, []byte("ping"))
		session.protected(ServerDirection, ApplicationDataContentType, []byte("pong"))
		conn, records, feedErr := feedSynthetic(session.stream, session.secrets, false)

		if feedErr != nil {
			state.Errorf("Test of tlsrecord.Conn.Feed function failed, cuts: %v, error: %s", positive, feedErr.Error())
			return
		}

		plain := applicationData(records)
		result := conn.Session()

		if (string(plain[ClientDirection]) != "ping") || (string(plain[ServerDirection]) != "pong") || (result.Protocol != "h2") || (result.ClientRandom != session.random) || (len(records) != len(session.stream)) {
			state.Errorf("Test of tlsrecord.Conn.Feed function failed, cuts: %v, plaintext should be ping and pong with protocol h2 in %d records, plaintext: %q, session: %+v, records: %d", positive, len(session.stream), plain, result, len(records))
			return
		}
	}
}

// Test if tlsrecord.Conn.Feed returns with the expected errors for protected records the TLS 1.3 record layer can't take, and that the error stays.
func TestProtectedRecordNegative(state *testing.T) {
	suite := cipherSuitesTLS13[0]
	finished := handshakeMessage(handshakeFinished, make([]byte, suite.newHash().Size()))
	encryptedExtensions := handshakeMessage(handshakeEncryptedExtensions, []byte{0, 0})
	negativeCases := []struct {
		Name       string
		IsFinished bool
		Add        func(session *synthetic)
		Err        error
	}{
		{Name: "ciphertext over the limit of TLS 1.3", IsFinished: false, Add: func(session *synthetic) {
			session.plain(ServerDirection, ApplicationDataContentType, make([]byte, maxCiphertextTLS13+1))
		}, Err: ErrRecordOverflow},
		{Name: "plaintext over the limit", IsFinished: false, Add: func(session *synthetic) {
			session.protected(ServerDirection, HandshakeContentType, make([]byte, maxPlaintext+1))
		}, Err: ErrRecordOverflow},
		{Name: "only zeros inside the protection", IsFinished: false, Add: func(session *synthetic) {
			session.protected(ServerDirection, ContentType(0), []byte{0, 0})
		}, Err: ErrUnexpectedRecord},
		{Name: "unknown content type inside the protection", IsFinished: false, Add: func(session *synthetic) {
			session.protected(ServerDirection, ContentType(99), []byte{1})
		}, Err: ErrUnexpectedRecord},
		{Name: "alert outside the protection", IsFinished: false, Add: func(session *synthetic) {
			session.plain(ServerDirection, AlertContentType, []byte{2, 40})
		}, Err: ErrUnexpectedRecord},
		{Name: "application data under the handshake keys", IsFinished: false, Add: func(session *synthetic) {
			session.protected(ServerDirection, ApplicationDataContentType, []byte("early"))
		}, Err: ErrUnexpectedRecord},
		{Name: "encrypted extensions cut", IsFinished: false, Add: func(session *synthetic) {
			session.protected(ServerDirection, HandshakeContentType, handshakeMessage(handshakeEncryptedExtensions, []byte{0, 5, 0}))
		}, Err: ErrMalformedHandshake},
		{Name: "encrypted extensions with two protocols", IsFinished: false, Add: func(session *synthetic) {
			session.protected(ServerDirection, HandshakeContentType, handshakeMessage(handshakeEncryptedExtensions, extensionBlock(helloExtension(extensionALPN, protocolsData("h2", "http/1.1")))))
		}, Err: ErrMalformedHandshake},
		{Name: "finished longer than a message that is read", IsFinished: false, Add: func(session *synthetic) {
			session.protected(ServerDirection, HandshakeContentType, []byte{handshakeFinished, 1, 0, 1, 0})
		}, Err: ErrMalformedHandshake},
		// a handshake message does not span a key change
		{Name: "start of a message behind the finished", IsFinished: false, Add: func(session *synthetic) {
			session.protected(ServerDirection, HandshakeContentType, slices.Concat(encryptedExtensions, finished, []byte{4, 0}))
		}, Err: ErrMalformedHandshake},
		{Name: "message that is skipped behind the finished", IsFinished: false, Add: func(session *synthetic) {
			session.protected(ClientDirection, HandshakeContentType, slices.Concat(finished, []byte{4, 0, 0, 9, 1}))
		}, Err: ErrMalformedHandshake},
		{Name: "start of a message behind the key update", IsFinished: true, Add: func(session *synthetic) {
			session.protected(ClientDirection, HandshakeContentType, append(handshakeMessage(handshakeKeyUpdate, []byte{0}), 4, 0))
		}, Err: ErrMalformedHandshake},
		{Name: "message that is skipped behind the key update", IsFinished: true, Add: func(session *synthetic) {
			session.protected(ServerDirection, HandshakeContentType, append(handshakeMessage(handshakeKeyUpdate, []byte{1}), 4, 0, 0, 9, 1))
		}, Err: ErrMalformedHandshake},
		{Name: "record sealed with the sequence number of the one before", IsFinished: true, Add: func(session *synthetic) {
			session.protected(ClientDirection, ApplicationDataContentType, []byte("ping"))
			session.sequences[ClientDirection]--
			session.protected(ClientDirection, ApplicationDataContentType, []byte("ping"))
		}, Err: ErrBadRecordMAC},
	}

	for _, negative := range negativeCases {
		session, err := startSynthetic(suite)

		if (err == nil) && negative.IsFinished {
			err = finishSynthetic(&session)
		}

		if err != nil {
			state.Fatalf("Test of tlsrecord.Conn.Feed failed, cannot create session, error: %s", err.Error())
		}

		negative.Add(&session)

		for _, intercept := range []bool{false, true} {
			err = testFinalError(session.stream, session.secrets, intercept, negative.Err)

			if err != nil {
				state.Errorf("Test of tlsrecord.Conn.Feed function failed, case: %s, intercept: %v, error: %s", negative.Name, intercept, err.Error())
				return
			}
		}
	}
}

// Test if tlsrecord.Conn.Feed returns with the expected errors for records and hellos that are not a start of a TLS session, and that the error stays.
func TestHelloRecordNegative(state *testing.T) {
	random := [randomLength]byte(bytes.Repeat([]byte{0x42}, randomLength))
	clientHello := handshakeMessage(handshakeClientHello, clientHelloBody(VersionTLS12, random, false, nil))
	serverHello := handshakeMessage(handshakeServerHello, serverHelloBody(VersionTLS12, random, tlsAES128GCMSHA256, helloExtension(extensionSupportedVersions, []byte{3, 4})))
	secret := make([]byte, cipherSuitesTLS13[0].newHash().Size())
	secrets := Secrets{Version: VersionTLS13, MasterKey: nil, ClientHandshakeTrafficSecret: secret, ServerHandshakeTrafficSecret: secret, ClientTrafficSecret: secret, ServerTrafficSecret: secret}
	client := func(data []byte) syntheticChunk { return syntheticChunk{direction: ClientDirection, data: data} }
	server := func(data []byte) syntheticChunk { return syntheticChunk{direction: ServerDirection, data: data} }
	negativeCases := []struct {
		Name   string
		Stream []syntheticChunk
		Err    error
	}{
		{Name: "unknown content type", Stream: []syntheticChunk{client([]byte{99, 3, 3, 0, 1, 0})}, Err: ErrUnexpectedRecord},
		{Name: "record of another protocol version", Stream: []syntheticChunk{client([]byte{byte(HandshakeContentType), 2, 0, 0, 1, 0})}, Err: ErrUnexpectedRecord},
		{Name: "record longer than any", Stream: []syntheticChunk{client([]byte{byte(HandshakeContentType), 3, 1, 0x48, 0x01})}, Err: ErrRecordOverflow},
		{Name: "application data in front of the hello", Stream: []syntheticChunk{client(plainRecord(ApplicationDataContentType, []byte("GET / HTTP/1.1\r\n\r\n")))}, Err: ErrUnexpectedRecord},
		{Name: "client hello longer than a message that is read", Stream: []syntheticChunk{client(plainRecord(HandshakeContentType, []byte{handshakeClientHello, 1, 0, 1, 3, 3}))}, Err: ErrMalformedHandshake},
		{Name: "client hello that ends in its random", Stream: []syntheticChunk{client(plainRecord(HandshakeContentType, handshakeMessage(handshakeClientHello, clientHello[handshakeHeaderLength:30])))}, Err: ErrMalformedHandshake},
		{Name: "server hello that ends in its random", Stream: []syntheticChunk{client(plainRecord(HandshakeContentType, clientHello)), server(plainRecord(HandshakeContentType, handshakeMessage(handshakeServerHello, serverHello[handshakeHeaderLength:30])))}, Err: ErrMalformedHandshake},
		{Name: "server hello of TLS 1.1", Stream: []syntheticChunk{client(plainRecord(HandshakeContentType, clientHello)), server(plainRecord(HandshakeContentType, handshakeMessage(handshakeServerHello, serverHelloBody(0x0302, random, tlsRSAWithAES128CBCSHA, nil))))}, Err: ErrUnsupportedVersion},
		{Name: "start of a message behind the server hello", Stream: []syntheticChunk{client(plainRecord(HandshakeContentType, clientHello)), server(plainRecord(HandshakeContentType, append(bytes.Clone(serverHello), handshakeEncryptedExtensions, 0)))}, Err: ErrMalformedHandshake},
		{Name: "start of a message of the client at the server hello", Stream: []syntheticChunk{client(plainRecord(HandshakeContentType, append(bytes.Clone(clientHello), handshakeFinished, 0))), server(plainRecord(HandshakeContentType, serverHello))}, Err: ErrMalformedHandshake},
	}

	for _, negative := range negativeCases {
		for _, intercept := range []bool{false, true} {
			err := testFinalError(negative.Stream, secrets, intercept, negative.Err)

			if err != nil {
				state.Errorf("Test of tlsrecord.Conn.Feed function failed, case: %s, intercept: %v, error: %s", negative.Name, intercept, err.Error())
				return
			}
		}
	}
}

// Test if an intercepting tlsrecord.Conn returns with the expected output for a ChangeCipherSpec of TLS 1.3 that comes while the records of its direction are held: it goes on as it came.
func TestInterceptCompatibilityPositive(state *testing.T) {
	suite := cipherSuitesTLS13[0]
	session, err := startSynthetic(suite)

	if err != nil {
		state.Fatalf("Test of tlsrecord.Conn.Feed failed, cannot create session, error: %s", err.Error())
	}

	finished := handshakeMessage(handshakeFinished, make([]byte, suite.newHash().Size()))
	session.protected(ServerDirection, HandshakeContentType, append(handshakeMessage(handshakeEncryptedExtensions, []byte{0, 0}), finished...))
	// the client sends its Certificate, then the ChangeCipherSpec for the middleboxes, then its Finished (RFC 8446 appendix D.4 allows it any time before the Finished)
	session.protected(ClientDirection, HandshakeContentType, handshakeMessage(11, bytes.Repeat([]byte{'c'}, 50)))
	session.plain(ClientDirection, ChangeCipherSpecContentType, []byte{1})
	changeCipherSpec := session.stream[len(session.stream)-1].data
	session.protected(ClientDirection, HandshakeContentType, finished)
	err = session.protect(ClientDirection, session.secrets.ClientTrafficSecret)

	if err != nil {
		state.Fatalf("Test of tlsrecord.Conn.Feed failed, cannot create session, error: %s", err.Error())
	}

	session.protected(ClientDirection, ApplicationDataContentType, []byte("ping"))
	conn, records, err := feedSynthetic(session.stream, session.secrets, true)

	if err != nil {
		state.Errorf("Test of tlsrecord.Conn.Feed function failed, error: %s", err.Error())
		return
	}

	// the ClientHello goes on and is shown, the protected records are held and sealed again, the ChangeCipherSpec between them is held too and goes on raw
	expected := []Action{ForwardAction, ShowAction, SealAction, ForwardAction, SealAction, SealAction}
	var actions []Action
	var held Record

	for _, record := range records {
		if record.Direction != ClientDirection {
			continue
		}

		actions = append(actions, record.Action)

		if record.ContentType == ChangeCipherSpecContentType {
			held = record
		}
	}

	if !slices.Equal(actions, expected) || held.Decrypted || !bytes.Equal(held.Raw, changeCipherSpec) || !bytes.Equal(held.Payload, []byte{1}) {
		state.Errorf("Test of tlsrecord.Conn.Feed function failed, actions of the client should be %v with the change cipher spec raw, actions: %v, record: %+v", expected, actions, held)
		return
	}

	// a record without protection has nothing to seal again
	encrypter := NewEncrypter()
	_, _, err = encrypter.Seal(held, held.Payload)

	if !errors.Is(err, ErrSeal) {
		state.Errorf("Test of tlsrecord.Encrypter.Seal function failed, error should be %v, error: %v", ErrSeal, err)
		return
	}

	// with the secrets nothing waits and nothing is left to release
	released := conn.Release()

	if conn.Waiting() || conn.Holding() || conn.HoldingFor(ClientDirection) || conn.HoldingFor(ServerDirection) || (len(released) != 0) {
		state.Errorf("Test of tlsrecord.Conn.Release function failed, nothing should wait or be released, waiting: %v, holding: %v, released: %d", conn.Waiting(), conn.Holding(), len(released))
		return
	}

	unsent := conn.Unsent()

	if (len(unsent[ClientDirection]) != 0) || (len(unsent[ServerDirection]) != 0) {
		state.Errorf("Test of tlsrecord.Conn.Unsent function failed, nothing should be unsent, unsent: %x", unsent)
		return
	}
}

// Test if tlsrecord.Conn.Feed returns with the expected output for TLS 1.2 sessions of each kind of protection, with and without encrypt-then-MAC.
func TestSyntheticTLS12Positive(state *testing.T) {
	for _, suiteID := range []uint16{tlsECDHERSAWithAES128GCMSHA256, tlsECDHERSAWithAES256GCMSHA384, tlsECDHERSAWithChaCha20Poly1305SHA256, tlsECDHERSAWithAES128CBCSHA256, tlsECDHERSAWithAES256CBCSHA, tlsRSAWith3DESEDECBCSHA} {
		for _, encryptThenMAC := range []bool{false, true} {
			session, err := newSynthetic12(suiteID, encryptThenMAC)

			if err == nil {
				err = session.finish()
			}

			if err == nil {
				err = errors.Join(session.protected(ClientDirection, ApplicationDataContentType, []byte("ping")), session.protected(ServerDirection, ApplicationDataContentType, nil), session.protected(ServerDirection, ApplicationDataContentType, []byte("pong")), session.protected(ServerDirection, AlertContentType, []byte{1, 0}))
			}

			if err != nil {
				state.Fatalf("Test of tlsrecord.Conn.Feed failed, cannot create session, error: %s", err.Error())
			}

			for _, isHeld := range []bool{false, true} {
				conn := New(holdLimit(), false)
				var records []Record

				if !isHeld {
					_, err = conn.SetSecrets(session.secrets)
				}

				if err == nil {
					records, err = feedChunks(&conn, session.stream)
				}

				if (err == nil) && isHeld {
					if !conn.Waiting() {
						state.Errorf("Test of tlsrecord.Conn.Feed function failed, suite: %s, the protected records should wait for the secrets", session.suite.name)
						return
					}

					released, secretsErr := conn.SetSecrets(session.secrets)
					records = append(records, released...)
					err = secretsErr
				}

				if err != nil {
					state.Errorf("Test of tlsrecord.Conn.Feed function failed, suite: %s, encrypt-then-MAC: %v, held: %v, error: %s", session.suite.name, encryptThenMAC, isHeld, err.Error())
					return
				}

				plain := applicationData(records)
				result := conn.Session()
				last := records[len(records)-1]

				if (string(plain[ClientDirection]) != "ping") || (string(plain[ServerDirection]) != "pong") || (result.Version != VersionTLS12) || (result.CipherSuite != suiteID) || (len(records) != len(session.stream)) {
					state.Errorf("Test of tlsrecord.Conn.Feed function failed, suite: %s, encrypt-then-MAC: %v, held: %v, plaintext should be ping and pong in %d records, plaintext: %q, session: %+v, records: %d", session.suite.name, encryptThenMAC, isHeld, len(session.stream), plain, result, len(records))
					return
				}

				// the Finished, the empty record and the data come before the alert of the server
				if (last.ContentType != AlertContentType) || !last.Decrypted || (last.Sequence != 3) || !bytes.Equal(last.Payload, []byte{1, 0}) {
					state.Errorf("Test of tlsrecord.Conn.Feed function failed, suite: %s, encrypt-then-MAC: %v, held: %v, the last record should be the alert with sequence 3, record: %+v", session.suite.name, encryptThenMAC, isHeld, last)
					return
				}
			}
		}
	}
}

// Test if tlsrecord.Conn.Feed returns with the expected errors for TLS 1.2 sessions, and that the error stays.
func TestSyntheticTLS12Negative(state *testing.T) {
	negativeCases := []struct {
		Name       string
		SuiteID    uint16
		IsFinished bool
		Add        func(session *synthetic12) (err error)
		Err        error
	}{
		{Name: "master key of 47 bytes", SuiteID: tlsECDHERSAWithAES128GCMSHA256, IsFinished: true, Add: func(session *synthetic12) (err error) {
			session.secrets.MasterKey = session.secrets.MasterKey[:masterKeyLength-1]
			return
		}, Err: ErrSecrets},
		{Name: "secrets of TLS 1.3", SuiteID: tlsECDHERSAWithAES128GCMSHA256, IsFinished: true, Add: func(session *synthetic12) (err error) {
			session.secrets.Version = VersionTLS13
			return
		}, Err: ErrSecrets},
		{Name: "change cipher spec under the keys", SuiteID: tlsECDHERSAWithAES128GCMSHA256, IsFinished: true, Add: func(session *synthetic12) (err error) {
			err = session.protected(ClientDirection, ChangeCipherSpecContentType, []byte{1})
			return
		}, Err: ErrRenegotiation},
		{Name: "change cipher spec inside a message that is skipped", SuiteID: tlsECDHERSAWithAES128GCMSHA256, IsFinished: false, Add: func(session *synthetic12) (err error) {
			session.plain(ClientDirection, HandshakeContentType, append([]byte{16, 0, 0, 100}, make([]byte, 10)...))
			session.plain(ClientDirection, ChangeCipherSpecContentType, []byte{1})
			return
		}, Err: ErrMalformedHandshake},
		{Name: "change cipher spec inside a message that is read", SuiteID: tlsECDHERSAWithAES128GCMSHA256, IsFinished: false, Add: func(session *synthetic12) (err error) {
			session.plain(ServerDirection, HandshakeContentType, []byte{handshakeFinished, 0, 0, 12, 1, 2, 3})
			session.plain(ServerDirection, ChangeCipherSpecContentType, []byte{1})
			return
		}, Err: ErrMalformedHandshake},
		{Name: "application data in front of the change cipher spec", SuiteID: tlsECDHERSAWithAES128GCMSHA256, IsFinished: false, Add: func(session *synthetic12) (err error) {
			session.plain(ClientDirection, ApplicationDataContentType, []byte("GET / HTTP/1.1\r\n\r\n"))
			return
		}, Err: ErrUnexpectedRecord},
		{Name: "second server hello", SuiteID: tlsECDHERSAWithAES128GCMSHA256, IsFinished: false, Add: func(session *synthetic12) (err error) {
			session.stream = append(session.stream, session.stream[1])
			return
		}, Err: ErrUnexpectedRecord},
		{Name: "record that ends in the explicit nonce", SuiteID: tlsECDHERSAWithAES128GCMSHA256, IsFinished: true, Add: func(session *synthetic12) (err error) {
			session.plain(ClientDirection, ApplicationDataContentType, make([]byte, explicitNonceLength-1))
			return
		}, Err: ErrBadRecordMAC},
		{Name: "record that ends in the tag", SuiteID: tlsECDHERSAWithChaCha20Poly1305SHA256, IsFinished: true, Add: func(session *synthetic12) (err error) {
			session.plain(ServerDirection, ApplicationDataContentType, make([]byte, 15))
			return
		}, Err: ErrBadRecordMAC},
		{Name: "record of half a block", SuiteID: tlsECDHERSAWithAES128CBCSHA, IsFinished: true, Add: func(session *synthetic12) (err error) {
			session.plain(ServerDirection, ApplicationDataContentType, make([]byte, 40))
			return
		}, Err: ErrBadRecordMAC},
		{Name: "record sealed with the sequence number of the one before", SuiteID: tlsECDHERSAWithAES128CBCSHA, IsFinished: true, Add: func(session *synthetic12) (err error) {
			session.sequences[ClientDirection]--
			err = session.protected(ClientDirection, ApplicationDataContentType, []byte("ping"))
			return
		}, Err: ErrBadRecordMAC},
	}

	for _, negative := range negativeCases {
		for _, encryptThenMAC := range []bool{false, true} {
			session, err := newSynthetic12(negative.SuiteID, encryptThenMAC)

			if (err == nil) && negative.IsFinished {
				err = session.finish()
			}

			if err == nil {
				err = negative.Add(&session)
			}

			if err != nil {
				state.Fatalf("Test of tlsrecord.Conn.Feed failed, cannot create session, error: %s", err.Error())
			}

			for _, intercept := range []bool{false, true} {
				err = testFinalError(session.stream, session.secrets, intercept, negative.Err)

				if err != nil {
					state.Errorf("Test of tlsrecord.Conn.Feed function failed, case: %s, encrypt-then-MAC: %v, intercept: %v, error: %s", negative.Name, encryptThenMAC, intercept, err.Error())
					return
				}
			}
		}
	}
}

// the hellos of a synthetic TLS 1.3 session and the handshake traffic keys of both directions, the records added to the session follow the ServerHello
func startSynthetic(suite *cipherSuiteTLS13) (session synthetic, err error) {
	session, err = newSynthetic(suite)

	if err != nil {
		return
	}

	session.stream = slices.Clone(session.stream[:2])
	err = errors.Join(session.protect(ServerDirection, session.secrets.ServerHandshakeTrafficSecret), session.protect(ClientDirection, session.secrets.ClientHandshakeTrafficSecret))
	return
}

// the rest of the handshake: EncryptedExtensions and Finished of the server, Finished of the client, then the application traffic keys of both directions
func finishSynthetic(session *synthetic) (err error) {
	finished := handshakeMessage(handshakeFinished, make([]byte, session.suite.newHash().Size()))
	session.protected(ServerDirection, HandshakeContentType, append(handshakeMessage(handshakeEncryptedExtensions, []byte{0, 0}), finished...))
	session.protected(ClientDirection, HandshakeContentType, finished)
	err = errors.Join(session.protect(ServerDirection, session.secrets.ServerTrafficSecret), session.protect(ClientDirection, session.secrets.ClientTrafficSecret))
	return
}

// the hellos of a TLS 1.2 session of the suite and the keys of both directions from a random master key, encryptThenMAC puts the extension into both hellos
func newSynthetic12(suiteID uint16, encryptThenMAC bool) (session synthetic12, err error) {
	session.suite, err = cipherSuiteByID(suiteID)

	if err != nil {
		return
	}

	session.secrets = Secrets{Version: VersionTLS12, MasterKey: make([]byte, masterKeyLength)}
	clientRandom := [randomLength]byte{}
	serverRandom := [randomLength]byte{}

	for _, target := range [][]byte{session.secrets.MasterKey, clientRandom[:], serverRandom[:]} {
		_, err = rand.Read(target)

		if err != nil {
			return
		}
	}

	var extensions []byte

	if encryptThenMAC {
		extensions = helloExtension(extensionEncryptThenMAC, nil)
	}

	session.plain(ClientDirection, HandshakeContentType, handshakeMessage(handshakeClientHello, clientHelloBody(VersionTLS12, clientRandom, false, extensions)))
	session.plain(ServerDirection, HandshakeContentType, handshakeMessage(handshakeServerHello, serverHelloBody(VersionTLS12, serverRandom, suiteID, extensions)))
	keys := keysFromMasterSecret(session.suite, session.secrets.MasterKey, clientRandom[:], serverRandom[:])
	// only CBC suites have a MAC to move behind the encryption
	isMACOutside := encryptThenMAC && (session.suite.newAEAD == nil)
	session.protections[ClientDirection], err = newProtection(session.suite, keys.clientMAC, keys.clientKey, keys.clientIV, isMACOutside)

	if err != nil {
		return
	}

	session.protections[ServerDirection], err = newProtection(session.suite, keys.serverMAC, keys.serverKey, keys.serverIV, isMACOutside)
	return
}

func (session *synthetic12) plain(direction Direction, contentType ContentType, fragment []byte) {
	session.stream = append(session.stream, syntheticChunk{direction: direction, data: plainRecord(contentType, fragment)})
}

func (session *synthetic12) protected(direction Direction, contentType ContentType, plaintext []byte) (err error) {
	var record []byte

	if session.protections[direction].aead != nil {
		record = sealAEAD(session.protections[direction], session.sequences[direction], contentType, [2]byte{3, 3}, plaintext)
	} else {
		record, err = sealCBC(session.protections[direction], session.sequences[direction], contentType, [2]byte{3, 3}, plaintext)

		if err != nil {
			return
		}
	}

	session.sequences[direction]++
	session.stream = append(session.stream, syntheticChunk{direction: direction, data: record})
	return
}

// the rest of the handshake: a key exchange message nothing is read from, then ChangeCipherSpec and the Finished under the keys of each side
func (session *synthetic12) finish() (err error) {
	session.plain(ClientDirection, HandshakeContentType, handshakeMessage(16, make([]byte, 33)))

	for _, direction := range []Direction{ClientDirection, ServerDirection} {
		session.plain(direction, ChangeCipherSpecContentType, []byte{1})
		err = session.protected(direction, HandshakeContentType, handshakeMessage(handshakeFinished, make([]byte, 12)))

		if err != nil {
			return
		}
	}

	return
}

// cut a message at the offsets that are inside it, in their order
func cutMessage(message []byte, offsets []int) (pieces [][]byte) {
	start := 0

	for _, offset := range offsets {
		if (offset <= start) || (offset >= len(message)) {
			continue
		}

		pieces = append(pieces, message[start:offset])
		start = offset
	}

	pieces = append(pieces, message[start:])
	return
}

// feed the stream to a conn, records are what came out until the first error
func feedChunks(conn *Conn, stream []syntheticChunk) (records []Record, err error) {
	for _, chunk := range stream {
		fed, feedErr := conn.Feed(chunk.direction, chunk.data)
		records = append(records, fed...)

		if err = feedErr; err != nil {
			return
		}
	}

	return
}

// feed the stream to a conn that has the secrets from the start
func feedSynthetic(stream []syntheticChunk, secrets Secrets, intercept bool) (conn Conn, records []Record, err error) {
	conn = New(holdLimit(), intercept)
	_, err = conn.SetSecrets(secrets)

	if err != nil {
		return
	}

	records, err = feedChunks(&conn, stream)
	return
}

// the application data of each direction that was decrypted, an intercepting conn gives each record once decrypted
func applicationData(records []Record) (plain [2][]byte) {
	for _, record := range records {
		if record.Decrypted && (record.ContentType == ApplicationDataContentType) {
			plain[record.Direction] = append(plain[record.Direction], record.Payload...)
		}
	}

	return
}

// the stream has to end with the expected error, which every later call gives again
func testFinalError(stream []syntheticChunk, secrets Secrets, intercept bool, expected error) (err error) {
	conn, _, feedErr := feedSynthetic(stream, secrets, intercept)

	if !errors.Is(feedErr, expected) {
		err = fmt.Errorf("error should be %s, error: %w", expected.Error(), feedErr)
		return
	}

	records, againErr := conn.Feed(ClientDirection, plainRecord(AlertContentType, []byte{1, 0}))

	if !errors.Is(againErr, expected) || (len(records) != 0) {
		err = fmt.Errorf("the next feed should give %s without records, records: %d, error: %w", expected.Error(), len(records), againErr)
		return
	}

	records, againErr = conn.SetSecrets(secrets)

	if !errors.Is(againErr, expected) || (len(records) != 0) {
		err = fmt.Errorf("the next secrets should give %s without records, records: %d, error: %w", expected.Error(), len(records), againErr)
		return
	}

	return
}
