// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
)

// Test if tlsrecord.DTLSConn.Feed returns with the expected output for hellos that come in fragments, out of order and more than once.
func TestDTLSFragmentsPositive(state *testing.T) {
	random := [randomLength]byte(bytes.Repeat([]byte{0x42}, randomLength))
	serverRandom := [randomLength]byte(bytes.Repeat([]byte{0x24}, randomLength))
	clientHello := clientHelloBody(VersionDTLS12, random, true, slices.Concat(helloExtension(extensionServerName, serverNameData(serverNameHostName, "dtls.test")), helloExtension(extensionALPN, protocolsData("coap", "h3"))))
	serverHello := serverHelloBody(VersionDTLS12, serverRandom, tlsECDHERSAWithAES128CBCSHA256, slices.Concat(helloExtension(extensionALPN, protocolsData("coap")), helloExtension(extensionEncryptThenMAC, nil)))
	cut := len(clientHello) / 2
	steps := []struct {
		Name       string
		Direction  Direction
		Datagram   []byte
		Sequences  []uint64
		ServerName string
		Version    uint16
	}{
		{Name: "end of the client hello", Direction: ClientDirection, Datagram: dtlsRecord(HandshakeContentType, 0, 1, dtlsFragment(handshakeClientHello, 0, len(clientHello), cut, clientHello[cut:])), Sequences: []uint64{1}, ServerName: "", Version: 0},
		{Name: "start of the client hello and some of its end again", Direction: ClientDirection, Datagram: dtlsRecord(HandshakeContentType, 0, 0, dtlsFragment(handshakeClientHello, 0, len(clientHello), 0, clientHello[:cut+5])), Sequences: []uint64{0}, ServerName: "dtls.test", Version: 0},
		{Name: "client hello again in one piece", Direction: ClientDirection, Datagram: dtlsRecord(HandshakeContentType, 0, 2, dtlsFragment(handshakeClientHello, 0, len(clientHello), 0, clientHello)), Sequences: []uint64{2}, ServerName: "dtls.test", Version: 0},
		{Name: "hello verify request", Direction: ServerDirection, Datagram: dtlsRecord(HandshakeContentType, 0, 0, dtlsFragment(3, 0, 7, 0, []byte{0xfe, 0xff, 4, 1, 2, 3, 4})), Sequences: []uint64{0}, ServerName: "dtls.test", Version: 0},
		{Name: "client hello after the hello verify request", Direction: ClientDirection, Datagram: dtlsRecord(HandshakeContentType, 0, 3, dtlsFragment(handshakeClientHello, 1, len(clientHello), 0, clientHello)), Sequences: []uint64{3}, ServerName: "dtls.test", Version: 0},
		{Name: "end of the server hello", Direction: ServerDirection, Datagram: dtlsRecord(HandshakeContentType, 0, 2, dtlsFragment(handshakeServerHello, 1, len(serverHello), 10, serverHello[10:])), Sequences: []uint64{2}, ServerName: "dtls.test", Version: 0},
		// two fragments in one record and two records in one datagram: the start of the ServerHello, the start of a Certificate nothing is read from, a ChangeCipherSpec
		{Name: "start of the server hello", Direction: ServerDirection, Datagram: slices.Concat(dtlsRecord(HandshakeContentType, 0, 1, slices.Concat(dtlsFragment(handshakeServerHello, 1, len(serverHello), 0, serverHello[:10]), dtlsFragment(11, 2, 1000, 0, make([]byte, 100)))), dtlsRecord(ChangeCipherSpecContentType, 0, 3, []byte{1})), Sequences: []uint64{1, 3}, ServerName: "dtls.test", Version: VersionDTLS12},
		// after the ServerHello no hello is read, not even one that would not parse
		{Name: "client hello after the server hello", Direction: ClientDirection, Datagram: dtlsRecord(HandshakeContentType, 0, 4, dtlsFragment(handshakeClientHello, 2, 3, 0, []byte{0xfe, 0xfd, 1})), Sequences: []uint64{4}, ServerName: "dtls.test", Version: VersionDTLS12},
		{Name: "alert", Direction: ClientDirection, Datagram: dtlsRecord(AlertContentType, 0, 5, []byte{1, 0}), Sequences: []uint64{5}, ServerName: "dtls.test", Version: VersionDTLS12},
	}

	for _, intercept := range []bool{false, true} {
		conn := NewDTLS(holdLimit(), intercept)
		datagrams := [2]uint64{}

		for _, step := range steps {
			records, err := conn.Feed(step.Direction, step.Datagram)

			if err != nil {
				state.Errorf("Test of tlsrecord.DTLSConn.Feed function failed, intercept: %v, step: %s, error: %s", intercept, step.Name, err.Error())
				return
			}

			var sequences []uint64
			raw := []byte{}

			for _, record := range records {
				sequences = append(sequences, record.Sequence)
				raw = append(raw, record.Raw...)

				// a conn that only reads shows the record, a relay sends it on as it came
				if (record.Direction != step.Direction) || (record.Epoch != 0) || record.Decrypted || (record.Datagram != datagrams[step.Direction]) || (intercept != (record.Action == ForwardAction)) || (len(record.Payload) != record.Length-dtlsRecordHeaderLength) {
					state.Errorf("Test of tlsrecord.DTLSConn.Feed function failed, intercept: %v, step: %s, record should be one of epoch 0 of datagram %d, record: %+v", intercept, step.Name, datagrams[step.Direction], record)
					return
				}
			}

			datagrams[step.Direction]++
			session := conn.Session()

			if !slices.Equal(sequences, step.Sequences) || (intercept != bytes.Equal(raw, step.Datagram)) || (session.ServerName != step.ServerName) || (session.Version != step.Version) {
				state.Errorf("Test of tlsrecord.DTLSConn.Feed function failed, intercept: %v, step: %s, records should be %v of a session with name %q and version 0x%04x, records: %v, session: %+v", intercept, step.Name, step.Sequences, step.ServerName, step.Version, sequences, session)
				return
			}
		}

		session := conn.Session()

		if (session.ClientRandom != random) || !slices.Equal(session.OfferedProtocols, []string{"coap", "h3"}) || (session.Protocol != "coap") || (session.CipherSuite != tlsECDHERSAWithAES128CBCSHA256) || !conn.encryptThenMAC || conn.Waiting() || conn.Holding() {
			state.Errorf("Test of tlsrecord.DTLSConn.Feed function failed, intercept: %v, session should have the random, the protocols and the suite of the hellos, session: %+v", intercept, session)
			return
		}
	}
}

// Test if tlsrecord.DTLSConn reads the handshake fragments of a record with the expected errors.
func TestDTLSHandshakeNegative(state *testing.T) {
	random := [randomLength]byte{}
	clientHello := clientHelloBody(VersionDTLS12, random, true, nil)
	serverHello := serverHelloBody(VersionDTLS12, random, tlsECDHERSAWithAES128GCMSHA256, nil)
	whole := dtlsFragment(handshakeClientHello, 0, len(clientHello), 0, clientHello)
	negativeCases := []struct {
		Name      string
		Direction Direction
		Before    []byte
		Fragments []byte
		Err       error
	}{
		{Name: "part of a fragment header", Direction: ClientDirection, Before: nil, Fragments: whole[:dtlsHandshakeHeaderLength-1], Err: ErrMalformedHandshake},
		{Name: "fragment that ends behind its record", Direction: ClientDirection, Before: nil, Fragments: whole[:len(whole)-1], Err: ErrMalformedHandshake},
		{Name: "fragment that ends behind its message", Direction: ClientDirection, Before: nil, Fragments: dtlsFragment(handshakeClientHello, 0, 10, 5, make([]byte, 10)), Err: ErrMalformedHandshake},
		{Name: "message longer than one that is read", Direction: ClientDirection, Before: nil, Fragments: dtlsFragment(handshakeClientHello, 0, maxHandshake+1, 0, []byte{0xfe}), Err: ErrMalformedHandshake},
		{Name: "fragments of two lengths", Direction: ClientDirection, Before: nil, Fragments: slices.Concat(dtlsFragment(handshakeClientHello, 0, 100, 0, make([]byte, 10)), dtlsFragment(handshakeClientHello, 0, 200, 10, make([]byte, 10))), Err: ErrMalformedHandshake},
		{Name: "client hello that ends in its version", Direction: ClientDirection, Before: nil, Fragments: dtlsFragment(handshakeClientHello, 0, 3, 0, []byte{0xfe, 0xfd, 1}), Err: ErrMalformedHandshake},
		{Name: "client hello without a cookie", Direction: ClientDirection, Before: nil, Fragments: dtlsFragment(handshakeClientHello, 0, len(clientHello)-1, 0, clientHelloBody(VersionDTLS12, random, false, nil)), Err: ErrMalformedHandshake},
		{Name: "server hello without a client hello", Direction: ServerDirection, Before: nil, Fragments: dtlsFragment(handshakeServerHello, 0, len(serverHello), 0, serverHello), Err: ErrUnexpectedRecord},
		{Name: "server hello that ends in its random", Direction: ServerDirection, Before: whole, Fragments: dtlsFragment(handshakeServerHello, 0, 20, 0, serverHello[:20]), Err: ErrMalformedHandshake},
		{Name: "server hello of TLS 1.2", Direction: ServerDirection, Before: whole, Fragments: dtlsFragment(handshakeServerHello, 0, len(serverHello), 0, serverHelloBody(VersionTLS12, random, tlsECDHERSAWithAES128GCMSHA256, nil)), Err: ErrUnsupportedVersion},
		{Name: "server hello with a suite of TLS 1.3", Direction: ServerDirection, Before: whole, Fragments: dtlsFragment(handshakeServerHello, 0, len(serverHello), 0, serverHelloBody(VersionDTLS12, random, tlsAES128GCMSHA256, nil)), Err: ErrUnsupportedCipherSuite},
	}

	for _, negative := range negativeCases {
		conn := NewDTLS(holdLimit(), false)
		err := conn.handleHandshake(&conn.halves[ClientDirection], negative.Before)

		if err != nil {
			state.Fatalf("Test of tlsrecord.DTLSConn.handleHandshake failed, case: %s, cannot read the client hello, error: %s", negative.Name, err.Error())
		}

		err = conn.handleHandshake(&conn.halves[negative.Direction], negative.Fragments)

		if !errors.Is(err, negative.Err) {
			state.Errorf("Test of tlsrecord.DTLSConn.handleHandshake function failed, case: %s, error should be %v, error: %v", negative.Name, negative.Err, err)
			return
		}
	}
}

// Test if tlsrecord.frameDTLSRecord returns with the expected output.
func TestFrameDTLSRecordPositive(state *testing.T) {
	positiveCases := []struct {
		Name        string
		Datagram    []byte
		ContentType ContentType
		Epoch       uint16
		Sequence    uint64
		Length      int
	}{
		{Name: "empty record", Datagram: dtlsRecord(AlertContentType, 0, 0, nil), ContentType: AlertContentType, Epoch: 0, Sequence: 0, Length: dtlsRecordHeaderLength},
		{Name: "record of epoch 1", Datagram: dtlsRecord(ApplicationDataContentType, 1, 0x010203040506, []byte("data")), ContentType: ApplicationDataContentType, Epoch: 1, Sequence: 0x010203040506, Length: dtlsRecordHeaderLength + 4},
		{Name: "highest epoch and sequence number", Datagram: dtlsRecord(HandshakeContentType, 0xffff, dtlsMaxSequence, []byte{1}), ContentType: HandshakeContentType, Epoch: 0xffff, Sequence: dtlsMaxSequence, Length: dtlsRecordHeaderLength + 1},
		{Name: "first of two records", Datagram: slices.Concat(dtlsRecord(ChangeCipherSpecContentType, 0, 7, []byte{1}), dtlsRecord(HandshakeContentType, 1, 0, make([]byte, 40))), ContentType: ChangeCipherSpecContentType, Epoch: 0, Sequence: 7, Length: dtlsRecordHeaderLength + 1},
		{Name: "longest record", Datagram: dtlsRecord(ApplicationDataContentType, 1, 1, make([]byte, maxCiphertext)), ContentType: ApplicationDataContentType, Epoch: 1, Sequence: 1, Length: dtlsRecordHeaderLength + maxCiphertext},
	}

	for _, positive := range positiveCases {
		contentType, epoch, sequence, length, err := frameDTLSRecord(positive.Datagram)

		if (err != nil) || (contentType != positive.ContentType) || (epoch != positive.Epoch) || (sequence != positive.Sequence) || (length != positive.Length) {
			state.Errorf("Test of tlsrecord.frameDTLSRecord function failed, case: %s, result should be %d %d %d %d, result: %d %d %d %d, error: %v", positive.Name, positive.ContentType, positive.Epoch, positive.Sequence, positive.Length, contentType, epoch, sequence, length, err)
			return
		}
	}
}

// Test if tlsrecord.frameDTLSRecord returns with the expected errors.
func TestFrameDTLSRecordNegative(state *testing.T) {
	record := dtlsRecord(HandshakeContentType, 0, 0, make([]byte, 20))
	negativeCases := []struct {
		Name     string
		Datagram []byte
		Err      error
	}{
		{Name: "one byte", Datagram: record[:1], Err: ErrUnexpectedRecord},
		{Name: "header without its last byte", Datagram: record[:dtlsRecordHeaderLength-1], Err: ErrUnexpectedRecord},
		{Name: "unknown content type", Datagram: append([]byte{99}, record[1:]...), Err: ErrUnexpectedRecord},
		{Name: "record of TLS", Datagram: append([]byte{byte(HandshakeContentType), 3, 3}, record[3:]...), Err: ErrUnexpectedRecord},
		{Name: "record longer than any", Datagram: dtlsRecord(ApplicationDataContentType, 1, 0, make([]byte, maxCiphertext+1)), Err: ErrRecordOverflow},
		{Name: "record that ends behind its datagram", Datagram: record[:len(record)-1], Err: ErrUnexpectedRecord},
	}

	for _, negative := range negativeCases {
		_, _, _, _, err := frameDTLSRecord(negative.Datagram)

		if !errors.Is(err, negative.Err) {
			state.Errorf("Test of tlsrecord.frameDTLSRecord function failed, case: %s, error should be %v, error: %v", negative.Name, negative.Err, err)
			return
		}
	}
}

// Test if tlsrecord.DTLSConn takes the records of a datagram with the expected errors.
func TestDTLSRecordNegative(state *testing.T) {
	session, err := readDTLSFixture(dtlsFixtures[0])

	if err != nil {
		state.Fatalf("Test of tlsrecord.DTLSConn.take failed, cannot read fixture, error: %s", err.Error())
	}

	keyed, err := keyedDTLS(session)

	if err != nil {
		state.Fatalf("Test of tlsrecord.DTLSConn.take failed, cannot read the session, error: %s", err.Error())
	}

	version := [2]byte{dtlsVersionMajor, 0xfd}
	sealer := keyed.halves[ClientDirection].sealer
	overflow := sealAEAD(sealer, uint64(dtlsProtectedEpoch)<<dtlsSequenceBits|500, ApplicationDataContentType, version, make([]byte, maxPlaintext+1))
	changeCipherSpec := sealAEAD(sealer, uint64(dtlsProtectedEpoch)<<dtlsSequenceBits|501, ChangeCipherSpecContentType, version, []byte{1})
	negativeCases := []struct {
		Name    string
		IsKeyed bool
		Raw     []byte
		Err     error
	}{
		{Name: "application data in epoch 0", IsKeyed: true, Raw: dtlsRecord(ApplicationDataContentType, 0, 9, []byte("GET / HTTP/1.1\r\n\r\n")), Err: ErrUnexpectedRecord},
		{Name: "protected record in front of the server hello", IsKeyed: false, Raw: dtlsRecord(ApplicationDataContentType, dtlsProtectedEpoch, 0, make([]byte, 40)), Err: ErrUnexpectedRecord},
		{Name: "record of epoch 3", IsKeyed: true, Raw: dtlsRecord(ApplicationDataContentType, 3, 0, make([]byte, 40)), Err: ErrRenegotiation},
		{Name: "plaintext over the limit", IsKeyed: true, Raw: dtlsRecord(ApplicationDataContentType, dtlsProtectedEpoch, 500, overflow[recordHeaderLength:]), Err: ErrRecordOverflow},
		{Name: "change cipher spec under the keys", IsKeyed: true, Raw: dtlsRecord(ChangeCipherSpecContentType, dtlsProtectedEpoch, 501, changeCipherSpec[recordHeaderLength:]), Err: ErrRenegotiation},
	}

	for _, negative := range negativeCases {
		conn := NewDTLS(holdLimit(), true)

		if negative.IsKeyed {
			conn = keyed
		}

		_, err = takeDTLS(&conn, ClientDirection, negative.Raw)

		if !errors.Is(err, negative.Err) {
			state.Errorf("Test of tlsrecord.DTLSConn.take function failed, case: %s, error should be %v, error: %v", negative.Name, negative.Err, err)
			return
		}
	}
}

// Test if tlsrecord.DTLSConn returns with the expected errors for secrets that do not fit the session, set before the first datagram and after the last one.
func TestDTLSSecretsNegative(state *testing.T) {
	session, err := readDTLSFixture(dtlsFixtures[2])

	if err != nil {
		state.Fatalf("Test of tlsrecord.DTLSConn.SetSecrets failed, cannot read fixture, error: %s", err.Error())
	}

	negativeCases := []struct {
		Name    string
		Secrets Secrets
	}{
		{Name: "master key of 47 bytes", Secrets: Secrets{Version: VersionDTLS12, MasterKey: session.secrets.MasterKey[:masterKeyLength-1]}},
		{Name: "no master key", Secrets: Secrets{Version: VersionDTLS12, MasterKey: nil}},
		{Name: "secrets of TLS 1.3", Secrets: Secrets{Version: VersionTLS13, MasterKey: session.secrets.MasterKey}},
	}

	for _, negative := range negativeCases {
		for _, isSecretsFirst := range []bool{true, false} {
			_, _, err = feedDTLS(session.datagrams, negative.Secrets, isSecretsFirst)

			if !errors.Is(err, ErrSecrets) {
				state.Errorf("Test of tlsrecord.DTLSConn.SetSecrets function failed, case: %s, secrets first: %v, error should be %v, error: %v", negative.Name, isSecretsFirst, ErrSecrets, err)
				return
			}
		}
	}
}

// Test if tlsrecord.DTLSConn.Feed returns with the expected error when more bytes wait for the secrets than the hold limit.
func TestDTLSHoldLimitNegative(state *testing.T) {
	session, err := readDTLSFixture(dtlsFixtures[0])

	if err != nil {
		state.Fatalf("Test of tlsrecord.DTLSConn.Feed failed, cannot read fixture, error: %s", err.Error())
	}

	for _, intercept := range []bool{false, true} {
		conn := NewDTLS(dtlsRecordHeaderLength, intercept)
		isProtected := false

		for _, datagram := range session.datagrams {
			for rest := datagram.data; len(rest) > 0; {
				_, epoch, _, length, frameErr := frameDTLSRecord(rest)

				if frameErr != nil {
					state.Fatalf("Test of tlsrecord.DTLSConn.Feed failed, cannot read datagram, error: %s", frameErr.Error())
				}

				isProtected = isProtected || (epoch == dtlsProtectedEpoch)
				rest = rest[length:]
			}

			_, err = conn.Feed(datagram.direction, datagram.data)

			// the records of epoch 0 never wait, the first datagram with a protected record is over the limit
			if isProtected {
				break
			}

			if err != nil {
				state.Errorf("Test of tlsrecord.DTLSConn.Feed function failed, intercept: %v, a datagram of epoch 0 should not wait, error: %s", intercept, err.Error())
				return
			}
		}

		if !isProtected || !errors.Is(err, ErrHoldQueueFull) {
			state.Errorf("Test of tlsrecord.DTLSConn.Feed function failed, intercept: %v, error should be %v, error: %v", intercept, ErrHoldQueueFull, err)
			return
		}
	}
}

// Test if an intercepting tlsrecord.DTLSConn returns with the expected output around Release: held records go on raw, later ones at once, with the secrets they are shown and new ones are the relay's to seal.
func TestDTLSReleasePositive(state *testing.T) {
	session, err := readDTLSFixture(dtlsFixtures[0])

	if err != nil {
		state.Fatalf("Test of tlsrecord.DTLSConn.Release failed, cannot read fixture, error: %s", err.Error())
	}

	keyed, err := keyedDTLS(session)

	if err != nil {
		state.Fatalf("Test of tlsrecord.DTLSConn.Release failed, cannot read the session, error: %s", err.Error())
	}

	// three more lines of the client under the keys of the session
	lines := []string{"second line\n", "third line\n", "fourth line\n"}
	var extra [][]byte

	for index, line := range lines {
		record, sealErr := sealDTLS(keyed.halves[ClientDirection].sealer, dtlsProtectedEpoch, uint64(1000+index), ApplicationDataContentType, [2]byte{dtlsVersionMajor, 0xfd}, []byte(line))

		if sealErr != nil {
			state.Fatalf("Test of tlsrecord.DTLSConn.Release failed, cannot seal record, error: %s", sealErr.Error())
		}

		extra = append(extra, record)
	}

	conn := NewDTLS(holdLimit(), true)

	for _, datagram := range session.datagrams {
		_, err = conn.Feed(datagram.direction, datagram.data)

		if err != nil {
			state.Fatalf("Test of tlsrecord.DTLSConn.Release failed, cannot feed datagram, error: %s", err.Error())
		}
	}

	// the direction holds its records since its first line
	records, err := conn.Feed(ClientDirection, extra[0])

	if (err != nil) || (len(records) != 0) || !conn.HoldingFor(ClientDirection) || !conn.HoldingFor(ServerDirection) {
		state.Errorf("Test of tlsrecord.DTLSConn.Feed function failed, the second line should be held, records: %d, holding: %v %v, error: %v", len(records), conn.HoldingFor(ClientDirection), conn.HoldingFor(ServerDirection), err)
		return
	}

	released := conn.Release()
	count := [2]int{}

	for _, record := range released {
		count[record.Direction]++

		if (record.Action != ForwardAction) || record.Decrypted || (record.ContentType != ApplicationDataContentType) || (len(record.Raw) != record.Length) {
			state.Errorf("Test of tlsrecord.DTLSConn.Release function failed, a released record should be application data that goes on raw, record: %+v", record)
			return
		}
	}

	if (count != [2]int{2, 1}) || !bytes.Equal(released[len(released)-1].Raw, extra[0]) || conn.Holding() || !conn.Waiting() || (len(conn.Release()) != 0) || (len(conn.Unsent()) != 0) {
		state.Errorf("Test of tlsrecord.DTLSConn.Release function failed, two lines of the client and one of the server should be released once, released: %v, holding: %v, waiting: %v", count, conn.Holding(), conn.Waiting())
		return
	}

	// after the release nothing is held
	records, err = conn.Feed(ClientDirection, extra[1])

	if (err != nil) || (len(records) != 1) || (records[0].Action != ForwardAction) || records[0].Decrypted || !bytes.Equal(records[0].Raw, extra[1]) || conn.Holding() {
		state.Errorf("Test of tlsrecord.DTLSConn.Feed function failed, the third line should go on raw at once, records: %+v, error: %v", records, err)
		return
	}

	// the secrets show what went on
	records, err = conn.SetSecrets(session.secrets)

	if err != nil {
		state.Errorf("Test of tlsrecord.DTLSConn.SetSecrets function failed, error: %s", err.Error())
		return
	}

	for _, record := range records {
		if !record.Decrypted || (record.Action != ShowAction) || (record.Raw != nil) {
			state.Errorf("Test of tlsrecord.DTLSConn.SetSecrets function failed, a record that went on should only be shown, record: %+v", record)
			return
		}
	}

	plain := applicationData(records)
	expected := [2]string{session.lines[ClientDirection] + lines[0] + lines[1], session.lines[ServerDirection]}

	if (string(plain[ClientDirection]) != expected[ClientDirection]) || (string(plain[ServerDirection]) != expected[ServerDirection]) || conn.Waiting() || (conn.Release() != nil) {
		state.Errorf("Test of tlsrecord.DTLSConn.SetSecrets function failed, plaintext should be %q, plaintext: %q, waiting: %v", expected, plain, conn.Waiting())
		return
	}

	// with the keys a record is decrypted at once and the relay's to seal, a copy of it is left out
	records, err = conn.Feed(ClientDirection, extra[2])

	if (err != nil) || (len(records) != 1) || (records[0].Action != SealAction) || !records[0].Decrypted || (string(records[0].Payload) != lines[2]) || !bytes.Equal(records[0].Raw, extra[2]) || (records[0].Sequence != 1002) || (records[0].Epoch != dtlsProtectedEpoch) {
		state.Errorf("Test of tlsrecord.DTLSConn.Feed function failed, the fourth line should be decrypted for the relay to seal, records: %+v, error: %v", records, err)
		return
	}

	records, err = conn.Feed(ClientDirection, extra[2])

	if (err != nil) || (len(records) != 0) {
		state.Errorf("Test of tlsrecord.DTLSConn.Feed function failed, a copy of a record should be left out, records: %+v, error: %v", records, err)
		return
	}
}

// Test if tlsrecord.DTLSEncrypter.Seal returns with the expected output at its limits: the shortest datagram that holds a record and the highest sequence number.
func TestDTLSEncrypterLimitsPositive(state *testing.T) {
	for _, suiteID := range []uint16{tlsECDHERSAWithAES128GCMSHA256, tlsECDHERSAWithChaCha20Poly1305SHA256, tlsECDHERSAWithAES128CBCSHA256, tlsECDHERSAWith3DESEDECBCSHA} {
		record, err := sealedDTLSRecord(suiteID, 10)

		if err != nil {
			state.Fatalf("Test of tlsrecord.DTLSEncrypter.Seal failed, cannot create protection, error: %s", err.Error())
		}

		// room for one byte of plaintext in each record
		maxLength := dtlsRecordHeaderLength + sealOverhead(record.sealer) + 1
		encrypter := NewDTLSEncrypter()
		sealed, err := encrypter.Seal(record, []byte("abc"), maxLength)

		if (err != nil) || (len(sealed) != 3) {
			state.Errorf("Test of tlsrecord.DTLSEncrypter.Seal function failed, suite: 0x%04x, three bytes should go into three records, records: %d, error: %v", suiteID, len(sealed), err)
			return
		}

		for index, wire := range sealed {
			contentType, epoch, sequence, length, frameErr := frameDTLSRecord(wire)

			if (frameErr != nil) || (contentType != ApplicationDataContentType) || (epoch != dtlsProtectedEpoch) || (sequence != 10+uint64(index)) || (length != len(wire)) || (len(wire) > maxLength) || (wire[1] != dtlsVersionMajor) {
				state.Errorf("Test of tlsrecord.DTLSEncrypter.Seal function failed, suite: 0x%04x, record %d should be application data of epoch 1 within %d bytes, type: %d, epoch: %d, sequence: %d, length: %d, error: %v", suiteID, index, maxLength, contentType, epoch, sequence, len(wire), frameErr)
				return
			}
		}

		// no plaintext is one empty record, with the next free number once the numbers moved
		record.Sequence = 5
		sealed, err = encrypter.Seal(record, nil, maxLength)

		if (err != nil) || (len(sealed) != 1) {
			state.Errorf("Test of tlsrecord.DTLSEncrypter.Seal function failed, suite: 0x%04x, no plaintext should be one record, records: %d, error: %v", suiteID, len(sealed), err)
			return
		}

		_, _, sequence, _, err := frameDTLSRecord(sealed[0])

		if (err != nil) || (sequence != 13) || (len(sealed[0]) > maxLength) {
			state.Errorf("Test of tlsrecord.DTLSEncrypter.Seal function failed, suite: 0x%04x, the empty record should have sequence 13 within %d bytes, sequence: %d, length: %d, error: %v", suiteID, maxLength, sequence, len(sealed[0]), err)
			return
		}
	}
}

// Test if tlsrecord.DTLSEncrypter.Seal returns with the expected errors.
func TestDTLSEncrypterNegative(state *testing.T) {
	record, err := sealedDTLSRecord(tlsECDHERSAWithAES128GCMSHA256, dtlsMaxSequence)

	if err != nil {
		state.Fatalf("Test of tlsrecord.DTLSEncrypter.Seal failed, cannot create protection, error: %s", err.Error())
	}

	withoutKeys := record
	withoutKeys.sealer = nil
	overhead := dtlsRecordHeaderLength + sealOverhead(record.sealer)
	negativeCases := []struct {
		Name      string
		Record    Record
		Plain     []byte
		MaxLength int
	}{
		{Name: "record that was not decrypted", Record: withoutKeys, Plain: []byte("abc"), MaxLength: MinDatagramLength},
		{Name: "datagram of no bytes", Record: record, Plain: []byte("abc"), MaxLength: 0},
		{Name: "datagram of a header", Record: record, Plain: []byte("abc"), MaxLength: dtlsRecordHeaderLength},
		{Name: "datagram without room for plaintext", Record: record, Plain: []byte("abc"), MaxLength: overhead},
		// the second record would need a number above 2^48-1
		{Name: "split at the highest sequence number", Record: record, Plain: []byte("abc"), MaxLength: overhead + 2},
	}

	for _, negative := range negativeCases {
		encrypter := NewDTLSEncrypter()
		_, err = encrypter.Seal(negative.Record, negative.Plain, negative.MaxLength)

		if !errors.Is(err, ErrSeal) {
			state.Errorf("Test of tlsrecord.DTLSEncrypter.Seal function failed, case: %s, error should be %v, error: %v", negative.Name, ErrSeal, err)
			return
		}
	}

	// the highest number itself is fine
	encrypter := NewDTLSEncrypter()
	sealed, err := encrypter.Seal(record, []byte("abc"), MinDatagramLength)

	if (err != nil) || (len(sealed) != 1) {
		state.Errorf("Test of tlsrecord.DTLSEncrypter.Seal function failed, a record should go on with the highest sequence number, records: %d, error: %v", len(sealed), err)
		return
	}
}

// a record as it is on the wire: content type, version, epoch, sequence number, length and payload
func dtlsRecord(contentType ContentType, epoch uint16, sequence uint64, payload []byte) (record []byte) {
	record = []byte{byte(contentType), dtlsVersionMajor, 0xfd}
	record = binary.BigEndian.AppendUint64(record, uint64(epoch)<<dtlsSequenceBits|sequence)
	record = binary.BigEndian.AppendUint16(record, uint16(len(payload)))
	record = append(record, payload...)
	return
}

// one fragment of a handshake message: message type, length of the message, message sequence, offset and length of the fragment, and the fragment
func dtlsFragment(messageType uint8, messageSequence uint16, length int, offset int, fragment []byte) (encoded []byte) {
	encoded = []byte{messageType, byte(length >> 16), byte(length >> 8), byte(length)}
	encoded = binary.BigEndian.AppendUint16(encoded, messageSequence)
	encoded = append(encoded, byte(offset>>16), byte(offset>>8), byte(offset), byte(len(fragment)>>16), byte(len(fragment)>>8), byte(len(fragment)))
	encoded = append(encoded, fragment...)
	return
}

// a relay's conn that read the session of a fixture with its secrets, so both directions have their keys
func keyedDTLS(session dtlsSession) (conn DTLSConn, err error) {
	conn = NewDTLS(holdLimit(), true)
	_, err = conn.SetSecrets(session.secrets)

	if err != nil {
		return
	}

	for _, datagram := range session.datagrams {
		_, err = conn.Feed(datagram.direction, datagram.data)

		if err != nil {
			return
		}
	}

	return
}

// what a conn does with one record of a datagram
func takeDTLS(conn *DTLSConn, direction Direction, raw []byte) (records []Record, err error) {
	contentType, epoch, sequence, length, err := frameDTLSRecord(raw)

	if err != nil {
		return
	}

	record := Record{Direction: direction, ContentType: contentType, Decrypted: false, Epoch: epoch, Sequence: sequence, Datagram: 0, Length: length, Payload: nil, Action: ShowAction, Raw: nil}
	records, err = conn.take(&conn.halves[direction], record, raw, nil)
	return
}

// a decrypted application data record of epoch 1 as a relay's conn gives it, with the write protection of zero keys of the suite
func sealedDTLSRecord(suiteID uint16, sequence uint64) (record Record, err error) {
	suite, err := cipherSuiteByID(suiteID)

	if err != nil {
		return
	}

	sealer, err := newProtection(suite, make([]byte, suite.macLength), make([]byte, suite.keyLength), make([]byte, suite.ivLength), false)

	if err != nil {
		return
	}

	record = Record{Direction: ClientDirection, ContentType: ApplicationDataContentType, Decrypted: true, Epoch: dtlsProtectedEpoch, Sequence: sequence, sealer: sealer, version: VersionDTLS12}
	record.header[1] = dtlsVersionMajor
	record.header[2] = 0xfd
	return
}
