// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	// the port of openssl s_server when the fixtures were recorded, the lines of a fixture name the sender with c or s
	fixtureClientMark string = "c"
	fixtureServerMark string = "s"
	// what the relay adds to the client line, more than one record of a minimal datagram
	dtlsGrowLength int = 3000
)

// a DTLS 1.2 session between openssl s_client and s_server -mtu 400 (OpenSSL 3.6.2), recorded on lo with its key log line:
// cookie exchange, a certificate fragmented over three datagrams, several records per datagram, one application data line each way
type dtlsFixture struct {
	FileName    string
	OpenSSLName string
	CipherSuite uint16
}

type dtlsDatagram struct {
	direction Direction
	data      []byte
}

// a fixture read from testdata
type dtlsSession struct {
	clientRandom [randomLength]byte
	secrets      Secrets
	datagrams    []dtlsDatagram
	lines        [2]string
}

var (
	dtlsFixtures = []dtlsFixture{
		{FileName: "dtls_ecdhe_rsa_aes128_gcm_sha256.txt", OpenSSLName: "ECDHE-RSA-AES128-GCM-SHA256", CipherSuite: tlsECDHERSAWithAES128GCMSHA256},
		{FileName: "dtls_ecdhe_rsa_chacha20_poly1305.txt", OpenSSLName: "ECDHE-RSA-CHACHA20-POLY1305", CipherSuite: tlsECDHERSAWithChaCha20Poly1305SHA256},
		{FileName: "dtls_ecdhe_rsa_aes256_sha.txt", OpenSSLName: "ECDHE-RSA-AES256-SHA", CipherSuite: tlsECDHERSAWithAES256CBCSHA},
		{FileName: "dtls_ecdhe_rsa_aes128_sha256.txt", OpenSSLName: "ECDHE-RSA-AES128-SHA256", CipherSuite: tlsECDHERSAWithAES128CBCSHA256},
	}
)

// Test if tlsrecord.DTLSConn.Feed returns with the expected output for sessions of OpenSSL, with the secrets first, last, and with the protected datagrams reversed and sent twice.
func TestDTLSFeedPositive(state *testing.T) {
	for _, fixture := range dtlsFixtures {
		session, err := readDTLSFixture(fixture)

		if err != nil {
			state.Fatalf("Test of tlsrecord.DTLSConn.Feed failed, cannot read fixture, error: %s", err.Error())
		}

		orders := map[string][]dtlsDatagram{
			"in order":           session.datagrams,
			"reversed and twice": reorderDTLS(session.datagrams),
		}

		for orderName, datagrams := range orders {
			for _, isSecretsFirst := range []bool{true, false} {
				plain, conn, feedErr := feedDTLS(datagrams, session.secrets, isSecretsFirst)

				if feedErr != nil {
					state.Errorf("Test of tlsrecord.DTLSConn.Feed failed, suite: %s, order: %s, secrets first: %v, error: %s", fixture.OpenSSLName, orderName, isSecretsFirst, feedErr.Error())
					return
				}

				if (string(plain[ClientDirection]) != session.lines[ClientDirection]) || (string(plain[ServerDirection]) != session.lines[ServerDirection]) {
					state.Errorf("Test of tlsrecord.DTLSConn.Feed failed, suite: %s, order: %s, secrets first: %v, plaintext should be %q, result: %q", fixture.OpenSSLName, orderName, isSecretsFirst, session.lines, plain)
					return
				}

				result := conn.Session()

				if (result.Version != VersionDTLS12) || (result.CipherSuite != fixture.CipherSuite) || (result.ClientRandom != session.clientRandom) {
					state.Errorf("Test of tlsrecord.DTLSConn.Feed failed, suite: %s, session should be DTLS1.2 0x%04x %x, result: %s 0x%04x %x", fixture.OpenSSLName, fixture.CipherSuite, session.clientRandom, VersionName(result.Version), result.CipherSuite, result.ClientRandom)
					return
				}
			}
		}
	}
}

// Test if tlsrecord.DTLSConn.Feed returns with the expected errors.
func TestDTLSFeedNegative(state *testing.T) {
	session, err := readDTLSFixture(dtlsFixtures[0])

	if err != nil {
		state.Fatalf("Test of tlsrecord.DTLSConn.Feed failed, cannot read fixture, error: %s", err.Error())
	}

	wrongKey := session.secrets
	wrongKey.MasterKey = bytes.Clone(wrongKey.MasterKey)
	wrongKey.MasterKey[0] ^= 1
	wrongVersion := session.secrets
	wrongVersion.Version = VersionTLS12
	negativeCases := []struct {
		Name      string
		Datagrams []dtlsDatagram
		Secrets   Secrets
		Expected  error
	}{
		{Name: "wrong master key", Datagrams: session.datagrams, Secrets: wrongKey, Expected: ErrBadRecordMAC},
		{Name: "secrets of TLS 1.2", Datagrams: session.datagrams, Secrets: wrongVersion, Expected: ErrSecrets},
		{Name: "truncated record", Datagrams: changeDTLS(session.datagrams, ClientDirection, handshakeClientHello, func(data []byte) []byte { return data[:len(data)-1] }), Secrets: session.secrets, Expected: ErrUnexpectedRecord},
		{Name: "dtls 1.0 server hello", Datagrams: changeDTLS(session.datagrams, ServerDirection, handshakeServerHello, func(data []byte) []byte {
			data[dtlsRecordHeaderLength+dtlsHandshakeHeaderLength+1] = 0xff
			return data
		}), Secrets: session.secrets, Expected: ErrUnsupportedVersion},
		{Name: "epoch 2", Datagrams: changeDTLS(session.datagrams, ClientDirection, 0, func(data []byte) []byte {
			data[dtlsEpochOffset+1] = 2
			return data
		}), Secrets: session.secrets, Expected: ErrRenegotiation},
	}

	for _, negative := range negativeCases {
		_, _, feedErr := feedDTLS(negative.Datagrams, negative.Secrets, true)

		if !errors.Is(feedErr, negative.Expected) {
			state.Errorf("Test of tlsrecord.DTLSConn.Feed failed, case: %s, return value was not %v instead: %v", negative.Name, negative.Expected, feedErr)
			return
		}
	}
}

// Test if tlsrecord.IsDTLSClientHello returns with the expected output.
func TestIsDTLSClientHelloPositive(state *testing.T) {
	session, err := readDTLSFixture(dtlsFixtures[0])

	if err != nil {
		state.Fatalf("Test of tlsrecord.IsDTLSClientHello failed, cannot read fixture, error: %s", err.Error())
	}

	positiveCases := []struct {
		Input         []byte
		IsClientHello bool
	}{
		{Input: session.datagrams[0].data, IsClientHello: true},
		{Input: session.datagrams[1].data, IsClientHello: false},
		{Input: session.datagrams[0].data[:dtlsRecordHeaderLength], IsClientHello: false},
		{Input: []byte{22, 3, 1, 0, 200, 1, 0, 0, 196, 3, 3, 0, 0, 0}, IsClientHello: false},
		{Input: []byte{}, IsClientHello: false},
	}

	for _, positive := range positiveCases {
		isClientHello := IsDTLSClientHello(positive.Input)

		if isClientHello != positive.IsClientHello {
			state.Errorf("Test of tlsrecord.IsDTLSClientHello function failed, input: %x, result should be %v, result: %v", positive.Input, positive.IsClientHello, isClientHello)
			return
		}
	}
}

// Test if tlsrecord.DTLSEncrypter returns with the expected output: identity seals the same records for ChaCha20-Poly1305, a grown line is split into records that fit a minimal datagram, a receiver reads them.
func TestDTLSEncrypterPositive(state *testing.T) {
	for _, fixture := range dtlsFixtures {
		session, err := readDTLSFixture(fixture)

		if err != nil {
			state.Fatalf("Test of tlsrecord.DTLSEncrypter failed, cannot read fixture, error: %s", err.Error())
		}

		for _, isGrown := range []bool{false, true} {
			err = testDTLSRelay(fixture, session, isGrown)

			if err != nil {
				state.Errorf("Test of tlsrecord.DTLSEncrypter failed, suite: %s, grown: %v, error: %s", fixture.OpenSSLName, isGrown, err.Error())
				return
			}
		}
	}
}

// Test if tlsrecord.DTLSEncrypter numbers the records as expected: the sender's numbers until a split, then the next free one, raw records only with a free number.
func TestDTLSSequencePositive(state *testing.T) {
	suite, err := cipherSuiteByID(tlsECDHERSAWithAES128GCMSHA256)

	if err != nil {
		state.Fatalf("Test of tlsrecord.DTLSEncrypter failed, error: %s", err.Error())
	}

	sealer, protectionErr := newProtection(suite, nil, make([]byte, suite.keyLength), make([]byte, suite.ivLength), false)

	if protectionErr != nil {
		state.Fatalf("Test of tlsrecord.DTLSEncrypter failed, error: %s", protectionErr.Error())
	}

	short := []byte("short")
	long := bytes.Repeat([]byte("x"), 2*MinDatagramLength)
	steps := []struct {
		Sequence  uint64
		Plain     []byte
		IsForward bool
		Expected  []uint64
	}{
		{Sequence: 3, Plain: short, IsForward: true, Expected: []uint64{3}},
		{Sequence: 5, Plain: short, IsForward: false, Expected: []uint64{5}},
		// a late record before any split keeps its number
		{Sequence: 4, Plain: short, IsForward: false, Expected: []uint64{4}},
		{Sequence: 6, Plain: long, IsForward: false, Expected: []uint64{6, 7, 8}},
		{Sequence: 7, Plain: short, IsForward: false, Expected: []uint64{9}},
		// a raw record whose number was taken can't go on, a later one can
		{Sequence: 8, Plain: nil, IsForward: true, Expected: nil},
		{Sequence: 20, Plain: nil, IsForward: true, Expected: []uint64{20}},
		{Sequence: 10, Plain: short, IsForward: false, Expected: []uint64{21}},
		{Sequence: 30, Plain: short, IsForward: false, Expected: []uint64{30}},
	}
	encrypter := NewDTLSEncrypter()

	for _, step := range steps {
		record := Record{Direction: ClientDirection, ContentType: ApplicationDataContentType, Decrypted: true, Epoch: 1, Sequence: step.Sequence, sealer: sealer, version: VersionDTLS12}
		record.header[1] = 0xfe
		record.header[2] = 0xfd
		var numbers []uint64

		if step.IsForward {
			if encrypter.Forward(record) {
				numbers = []uint64{step.Sequence}
			}
		} else {
			sealed, sealErr := encrypter.Seal(record, step.Plain, MinDatagramLength)

			if sealErr != nil {
				state.Fatalf("Test of tlsrecord.DTLSEncrypter failed, sequence: %d, error: %s", step.Sequence, sealErr.Error())
			}

			for _, wire := range sealed {
				if len(wire) > MinDatagramLength {
					state.Errorf("Test of tlsrecord.DTLSEncrypter failed, sequence: %d, record should fit %d bytes, length: %d", step.Sequence, MinDatagramLength, len(wire))
					return
				}

				_, epoch, sequence, _, frameErr := frameDTLSRecord(wire)

				if (frameErr != nil) || (epoch != 1) {
					state.Fatalf("Test of tlsrecord.DTLSEncrypter failed, sequence: %d, epoch: %d, error: %v", step.Sequence, epoch, frameErr)
				}

				numbers = append(numbers, sequence)
			}
		}

		if !slices.Equal(numbers, step.Expected) {
			state.Errorf("Test of tlsrecord.DTLSEncrypter failed, sequence: %d, numbers should be %v, result: %v", step.Sequence, step.Expected, numbers)
			return
		}
	}
}

// Test if an intercepting tlsrecord.DTLSConn holds the application data until the secrets come, and lets it go on raw on Release.
func TestDTLSHoldPositive(state *testing.T) {
	session, err := readDTLSFixture(dtlsFixtures[0])

	if err != nil {
		state.Fatalf("Test of tlsrecord.DTLSConn hold failed, cannot read fixture, error: %s", err.Error())
	}

	for _, isReleased := range []bool{false, true} {
		conn := NewDTLS(holdLimit(), true)
		var applicationData []Record

		for _, datagram := range session.datagrams {
			records, feedErr := conn.Feed(datagram.direction, datagram.data)

			if feedErr != nil {
				state.Fatalf("Test of tlsrecord.DTLSConn hold failed, error: %s", feedErr.Error())
			}

			for _, record := range records {
				if record.Action != ForwardAction {
					state.Errorf("Test of tlsrecord.DTLSConn hold failed, record of epoch %d sequence %d should go on raw, action: %d", record.Epoch, record.Sequence, record.Action)
					return
				}

				if record.ContentType == ApplicationDataContentType {
					applicationData = append(applicationData, record)
				}
			}
		}

		if (len(applicationData) != 0) || !conn.Holding() || !conn.Waiting() {
			state.Errorf("Test of tlsrecord.DTLSConn hold failed, the application data should be held, sent: %d, holding: %v, waiting: %v", len(applicationData), conn.Holding(), conn.Waiting())
			return
		}

		expected := SealAction

		if isReleased {
			expected = ShowAction

			for _, record := range conn.Release() {
				if (record.Action != ForwardAction) || (len(record.Raw) == 0) {
					state.Errorf("Test of tlsrecord.DTLSConn hold failed, a released record should go on raw, action: %d", record.Action)
					return
				}
			}
		}

		records, secretsErr := conn.SetSecrets(session.secrets)

		if secretsErr != nil {
			state.Fatalf("Test of tlsrecord.DTLSConn hold failed, error: %s", secretsErr.Error())
		}

		plain := [2]string{}

		for _, record := range records {
			// the Finished of both sides went on raw and is only shown
			if record.ContentType != ApplicationDataContentType {
				continue
			}

			if !record.Decrypted || (record.Action != expected) || ((expected == SealAction) != (record.Raw != nil)) {
				state.Errorf("Test of tlsrecord.DTLSConn hold failed, released: %v, record of epoch %d sequence %d should be decrypted with action %d, decrypted: %v, action: %d", isReleased, record.Epoch, record.Sequence, expected, record.Decrypted, record.Action)
				return
			}

			plain[record.Direction] += string(record.Payload)
		}

		if plain != session.lines {
			state.Errorf("Test of tlsrecord.DTLSConn hold failed, released: %v, plaintext should be %q, result: %q", isReleased, session.lines, plain)
			return
		}
	}
}

// Test if the replay window returns with the expected output.
func TestReplayWindowPositive(state *testing.T) {
	window := replayWindow{}
	steps := []struct {
		Sequence uint64
		IsNew    bool
	}{
		{Sequence: 5, IsNew: true},
		{Sequence: 5, IsNew: false},
		{Sequence: 3, IsNew: true},
		{Sequence: 3, IsNew: false},
		{Sequence: 70, IsNew: true},
		{Sequence: 6, IsNew: false},
		{Sequence: 7, IsNew: true},
		{Sequence: 7, IsNew: false},
		{Sequence: 1000, IsNew: true},
		{Sequence: 70, IsNew: false},
		{Sequence: 999, IsNew: true},
	}

	for _, step := range steps {
		isNew := window.accept(step.Sequence)

		if isNew != step.IsNew {
			state.Errorf("Test of the replay window failed, sequence: %d, result should be %v, result: %v", step.Sequence, step.IsNew, isNew)
			return
		}
	}
}

// relay a fixture through an intercepting conn and a DTLSEncrypter into a receiving conn: the application data is sealed again, grown by dtlsGrowLength bytes when isGrown
// each sealed record goes into a datagram of its own, which keeps every datagram within MinDatagramLength
func testDTLSRelay(fixture dtlsFixture, session dtlsSession, isGrown bool) (err error) {
	relay := NewDTLS(holdLimit(), true)
	receiver := NewDTLS(holdLimit(), false)
	encrypters := [2]DTLSEncrypter{NewDTLSEncrypter(), NewDTLSEncrypter()}
	received := [2][]byte{}
	expected := session.lines
	_, err = relay.SetSecrets(session.secrets)

	if err != nil {
		return
	}

	_, err = receiver.SetSecrets(session.secrets)

	if err != nil {
		return
	}

	for _, datagram := range session.datagrams {
		records, feedErr := relay.Feed(datagram.direction, datagram.data)

		if err = feedErr; err != nil {
			return
		}

		var wires [][]byte

		for _, record := range records {
			switch record.Action {
			case ForwardAction:
				if !encrypters[record.Direction].Forward(record) {
					err = fmt.Errorf("record of epoch %d sequence %d can't go on raw", record.Epoch, record.Sequence)
					return
				}

				wires = append(wires, record.Raw)
			case SealAction:
				plain := record.Payload

				if isGrown && (record.ContentType == ApplicationDataContentType) {
					plain = append(bytes.Repeat([]byte("+"), dtlsGrowLength), record.Payload...)
				}

				sealed, sealErr := encrypters[record.Direction].Seal(record, plain, MinDatagramLength)

				if err = sealErr; err != nil {
					return
				}

				// ChaCha20-Poly1305 has no explicit nonce and no random iv, the same keys and number give the same record
				if !isGrown && (fixture.CipherSuite == tlsECDHERSAWithChaCha20Poly1305SHA256) && ((len(sealed) != 1) || !bytes.Equal(sealed[0], record.Raw)) {
					err = fmt.Errorf("identity seal of epoch %d sequence %d is not the record OpenSSL sent", record.Epoch, record.Sequence)
					return
				}

				if isGrown && (record.ContentType == ApplicationDataContentType) && (len(sealed) < 2) {
					err = fmt.Errorf("a grown line of %d bytes went into %d records", len(plain), len(sealed))
					return
				}

				wires = append(wires, sealed...)
			default:
				err = fmt.Errorf("record of epoch %d sequence %d came with action %d", record.Epoch, record.Sequence, record.Action)
				return
			}
		}

		for _, wire := range wires {
			receivedRecords, receiveErr := receiver.Feed(datagram.direction, wire)

			if err = receiveErr; err != nil {
				err = fmt.Errorf("receiver: %w", err)
				return
			}

			for _, receivedRecord := range receivedRecords {
				if receivedRecord.Decrypted && (receivedRecord.ContentType == ApplicationDataContentType) {
					received[receivedRecord.Direction] = append(received[receivedRecord.Direction], receivedRecord.Payload...)
				}
			}
		}
	}

	if isGrown {
		for index := range expected {
			expected[index] = strings.Repeat("+", dtlsGrowLength) + expected[index]
		}
	}

	if (string(received[ClientDirection]) != expected[ClientDirection]) || (string(received[ServerDirection]) != expected[ServerDirection]) {
		err = fmt.Errorf("receiver plaintext should be %q, result: %q", expected, received)
	}

	return
}

// read a fixture: the CLIENT_RANDOM line of the client's key log, then one line per datagram with its sender and its bytes in hex
func readDTLSFixture(fixture dtlsFixture) (session dtlsSession, err error) {
	content, readErr := os.ReadFile(filepath.Join("testdata", fixture.FileName))

	if err = readErr; err != nil {
		return
	}

	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)

		switch {
		case (len(fields) == 3) && (fields[0] == "CLIENT_RANDOM"):
			random, randomErr := hex.DecodeString(fields[1])
			masterKey, keyErr := hex.DecodeString(fields[2])

			if err = errors.Join(randomErr, keyErr); err != nil {
				return
			}

			copy(session.clientRandom[:], random)
			session.secrets = Secrets{Version: VersionDTLS12, MasterKey: masterKey}
		case (len(fields) == 2) && ((fields[0] == fixtureClientMark) || (fields[0] == fixtureServerMark)):
			data, dataErr := hex.DecodeString(fields[1])

			if err = dataErr; err != nil {
				return
			}

			direction := ClientDirection

			if fields[0] == fixtureServerMark {
				direction = ServerDirection
			}

			session.datagrams = append(session.datagrams, dtlsDatagram{direction: direction, data: data})
		default:
			err = fmt.Errorf("unexpected line in %s: %q", fixture.FileName, line)
			return
		}
	}

	session.lines = [2]string{"hello dtls " + fixture.OpenSSLName + "\n", "hello from server " + fixture.OpenSSLName + "\n"}
	return
}

// feed the datagrams to a reading conn, the secrets before the first one or after the last one; plain is the application data of each direction
func feedDTLS(datagrams []dtlsDatagram, secrets Secrets, isSecretsFirst bool) (plain [2][]byte, conn DTLSConn, err error) {
	conn = NewDTLS(holdLimit(), false)
	var records []Record

	if isSecretsFirst {
		records, err = conn.SetSecrets(secrets)

		if err != nil {
			return
		}
	}

	for _, datagram := range datagrams {
		fed, feedErr := conn.Feed(datagram.direction, datagram.data)
		records = append(records, fed...)

		if err = feedErr; err != nil {
			return
		}
	}

	if !isSecretsFirst {
		released, secretsErr := conn.SetSecrets(secrets)
		records = append(records, released...)

		if err = secretsErr; err != nil {
			return
		}
	}

	for _, record := range records {
		if record.Decrypted && (record.ContentType == ApplicationDataContentType) {
			plain[record.Direction] = append(plain[record.Direction], record.Payload...)
		}
	}

	return
}

// the datagrams up to the ServerHello as they came, the rest backwards and each one twice
func reorderDTLS(datagrams []dtlsDatagram) (reordered []dtlsDatagram) {
	index := slices.IndexFunc(datagrams, func(datagram dtlsDatagram) bool {
		return (datagram.direction == ServerDirection) && (datagram.data[dtlsRecordHeaderLength] == handshakeServerHello)
	})
	reordered = slices.Clone(datagrams[:index+1])

	for _, datagram := range slices.Backward(datagrams[index+1:]) {
		reordered = append(reordered, datagram, datagram)
	}

	return
}

// a copy of the datagrams with the first one of the direction that starts with the handshake message type changed, message type 0 is the first application data datagram
func changeDTLS(datagrams []dtlsDatagram, direction Direction, messageType uint8, change func([]byte) []byte) (changed []dtlsDatagram) {
	isChanged := false

	for _, datagram := range datagrams {
		data := bytes.Clone(datagram.data)
		isMatch := (datagram.direction == direction) && (len(data) > dtlsRecordHeaderLength)

		if messageType == 0 {
			isMatch = isMatch && (ContentType(data[0]) == ApplicationDataContentType)
		} else {
			isMatch = isMatch && (ContentType(data[0]) == HandshakeContentType) && (data[dtlsRecordHeaderLength] == messageType)
		}

		if isMatch && !isChanged {
			isChanged = true
			data = change(data)
		}

		changed = append(changed, dtlsDatagram{direction: datagram.direction, data: data})
	}

	return
}
