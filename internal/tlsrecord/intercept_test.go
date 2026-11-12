// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord_test

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	_ "unsafe"

	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// the bytes the grow rule adds to the first application data record of its direction, more than one record holds
	growLength int = 20000
	// the index of the server's application data record the drop rule leaves out
	dropIndex int = 1
)

type ruleKind string

// crypto/tls has no setting for the TLS 1.3 suites, the test narrows its default lists to the one suite of a case
// both are pushed with go:linkname by crypto/tls itself (go.dev/issue/67401)
//
//go:linkname defaultCipherSuitesTLS13 crypto/tls.defaultCipherSuitesTLS13
var defaultCipherSuitesTLS13 []uint16

//go:linkname defaultCipherSuitesTLS13NoAES crypto/tls.defaultCipherSuitesTLS13NoAES
var defaultCipherSuitesTLS13NoAES []uint16

const (
	identityRuleKind ruleKind = "identity"
	growRuleKind     ruleKind = "grow"
	dropRuleKind     ruleKind = "drop"
)

type interceptCase struct {
	Session   testCase
	Rule      ruleKind
	Direction tlsrecord.Direction
}

// a relay in the middle of a crypto/tls session as the proxy is: whole records go on raw or are held, decrypted, changed by the rule and sealed again
// the secrets come from the key log of the client, as the uprobe gives them, polled while records wait
type relay struct {
	mutex      *sync.Mutex
	conn       tlsrecord.Conn
	encrypters [2]tlsrecord.Encrypter
	outputs    [2]*net.TCPConn
	keyLog     *lockedBuffer
	version    uint16
	masterKey  []byte
	rule       interceptCase
	// what the rule made of the application data, per direction, and how many records went which way
	sent      [2][]byte
	appCount  [2]int
	sealed    [2]int
	identical [2]int
	split     int
	dropped   int
	offsets   [2]int64
	err       error
}

type lockedBuffer struct {
	mutex  *sync.Mutex
	buffer bytes.Buffer
}

func (locked *lockedBuffer) Write(data []byte) (count int, err error) {
	locked.mutex.Lock()
	defer locked.mutex.Unlock()
	count, err = locked.buffer.Write(data)
	return
}

func (locked *lockedBuffer) String() (text string) {
	locked.mutex.Lock()
	defer locked.mutex.Unlock()
	text = locked.buffer.String()
	return
}

// Test if tlsrecord.Encrypter returns with the expected output.
func TestEncrypterPositive(state *testing.T) {
	state.Setenv("GODEBUG", "tls3des=1")
	ecdsaCertificate, rsaCertificate, err := newCertificates()

	if err != nil {
		state.Fatalf("Test of tlsrecord.Encrypter failed, cannot create certificates, error: %s", err.Error())
	}

	sessions := []testCase{
		{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_256_GCM_SHA384, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS13, CipherSuite: tls.TLS_CHACHA20_POLY1305_SHA256, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_RSA_WITH_AES_128_GCM_SHA256, Certificate: rsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, Certificate: rsaCertificate},
	}

	defaultSuites, defaultSuitesNoAES := defaultCipherSuitesTLS13, defaultCipherSuitesTLS13NoAES

	defer func() {
		defaultCipherSuitesTLS13, defaultCipherSuitesTLS13NoAES = defaultSuites, defaultSuitesNoAES
	}()

	for _, session := range sessions {
		if session.Version == tls.VersionTLS13 {
			defaultCipherSuitesTLS13 = []uint16{session.CipherSuite}
			defaultCipherSuitesTLS13NoAES = []uint16{session.CipherSuite}
		}

		positiveCases := []interceptCase{
			{Session: session, Rule: identityRuleKind, Direction: tlsrecord.ClientDirection},
			{Session: session, Rule: growRuleKind, Direction: tlsrecord.ServerDirection},
			{Session: session, Rule: growRuleKind, Direction: tlsrecord.ClientDirection},
			{Session: session, Rule: dropRuleKind, Direction: tlsrecord.ServerDirection},
		}

		for _, positive := range positiveCases {
			err = testIntercept(positive)

			if err != nil {
				state.Errorf("Test of tlsrecord.Encrypter failed, version: 0x%04x, cipher suite: %s, rule: %s %d, error: %s", session.Version, tls.CipherSuiteName(session.CipherSuite), positive.Rule, positive.Direction, err.Error())
				return
			}
		}
	}
}

// Test if tlsrecord.Encrypter returns with the expected errors.
func TestEncrypterNegative(state *testing.T) {
	ecdsaCertificate, _, err := newCertificates()

	if err != nil {
		state.Fatalf("Test of tlsrecord.Encrypter failed, cannot create certificates, error: %s", err.Error())
	}

	serverConfig, clientConfig, keyLog := newConfigs(testCase{Version: tls.VersionTLS13, CipherSuite: 0, Certificate: ecdsaCertificate})
	chunks, _, runErr := runSession(testCase{Version: tls.VersionTLS13, CipherSuite: 0, Certificate: ecdsaCertificate}, serverConfig, clientConfig, keyLog, false)

	if runErr != nil {
		state.Fatalf("Test of tlsrecord.Encrypter failed, cannot run session, error: %s", runErr.Error())
	}

	// a record that was not held has nothing to seal with
	encrypter := tlsrecord.NewEncrypter()
	conn := tlsrecord.New(holdLimit, true)
	records, feedErr := conn.Feed(chunks[0].direction, chunks[0].data)

	if (feedErr != nil) || (len(records) == 0) {
		state.Fatalf("Test of tlsrecord.Encrypter failed, cannot feed client hello, error: %v", feedErr)
	}

	_, _, sealErr := encrypter.Seal(records[0], records[0].Payload)

	if !errors.Is(sealErr, tlsrecord.ErrSeal) {
		state.Errorf("Test of tlsrecord.Encrypter failed, seal of a forwarded record return value was not %v instead: %v", tlsrecord.ErrSeal, sealErr)
		return
	}

	// without secrets the held records only go on through Release or Unsent, and only once
	conn = tlsrecord.New(holdLimit, true)
	var held int

	for _, chunk := range chunks {
		records, feedErr = conn.Feed(chunk.direction, chunk.data)

		if feedErr != nil {
			state.Fatalf("Test of tlsrecord.Encrypter failed, cannot feed session, error: %s", feedErr.Error())
		}

		for _, record := range records {
			if record.Action == tlsrecord.SealAction {
				state.Errorf("Test of tlsrecord.Encrypter failed, record without secrets return value was not forwarded instead: %v", record.Action)
				return
			}
		}
	}

	if !conn.Holding() {
		state.Errorf("Test of tlsrecord.Conn.Holding failed, return value was not true instead: false")
		return
	}

	for _, record := range conn.Release() {
		held += record.Length
	}

	unsent := conn.Unsent()

	if (held == 0) || (len(unsent[tlsrecord.ClientDirection]) != 0) || conn.Holding() {
		state.Errorf("Test of tlsrecord.Conn.Release failed, released %d bytes, %d bytes left, holding %v", held, len(unsent[tlsrecord.ClientDirection]), conn.Holding())
		return
	}
}

// one session through the relay, then once more resumed; what the peers received has to be what the relay sent, and the rule has to have done its work
func testIntercept(positive interceptCase) (err error) {
	serverConfig, clientConfig, _ := newConfigs(positive.Session)
	keyLog := &lockedBuffer{mutex: &sync.Mutex{}, buffer: bytes.Buffer{}}
	clientConfig.KeyLogWriter = keyLog
	var masterKey []byte

	for _, resumed := range []bool{false, true} {
		currentRelay, runErr := runRelayedSession(positive, serverConfig, clientConfig, keyLog, masterKey, resumed)

		if err = runErr; err != nil {
			err = fmt.Errorf("resumed %v: %w", resumed, err)
			return
		}

		masterKey = currentRelay.masterKey

		err = checkRelay(positive, currentRelay)

		if err != nil {
			err = fmt.Errorf("resumed %v: %w", resumed, err)
			return
		}
	}

	return
}

func checkRelay(positive interceptCase, currentRelay *relay) (err error) {
	for _, direction := range []tlsrecord.Direction{tlsrecord.ClientDirection, tlsrecord.ServerDirection} {
		// every application data record went through the relay, sealed again
		if (currentRelay.appCount[direction] == 0) || (currentRelay.sealed[direction] < currentRelay.appCount[direction]-currentRelay.dropped) {
			err = fmt.Errorf("direction %d: %d application data records, %d sealed", direction, currentRelay.appCount[direction], currentRelay.sealed[direction])
			return
		}
	}

	switch positive.Rule {
	case identityRuleKind:
		// an AEAD record sealed again with the same key, nonce and padding is the record that came, a CBC record gets a fresh iv
		isCBC := (positive.Session.Version == tls.VersionTLS12) && (bytes.Contains([]byte(tls.CipherSuiteName(positive.Session.CipherSuite)), []byte("CBC")))

		if !isCBC && (currentRelay.identical != currentRelay.sealed) {
			err = fmt.Errorf("identity rule: %v records sealed, %v identical", currentRelay.sealed, currentRelay.identical)
		}
	case growRuleKind:
		if (currentRelay.split == 0) || (currentRelay.offsets[positive.Direction] < 1) {
			err = fmt.Errorf("grow rule: %d splits, offset %d", currentRelay.split, currentRelay.offsets[positive.Direction])
		}
	case dropRuleKind:
		if (currentRelay.dropped != 1) || (currentRelay.offsets[positive.Direction] != -1) {
			err = fmt.Errorf("drop rule: %d dropped, offset %d", currentRelay.dropped, currentRelay.offsets[positive.Direction])
		}
	}

	return
}

// client and server over loopback with the relay in between: the client sends the request, the server answers with the response and closes
// the client reads until the close_notify, the server reads the request and what the grow rule adds to it
// masterKey is the one of the full TLS 1.2 session for its resumption, crypto/tls logs no line for a resumed session
func runRelayedSession(positive interceptCase, serverConfig *tls.Config, clientConfig *tls.Config, keyLog *lockedBuffer, masterKey []byte, resumed bool) (currentRelay *relay, err error) {
	serverListener, relayListener, listenErr := listenPair()

	if err = listenErr; err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, serverListener.Close(), relayListener.Close())
	}()

	requestExtra := 0

	if (positive.Rule == growRuleKind) && (positive.Direction == tlsrecord.ClientDirection) {
		requestExtra = growLength
	}

	serverErrChannel := make(chan error, 1)
	serverRequest := make([]byte, requestLength+requestExtra)

	// test tls server
	go func() {
		serverErrChannel <- serveRelayed(serverListener, serverConfig, serverRequest)
	}()

	currentRelay = &relay{
		mutex:      &sync.Mutex{},
		conn:       tlsrecord.New(holdLimit, true),
		encrypters: [2]tlsrecord.Encrypter{tlsrecord.NewEncrypter(), tlsrecord.NewEncrypter()},
		keyLog:     keyLog,
		version:    positive.Session.Version,
		masterKey:  masterKey,
		rule:       positive,
	}
	relayErrChannel := make(chan error, 1)

	// the relay in the middle
	go func() {
		relayErrChannel <- currentRelay.serve(relayListener, serverListener.Addr().String())
	}()

	connection, dialErr := net.DialTimeout("tcp", relayListener.Addr().String(), time.Minute)

	if err = dialErr; err != nil {
		return
	}

	client := tls.Client(connection, clientConfig)
	_, writeErr := client.Write(payload(requestLength))
	response, readErr := io.ReadAll(client)
	didResume := client.ConnectionState().DidResume
	cipherSuite := client.ConnectionState().CipherSuite
	err = errors.Join(writeErr, readErr, client.Close(), <-serverErrChannel, <-relayErrChannel)

	if err != nil {
		return
	}

	if cipherSuite != positive.Session.CipherSuite {
		err = fmt.Errorf("client.ConnectionState().CipherSuite return value was not %s instead: %s", tls.CipherSuiteName(positive.Session.CipherSuite), tls.CipherSuiteName(cipherSuite))
		return
	}

	if didResume != resumed {
		err = fmt.Errorf("client.ConnectionState().DidResume return value was not %v instead: %v", resumed, didResume)
		return
	}

	if !bytes.Equal(response, currentRelay.sent[tlsrecord.ServerDirection]) {
		err = fmt.Errorf("client received %d bytes, the relay sent %d", len(response), len(currentRelay.sent[tlsrecord.ServerDirection]))
		return
	}

	if !bytes.Equal(serverRequest, currentRelay.sent[tlsrecord.ClientDirection]) {
		err = fmt.Errorf("server received %d bytes, the relay sent %d", len(serverRequest), len(currentRelay.sent[tlsrecord.ClientDirection]))
		return
	}

	// what the peers sent before the rule
	if (positive.Rule == identityRuleKind) && (!bytes.Equal(response, payload(responseLength)) || !bytes.Equal(serverRequest, payload(requestLength))) {
		err = errors.New("identity rule changed the application data")
	}

	return
}

func listenPair() (serverListener net.Listener, relayListener net.Listener, err error) {
	serverListener, err = net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		return
	}

	relayListener, err = net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		err = errors.Join(err, serverListener.Close())
	}

	return
}

func serveRelayed(listener net.Listener, config *tls.Config, request []byte) (err error) {
	connection, acceptErr := listener.Accept()

	if err = acceptErr; err != nil {
		return
	}

	server := tls.Server(connection, config)
	_, readErr := io.ReadFull(server, request)
	_, writeErr := server.Write(payload(responseLength))
	err = errors.Join(readErr, writeErr, server.Close())
	return
}

// accept the client, dial the server and relay both directions until both ended
func (currentRelay *relay) serve(listener net.Listener, serverAddress string) (err error) {
	clientConnection, acceptErr := listener.Accept()

	if err = acceptErr; err != nil {
		return
	}

	serverConnection, dialErr := net.DialTimeout("tcp", serverAddress, time.Minute)

	if err = dialErr; err != nil {
		err = errors.Join(err, clientConnection.Close())
		return
	}

	client := clientConnection.(*net.TCPConn)
	server := serverConnection.(*net.TCPConn)
	currentRelay.outputs = [2]*net.TCPConn{server, client}
	done := make(chan struct{})
	waitGroup := sync.WaitGroup{}

	// secrets poll while records wait for them
	waitGroup.Go(func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				currentRelay.mutex.Lock()
				currentRelay.lookup()
				currentRelay.mutex.Unlock()
			}
		}
	})

	readersGroup := sync.WaitGroup{}

	// client to server
	readersGroup.Go(func() {
		currentRelay.relayHalf(client, tlsrecord.ClientDirection)
	})

	currentRelay.relayHalf(server, tlsrecord.ServerDirection)
	readersGroup.Wait()
	close(done)
	waitGroup.Wait()
	err = errors.Join(currentRelay.err, client.Close(), server.Close())
	return
}

func (currentRelay *relay) relayHalf(source *net.TCPConn, direction tlsrecord.Direction) {
	buffer := make([]byte, 4096)

	for {
		count, readErr := source.Read(buffer)

		if count > 0 {
			currentRelay.mutex.Lock()
			records, feedErr := currentRelay.conn.Feed(direction, buffer[:count])
			currentRelay.handle(records)
			currentRelay.err = errors.Join(currentRelay.err, feedErr)

			if feedErr == nil {
				currentRelay.lookup()
			}

			currentRelay.mutex.Unlock()
		}

		if readErr != nil {
			// the other side of the relay half-closes too, a write after the peer left is no failure of the relay
			_ = currentRelay.outputs[direction].CloseWrite()
			return
		}
	}
}

// the secrets once the client logged them, while records wait
func (currentRelay *relay) lookup() {
	if !currentRelay.conn.Waiting() || (currentRelay.err != nil) {
		return
	}

	secrets, isComplete := secretsOf(currentRelay.conn.Session().ClientRandom, currentRelay.version, currentRelay.keyLog.String())

	if !isComplete && (currentRelay.version == tls.VersionTLS12) && (currentRelay.masterKey != nil) {
		secrets.MasterKey = currentRelay.masterKey
		isComplete = true
	}

	if !isComplete {
		return
	}

	currentRelay.masterKey = secrets.MasterKey

	records, secretsErr := currentRelay.conn.SetSecrets(secrets)
	currentRelay.handle(records)
	currentRelay.err = errors.Join(currentRelay.err, secretsErr)
}

// what the proxy does with each record, under the mutex so the writes of a direction keep their order
func (currentRelay *relay) handle(records []tlsrecord.Record) {
	for _, record := range records {
		output := currentRelay.outputs[record.Direction]
		var wire []byte

		switch record.Action {
		case tlsrecord.ShowAction:
			continue
		case tlsrecord.ForwardAction:
			wire = record.Raw
		case tlsrecord.SealAction:
			plaintext, isDropped := currentRelay.apply(record)

			if isDropped {
				currentRelay.encrypters[record.Direction].Drop(record)
				currentRelay.dropped++
				currentRelay.offsets[record.Direction] = currentRelay.encrypters[record.Direction].Offset()
				continue
			}

			sealed, count, sealErr := currentRelay.encrypters[record.Direction].Seal(record, plaintext)

			if sealErr != nil {
				currentRelay.err = errors.Join(currentRelay.err, sealErr)
				return
			}

			wire = sealed
			currentRelay.sealed[record.Direction]++
			currentRelay.offsets[record.Direction] = currentRelay.encrypters[record.Direction].Offset()

			if count > 1 {
				currentRelay.split++
			}

			if bytes.Equal(sealed, record.Raw) {
				currentRelay.identical[record.Direction]++
			}
		}

		// a peer that left early is seen by the other end of the test
		_, _ = output.Write(wire)
	}
}

// the rule of the test case on the application data of a held record
func (currentRelay *relay) apply(record tlsrecord.Record) (plaintext []byte, isDropped bool) {
	plaintext = record.Payload

	if record.ContentType != tlsrecord.ApplicationDataContentType {
		return
	}

	index := currentRelay.appCount[record.Direction]
	currentRelay.appCount[record.Direction]++

	if record.Direction == currentRelay.rule.Direction {
		switch {
		case (currentRelay.rule.Rule == growRuleKind) && (index == 0):
			plaintext = append(bytes.Clone(plaintext), bytes.Repeat([]byte{'x'}, growLength)...)
		case (currentRelay.rule.Rule == dropRuleKind) && (index == dropIndex):
			isDropped = true
			return
		default:
		}
	}

	currentRelay.sent[record.Direction] = append(currentRelay.sent[record.Direction], plaintext...)
	return
}

// the key log lines of one session, complete once the master key or all four TLS 1.3 secrets are there
func secretsOf(clientRandom [32]byte, version uint16, keyLog string) (secrets tlsrecord.Secrets, isComplete bool) {
	secrets.Version = version
	random := hex.EncodeToString(clientRandom[:])
	targets := map[string]*[]byte{
		"CLIENT_RANDOM":                   &secrets.MasterKey,
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET": &secrets.ClientHandshakeTrafficSecret,
		"SERVER_HANDSHAKE_TRAFFIC_SECRET": &secrets.ServerHandshakeTrafficSecret,
		"CLIENT_TRAFFIC_SECRET_0":         &secrets.ClientTrafficSecret,
		"SERVER_TRAFFIC_SECRET_0":         &secrets.ServerTrafficSecret,
	}

	for line := range strings.Lines(keyLog) {
		fields := strings.Fields(line)

		if (len(fields) != 3) || (fields[1] != random) {
			continue
		}

		target, found := targets[fields[0]]
		secret, decodeErr := hex.DecodeString(fields[2])

		if found && (decodeErr == nil) {
			*target = secret
		}
	}

	if version == tls.VersionTLS12 {
		isComplete = len(secrets.MasterKey) != 0
		return
	}

	isComplete = (len(secrets.ClientHandshakeTrafficSecret) != 0) && (len(secrets.ServerHandshakeTrafficSecret) != 0) && (len(secrets.ClientTrafficSecret) != 0) && (len(secrets.ServerTrafficSecret) != 0)
	return
}
