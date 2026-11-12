// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord_test

import (
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	holdLimit      int    = 1 << 20
	serverName     string = "decerter.test"
	protocol       string = "decerter-test"
	requestLength  int    = 3000
	responseLength int    = 40000
)

type chunk struct {
	direction tlsrecord.Direction
	data      []byte
}

// the client end of a session, it records what the client writes and reads in the order the client sees it, as the proxy in the middle does
type tap struct {
	net.Conn
	mutex  *sync.Mutex
	chunks *[]chunk
}

type testCase struct {
	Version     uint16
	CipherSuite uint16
	Certificate tls.Certificate
}

func (tap tap) Read(buffer []byte) (count int, err error) {
	count, err = tap.Conn.Read(buffer)

	if count > 0 {
		tap.mutex.Lock()
		defer tap.mutex.Unlock()
		*tap.chunks = append(*tap.chunks, chunk{direction: tlsrecord.ServerDirection, data: bytes.Clone(buffer[:count])})
	}

	return
}

func (tap tap) Write(buffer []byte) (count int, err error) {
	tap.mutex.Lock()
	*tap.chunks = append(*tap.chunks, chunk{direction: tlsrecord.ClientDirection, data: bytes.Clone(buffer)})
	tap.mutex.Unlock()
	count, err = tap.Conn.Write(buffer)
	return
}

// Test if tlsrecord.Feed returns with the expected output.
func TestFeedPositive(state *testing.T) {
	// crypto/tls only offers 3DES when asked to
	state.Setenv("GODEBUG", "tls3des=1")
	ecdsaCertificate, rsaCertificate, err := newCertificates()

	if err != nil {
		state.Fatalf("Test of tlsrecord.Feed failed, cannot create certificates, error: %s", err.Error())
	}

	positiveCases := []testCase{
		{Version: tls.VersionTLS13, CipherSuite: 0, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, Certificate: ecdsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, Certificate: rsaCertificate},
		{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, Certificate: rsaCertificate},
	}

	for _, positive := range positiveCases {
		err = testFeedSessions(positive)

		if err != nil {
			state.Errorf("Test of tlsrecord.Feed failed, version: 0x%04x, cipher suite: %s, error: %s", positive.Version, tls.CipherSuiteName(positive.CipherSuite), err.Error())
			return
		}
	}
}

// Test if tlsrecord.Feed returns with the expected errors.
func TestFeedNegative(state *testing.T) {
	ecdsaCertificate, _, err := newCertificates()

	if err != nil {
		state.Fatalf("Test of tlsrecord.Feed failed, cannot create certificates, error: %s", err.Error())
	}

	err = testFeedErrors(testCase{Version: tls.VersionTLS13, CipherSuite: 0, Certificate: ecdsaCertificate})

	if err != nil {
		state.Errorf("Test of tlsrecord.Feed failed, error: %s", err.Error())
		return
	}

	err = testFeedErrors(testCase{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, Certificate: ecdsaCertificate})

	if err != nil {
		state.Errorf("Test of tlsrecord.Feed failed, error: %s", err.Error())
		return
	}
}

// Test if tlsrecord.IsClientHello returns with the expected output.
func TestIsClientHelloPositive(state *testing.T) {
	positiveCases := []struct {
		Input         []byte
		IsClientHello bool
		Decided       bool
	}{
		{Input: []byte{}, IsClientHello: false, Decided: false},
		{Input: []byte{22, 3, 1}, IsClientHello: false, Decided: false},
		{Input: []byte{22, 3, 1, 0, 200, 1}, IsClientHello: true, Decided: true},
		{Input: []byte{22, 3, 3, 0, 200, 1, 0, 0, 196}, IsClientHello: true, Decided: true},
		{Input: []byte{22, 3, 1, 0, 200, 2}, IsClientHello: false, Decided: true},
		{Input: []byte("GET / HTTP/1.1\r\n"), IsClientHello: false, Decided: true},
		{Input: []byte("G"), IsClientHello: false, Decided: true},
	}

	for _, positive := range positiveCases {
		isClientHello, decided := tlsrecord.IsClientHello(positive.Input)

		if (isClientHello != positive.IsClientHello) || (decided != positive.Decided) {
			state.Errorf("Test of tlsrecord.IsClientHello function failed, input: %q, result should be %v %v, result: %v %v", positive.Input, positive.IsClientHello, positive.Decided, isClientHello, decided)
			return
		}
	}
}

// a full and a resumed session, each read once with the secrets there when the first record needs them and once out of the hold queue
func testFeedSessions(positive testCase) (err error) {
	// the session ticket keys of the server and the session cache of the client live in the configs
	serverConfig, clientConfig, keyLog := newConfigs(positive)

	var masterKey []byte

	for _, resumed := range []bool{false, true} {
		keyLog.Reset()
		chunks, secrets, runErr := runSession(positive, serverConfig, clientConfig, keyLog, resumed)

		if err = runErr; err != nil {
			return
		}

		// a resumed TLS 1.2 session goes on with the master key of the full one, crypto/tls logs it only there
		if positive.Version == tls.VersionTLS12 {
			if !resumed {
				masterKey = secrets.MasterKey
			}

			secrets.MasterKey = masterKey
		}

		// the same bytes as the client saw them and one by one, records and handshake messages then never end with a chunk
		for _, stream := range [][]chunk{chunks, splitChunks(chunks)} {
			for _, held := range []bool{false, true} {
				err = checkSession(positive, stream, secrets, held)

				if err != nil {
					err = fmt.Errorf("resumed %v, held %v, %d chunks: %w", resumed, held, len(stream), err)
					return
				}
			}
		}
	}

	return
}

func testFeedErrors(negative testCase) (err error) {
	serverConfig, clientConfig, keyLog := newConfigs(negative)
	chunks, secrets, runErr := runSession(negative, serverConfig, clientConfig, keyLog, false)

	if err = runErr; err != nil {
		return
	}

	// secrets of another session
	wrongSecrets := tlsrecord.Secrets{
		Version:                      secrets.Version,
		MasterKey:                    bytes.Repeat([]byte{1}, len(secrets.MasterKey)),
		ClientHandshakeTrafficSecret: bytes.Repeat([]byte{1}, len(secrets.ClientHandshakeTrafficSecret)),
		ServerHandshakeTrafficSecret: bytes.Repeat([]byte{1}, len(secrets.ServerHandshakeTrafficSecret)),
		ClientTrafficSecret:          bytes.Repeat([]byte{1}, len(secrets.ClientTrafficSecret)),
		ServerTrafficSecret:          bytes.Repeat([]byte{1}, len(secrets.ServerTrafficSecret)),
	}
	_, _, _, feedErr := feedSession(holdLimit, chunks, wrongSecrets, false)

	if !errors.Is(feedErr, tlsrecord.ErrBadRecordMAC) {
		err = fmt.Errorf("feed with wrong secrets return value was not %v instead: %v", tlsrecord.ErrBadRecordMAC, feedErr)
		return
	}

	// secrets of the other version
	wrongSecrets = secrets
	wrongSecrets.Version = tlsrecord.VersionTLS12 + tlsrecord.VersionTLS13 - secrets.Version
	_, _, _, feedErr = feedSession(holdLimit, chunks, wrongSecrets, false)

	if !errors.Is(feedErr, tlsrecord.ErrSecrets) {
		err = fmt.Errorf("feed with secrets of the wrong version return value was not %v instead: %v", tlsrecord.ErrSecrets, feedErr)
		return
	}

	// the secrets never come
	_, _, _, feedErr = feedSession(requestLength, chunks, secrets, true)

	if !errors.Is(feedErr, tlsrecord.ErrHoldQueueFull) {
		err = fmt.Errorf("feed without secrets return value was not %v instead: %v", tlsrecord.ErrHoldQueueFull, feedErr)
		return
	}

	// not a TLS stream, and the error stays
	conn := tlsrecord.New(holdLimit, false)
	_, feedErr = conn.Feed(tlsrecord.ClientDirection, []byte("GET / HTTP/1.1\r\n\r\n"))

	if !errors.Is(feedErr, tlsrecord.ErrUnexpectedRecord) {
		err = fmt.Errorf("feed of a plain stream return value was not %v instead: %v", tlsrecord.ErrUnexpectedRecord, feedErr)
		return
	}

	_, feedErr = conn.Feed(tlsrecord.ClientDirection, chunks[0].data)

	if !errors.Is(feedErr, tlsrecord.ErrUnexpectedRecord) {
		err = fmt.Errorf("feed after an error return value was not %v instead: %v", tlsrecord.ErrUnexpectedRecord, feedErr)
		return
	}

	return
}

// the decrypted application data has to be what the two ends sent, in the order they sent it, and the session what crypto/tls negotiated
func checkSession(positive testCase, chunks []chunk, secrets tlsrecord.Secrets, held bool) (err error) {
	plain, order, session, feedErr := feedSession(holdLimit, chunks, secrets, held)

	if err = feedErr; err != nil {
		return
	}

	if !bytes.Equal(plain[tlsrecord.ClientDirection], payload(requestLength)) {
		err = fmt.Errorf("client application data return value was not the request instead: %d bytes", len(plain[tlsrecord.ClientDirection]))
		return
	}

	if !bytes.Equal(plain[tlsrecord.ServerDirection], payload(responseLength)) {
		err = fmt.Errorf("server application data return value was not the response instead: %d bytes", len(plain[tlsrecord.ServerDirection]))
		return
	}

	// every record of the request comes before the first one of the response
	if !slices.IsSortedFunc(order, func(first tlsrecord.Direction, second tlsrecord.Direction) int { return cmp.Compare(first, second) }) {
		err = fmt.Errorf("application data order return value was not request then response instead: %v", order)
		return
	}

	if (session.Version != positive.Version) || (session.ServerName != serverName) || (session.Protocol != protocol) {
		err = fmt.Errorf("session return value was not %v %v %v instead: %v %v %v", positive.Version, serverName, protocol, session.Version, session.ServerName, session.Protocol)
		return
	}

	if (positive.CipherSuite != 0) && (session.CipherSuite != positive.CipherSuite) {
		err = fmt.Errorf("session.CipherSuite return value was not %v instead: %v", positive.CipherSuite, session.CipherSuite)
		return
	}

	return
}

// feed a recorded session, held false sets the secrets when the first record waits for them, held true after the last byte
func feedSession(limit int, chunks []chunk, secrets tlsrecord.Secrets, held bool) (plain [2][]byte, order []tlsrecord.Direction, session tlsrecord.Session, err error) {
	conn := tlsrecord.New(limit, false)
	isSet := false
	collect := func(records []tlsrecord.Record) {
		for _, record := range records {
			if record.Decrypted && (record.ContentType == tlsrecord.ApplicationDataContentType) {
				plain[record.Direction] = append(plain[record.Direction], record.Payload...)
				order = append(order, record.Direction)
			}
		}
	}

	for _, chunk := range chunks {
		records, feedErr := conn.Feed(chunk.direction, chunk.data)

		if err = feedErr; err != nil {
			return
		}

		collect(records)

		if !held && !isSet && conn.Waiting() {
			isSet = true
			records, err = conn.SetSecrets(secrets)

			if err != nil {
				return
			}

			collect(records)
		}
	}

	if held {
		if !conn.Waiting() {
			err = errors.New("conn.Waiting return value was not true instead: false")
			return
		}

		records, secretsErr := conn.SetSecrets(secrets)

		if err = secretsErr; err != nil {
			return
		}

		collect(records)
	}

	session = conn.Session()
	return
}

// the key log of the client config gives the secrets of its sessions
func newConfigs(positive testCase) (serverConfig *tls.Config, clientConfig *tls.Config, keyLog *bytes.Buffer) {
	keyLog = &bytes.Buffer{}
	serverConfig = &tls.Config{
		Certificates: []tls.Certificate{positive.Certificate},
		MinVersion:   positive.Version,
		MaxVersion:   positive.Version,
		NextProtos:   []string{protocol},
	}
	clientConfig = &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         positive.Version,
		MaxVersion:         positive.Version,
		NextProtos:         []string{protocol},
		ClientSessionCache: tls.NewLRUClientSessionCache(1),
		KeyLogWriter:       keyLog,
	}

	if positive.CipherSuite != 0 {
		serverConfig.CipherSuites = []uint16{positive.CipherSuite}
		clientConfig.CipherSuites = []uint16{positive.CipherSuite}
	}

	return
}

// one crypto/tls session over loopback: the client sends the request, the server answers with the response
func runSession(positive testCase, serverConfig *tls.Config, clientConfig *tls.Config, keyLog *bytes.Buffer, resumed bool) (chunks []chunk, secrets tlsrecord.Secrets, err error) {
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")

	if err = listenErr; err != nil {
		return
	}

	serverErrChannel := make(chan error, 1)

	// test tls server
	go func() {
		serverErrChannel <- serveSession(listener, serverConfig)
	}()

	connection, dialErr := net.DialTimeout("tcp", listener.Addr().String(), time.Minute)

	if err = dialErr; err != nil {
		err = errors.Join(err, listener.Close(), <-serverErrChannel)
		return
	}

	client := tls.Client(tap{Conn: connection, mutex: &sync.Mutex{}, chunks: &chunks}, clientConfig)
	response := make([]byte, responseLength)
	_, writeErr := client.Write(payload(requestLength))
	_, readErr := io.ReadFull(client, response)
	didResume := client.ConnectionState().DidResume
	err = errors.Join(writeErr, readErr, client.Close(), <-serverErrChannel, listener.Close())

	if err != nil {
		return
	}

	if !bytes.Equal(response, payload(responseLength)) {
		err = errors.New("response of the test server was not the expected one")
		return
	}

	if didResume != resumed {
		err = fmt.Errorf("client.ConnectionState().DidResume return value was not %v instead: %v", resumed, didResume)
		return
	}

	secrets, err = parseKeyLog(positive.Version, keyLog.String())
	return
}

func serveSession(listener net.Listener, config *tls.Config) (err error) {
	connection, acceptErr := listener.Accept()

	if err = acceptErr; err != nil {
		return
	}

	server := tls.Server(connection, config)
	request := make([]byte, requestLength)
	_, readErr := io.ReadFull(server, request)
	_, writeErr := server.Write(payload(responseLength))
	// the close_notify of the client ends the session
	_, drainErr := io.Copy(io.Discard, server)
	err = errors.Join(readErr, writeErr, drainErr, server.Close())

	if (err == nil) && !bytes.Equal(request, payload(requestLength)) {
		err = errors.New("request of the test client was not the expected one")
	}

	return
}

// every byte in a chunk of its own, in the same order
func splitChunks(chunks []chunk) (split []chunk) {
	for _, whole := range chunks {
		for index := range whole.data {
			split = append(split, chunk{direction: whole.direction, data: whole.data[index : index+1]})
		}
	}

	return
}

// NSS key log lines to the secrets of the session
func parseKeyLog(version uint16, keyLog string) (secrets tlsrecord.Secrets, err error) {
	secrets.Version = version
	targets := map[string]*[]byte{
		"CLIENT_RANDOM":                   &secrets.MasterKey,
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET": &secrets.ClientHandshakeTrafficSecret,
		"SERVER_HANDSHAKE_TRAFFIC_SECRET": &secrets.ServerHandshakeTrafficSecret,
		"CLIENT_TRAFFIC_SECRET_0":         &secrets.ClientTrafficSecret,
		"SERVER_TRAFFIC_SECRET_0":         &secrets.ServerTrafficSecret,
	}

	for line := range strings.Lines(keyLog) {
		fields := strings.Fields(line)
		target, found := targets[fields[0]]

		if !found || (len(fields) != 3) {
			continue
		}

		*target, err = hex.DecodeString(fields[2])

		if err != nil {
			return
		}
	}

	return
}

func payload(length int) (data []byte) {
	data = make([]byte, length)

	for index := range data {
		data[index] = byte(index % 251)
	}

	return
}

// self signed test certificates, one with an ECDSA and one with an RSA key
func newCertificates() (ecdsaCertificate tls.Certificate, rsaCertificate tls.Certificate, err error) {
	ecdsaKey, ecdsaErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err = ecdsaErr; err != nil {
		return
	}

	rsaKey, rsaErr := rsa.GenerateKey(rand.Reader, 2048)

	if err = rsaErr; err != nil {
		return
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	ecdsaDER, ecdsaErr := x509.CreateCertificate(rand.Reader, template, template, &ecdsaKey.PublicKey, ecdsaKey)

	if err = ecdsaErr; err != nil {
		return
	}

	rsaDER, rsaErr := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)

	if err = rsaErr; err != nil {
		return
	}

	ecdsaCertificate = tls.Certificate{Certificate: [][]byte{ecdsaDER}, PrivateKey: ecdsaKey}
	rsaCertificate = tls.Certificate{Certificate: [][]byte{rsaDER}, PrivateKey: rsaKey}
	return
}
