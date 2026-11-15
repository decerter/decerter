// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/output"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
)

var (
	// the maps the proxy is given when it has the secrets object, the tests answer the lookups themselves
	testSecretsMaps = map[bpf.BpfMapName]*ebpf.Map{}
	// one self signed certificate for every TLS server of the tests
	testCertificate = sync.OnceValues(newCertificate)
	errTestLookup   = errors.New("test lookup failed")
)

// bytes written from several goroutines: a key log, the log of a test
type lockedBuffer struct {
	mutex  *sync.Mutex
	buffer *bytes.Buffer
}

func newLockedBuffer() (locked *lockedBuffer) {
	locked = &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}
	return
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

// a logger into a buffer the test can read while the proxy writes
func bufferLogger() (logger *slog.Logger, logs *lockedBuffer) {
	logs = newLockedBuffer()
	logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{AddSource: false, Level: slog.LevelDebug, ReplaceAttr: nil}))
	return
}

func discardLogger() (logger *slog.Logger) {
	logger = slog.New(slog.DiscardHandler)
	return
}

// a self signed ECDSA certificate
func newCertificate() (certificate tls.Certificate, err error) {
	key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err = keyErr; err != nil {
		return
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "decerter.test"},
		DNSNames:     []string{"decerter.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, createErr := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	if err = createErr; err != nil {
		return
	}

	certificate = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return
}

// the configs of a test session of one version, the client writes its key log into keyLog
func tlsConfigs(state *testing.T, version uint16, protocols []string, keyLog io.Writer) (serverConfig *tls.Config, clientConfig *tls.Config) {
	certificate, err := testCertificate()

	if err != nil {
		state.Fatalf("Test of the tls proxy failed, cannot create certificate, error: %s", err.Error())
	}

	serverConfig = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: version, MaxVersion: version, NextProtos: protocols}
	clientConfig = &tls.Config{InsecureSkipVerify: true, ServerName: "decerter.test", MinVersion: version, MaxVersion: version, NextProtos: protocols, KeyLogWriter: keyLog} // #nosec G402 -- a test session against the test's own certificate
	return
}

// the secrets of one session from a key log as secrets.Lookup gives them: found once the master key or all four TLS 1.3 secrets are there
func keyLogSecrets(keyLog string, clientRandom [32]byte, version uint16) (secrets tlsrecord.Secrets, found bool) {
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

		target, isKnown := targets[fields[0]]
		secret, decodeErr := hex.DecodeString(fields[2])

		if isKnown && (decodeErr == nil) {
			*target = secret
		}
	}

	if version != tlsrecord.VersionTLS13 {
		found = len(secrets.MasterKey) != 0
		return
	}

	found = (len(secrets.ClientHandshakeTrafficSecret) != 0) && (len(secrets.ServerHandshakeTrafficSecret) != 0) && (len(secrets.ClientTrafficSecret) != 0) && (len(secrets.ServerTrafficSecret) != 0)
	return
}

// a secrets_map lookup that answers from a key log, ready false keeps the secrets back as an uprobe that did not see them yet; calls counts the lookups
// readyAfter > 0 lets the secrets come from that many lookups on, err fails every lookup after errAfter, isCorrupt gives secrets with every byte changed
type keyLogLookup struct {
	keyLog     *lockedBuffer
	version    uint16
	ready      *atomic.Bool
	calls      *atomic.Int64
	readyAfter int64
	err        error
	errAfter   int64
	isCorrupt  bool
}

func newKeyLogLookup(keyLog *lockedBuffer, version uint16, isReady bool) (lookup *keyLogLookup) {
	lookup = &keyLogLookup{keyLog: keyLog, version: version, ready: &atomic.Bool{}, calls: &atomic.Int64{}, readyAfter: 0, err: nil, errAfter: 0, isCorrupt: false}
	lookup.ready.Store(isReady)
	return
}

func (lookup *keyLogLookup) lookup(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (secrets tlsrecord.Secrets, found bool, err error) {
	call := lookup.calls.Add(1)

	if (lookup.err != nil) && (call > lookup.errAfter) {
		err = lookup.err
		return
	}

	if !lookup.ready.Load() && ((lookup.readyAfter == 0) || (call <= lookup.readyAfter)) {
		return
	}

	secrets, found = keyLogSecrets(lookup.keyLog.String(), clientRandom, lookup.version)

	if !lookup.isCorrupt {
		return
	}

	for _, secret := range []*[]byte{&secrets.MasterKey, &secrets.ClientHandshakeTrafficSecret, &secrets.ServerHandshakeTrafficSecret, &secrets.ClientTrafficSecret, &secrets.ServerTrafficSecret} {
		corrupted := bytes.Clone(*secret)

		for index := range corrupted {
			corrupted[index] ^= 0xff
		}

		*secret = corrupted
	}

	return
}

// the proxy asks lookup for the secrets until the test ends; tests that set it don't run in parallel
func useSecrets(state *testing.T, lookup func(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (tlsrecord.Secrets, bool, error)) {
	previous := secretsByRandom
	secretsByRandom = lookup
	state.Cleanup(func() {
		secretsByRandom = previous
	})
}

// the proxy asks lookup for the flows of its clients until the test ends; tests that set it don't run in parallel
func useFlows(state *testing.T, lookup func(client netip.AddrPort, ipProtocol uint8, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (uint64, redirect.Flow, error)) {
	previous := flowByClient
	flowByClient = lookup
	state.Cleanup(func() {
		flowByClient = previous
	})
}

// every client is the flow to destination with cookie 1
func fixedFlow(flow redirect.Flow) (lookup func(client netip.AddrPort, ipProtocol uint8, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (uint64, redirect.Flow, error)) {
	lookup = func(client netip.AddrPort, ipProtocol uint8, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (cookie uint64, found redirect.Flow, err error) {
		cookie = 1
		found = flow
		found.IPProtocol = ipProtocol
		found.Client = client
		return
	}
	return
}

// what run printed on stdout, the flow and record lines of the proxy
func captureStdout(state *testing.T, run func()) (printed string) {
	reader, writer, err := os.Pipe()

	if err != nil {
		state.Fatalf("Test of the proxy output failed, cannot create pipe, error: %s", err.Error())
	}

	outputChannel := make(chan []byte, 1)

	// stdout reader
	go func() {
		data, readErr := io.ReadAll(reader)

		if readErr != nil {
			state.Errorf("Test of the proxy output failed, cannot read stdout, error: %s", readErr.Error())
		}

		outputChannel <- data
	}()

	previous := os.Stdout
	previousOutput := output.Stdout
	os.Stdout = writer
	output.Stdout = output.NewWriter(writer)

	defer func() {
		os.Stdout = previous
		output.Stdout = previousOutput

		if closeErr := writer.Close(); closeErr != nil {
			state.Errorf("Test of the proxy output failed, cannot close pipe, error: %s", closeErr.Error())
		}

		printed = string(<-outputChannel)

		if closeErr := reader.Close(); closeErr != nil {
			state.Errorf("Test of the proxy output failed, cannot close pipe, error: %s", closeErr.Error())
		}
	}()

	run()
	return
}

// poll condition until it holds, false after a few seconds
func waitFor(condition func() bool) (isMet bool) {
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		if condition() {
			isMet = true
			return
		}

		time.Sleep(2 * time.Millisecond)
	}

	return
}

// the payloads of the messages of a flow of the history by direction, and their origins
func historyPayloads(recorder *history.History, flowID uint64) (payloads [2][]byte, origins []api.Origin) {
	messages, _, _ := recorder.Messages(flowID, 0, 1000)

	for _, message := range messages {
		_, payload, _, _ := recorder.Message(message.ID)
		direction := tlsrecord.ServerDirection

		if message.Direction == api.UpDirection {
			direction = tlsrecord.ClientDirection
		}

		payloads[direction] = append(payloads[direction], payload...)
		origins = append(origins, message.Origin)
	}

	return
}

// the conn of one side of a recorded session, every write is kept in the order the sides wrote
type recordingConn struct {
	net.Conn
	direction tlsrecord.Direction
	mutex     *sync.Mutex
	chunks    *[]TLSChunk
}

func (connection recordingConn) Write(data []byte) (count int, err error) {
	connection.mutex.Lock()
	*connection.chunks = append(*connection.chunks, TLSChunk{direction: connection.direction, data: bytes.Clone(data)})
	connection.mutex.Unlock()
	count, err = connection.Conn.Write(data)
	return
}

// a whole TLS session over a pipe: the client sends request and closes, the server answers with response and closes
// chunks are the bytes each side wrote in their order, keyLog the client's key log, clientRandom the random of its ClientHello
func recordTLS(state *testing.T, version uint16, protocols []string, request []byte, response []byte) (chunks []TLSChunk, keyLog *lockedBuffer, clientRandom [32]byte) {
	keyLog = newLockedBuffer()
	serverConfig, clientConfig := tlsConfigs(state, version, protocols, keyLog)
	clientEnd, serverEnd := net.Pipe()
	mutex := &sync.Mutex{}
	client := tls.Client(recordingConn{Conn: clientEnd, direction: tlsrecord.ClientDirection, mutex: mutex, chunks: &chunks}, clientConfig)
	server := tls.Server(recordingConn{Conn: serverEnd, direction: tlsrecord.ServerDirection, mutex: mutex, chunks: &chunks}, serverConfig)
	serverErrChannel := make(chan error, 1)

	// test server
	go func() {
		_, readErr := io.ReadAll(server)
		_, writeErr := server.Write(response)
		serverErrChannel <- errors.Join(readErr, writeErr, server.Close())
	}()

	_, err := client.Write(request)
	err = errors.Join(err, client.CloseWrite())
	_, readErr := io.ReadAll(client)
	err = errors.Join(err, readErr, <-serverErrChannel, client.Close())

	if err != nil {
		state.Fatalf("Test of the tls proxy failed, cannot record a tls session, error: %s", err.Error())
	}

	mutex.Lock()
	defer mutex.Unlock()
	hello, isComplete, helloErr := tlsrecord.ReadClientHello(chunks[0].data)

	if !isComplete || (helloErr != nil) {
		state.Fatalf("Test of the tls proxy failed, cannot read the recorded ClientHello, error: %v", helloErr)
	}

	clientRandom = hello.ClientRandom
	return
}

// an observer of flow 1 of a new history, chunks queued and closed as the relay hands them over
func observeChunks(chunks []TLSChunk, isClosed bool, logger *slog.Logger) (observer *TLSObserver, recorder *history.History) {
	recorder = history.New(history.DefaultLimits(), nil)
	values := filter.Values{}
	flowID := recorder.OpenFlow(1, values, [32]byte{})
	observer = NewTLSObserver(intercept.FlowOf(flowID, 1, testFlow, testClient, values), recorder, testSecretsMaps)

	for _, chunk := range chunks {
		observer.Observe(chunk.direction, chunk.data, logger)
	}

	if isClosed {
		observer.Close()
	}

	return
}

// Test if proxy.watchTLS returns with the expected output: the application data of TLS 1.2 and 1.3 sessions is printed and goes into the history,
// the HTTP layer reads its exchange, a ClientHello in pieces is read, secrets that come late are polled for.
func TestWatchTLSPositive(state *testing.T) {
	request := []byte("GET /watch HTTP/1.1\r\nHost: decerter.test\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	positiveCases := []struct {
		Name      string
		Version   uint16
		Protocols []string
		IsSplit   bool
		IsLate    bool
		IsHTTP    bool
	}{
		{Name: "tls 1.3", Version: tls.VersionTLS13, Protocols: nil, IsSplit: false, IsLate: false, IsHTTP: false},
		{Name: "tls 1.2 with http", Version: tls.VersionTLS12, Protocols: []string{"http/1.1"}, IsSplit: false, IsLate: false, IsHTTP: true},
		{Name: "tls 1.3 with http and a ClientHello in pieces", Version: tls.VersionTLS13, Protocols: []string{"http/1.1"}, IsSplit: true, IsLate: false, IsHTTP: true},
		{Name: "tls 1.3 with late secrets", Version: tls.VersionTLS13, Protocols: nil, IsSplit: false, IsLate: true, IsHTTP: false},
	}

	for _, positive := range positiveCases {
		chunks, keyLog, _ := recordTLS(state, positive.Version, positive.Protocols, request, response)
		lookup := newKeyLogLookup(keyLog, positive.Version, !positive.IsLate)
		useSecrets(state, lookup.lookup)

		if positive.IsSplit {
			first := chunks[0]
			chunks = append([]TLSChunk{{direction: first.direction, data: first.data[:1]}, {direction: first.direction, data: first.data[1:3]}, {direction: first.direction, data: first.data[3:]}}, chunks[1:]...)
		}

		logger, logs := bufferLogger()
		observer, recorder := observeChunks(chunks, !positive.IsLate, logger)

		if positive.IsHTTP {
			observer.http = newHTTPFlow(observer.interceptFlow.ID, recorder, HTTPLayer{Pipeline: nil, Timeout: time.Second})
		}

		output := captureStdout(state, func() {
			if !positive.IsLate {
				watchTLS(state.Context(), observer, logger)
				return
			}

			// the first lookup finds nothing, the poll finds the secrets once they are there
			doneChannel := make(chan struct{})

			// tls observer
			go func() {
				watchTLS(state.Context(), observer, logger)
				close(doneChannel)
			}()

			isPolled := waitFor(func() bool {
				return lookup.calls.Load() >= 2
			})
			lookup.ready.Store(true)
			isDecrypted := waitFor(func() bool {
				payloads, _ := historyPayloads(recorder, 1)
				return len(payloads[tlsrecord.ServerDirection]) != 0
			})
			observer.Close()
			<-doneChannel

			if !isPolled || !isDecrypted {
				state.Errorf("Test of proxy.watchTLS function failed, case %q, the late secrets should be polled for, lookups: %d", positive.Name, lookup.calls.Load())
			}
		})
		payloads, _ := historyPayloads(recorder, 1)

		if !bytes.Equal(payloads[tlsrecord.ClientDirection], request) || !bytes.Equal(payloads[tlsrecord.ServerDirection], response) || !observer.Active() {
			state.Errorf("Test of proxy.watchTLS function failed, case %q, the history should have the request and the response, up: %q, down: %q, logs: %s", positive.Name, payloads[tlsrecord.ClientDirection], payloads[tlsrecord.ServerDirection], logs.String())
			return
		}

		if (strings.Count(output, "sni=\"decerter.test\"") != 1) || !strings.Contains(output, "direction=up sequence=") || !strings.Contains(output, "GET /watch") || !strings.Contains(output, "direction=down") {
			state.Errorf("Test of proxy.watchTLS function failed, case %q, the session line and both records should be printed, output: %q", positive.Name, output)
			return
		}

		exchanges, _, _ := recorder.Exchanges(1, 0, 10)

		if positive.IsHTTP && ((len(exchanges) != 1) || (exchanges[0].Request == nil) || (exchanges[0].Request.Target != "/watch") || (exchanges[0].Response == nil) || (exchanges[0].Response.Status != 200)) {
			state.Errorf("Test of proxy.watchTLS function failed, case %q, the history should have the exchange, exchanges: %+v", positive.Name, exchanges)
			return
		}
	}
}

// Test if proxy.watchTLS returns with the expected errors: a flow that is not TLS stops the observer without a warning, missing secrets and a failed lookup stop it with one,
// an observer the relay stopped or a cancelled context ends it.
func TestWatchTLSNegative(state *testing.T) {
	chunks, keyLog, _ := recordTLS(state, tls.VersionTLS13, nil, []byte("request"), []byte("response"))
	negativeCases := []struct {
		Name      string
		Chunks    []TLSChunk
		Lookup    *keyLogLookup
		IsStopped bool
		IsCancel  bool
		Warning   string
	}{
		{Name: "server first", Chunks: []TLSChunk{{direction: tlsrecord.ServerDirection, data: []byte("220 smtp\r\n")}}, Lookup: newKeyLogLookup(keyLog, tls.VersionTLS13, true), IsStopped: false, IsCancel: false, Warning: ""},
		{Name: "no ClientHello", Chunks: []TLSChunk{{direction: tlsrecord.ClientDirection, data: []byte("GET / HTTP/1.1\r\n\r\n")}}, Lookup: newKeyLogLookup(keyLog, tls.VersionTLS13, true), IsStopped: false, IsCancel: false, Warning: ""},
		{Name: "no secrets", Chunks: chunks, Lookup: newKeyLogLookup(keyLog, tls.VersionTLS13, false), IsStopped: false, IsCancel: false, Warning: ErrNoSecrets.Error()},
		{Name: "lookup error", Chunks: chunks, Lookup: &keyLogLookup{keyLog: keyLog, version: tls.VersionTLS13, ready: &atomic.Bool{}, calls: &atomic.Int64{}, readyAfter: 0, err: errTestLookup, errAfter: 0, isCorrupt: false}, IsStopped: false, IsCancel: false, Warning: errTestLookup.Error()},
		{Name: "stopped by the relay", Chunks: chunks, Lookup: newKeyLogLookup(keyLog, tls.VersionTLS13, true), IsStopped: true, IsCancel: false, Warning: ErrObserverBehind.Error()},
		{Name: "cancelled", Chunks: chunks, Lookup: newKeyLogLookup(keyLog, tls.VersionTLS13, true), IsStopped: false, IsCancel: true, Warning: ""},
	}

	for _, negative := range negativeCases {
		useSecrets(state, negative.Lookup.lookup)
		logger, logs := bufferLogger()
		observer, recorder := observeChunks(negative.Chunks, true, logger)
		ctx := state.Context()

		if negative.IsStopped {
			observer.Stop(ErrObserverBehind, logger)
		}

		if negative.IsCancel {
			cancelledCtx, cancel := context.WithCancel(ctx)
			cancel()
			ctx = cancelledCtx
		}

		output := captureStdout(state, func() {
			watchTLS(ctx, observer, logger)
		})
		payloads, _ := historyPayloads(recorder, 1)

		if (len(payloads[0]) != 0) || (len(payloads[1]) != 0) || (output != "") {
			state.Errorf("Test of proxy.watchTLS function failed, case %q, nothing should be decrypted, output: %q", negative.Name, output)
			return
		}

		if !negative.IsCancel && observer.Active() {
			state.Errorf("Test of proxy.watchTLS function failed, case %q, the observer should be stopped", negative.Name)
			return
		}

		if ((negative.Warning != "") && !strings.Contains(logs.String(), negative.Warning)) || ((negative.Warning == "") && strings.Contains(logs.String(), "level=WARN")) {
			state.Errorf("Test of proxy.watchTLS function failed, case %q, the warning should be %q, logs: %s", negative.Name, negative.Warning, logs.String())
			return
		}
	}
}

// Test if proxy.printRecord returns with the expected output: the plaintext is escaped and cut at intercept.MaxPrintBytes.
func TestPrintRecordPositive(state *testing.T) {
	session := tlsrecord.Session{Version: tlsrecord.VersionTLS12, CipherSuite: 0xc02b, ServerName: "a\"b", Protocol: "h2"}
	record := tlsrecord.Record{Direction: tlsrecord.ServerDirection, Sequence: 3, Payload: append([]byte("line\n\x00"), bytes.Repeat([]byte("x"), intercept.MaxPrintBytes)...)}
	flow := intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{})
	flow.Session = session
	output := captureStdout(state, func() {
		printSession(flow, intercept.TLSLayer)
		printRecord(flow, intercept.TLSLayer, record)
		printFlow(redirect.Flow{OriginalDestination: testFlow.OriginalDestination, IPProtocol: testFlow.IPProtocol, Tgid: 1, UID: 2, Comm: "app", Mark: 0x10064}, "app --flag", testClient, "1B", "2B", 1500*time.Microsecond)
	})
	// a comm the process set to a terminal escape sequence
	hostile := flow
	hostile.Comm = "\x1b]0;x\x07\x1b[2J"
	hostileOutput := captureStdout(state, func() {
		printSession(hostile, intercept.TLSLayer)
		printFlow(redirect.Flow{OriginalDestination: testFlow.OriginalDestination, IPProtocol: testFlow.IPProtocol, Tgid: 1, UID: 2, Comm: hostile.Comm, Mark: 0}, "app", testClient, "1B", "2B", time.Millisecond)
	})
	expected := []string{
		"tls pid=", "version=TLS1.2 suite=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 sni=\"a\\\"b\" alpn=\"h2\"\n",
		"direction=down sequence=3 length=", " shown=",
		"tcp pid=1 uid=2 comm=app 93.184.216.34:443 client=127.0.0.1:40000 mark=0x10064 up=1B down=2B duration=2ms cmdline=\"app --flag\"\n",
	}

	for _, part := range expected {
		if !strings.Contains(output, part) {
			state.Errorf("Test of proxy.printRecord function failed, the output should contain %q, output: %q", part, shorten(output))
			return
		}
	}

	if !strings.Contains(hostileOutput, "comm=\\x1b]0;x\\x07\\x1b[2J 93.184.216.34:443 client=127.0.0.1:40000 version=TLS1.2") || !strings.Contains(hostileOutput, "tcp pid=1 uid=2 comm=\\x1b]0;x\\x07\\x1b[2J 93.184.216.34:443") || strings.Contains(hostileOutput, "\x1b") {
		state.Errorf("Test of proxy.printSession function failed, the comm should be escaped in the session and the flow line, output: %q", hostileOutput)
		return
	}

	if strings.Contains(output, "\x00") || (strings.Count(output, "x") > intercept.MaxPrintBytes) {
		state.Errorf("Test of proxy.printRecord function failed, the payload should be escaped and cut, output: %q", shorten(output))
		return
	}
}
