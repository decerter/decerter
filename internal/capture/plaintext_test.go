// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/pcapng"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// the first sequence numbers of the TCP connections of the tests
	testClientISN uint32 = 1000
	testServerISN uint32 = 5000
	// pcapng block types the tests read back
	enhancedPacketBlockType    uint32 = 6
	decryptionSecretsBlockType uint32 = 10
)

var (
	tlsClient = Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 40000}
	tlsServer = Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 443}
	// the maps of a recorder with the secrets uprobe, the lookups of the tests never touch them
	testBpfMaps = map[bpf.BpfMapName]*ebpf.Map{}
)

// one write of a TLS session as its peer got it
type sessionChunk struct {
	direction tlsrecord.Direction
	data      []byte
}

// a TLS session crypto/tls made over a pipe: every write of both sides in order, the key log of the client and the secrets in it
type tlsSession struct {
	chunks       []sessionChunk
	keyLog       string
	clientRandom [32]byte
	secrets      tlsrecord.Secrets
	version      uint16
	cipherSuite  uint16
	request      []byte
	response     []byte
}

// a conn that notes every write before it goes to the peer
type recordingConn struct {
	net.Conn
	direction tlsrecord.Direction
	mutex     *sync.Mutex
	chunks    *[]sessionChunk
}

func (conn *recordingConn) Write(data []byte) (count int, err error) {
	conn.mutex.Lock()
	*conn.chunks = append(*conn.chunks, sessionChunk{direction: conn.direction, data: bytes.Clone(data)})
	conn.mutex.Unlock()
	count, err = conn.Conn.Write(data)
	return
}

// a self-signed certificate of example.com
func testCertificate() (certificate tls.Certificate, err error) {
	key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err = keyErr; err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, certificateErr := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)

	if err = certificateErr; err != nil {
		return
	}

	certificate = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return
}

// run a TLS session of version between crypto/tls client and server over a pipe: the client sends request, the server answers with response
// the pipes are closed without close_notify, nothing reads it
func runTLSSession(version uint16, request []byte, response []byte) (session tlsSession, err error) {
	certificate, certificateErr := testCertificate()

	if err = certificateErr; err != nil {
		return
	}

	clientPipe, serverPipe := net.Pipe()
	mutex := &sync.Mutex{}
	keyLog := &bytes.Buffer{}
	serverConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: version, MaxVersion: version, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	clientConfig := &tls.Config{ServerName: "example.com", InsecureSkipVerify: true, MinVersion: version, MaxVersion: version, NextProtos: []string{"http/1.1"}, KeyLogWriter: keyLog}
	server := tls.Server(&recordingConn{Conn: serverPipe, direction: tlsrecord.ServerDirection, mutex: mutex, chunks: &session.chunks}, serverConfig)
	client := tls.Client(&recordingConn{Conn: clientPipe, direction: tlsrecord.ClientDirection, mutex: mutex, chunks: &session.chunks}, clientConfig)
	errChannel := make(chan error, 1)

	// the server of the test
	go func() {
		received := make([]byte, len(request))
		_, serverErr := io.ReadFull(server, received)

		if serverErr == nil {
			_, serverErr = server.Write(response)
		}

		errChannel <- serverErr
	}()

	_, err = client.Write(request)

	if err == nil {
		received := make([]byte, len(response))
		_, err = io.ReadFull(client, received)
	}

	// a client that failed leaves the server waiting, the closed pipes end it; the server of a session that went through is done first
	if err != nil {
		err = errors.Join(err, clientPipe.Close(), serverPipe.Close(), <-errChannel)
		return
	}

	err = errors.Join(<-errChannel, clientPipe.Close(), serverPipe.Close())

	if err != nil {
		return
	}

	connectionState := client.ConnectionState()
	session.keyLog = keyLog.String()
	session.clientRandom = [32]byte(session.chunks[0].data[11:43])
	session.version = connectionState.Version
	session.cipherSuite = connectionState.CipherSuite
	session.secrets = secretsOfKeyLog(session.clientRandom, session.version, session.keyLog)
	session.request = request
	session.response = response
	return
}

// the secrets of one session in NSS key log lines
func secretsOfKeyLog(clientRandom [32]byte, version uint16, keyLog string) (secrets tlsrecord.Secrets) {
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

		if target, found := targets[fields[0]]; found {
			*target, _ = hex.DecodeString(fields[2])
		}
	}

	return
}

// the bytes one side of the session sent
func (session tlsSession) sent(direction tlsrecord.Direction) (data []byte) {
	for _, chunk := range session.chunks {
		if chunk.direction == direction {
			data = append(data, chunk.data...)
		}
	}

	return
}

// the last write of one side
func (session tlsSession) lastChunk(direction tlsrecord.Direction) (data []byte) {
	for _, chunk := range session.chunks {
		if chunk.direction == direction {
			data = chunk.data
		}
	}

	return
}

// what the lookups of the secrets of the tests answer, safe for the goroutine of a writer
type testSecrets struct {
	mutex   *sync.Mutex
	found   bool
	secrets map[[32]byte]tlsrecord.Secrets
	keyLogs map[[32]byte]string
	err     error
	lookups int
}

// answer the lookups of secretsByRandom and keyLogByRandom from the sessions, found tells whether the uprobe has seen them yet; the old lookups come back when the test ends
func useTestSecrets(state *testing.T, found bool, sessions ...tlsSession) (current *testSecrets) {
	current = &testSecrets{mutex: &sync.Mutex{}, found: found, secrets: map[[32]byte]tlsrecord.Secrets{}, keyLogs: map[[32]byte]string{}, err: nil, lookups: 0}

	for _, session := range sessions {
		current.secrets[session.clientRandom] = session.secrets
		current.keyLogs[session.clientRandom] = session.keyLog
	}

	oldSecrets, oldKeyLog := secretsByRandom, keyLogByRandom
	state.Cleanup(func() {
		secretsByRandom = oldSecrets
		keyLogByRandom = oldKeyLog
	})
	secretsByRandom = func(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (sessionSecrets tlsrecord.Secrets, found bool, err error) {
		current.mutex.Lock()
		defer current.mutex.Unlock()
		current.lookups++
		sessionSecrets, found = current.secrets[clientRandom]
		found = found && current.found
		err = current.err
		return
	}
	keyLogByRandom = func(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (keyLog string, found bool, err error) {
		current.mutex.Lock()
		defer current.mutex.Unlock()
		current.lookups++
		keyLog, found = current.keyLogs[clientRandom]
		found = found && current.found
		err = current.err
		return
	}
	return
}

func (current *testSecrets) setFound(found bool) {
	current.mutex.Lock()
	defer current.mutex.Unlock()
	current.found = found
}

// how often the secrets were looked up so far
func (current *testSecrets) lookupCount() (count int) {
	current.mutex.Lock()
	defer current.mutex.Unlock()
	count = current.lookups
	return
}

func (current *testSecrets) setErr(err error) {
	current.mutex.Lock()
	defer current.mutex.Unlock()
	current.err = err
}

// a TCP connection as the capture programs see it: the handshake, every chunk as one segment that acknowledges what the other side sent, and with isClosed the FIN of both sides
func tcpPackets(cookie uint64, client Endpoint, server Endpoint, chunks []sessionChunk, isClosed bool) (packets []capturebpf.Packet) {
	next := [2]uint32{testClientISN, testServerISN}
	endpoints := [2]Endpoint{client, server}
	add := func(direction tlsrecord.Direction, flags uint8, payload []byte) {
		other := otherDirection(direction)
		acknowledgment := uint32(0)

		if flags&ACKFlag != 0 {
			acknowledgment = next[other]
		}

		data := TCPPacket(nil, endpoints[direction], endpoints[other], next[direction], acknowledgment, flags, payload)
		packets = append(packets, capturebpf.Packet{Cookie: cookie, FlowCookie: cookie, TimestampNs: uint64(len(packets)+1) * 1000, Length: uint32(len(data)), IsIngress: direction == tlsrecord.ServerDirection, Data: data})
		next[direction] += uint32(len(payload))

		if flags&(SYNFlag|FINFlag) != 0 {
			next[direction]++
		}
	}
	add(tlsrecord.ClientDirection, SYNFlag, nil)
	add(tlsrecord.ServerDirection, SYNFlag|ACKFlag, nil)
	add(tlsrecord.ClientDirection, ACKFlag, nil)

	for _, chunk := range chunks {
		add(chunk.direction, ACKFlag|PSHFlag, chunk.data)
	}

	if isClosed {
		add(tlsrecord.ClientDirection, FINFlag|ACKFlag, nil)
		add(tlsrecord.ServerDirection, FINFlag|ACKFlag, nil)
		add(tlsrecord.ClientDirection, ACKFlag, nil)
	}

	return
}

// a recorder that writes a pcapng stream into output, every block is one write, with the maps of the secrets uprobe
func testRecorder(output io.Writer, plaintext bool, start time.Time) (current recorder, err error) {
	snaplen := capturebpf.MaxSnaplen

	if plaintext {
		snaplen = max(snaplen, SynthesizedLength)
	}

	writer, writerErr := pcapng.New(output, snaplen, true)

	if err = writerErr; err != nil {
		return
	}

	current = newRecorder(&writer, plaintext, 0, nil, testBpfMaps, nil, start, slog.New(slog.DiscardHandler))
	return
}

// feed the packets to the recorder as a writer behind the hub does: one millisecond apart, a tick whenever one is due; before runs in front of each packet
func feedRecorder(current *recorder, packets []capturebpf.Packet, start time.Time, before func(index int)) (err error) {
	for index, packet := range packets {
		if before != nil {
			before(index)
		}

		now := start.Add(time.Duration(index+1) * time.Millisecond)
		err = current.handle(packet, now)

		if (err == nil) && !now.Before(current.nextWake) {
			err = current.tick(now)
		}

		if err != nil {
			err = fmt.Errorf("packet %d: %w", index, err)
			return
		}
	}

	return
}

// one block of a pcapng the tests read back: a packet with its parsed headers or the key log of a DSB
type pcapBlock struct {
	blockType uint32
	data      []byte
	isInbound bool
	comment   string
	header    packetHeader
	isParsed  bool
	payload   []byte
}

// the packet and decryption secrets blocks of a pcapng section
func readBlocks(data []byte) (blocks []pcapBlock, err error) {
	for len(data) >= 12 {
		blockType := binary.LittleEndian.Uint32(data[0:])
		totalLength := int(binary.LittleEndian.Uint32(data[4:]))

		if (totalLength < 12) || (totalLength > len(data)) {
			err = fmt.Errorf("block length %d with %d bytes left", totalLength, len(data))
			return
		}

		body := data[8 : totalLength-4]
		data = data[totalLength:]

		switch blockType {
		case decryptionSecretsBlockType:
			length := int(binary.LittleEndian.Uint32(body[4:]))
			blocks = append(blocks, pcapBlock{blockType: blockType, data: bytes.Clone(body[8 : 8+length])})
		case enhancedPacketBlockType:
			capturedLength := int(binary.LittleEndian.Uint32(body[12:]))
			block := pcapBlock{blockType: blockType, data: bytes.Clone(body[20 : 20+capturedLength])}
			options := body[20+(capturedLength+3)/4*4:]

			for len(options) >= 4 {
				code := binary.LittleEndian.Uint16(options[0:])
				length := int(binary.LittleEndian.Uint16(options[2:]))

				switch code {
				case 1:
					block.comment = string(options[4 : 4+length])
				case 2:
					block.isInbound = binary.LittleEndian.Uint32(options[4:])&3 == 1
				default:
				}

				options = options[min(len(options), 4+(length+3)/4*4):]
			}

			block.header, block.isParsed = parsePacket(block.data)

			if block.isParsed && (block.header.payloadOffset <= len(block.data)) {
				block.payload = block.data[block.header.payloadOffset:]
			}

			blocks = append(blocks, block)
		default:
		}
	}

	return
}

// what the packets of the blocks carry by direction, and their comments
func streamsOf(blocks []pcapBlock) (streams [2][]byte, comments []string) {
	for _, block := range blocks {
		if block.blockType != enhancedPacketBlockType {
			continue
		}

		direction := tlsrecord.ClientDirection

		if block.isInbound {
			direction = tlsrecord.ServerDirection
		}

		streams[direction] = append(streams[direction], block.payload...)

		if block.comment != "" {
			comments = append(comments, block.comment)
		}
	}

	return
}

// the TLS 1.2 and TLS 1.3 sessions of the tests, each one a request and its response
func testSessions(state *testing.T) (sessions []tlsSession) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		request := fmt.Appendf(nil, "GET /%s HTTP/1.1\r\nHost: example.com\r\n\r\n", tlsrecord.VersionName(version))
		response := fmt.Appendf(nil, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n%04x!", version)
		session, err := runTLSSession(version, request, response)

		if err != nil {
			state.Fatalf("Test of capture plaintext failed, cannot run a %s session, error: %s", tlsrecord.VersionName(version), err.Error())
		}

		sessions = append(sessions, session)
	}

	return
}

// the comment of the first decrypted packet of the session
func (session tlsSession) description() (text string) {
	text = notePrefix + "decrypted tls session: " + tlsrecord.VersionName(session.version) + ", " + tlsrecord.CipherSuiteName(session.cipherSuite) + ", server name example.com, alpn http/1.1"
	return
}

// TLS records of application data that nothing can decrypt, count of them with 16384 bytes each, in chunks of the client of at most 32 KiB
func opaqueChunks(count int) (chunks []sessionChunk) {
	data := []byte{}

	for range count {
		data = append(data, byte(tlsrecord.ApplicationDataContentType), 3, 3, 0x40, 0)
		data = append(data, bytes.Repeat([]byte{0xA5}, 16384)...)
	}

	for chunk := range slices.Chunk(data, 32<<10) {
		chunks = append(chunks, sessionChunk{direction: tlsrecord.ClientDirection, data: chunk})
	}

	return
}

// the secrets of the session with every secret replaced by zeros of its length
func (session tlsSession) wrongSecrets() (secrets tlsrecord.Secrets) {
	zero := func(secret []byte) (result []byte) {
		if secret != nil {
			result = make([]byte, len(secret))
		}

		return
	}
	secrets = tlsrecord.Secrets{
		Version:                      session.secrets.Version,
		MasterKey:                    zero(session.secrets.MasterKey),
		ClientHandshakeTrafficSecret: zero(session.secrets.ClientHandshakeTrafficSecret),
		ServerHandshakeTrafficSecret: zero(session.secrets.ServerHandshakeTrafficSecret),
		ClientTrafficSecret:          zero(session.secrets.ClientTrafficSecret),
		ServerTrafficSecret:          zero(session.secrets.ServerTrafficSecret),
	}
	return
}

// the packets without the one that carries the last chunk of the server, the response: the FIN of the client acknowledges it
func withoutResponse(session tlsSession) (packets []capturebpf.Packet) {
	packets = tcpPackets(1, tlsClient, tlsServer, session.chunks, true)
	last := slices.IndexFunc(session.chunks, func(chunk sessionChunk) bool {
		return (chunk.direction == tlsrecord.ServerDirection) && bytes.Equal(chunk.data, session.lastChunk(tlsrecord.ServerDirection))
	})
	packets = slices.Delete(packets, 3+last, 4+last)
	return
}

// a TLS record of application data of which only the header and 10 bytes came
var partialRecord = sessionChunk{direction: tlsrecord.ClientDirection, data: append([]byte{byte(tlsrecord.ApplicationDataContentType), 3, 3, 0, 100}, bytes.Repeat([]byte{1}, 10)...)}

// a DTLS 1.2 session of OpenSSL from the fixtures of internal/tlsrecord: the CLIENT_RANDOM line of the key log, then one line per datagram with its sender and its bytes in hex
// the request and the response are the lines of application data the client and the server sent
func readDTLSSession(fileName string, openSSLName string, cipherSuite uint16) (session tlsSession, err error) {
	content, readErr := os.ReadFile(filepath.Join("..", "tlsrecord", "testdata", fileName))

	if err = readErr; err != nil {
		return
	}

	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)
		data, decodeErr := hex.DecodeString(fields[len(fields)-1])

		if err = decodeErr; err != nil {
			return
		}

		switch fields[0] {
		case "CLIENT_RANDOM":
			random, randomErr := hex.DecodeString(fields[1])

			if err = randomErr; err != nil {
				return
			}

			session.keyLog = line
			session.clientRandom = [32]byte(random)
			session.secrets = tlsrecord.Secrets{Version: tlsrecord.VersionDTLS12, MasterKey: data}
		case "c":
			session.chunks = append(session.chunks, sessionChunk{direction: tlsrecord.ClientDirection, data: data})
		default:
			session.chunks = append(session.chunks, sessionChunk{direction: tlsrecord.ServerDirection, data: data})
		}
	}

	session.version = tlsrecord.VersionDTLS12
	session.cipherSuite = cipherSuite
	session.request = []byte("hello dtls " + openSSLName + "\n")
	session.response = []byte("hello from server " + openSSLName + "\n")
	return
}

var (
	dtlsClient = Endpoint{Address: netip.MustParseAddr("2001:db8::10"), Port: 40000}
	dtlsServer = Endpoint{Address: netip.MustParseAddr("2001:db8::20"), Port: 4433}
)

// every chunk as one UDP datagram
func udpPackets(cookie uint64, client Endpoint, server Endpoint, chunks []sessionChunk) (packets []capturebpf.Packet) {
	for _, chunk := range chunks {
		data := UDPPacket(nil, client, server, chunk.data)

		if chunk.direction == tlsrecord.ServerDirection {
			data = UDPPacket(nil, server, client, chunk.data)
		}

		packets = append(packets, capturebpf.Packet{Cookie: cookie, FlowCookie: cookie, TimestampNs: uint64(len(packets)+1) * 1000, Length: uint32(len(data)), IsIngress: chunk.direction == tlsrecord.ServerDirection, Data: data})
	}

	return
}

// the DTLS session of the tests
func testDTLSSession(state *testing.T) (session tlsSession) {
	session, err := readDTLSSession("dtls_ecdhe_rsa_aes128_gcm_sha256.txt", "ECDHE-RSA-AES128-GCM-SHA256", 0xc02f)

	if err != nil {
		state.Fatalf("Test of capture plaintext failed, cannot read the DTLS fixture, error: %s", err.Error())
	}

	return
}

// an output that keeps what is written to it and fails from its write limit on
type failingWriter struct {
	writes int
	limit  int
	output []byte
}

var errTestWrite = errors.New("the output of the test is full")

func (writer *failingWriter) Write(data []byte) (count int, err error) {
	if writer.writes >= writer.limit {
		err = errTestWrite
		return
	}

	writer.writes++
	writer.output = append(writer.output, data...)
	count = len(data)
	return
}

// one run of a recorder in a test: the packets, the bytes other flows keep, a last tick this long after the start when it is not zero, and the packet from which on the secrets are found, -1 for never
// known are the sessions that started before the writer, scope its filter, which looks the flows up with testLookup; isKeyless is a capture without the secrets uprobe
type recording struct {
	plaintext bool
	packets   []capturebpf.Packet
	otherHeld int
	tick      time.Duration
	foundAt   int
	known     map[uint64][32]byte
	scope     *filter.Filter
	isKeyless bool
}

// write the packets into output, then the end of the capture
func (run recording) record(output io.Writer, secrets *testSecrets) (current recorder, err error) {
	start := time.Now()
	secrets.setFound(run.foundAt == 0)
	current, err = testRecorder(output, run.plaintext, start)

	if err != nil {
		return
	}

	current.heldBytes = run.otherHeld
	current.known = run.known
	current.gate = newGate(run.scope, false, nil, current.logger)
	current.gate.lookup = testLookup

	if run.isKeyless {
		current.secretsBpfMaps = nil
	}

	err = feedRecorder(&current, run.packets, start, func(index int) {
		if index == run.foundAt {
			secrets.setFound(true)
		}
	})

	if (err == nil) && (run.tick > 0) {
		err = current.tick(start.Add(run.tick))
	}

	if err == nil {
		err = current.finish()
	}

	return
}

// the blocks the run writes
func (run recording) blocks(secrets *testSecrets) (blocks []pcapBlock, current recorder, err error) {
	output := bytes.Buffer{}
	current, err = run.record(&output, secrets)

	if err != nil {
		return
	}

	blocks, err = readBlocks(output.Bytes())
	return
}

// the run with an output that fails at each of its writes in turn has to end with pcapng.ErrWrite every time
func (run recording) checkWriteErrors(secrets *testSecrets, writes int) (err error) {
	for limit := range writes {
		// the section header and the interface blocks come first
		_, recordErr := run.record(&failingWriter{writes: 0, limit: limit + 2, output: nil}, secrets)

		if !errors.Is(recordErr, pcapng.ErrWrite) {
			err = fmt.Errorf("the run should fail with %w when write %d of %d fails, error: %s", pcapng.ErrWrite, limit, writes, fmt.Sprint(recordErr))
			return
		}
	}

	return
}

// the first chunk of the session, the ClientHello, in two segments
func splitHello(session tlsSession) (chunks []sessionChunk) {
	chunks = slices.Concat([]sessionChunk{{direction: tlsrecord.ClientDirection, data: session.chunks[0].data[:100]}, {direction: tlsrecord.ClientDirection, data: session.chunks[0].data[100:]}}, session.chunks[1:])
	return
}

// Test if the plaintext recorder returns with the expected output for TLS 1.2 and 1.3 sessions: the decrypted request and response as synthesized packets, whether the secrets are there at once, come later or come with the FIN.
func TestPlaintextTLSPositive(state *testing.T) {
	positiveCases := []struct {
		Name   string
		Chunks func(session tlsSession) []sessionChunk
		// the secrets are found from this packet on, counted from the end when negative
		FoundAt int
	}{
		{Name: "at once", Chunks: func(session tlsSession) []sessionChunk { return session.chunks }, FoundAt: 0},
		{Name: "behind the response", Chunks: func(session tlsSession) []sessionChunk { return session.chunks }, FoundAt: -4},
		{Name: "with the fin", Chunks: func(session tlsSession) []sessionChunk { return session.chunks }, FoundAt: -3},
		{Name: "client hello in two segments", Chunks: splitHello, FoundAt: 0},
	}

	for _, session := range testSessions(state) {
		for _, positive := range positiveCases {
			run := recording{plaintext: true, packets: tcpPackets(1, tlsClient, tlsServer, positive.Chunks(session), true), otherHeld: 0, tick: 0, foundAt: positive.FoundAt, known: nil, scope: nil, isKeyless: false}

			if run.foundAt < 0 {
				run.foundAt += len(run.packets)
			}

			secrets := useTestSecrets(state, false, session)
			blocks, current, err := run.blocks(secrets)

			if err != nil {
				state.Fatalf("Test of capture plaintext failed, case %q %s, error: %s", positive.Name, tlsrecord.VersionName(session.version), err.Error())
			}

			streams, comments := streamsOf(blocks)

			if !bytes.Equal(streams[tlsrecord.ClientDirection], session.request) || !bytes.Equal(streams[tlsrecord.ServerDirection], session.response) {
				state.Errorf("Test of capture plaintext failed, case %q %s, streams should be %q and %q, streams: %q", positive.Name, tlsrecord.VersionName(session.version), session.request, session.response, streams)
				return
			}

			if !slices.Equal(comments, []string{session.description()}) || (current.keyedSessions != 1) || (current.heldBytes != 0) || (len(current.holding) != 0) {
				state.Errorf("Test of capture plaintext failed, case %q %s, the first decrypted packet should have the comment %q, comments: %q, decrypted: %d, held: %d", positive.Name, tlsrecord.VersionName(session.version), session.description(), comments, current.keyedSessions, current.heldBytes)
				return
			}

			// a synthesized SYN, SYN-ACK and ACK, and the FIN of both sides with its ACK at the end
			flags := []uint8{}

			for _, block := range blocks {
				flags = append(flags, block.header.flags)
			}

			if !slices.Equal(flags[:3], []uint8{SYNFlag, SYNFlag | ACKFlag, ACKFlag}) || !slices.Equal(flags[len(flags)-4:], []uint8{FINFlag | ACKFlag, ACKFlag, FINFlag | ACKFlag, ACKFlag}) {
				state.Errorf("Test of capture plaintext failed, case %q %s, the connection should open and close as the real one, flags: %v", positive.Name, tlsrecord.VersionName(session.version), flags)
				return
			}

			err = run.checkWriteErrors(secrets, len(blocks))

			if err != nil {
				state.Errorf("Test of capture plaintext failed, case %q %s, error: %s", positive.Name, tlsrecord.VersionName(session.version), err.Error())
				return
			}
		}
	}
}

// the session with two more segments of the server that were not captured, each one acknowledged by the client on its own, then the FIN
func withLostSegments(session tlsSession) (packets []capturebpf.Packet) {
	lost := []sessionChunk{{direction: tlsrecord.ServerDirection, data: []byte("lost one")}, {direction: tlsrecord.ClientDirection, data: nil}, {direction: tlsrecord.ServerDirection, data: []byte("lost two")}, {direction: tlsrecord.ClientDirection, data: nil}}
	packets = tcpPackets(1, tlsClient, tlsServer, slices.Concat(session.chunks, lost), true)
	first := 3 + len(session.chunks)
	packets = slices.Delete(packets, first+2, first+3)
	packets = slices.Delete(packets, first, first+1)
	return
}

// Test if the plaintext recorder returns with the expected errors for TLS sessions it can't decrypt, or not to their end: the bytes it could not decrypt are written as they were captured, with a comment that says why.
func TestPlaintextTLSNegative(state *testing.T) {
	sessionPackets := func(session tlsSession) []capturebpf.Packet {
		return tcpPackets(1, tlsClient, tlsServer, session.chunks, true)
	}
	openPackets := func(session tlsSession) []capturebpf.Packet {
		return tcpPackets(1, tlsClient, tlsServer, session.chunks, false)
	}
	negativeCases := []struct {
		Name    string
		Packets func(session tlsSession) []capturebpf.Packet
		// the secrets are found from this packet on, counted from the end when negative; never when zero
		FoundAt int
		Wrong   bool
		LookErr error
		// the bytes that other flows keep
		OtherHeld int
		// a tick this long after the start once every packet is there
		Tick time.Duration
		// what the comments have to contain, with IsLost followed by the bytes of the response that were not captured
		Note        string
		IsLost      bool
		IsDecrypted bool
		// the streams are the bytes the sides sent, nothing was decrypted
		IsRaw bool
		// the first writes that fail in turn, every one when zero: the held bytes are written from the fourth one on
		FailedWrites int
	}{
		{Name: "no secrets before the fin", Packets: sessionPackets, LookErr: errors.New("secrets_map is not there"), Note: "tls session not decrypted: " + closedReason, IsRaw: true},
		{Name: "no secrets before the capture stopped", Packets: openPackets, Note: "tls session not decrypted: " + stoppedReason, IsRaw: true},
		{Name: "no secrets before the hold timeout", Packets: openPackets, Tick: holdTimeout + time.Second, Note: "tls session not decrypted: " + timeoutReason, IsRaw: true},
		{
			Name: "no secrets before the rst",
			Packets: func(session tlsSession) []capturebpf.Packet {
				packets := tcpPackets(1, tlsClient, tlsServer, session.chunks, false)
				reset := TCPPacket(nil, tlsClient, tlsServer, testClientISN+1+uint32(len(session.sent(tlsrecord.ClientDirection))), 0, RSTFlag, nil)
				return append(packets, capturebpf.Packet{Cookie: 1, FlowCookie: 1, TimestampNs: 1 << 20, Length: uint32(len(reset)), IsIngress: false, Data: reset})
			},
			Note:  "tls session not decrypted: " + closedReason,
			IsRaw: true,
		},
		{
			Name: "secrets with the rst",
			Packets: func(session tlsSession) []capturebpf.Packet {
				packets := tcpPackets(1, tlsClient, tlsServer, session.chunks, false)
				reset := TCPPacket(nil, tlsClient, tlsServer, testClientISN+1+uint32(len(session.sent(tlsrecord.ClientDirection))), 0, RSTFlag, nil)
				return append(packets, capturebpf.Packet{Cookie: 1, FlowCookie: 1, TimestampNs: 1 << 20, Length: uint32(len(reset)), IsIngress: false, Data: reset})
			},
			FoundAt:     -1,
			IsDecrypted: true,
		},
		{
			Name: "no tls behind the client hello",
			Packets: func(session tlsSession) []capturebpf.Packet {
				return tcpPackets(1, tlsClient, tlsServer, []sessionChunk{session.chunks[0], {direction: tlsrecord.ClientDirection, data: []byte("GARBAGE\r\n")}}, true)
			},
			Note: "tls session not decrypted: ",
		},
		{Name: "wrong secrets at once", Packets: sessionPackets, FoundAt: 1, Wrong: true, Note: "tls decryption stopped, the rest of the connection is written encrypted: "},
		{Name: "wrong secrets for the records that waited", Packets: sessionPackets, FoundAt: -3, Wrong: true, Note: "tls decryption stopped, the rest of the connection is written encrypted: "},
		{Name: "response lost while the secrets are not there", Packets: withoutResponse, Note: "tls session not decrypted: ", IsLost: true},
		{Name: "response lost, the secrets come with its acknowledgment", Packets: withoutResponse, FoundAt: -3, Note: "tls decryption stopped, the rest of the connection is written encrypted: ", IsLost: true, IsDecrypted: true},
		{Name: "response lost in a decrypted session", Packets: withoutResponse, FoundAt: 1, Note: "tls decryption stopped, the rest of the connection is written encrypted: ", IsLost: true, IsDecrypted: true},
		{
			Name:        "segments lost in a decrypted session",
			Packets:     withLostSegments,
			FoundAt:     1,
			Note:        "tls decryption stopped, the rest of the connection is written encrypted: " + fmt.Sprintf(missingFormat, 8, "server") + "; " + fmt.Sprintf(missingFormat, 8, "server"),
			IsDecrypted: true,
		},
		{
			Name: "fin inside a record",
			Packets: func(session tlsSession) []capturebpf.Packet {
				return tcpPackets(1, tlsClient, tlsServer, append(slices.Clone(session.chunks), partialRecord), true)
			},
			FoundAt:     1,
			Note:        "tls decryption stopped, the rest of the connection is written encrypted: " + partialReason,
			IsDecrypted: true,
		},
		{
			Name: "capture stopped inside a record",
			Packets: func(session tlsSession) []capturebpf.Packet {
				return tcpPackets(1, tlsClient, tlsServer, append(slices.Clone(session.chunks), partialRecord), false)
			},
			FoundAt:     1,
			Note:        "tls decryption stopped, the rest of the connection is written encrypted: " + partialReason,
			IsDecrypted: true,
		},
		{
			Name: "too many bytes wait for the secrets",
			Packets: func(session tlsSession) []capturebpf.Packet {
				return tcpPackets(1, tlsClient, tlsServer, slices.Concat(session.chunks, opaqueChunks(maxHoldBytes/16384+1)), true)
			},
			Note:         "tls session not decrypted: " + holdLimitReason,
			FailedWrites: 8,
		},
		{Name: "too many bytes of all flows wait for secrets", Packets: sessionPackets, OtherHeld: maxTotalHoldBytes, Note: "tls session not decrypted: " + totalLimitReason, IsRaw: true},
	}

	for _, session := range testSessions(state) {
		for _, negative := range negativeCases {
			run := recording{plaintext: true, packets: negative.Packets(session), otherHeld: negative.OtherHeld, tick: negative.Tick, foundAt: negative.FoundAt, known: nil, scope: nil, isKeyless: false}

			switch {
			case run.foundAt < 0:
				run.foundAt += len(run.packets)
			case run.foundAt == 0:
				run.foundAt = -1
			default:
			}

			secrets := useTestSecrets(state, false, session)
			secrets.setErr(negative.LookErr)

			if negative.Wrong {
				secrets.secrets[session.clientRandom] = session.wrongSecrets()
			}

			blocks, current, err := run.blocks(secrets)

			if err != nil {
				state.Fatalf("Test of capture plaintext failed, case %q %s, error: %s", negative.Name, tlsrecord.VersionName(session.version), err.Error())
			}

			streams, comments := streamsOf(blocks)
			note := strings.Join(comments, "\n")
			expectedNote := negative.Note

			if negative.IsLost {
				expectedNote += fmt.Sprintf(missingFormat, len(session.lastChunk(tlsrecord.ServerDirection)), "server")
			}

			if !strings.Contains(note, expectedNote) || (bytes.Contains(streams[tlsrecord.ClientDirection], session.request) != negative.IsDecrypted) {
				state.Errorf("Test of capture plaintext failed, case %q %s, comments should have %q, request decrypted should be %v, comments: %q, client stream: %d bytes", negative.Name, tlsrecord.VersionName(session.version), expectedNote, negative.IsDecrypted, comments, len(streams[tlsrecord.ClientDirection]))
				return
			}

			if negative.IsRaw && (!bytes.Equal(streams[tlsrecord.ClientDirection], session.sent(tlsrecord.ClientDirection)) || !bytes.Equal(streams[tlsrecord.ServerDirection], session.sent(tlsrecord.ServerDirection))) {
				state.Errorf("Test of capture plaintext failed, case %q %s, the streams should be the %d and %d bytes the sides sent, streams: %d and %d bytes", negative.Name, tlsrecord.VersionName(session.version), len(session.sent(tlsrecord.ClientDirection)), len(session.sent(tlsrecord.ServerDirection)), len(streams[0]), len(streams[1]))
				return
			}

			if (current.heldBytes != negative.OtherHeld) || (len(current.holding) != 0) || (current.keylessSessions+current.keyedSessions != 1) {
				state.Errorf("Test of capture plaintext failed, case %q %s, nothing should be held at the end, held: %d, holding: %v, sessions: %d and %d", negative.Name, tlsrecord.VersionName(session.version), current.heldBytes-negative.OtherHeld, current.holding, current.keyedSessions, current.keylessSessions)
				return
			}

			writes := len(blocks)

			if negative.FailedWrites > 0 {
				writes = negative.FailedWrites
			}

			err = run.checkWriteErrors(secrets, writes)

			if err != nil {
				state.Errorf("Test of capture plaintext failed, case %q %s, error: %s", negative.Name, tlsrecord.VersionName(session.version), err.Error())
				return
			}
		}
	}
}

// Test if the plaintext recorder returns with the expected output for TCP connections without TLS: one that was open before the capture and whose first packet is the server's, one the server refused, and ones whose bytes were not captured when the capture stopped.
func TestPlaintextTCPPositive(state *testing.T) {
	server := Endpoint{Address: tlsServer.Address, Port: 6379}
	captured := func(isIngress bool, sequence uint32, acknowledgment uint32, flags uint8, payload []byte) (packet capturebpf.Packet) {
		data := TCPPacket(nil, tlsClient, server, sequence, acknowledgment, flags, payload)

		if isIngress {
			data = TCPPacket(nil, server, tlsClient, sequence, acknowledgment, flags, payload)
		}

		packet = capturebpf.Packet{Cookie: 9, FlowCookie: 9, TimestampNs: 1000, Length: uint32(len(data)), IsIngress: isIngress, Data: data}
		return
	}
	positiveCases := []struct {
		Name     string
		Packets  []capturebpf.Packet
		Flags    []uint8
		Streams  [2]string
		Comments []string
	}{
		{
			Name:     "server first",
			Packets:  []capturebpf.Packet{captured(true, 7000, 5000, ACKFlag|PSHFlag, []byte("+PONG\r\n")), captured(false, 5000, 7007, ACKFlag|PSHFlag, []byte("PING\r\n"))},
			Flags:    []uint8{SYNFlag, SYNFlag | ACKFlag, ACKFlag, ACKFlag | PSHFlag, ACKFlag | PSHFlag},
			Streams:  [2]string{"PING\r\n", "+PONG\r\n"},
			Comments: nil,
		},
		{
			Name:     "refused",
			Packets:  []capturebpf.Packet{captured(false, 4999, 0, SYNFlag, nil), captured(true, 0, 5000, RSTFlag|ACKFlag, nil)},
			Flags:    []uint8{SYNFlag, RSTFlag | ACKFlag},
			Streams:  [2]string{"", ""},
			Comments: nil,
		},
		{
			Name:     "fin behind a hole when the capture stopped",
			Packets:  []capturebpf.Packet{captured(true, 7000, 5000, FINFlag|ACKFlag, nil), captured(false, 5001, 7001, FINFlag|ACKFlag, []byte("ING"))},
			Flags:    []uint8{SYNFlag, SYNFlag | ACKFlag, ACKFlag, FINFlag | ACKFlag, ACKFlag, ACKFlag | PSHFlag, FINFlag | ACKFlag, ACKFlag},
			Streams:  [2]string{"ING", ""},
			Comments: []string{notePrefix + fmt.Sprintf(missingFormat, 1, "client")},
		},
		{
			Name:     "last bytes lost",
			Packets:  []capturebpf.Packet{captured(false, 5000, 7000, ACKFlag|PSHFlag, []byte("PING\r\n")), captured(false, 5006, 7007, ACKFlag, nil)},
			Flags:    []uint8{SYNFlag, SYNFlag | ACKFlag, ACKFlag, ACKFlag | PSHFlag, ACKFlag},
			Streams:  [2]string{"PING\r\n", ""},
			Comments: []string{notePrefix + fmt.Sprintf(missingFormat, 7, "server")},
		},
	}

	for _, positive := range positiveCases {
		secrets := useTestSecrets(state, false)
		run := recording{plaintext: true, packets: positive.Packets, otherHeld: 0, tick: 0, foundAt: -1, known: nil, scope: nil, isKeyless: false}
		blocks, _, err := run.blocks(secrets)

		if err != nil {
			state.Fatalf("Test of capture plaintext failed, case %q, error: %s", positive.Name, err.Error())
		}

		streams, comments := streamsOf(blocks)
		flags := []uint8{}

		for _, block := range blocks {
			flags = append(flags, block.header.flags)
		}

		if !slices.Equal(flags, positive.Flags) || (string(streams[0]) != positive.Streams[0]) || (string(streams[1]) != positive.Streams[1]) || !slices.Equal(comments, positive.Comments) {
			state.Errorf("Test of capture plaintext failed, case %q, flags should be %v with streams %q and comments %q, flags: %v, streams: %q, comments: %q", positive.Name, positive.Flags, positive.Streams, positive.Comments, flags, streams, comments)
			return
		}

		err = run.checkWriteErrors(secrets, len(blocks))

		if err != nil {
			state.Errorf("Test of capture plaintext failed, case %q, error: %s", positive.Name, err.Error())
			return
		}
	}
}

// Test if the plaintext recorder returns with the expected output for a DTLS 1.2 session of OpenSSL: one synthesized datagram per line of application data, whether the secrets are there at once or come with the last datagram.
func TestPlaintextDTLSPositive(state *testing.T) {
	session := testDTLSSession(state)
	packets := udpPackets(3, dtlsClient, dtlsServer, session.chunks)
	positiveCases := []struct {
		Name    string
		FoundAt int
	}{
		{Name: "at once", FoundAt: 0},
		{Name: "with the last datagram", FoundAt: len(packets) - 1},
	}
	description := notePrefix + "decrypted dtls session: " + tlsrecord.VersionName(session.version) + ", " + tlsrecord.CipherSuiteName(session.cipherSuite)

	for _, positive := range positiveCases {
		secrets := useTestSecrets(state, false, session)
		run := recording{plaintext: true, packets: packets, otherHeld: 0, tick: 0, foundAt: positive.FoundAt, known: nil, scope: nil, isKeyless: false}
		blocks, current, err := run.blocks(secrets)

		if err != nil {
			state.Fatalf("Test of capture plaintext failed, case %q, error: %s", positive.Name, err.Error())
		}

		streams, comments := streamsOf(blocks)

		if !bytes.Equal(streams[tlsrecord.ClientDirection], session.request) || !bytes.Equal(streams[tlsrecord.ServerDirection], session.response) || !slices.Equal(comments, []string{description}) {
			state.Errorf("Test of capture plaintext failed, case %q, streams should be %q and %q with the comment %q, streams: %q, comments: %q", positive.Name, session.request, session.response, description, streams, comments)
			return
		}

		// the addresses of the datagrams as they were, valid UDP checksums
		for _, block := range blocks {
			if (block.header.protocol != syscall.IPPROTO_UDP) || ((block.header.source != dtlsClient) && (block.header.source != dtlsServer)) || (transportChecksum(block.data, ipv6HeaderLength, syscall.IPPROTO_UDP) != 0) {
				state.Errorf("Test of capture plaintext failed, case %q, every packet should be a valid datagram of the session, packet: %x", positive.Name, block.data)
				return
			}
		}

		if (current.keyedSessions != 1) || (current.heldBytes != 0) || (len(current.holding) != 0) {
			state.Errorf("Test of capture plaintext failed, case %q, one session should be decrypted and nothing held, decrypted: %d, held: %d", positive.Name, current.keyedSessions, current.heldBytes)
			return
		}

		err = run.checkWriteErrors(secrets, len(blocks))

		if err != nil {
			state.Errorf("Test of capture plaintext failed, case %q, error: %s", positive.Name, err.Error())
			return
		}
	}
}

// Test if the plaintext recorder returns with the expected errors for DTLS sessions it can't decrypt, or not to their end, and for datagrams it can't build again: they are written as they were captured, with a comment that says why.
func TestPlaintextDTLSNegative(state *testing.T) {
	session := testDTLSSession(state)
	packets := udpPackets(3, dtlsClient, dtlsServer, session.chunks)
	sentDatagrams := [2][]byte{session.sent(tlsrecord.ClientDirection), session.sent(tlsrecord.ServerDirection)}
	largeDatagrams := []sessionChunk{session.chunks[0]}

	for range maxHoldBytes/60000 + 1 {
		largeDatagrams = append(largeDatagrams, sessionChunk{direction: tlsrecord.ServerDirection, data: bytes.Repeat([]byte{0x17}, 60000)})
	}

	cut := slices.Clone(packets[:1])
	cut[0].Length += 100
	icmp := TCPPacket(nil, dtlsClient, dtlsServer, 1, 0, ACKFlag, []byte("ping"))
	icmp[ipv6NextHeaderOffset] = syscall.IPPROTO_ICMPV6
	negativeCases := []struct {
		Name      string
		Packets   []capturebpf.Packet
		FoundAt   int
		LookErr   error
		OtherHeld int
		Tick      time.Duration
		Note      string
		// the streams that have to be written, nil when they are not checked
		Streams *[2][]byte
		// the decrypted lines are there
		IsDecrypted bool
	}{
		{Name: "no secrets before the capture stopped", Packets: packets, FoundAt: -1, LookErr: errors.New("secrets_map is not there"), Note: "dtls session not decrypted: " + stoppedReason, Streams: &sentDatagrams},
		{Name: "no secrets before the hold timeout", Packets: packets, FoundAt: -1, Tick: holdTimeout + time.Second, Note: "dtls session not decrypted: " + timeoutReason, Streams: &sentDatagrams},
		{Name: "too many bytes wait for the secrets", Packets: udpPackets(3, dtlsClient, dtlsServer, largeDatagrams), FoundAt: -1, Note: "dtls session not decrypted: " + holdLimitReason},
		{Name: "too many bytes of all flows wait for secrets", Packets: packets, FoundAt: -1, OtherHeld: maxTotalHoldBytes, Note: "dtls session not decrypted: " + totalLimitReason, Streams: &sentDatagrams},
		{
			Name:    "client hello that can't be read",
			Packets: udpPackets(3, dtlsClient, dtlsServer, []sessionChunk{{direction: tlsrecord.ClientDirection, data: session.chunks[0].data[:20]}, session.chunks[1]}),
			FoundAt: -1,
			Note:    "dtls session not decrypted: " + clientHelloReason + ": ",
			Streams: &[2][]byte{session.chunks[0].data[:20], session.chunks[1].data},
		},
		{
			Name:        "datagram that is no dtls in a decrypted session",
			Packets:     udpPackets(3, dtlsClient, dtlsServer, append(slices.Clone(session.chunks), sessionChunk{direction: tlsrecord.ClientDirection, data: []byte("no dtls")}, sessionChunk{direction: tlsrecord.ServerDirection, data: []byte("after")})),
			FoundAt:     0,
			Note:        droppedRecordNote,
			Streams:     &[2][]byte{slices.Concat(session.request, []byte("no dtls")), slices.Concat(session.response, []byte("after"))},
			IsDecrypted: true,
		},
		{
			Name:    "datagrams that are no dtls",
			Packets: udpPackets(4, dtlsClient, dtlsServer, []sessionChunk{{direction: tlsrecord.ClientDirection, data: []byte("query")}, {direction: tlsrecord.ServerDirection, data: []byte("answer")}}),
			FoundAt: -1,
			Streams: &[2][]byte{[]byte("query"), []byte("answer")},
		},
		{
			Name:    "datagram the snaplen cut and a packet of another protocol",
			Packets: append(cut, capturebpf.Packet{Cookie: 5, FlowCookie: 5, TimestampNs: 1, Length: uint32(len(icmp)), IsIngress: false, Data: icmp}),
			FoundAt: -1,
			Note:    "",
		},
	}

	for _, negative := range negativeCases {
		secrets := useTestSecrets(state, false, session)
		secrets.setErr(negative.LookErr)
		run := recording{plaintext: true, packets: negative.Packets, otherHeld: negative.OtherHeld, tick: negative.Tick, foundAt: negative.FoundAt, known: nil, scope: nil, isKeyless: false}
		blocks, current, err := run.blocks(secrets)

		if err != nil {
			state.Fatalf("Test of capture plaintext failed, case %q, error: %s", negative.Name, err.Error())
		}

		streams, comments := streamsOf(blocks)
		note := strings.Join(comments, "\n")

		if !strings.Contains(note, negative.Note) || ((negative.Note == "") != (len(comments) == 0)) || (bytes.Contains(streams[tlsrecord.ClientDirection], session.request) != negative.IsDecrypted) {
			state.Errorf("Test of capture plaintext failed, case %q, comments should have %q, decrypted should be %v, comments: %q, streams: %q", negative.Name, negative.Note, negative.IsDecrypted, comments, streams)
			return
		}

		if (negative.Streams != nil) && (!bytes.Equal(streams[0], negative.Streams[0]) || !bytes.Equal(streams[1], negative.Streams[1])) {
			state.Errorf("Test of capture plaintext failed, case %q, streams should be %q, streams: %q", negative.Name, *negative.Streams, streams)
			return
		}

		if (len(blocks) != len(negative.Packets)) && !negative.IsDecrypted {
			state.Errorf("Test of capture plaintext failed, case %q, every packet should be written once, packets: %d, written: %d", negative.Name, len(negative.Packets), len(blocks))
			return
		}

		if (current.heldBytes != negative.OtherHeld) || (len(current.holding) != 0) {
			state.Errorf("Test of capture plaintext failed, case %q, nothing should be held at the end, held: %d, holding: %v", negative.Name, current.heldBytes-negative.OtherHeld, current.holding)
			return
		}

		err = run.checkWriteErrors(secrets, len(blocks))

		if err != nil {
			state.Errorf("Test of capture plaintext failed, case %q, error: %s", negative.Name, err.Error())
			return
		}
	}
}
