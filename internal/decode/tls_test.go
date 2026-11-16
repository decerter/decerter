// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
)

// the contexts of the TLS tests: a tcp read to port 443, the handshake records decerter kept of a TLS and of a DTLS flow, a udp datagram
var (
	tlsTCPContext  = Context{Transport: StreamTransport, Layer: v1.TCPLayer, Direction: v1.UpDirection, ServerPort: 443, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false}
	keptContext    = Context{Transport: StreamTransport, Layer: v1.TLSLayer, Direction: v1.DownDirection, ServerPort: 443, ALPN: "h2", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: true}
	keptDTLS       = Context{Transport: DatagramTransport, Layer: v1.DTLSLayer, Direction: v1.UpDirection, ServerPort: 4433, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: true}
	dtlsUDPContext = Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 4433, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false}
)

func be24(value int) (data []byte) {
	data = []byte{byte(value >> 16), byte(value >> 8), byte(value)}
	return
}

func tlsRecord(contentType byte, version uint16, payload []byte) (data []byte) {
	data = join([]byte{contentType}, be16(version), be16(uint16(len(payload))), payload)
	return
}

func dtlsRecord(contentType byte, epoch uint16, sequence uint32, payload []byte) (data []byte) {
	data = join([]byte{contentType}, be16(0xfefd), be16(epoch), be16(0), be32(sequence), be16(uint16(len(payload))), payload)
	return
}

func handshakeMessage(messageType byte, body []byte) (data []byte) {
	data = join([]byte{messageType}, be24(len(body)), body)
	return
}

// a whole DTLS handshake message, one fragment
func dtlsMessage(messageType byte, sequence uint16, body []byte) (data []byte) {
	data = join([]byte{messageType}, be24(len(body)), be16(sequence), be24(0), be24(len(body)), body)
	return
}

func extension(extensionType uint16, data []byte) (encoded []byte) {
	encoded = join(be16(extensionType), be16(uint16(len(data))), data)
	return
}

func vector16(data []byte) (encoded []byte) {
	encoded = join(be16(uint16(len(data))), data)
	return
}

// a self-signed ECDSA certificate for decerter.test and 127.0.0.1
func testCertificate(state testing.TB) (certificate tls.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		state.Fatalf("Could not make a key, error: %s", err.Error())
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{CommonName: "decerter.test", Organization: []string{"DECERTER"}},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:              []string{"decerter.test", "*.decerter.test"},
		IPAddresses:           []net.IP{netip.MustParseAddr("127.0.0.1").AsSlice()},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	if err != nil {
		state.Fatalf("Could not make a certificate, error: %s", err.Error())
	}

	certificate = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return
}

// a conn that keeps what it writes
type recording struct {
	net.Conn

	mutex   *sync.Mutex
	written *bytes.Buffer
}

func (recording recording) Write(data []byte) (written int, err error) {
	recording.mutex.Lock()
	recording.written.Write(data)
	recording.mutex.Unlock()
	written, err = recording.Conn.Write(data)
	return
}

// the bytes crypto/tls sends each way in a handshake of that version over a pipe
func goHandshake(state testing.TB, version uint16) (up []byte, down []byte) {
	clientSide, serverSide := net.Pipe()
	mutex := &sync.Mutex{}
	upBuffer, downBuffer := &bytes.Buffer{}, &bytes.Buffer{}
	client := tls.Client(recording{Conn: clientSide, mutex: mutex, written: upBuffer}, &tls.Config{ServerName: "decerter.test", InsecureSkipVerify: true, MinVersion: version, MaxVersion: version, NextProtos: []string{"h2", "http/1.1"}})
	server := tls.Server(recording{Conn: serverSide, mutex: mutex, written: downBuffer}, &tls.Config{Certificates: []tls.Certificate{testCertificate(state)}, MinVersion: version, MaxVersion: version, NextProtos: []string{"h2"}})
	waitGroup := sync.WaitGroup{}
	errs := make([]error, 2)
	waitGroup.Go(func() { errs[0] = client.HandshakeContext(state.Context()) })
	waitGroup.Go(func() { errs[1] = server.HandshakeContext(state.Context()) })
	waitGroup.Wait()

	if (errs[0] != nil) || (errs[1] != nil) {
		state.Fatalf("Could not make the handshake, errors: %v", errs)
	}

	for _, conn := range []*tls.Conn{client, server} {
		_ = conn.NetConn().Close()
	}

	mutex.Lock()
	up, down = bytes.Clone(upBuffer.Bytes()), bytes.Clone(downBuffer.Bytes())
	mutex.Unlock()
	return
}

// the handshake records decerter keeps of a TLS 1.3 server: ServerHello, Change Cipher Spec, then the plaintext of the records it decrypted with the
// Certificate over two of them, and a New Session Ticket
func tls13ServerTranscript(state testing.TB) (data []byte) {
	random := bytes.Repeat([]byte{0x11}, 32)
	sessionID := bytes.Repeat([]byte{0x22}, 32)
	keyShare := join(be16(0x001d), vector16(bytes.Repeat([]byte{0x33}, 32)))
	serverHello := handshakeMessage(2, join(be16(0x0303), random, []byte{32}, sessionID, be16(0x1301), []byte{0}, vector16(join(extension(43, be16(0x0304)), extension(51, keyShare)))))
	encryptedExtensions := handshakeMessage(8, vector16(extension(16, vector16([]byte{2, 'h', '2'}))))
	der := testCertificate(state).Certificate[0]
	certificate := handshakeMessage(11, join([]byte{0}, be24(3+len(der)+2), be24(len(der)), der, be16(0)))
	verify := handshakeMessage(15, join(be16(0x0403), vector16(bytes.Repeat([]byte{0x44}, 70))))
	finished := handshakeMessage(20, bytes.Repeat([]byte{0x55}, 32))
	ticket := handshakeMessage(4, join(be32(7200), be32(0x01020304), []byte{1, 0}, vector16([]byte("ticket")), vector16(extension(42, be32(16384)))))
	half := len(encryptedExtensions) + len(certificate)/2
	flight := join(encryptedExtensions, certificate, verify, finished)
	data = join(tlsRecord(22, 0x0303, serverHello), tlsRecord(20, 0x0303, []byte{1}), tlsRecord(22, 0x0303, flight[:half]), tlsRecord(22, 0x0303, flight[half:]), tlsRecord(22, 0x0303, ticket))
	return
}

// a DTLS 1.2 ClientHello with a cookie, the version 0xfefd and the server_name extension
func dtlsClientHello(cookie []byte) (data []byte) {
	body := join(be16(0xfefd), bytes.Repeat([]byte{0x66}, 32), []byte{0}, []byte{byte(len(cookie))}, cookie, vector16(join(be16(0xc02b), be16(0x0a0a))), []byte{1, 0},
		vector16(extension(0, vector16(join([]byte{0}, vector16([]byte("decerter.test")))))))
	data = dtlsRecord(22, 0, 1, dtlsMessage(1, 1, body))
	return
}

// Test if decode.Decode returns with the expected output for TLS ClientHellos of curl (OpenSSL): every extension, and the JA3 and JA4 that tshark 4.4 gives for
// them, as a tcp read to port 443 and as the handshake decerter kept.
func TestTLSClientHelloPositive(state *testing.T) {
	testCases := map[string]struct {
		file     string
		summary  string
		ja3      string
		ja4      string
		ja3Start string
	}{
		"TLS 1.3": {file: "curl13_client_hello.bin", summary: "Client Hello SNI localhost ALPN h2,http/1.1", ja3: "7a73fb0bdeaa2a79fadf356c34e7577e", ja4: "t13d3013h2_1d37bd780c83_8537cf56674e", ja3Start: "771,4866-4867-4865-49196-49200-159-"},
		"TLS 1.2": {file: "curl12_client_hello.bin", summary: "Client Hello ALPN http/1.1", ja3: "bc7de5a7802f06a1b5e27702af7ea1b7", ja4: "t12i2707h1_a2460661a67a_eed5f1524d5c", ja3Start: "771,49196-49200-159-"},
	}

	for name, testCase := range testCases {
		data, err := os.ReadFile("testdata/tls/" + testCase.file)

		if err != nil {
			state.Fatalf("Could not read %s, error: %s", testCase.file, err.Error())
		}

		for _, context := range []Context{tlsTCPContext, keptContext} {
			result := mustDecode(state, data, context, "")
			ja3Full := findNode(result.Tree, "tls.handshake.ja3_full")

			if (result.Protocol != tlsProtocol) || (result.Summary != testCase.summary) || (len(errorsOf(result.Tree)) > 0) || (ja3Full == nil) || !strings.HasPrefix(ja3Full.Value, testCase.ja3Start) {
				state.Errorf("Test of decode.Decode failed, the %s ClientHello should decode as tls, summary: %q, errors: %v, ja3: %+v", name, result.Summary, errorsOf(result.Tree), ja3Full)
				continue
			}

			checkValues(state, "decode.Decode "+name, result, map[string]string{"tls.handshake.ja3": testCase.ja3, "tls.handshake.ja4": testCase.ja4, "tls.record.content_type": "Handshake (22)", "tls.handshake.type": "Client Hello (1)"})
		}
	}

	data, _ := os.ReadFile("testdata/tls/curl13_client_hello.bin")
	result := mustDecode(state, data, tlsTCPContext, "")
	checkValues(state, "decode.Decode", result, map[string]string{
		"tls.handshake.extensions_server_name":       "localhost",
		"tls.handshake.extensions_alpn_str#0":        "h2",
		"tls.handshake.extensions_alpn_str#1":        "http/1.1",
		"tls.handshake.extensions.supported_version": "TLS 1.3 (0x0304)",
		"tls.handshake.ciphersuite#0":                "TLS_AES_256_GCM_SHA384 (0x1302)",
	})

	for _, name := range []string{"tls.handshake.extensions_supported_group", "tls.handshake.sig_hash_alg", "tls.handshake.extensions_key_share_group", "tls.extension.psk_ke_mode", "tls.handshake.random", "tls.handshake.session_id"} {
		if findNode(result.Tree, name) == nil {
			state.Errorf("Test of decode.Decode failed, the TLS 1.3 ClientHello should have %s", name)
		}
	}
}

// Test if decode.Decode returns with the expected output for the handshakes of crypto/tls as they go over tcp: TLS 1.2 with the server's certificate, key
// exchange, ticket and the encrypted Finished after Change Cipher Spec; TLS 1.3 with application data after the ServerHello. And the TLS 1.3 records decerter kept
// of a server with the decrypted Certificate put together from two records, and a HelloRetryRequest.
func TestTLSHandshakePositive(state *testing.T) {
	up, down := goHandshake(state, tls.VersionTLS12)
	result := mustDecode(state, down, tlsTCPContext, "")

	if (result.Protocol != tlsProtocol) || (len(errorsOf(result.Tree)) > 0) ||
		(result.Summary != "Server Hello TLS 1.2 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ALPN h2, Certificate CN=decerter.test,O=DECERTER, Server Key Exchange, Server Hello Done, Change Cipher Spec, Encrypted Handshake Message") {
		state.Errorf("Test of decode.Decode failed, the TLS 1.2 server flight should decode, summary: %q, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	checkValues(state, "decode.Decode", result, map[string]string{
		"x509.subject":                      "CN=decerter.test,O=DECERTER",
		"x509.issuer":                       "CN=decerter.test,O=DECERTER",
		"x509.not_before":                   "2026-01-01T00:00:00Z",
		"x509.not_after":                    "2036-01-01T00:00:00Z",
		"x509.serial_number":                "1092",
		"x509.san.name#0":                   "DNS:decerter.test",
		"x509.san.name#2":                   "IP:127.0.0.1",
		"tls.handshake.server_named_curve":  "x25519 (0x001d)",
		"tls.handshake.extensions_alpn_str": "h2",
	})

	if ja3s := findNode(result.Tree, "tls.handshake.ja3s_full"); (ja3s == nil) || !strings.HasPrefix(ja3s.Value, "771,49195,") {
		state.Errorf("Test of decode.Decode failed, the ServerHello should have its JA3S, node: %+v", ja3s)
	}

	result = mustDecode(state, up, tlsTCPContext, "")

	if (result.Summary != "Client Hello SNI decerter.test ALPN h2,http/1.1, Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message") || (len(errorsOf(result.Tree)) > 0) {
		state.Errorf("Test of decode.Decode failed, the TLS 1.2 client flight should decode, summary: %q, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	_, down = goHandshake(state, tls.VersionTLS13)
	result = mustDecode(state, down, tlsTCPContext, "")

	if !strings.HasPrefix(result.Summary, "Server Hello TLS 1.3 TLS_AES_128_GCM_SHA256, Change Cipher Spec, Application Data") || (len(errorsOf(result.Tree)) > 0) {
		state.Errorf("Test of decode.Decode failed, the TLS 1.3 server flight should be application data after the ServerHello, summary: %q, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	transcript := tls13ServerTranscript(state)
	result = mustDecode(state, transcript, keptContext, "")
	reassembled := findNode(result.Tree, "tls.handshake.reassembled")

	if (result.Protocol != tlsProtocol) || (result.Candidates[0].Basis != v1.ContextDecodeBasis) || (len(errorsOf(result.Tree)) > 0) || (reassembled == nil) || (reassembled.Label != "Reassembled handshake message (2 fragments)") ||
		(result.Summary != "Server Hello TLS 1.3 TLS_AES_128_GCM_SHA256, Change Cipher Spec, Encrypted Extensions, Certificate CN=decerter.test,O=DECERTER, Certificate Verify, Finished, New Session Ticket") {
		state.Errorf("Test of decode.Decode failed, the kept TLS 1.3 records should decode, summary: %q, errors: %v, reassembled: %+v", result.Summary, errorsOf(result.Tree), reassembled)
	}

	checkValues(state, "decode.Decode", result, map[string]string{
		"x509.subject":                               "CN=decerter.test,O=DECERTER",
		"tls.handshake.extensions_alpn_str":          "h2",
		"tls.handshake.extensions.supported_version": "TLS 1.3 (0x0304)",
		"tls.handshake.extensions_key_share_group":   "x25519 (0x001d)",
		"tls.handshake.sig_hash_alg":                 "ecdsa_secp256r1_sha256 (0x0403)",
		"tls.handshake.session_ticket_lifetime_hint": "7200",
		"tls.handshake.max_early_data_size":          "16384",
	})

	// the subject of the certificate spans its DER over the two records: it starts in the third record and ends in the fourth
	subject := findNode(result.Tree, "x509.subject")
	boundary := result.Tree[2].Offset + result.Tree[2].Length

	if (subject == nil) || (subject.Offset >= boundary) || (subject.Offset+subject.Length <= boundary) {
		state.Errorf("Test of decode.Decode failed, the subject should span the end of the third record at %d, node: %+v", boundary, subject)
	}

	retry := handshakeMessage(2, join(be16(0x0303), helloRetryRandom, []byte{0}, be16(0x1302), []byte{0}, vector16(join(extension(43, be16(0x0304)), extension(51, be16(0x0017))))))

	if result = mustDecode(state, tlsRecord(22, 0x0303, retry), keptContext, ""); (result.Summary != "Hello Retry Request TLS 1.3 TLS_AES_256_GCM_SHA384") || (findNode(result.Tree, "tls.handshake.extensions_key_share_selected_group") == nil) {
		state.Errorf("Test of decode.Decode failed, the HelloRetryRequest should be known by its random, summary: %q, tree: %+v", result.Summary, result.Tree)
	}

	alerts := join(tlsRecord(21, 0x0303, []byte{2, 40}), tlsRecord(21, 0x0303, []byte{1, 0}))

	if result = mustDecode(state, alerts, tlsTCPContext, ""); result.Summary != "Alert fatal handshake_failure, Alert warning close_notify" {
		state.Errorf("Test of decode.Decode failed, the alerts should decode, summary: %q", result.Summary)
	}
}

// Test if decode.Decode returns with the expected output for DTLS: a ClientHello with a cookie and JA4 of protocol d, a HelloVerifyRequest, a fragment of a
// message shown as it is, an encrypted record of epoch 1, a DTLS 1.3 record with the unified header, and the records decerter kept by the flow's layer.
func TestDTLSPositive(state *testing.T) {
	hello := dtlsClientHello([]byte{0xc0, 0x0c})
	result := mustDecode(state, hello, dtlsUDPContext, "")

	if (result.Protocol != dtlsProtocol) || (result.Summary != "Client Hello SNI decerter.test") || (len(errorsOf(result.Tree)) > 0) {
		state.Fatalf("Test of decode.Decode failed, the DTLS ClientHello should decode, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "decode.Decode", result, map[string]string{"dtls.handshake.cookie": "c00c", "dtls.record.epoch": "0", "dtls.record.sequence_number": "1", "tls.handshake.ciphersuite#1": "GREASE (0x0a0a)"})

	if ja4 := findNode(result.Tree, "tls.handshake.ja4"); (ja4 == nil) || !strings.HasPrefix(ja4.Value, "dd2d0101") {
		state.Errorf("Test of decode.Decode failed, the JA4 should be of DTLS 1.2 with one suite without GREASE and one extension, node: %+v", ja4)
	}

	verify := dtlsRecord(22, 0, 0, dtlsMessage(3, 0, join(be16(0xfeff), []byte{2, 0xc0, 0x0c})))
	fragment := dtlsRecord(22, 0, 2, join([]byte{11}, be24(100), be16(2), be24(0), be24(10), bytes.Repeat([]byte{7}, 10)))
	encrypted := dtlsRecord(22, 1, 0, bytes.Repeat([]byte{9}, 40))
	unified := join([]byte{0x2c | 0x01}, be16(5), be16(16), bytes.Repeat([]byte{8}, 16))
	result = mustDecode(state, join(verify, fragment, encrypted, unified), dtlsUDPContext, "")

	if (result.Summary != "Hello Verify Request, Certificate (fragment), Encrypted Handshake Message, Encrypted Record") || (len(errorsOf(result.Tree)) > 0) || (len(result.Tree) != 4) {
		state.Errorf("Test of decode.Decode failed, the DTLS records should decode, summary: %q, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	checkValues(state, "decode.Decode", result, map[string]string{"dtls.handshake.fragment_length#1": "10", "dtls.unified.epoch": "1", "dtls.record.length": "16"})

	// kept: epoch 1 is plaintext
	kept := join(hello, dtlsRecord(22, 1, 0, dtlsMessage(20, 4, bytes.Repeat([]byte{5}, 12))))

	if result = mustDecode(state, kept, keptDTLS, ""); (result.Protocol != dtlsProtocol) || (result.Candidates[0].Reason != "the handshake records decerter kept of the DTLS flow") || (result.Summary != "Client Hello SNI decerter.test, Finished") {
		state.Errorf("Test of decode.Decode failed, the kept DTLS records should decode with the Finished, result: %+v", result)
	}
}

// Test if decode.Decode returns with the expected errors for TLS: a record header or record cut short, a handshake message past the end of the data, a hello
// whose fields run past its end, an extension that does not fill its length, a certificate that is no DER, and bytes after the last field.
func TestTLSNegative(state *testing.T) {
	hello, _ := os.ReadFile("testdata/tls/curl12_client_hello.bin")
	badExtension := handshakeMessage(1, join(be16(0x0303), make([]byte, 32), []byte{0}, vector16(be16(0x1301)), []byte{1, 0}, vector16(extension(10, []byte{0, 4, 0, 0x1d}))))
	certificate := handshakeMessage(11, join(be24(7), be24(4), []byte{1, 2, 3, 4}))
	testCases := map[string]struct {
		data     []byte
		context  Context
		expected string
	}{
		"short header":   {data: join(tlsRecord(21, 0x0303, []byte{1, 0}), []byte{22, 3}), context: tlsTCPContext, expected: "tls.record: the 5-byte record header is cut short, 2 bytes are here"},
		"short record":   {data: hello[:100], context: tlsTCPContext, expected: "tls.record: the record goes on past the end of the data: 95 of its 195 bytes are here; a handshake message goes on past the end of the data: 95 of its 195 bytes are here"},
		"bad extension":  {data: tlsRecord(22, 0x0303, badExtension), context: tlsTCPContext, expected: ""},
		"no DER":         {data: tlsRecord(22, 0x0303, certificate), context: keptContext, expected: ""},
		"trailing bytes": {data: tlsRecord(22, 0x0303, handshakeMessage(14, []byte{1, 2})), context: tlsTCPContext, expected: "tls.handshake: 2 bytes after the last field"},
	}

	for name, testCase := range testCases {
		result := mustDecode(state, testCase.data, testCase.context, tlsProtocol)
		errors := errorsOf(result.Tree)

		if (result.Error != "") || (len(errors) == 0) || ((testCase.expected != "") && (errors[0] != testCase.expected)) {
			state.Errorf("Test of decode.Decode failed, %s should fail with %q, errors: %v", name, testCase.expected, errors)
		}
	}

	if result := mustDecode(state, []byte("GET / HTTP/1.1\r\n\r\n"), tlsTCPContext, ""); result.Protocol == tlsProtocol {
		state.Errorf("Test of decode.Decode failed, HTTP to port 443 should not be tls, result: %+v", result)
	}
}

// the seed corpus of FuzzTLS: the curl hellos, the crypto/tls flights, the kept TLS 1.3 records, alerts and a record cut short
func tlsSeeds(fuzz *testing.F) (seeds [][]byte) {
	for _, file := range []string{"curl13_client_hello.bin", "curl12_client_hello.bin"} {
		data, err := os.ReadFile("testdata/tls/" + file)

		if err != nil {
			fuzz.Fatalf("Could not read %s, error: %s", file, err.Error())
		}

		seeds = append(seeds, data)
	}

	up, down := goHandshake(fuzz, tls.VersionTLS12)
	_, down13 := goHandshake(fuzz, tls.VersionTLS13)
	transcript := tls13ServerTranscript(fuzz)
	seeds = append(seeds, up, down, down13, transcript, transcript[:len(transcript)/2], tlsRecord(21, 0x0303, []byte{2, 40}))
	return
}

// Fuzz if decode.Decode never fails on any bytes as TLS, as records over tcp and as the records decerter kept: no error and a tree inside the bytes with printable
// strings only.
func FuzzTLS(fuzz *testing.F) {
	for _, seed := range tlsSeeds(fuzz) {
		fuzz.Add(seed)
	}

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		for _, context := range []Context{tlsTCPContext, keptContext} {
			for _, as := range []string{"", tlsProtocol} {
				result, err := Decode(data, context, as)

				if err != nil {
					state.Fatalf("Fuzz of decode.Decode failed, it should take any bytes, error: %s", err.Error())
				}

				if problems := shapeErrors(result.Tree, 0, result.Length); (len(problems) > 0) || (result.Error != "") {
					state.Fatalf("Fuzz of decode.Decode failed, the tree should fit its bytes, problems: %v, error: %s", problems, result.Error)
				}
			}
		}
	})
}

// Fuzz if decode.Decode never fails on any bytes as DTLS, as a datagram and as the records decerter kept: no error and a tree inside the bytes with printable
// strings only.
func FuzzDTLS(fuzz *testing.F) {
	hello := dtlsClientHello([]byte{0xc0, 0x0c})
	fuzz.Add(hello)
	fuzz.Add(dtlsRecord(22, 0, 0, dtlsMessage(3, 0, join(be16(0xfeff), []byte{2, 0xc0, 0x0c}))))
	fuzz.Add(dtlsRecord(22, 0, 2, join([]byte{11}, be24(100), be16(2), be24(0), be24(10), bytes.Repeat([]byte{7}, 10))))
	fuzz.Add(join([]byte{0x2d}, be16(5), be16(16), bytes.Repeat([]byte{8}, 16)))
	fuzz.Add(join(hello, dtlsRecord(22, 1, 0, dtlsMessage(20, 4, bytes.Repeat([]byte{5}, 12)))))

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		for _, context := range []Context{dtlsUDPContext, keptDTLS} {
			for _, as := range []string{"", dtlsProtocol} {
				result, err := Decode(data, context, as)

				if err != nil {
					state.Fatalf("Fuzz of decode.Decode failed, it should take any bytes, error: %s", err.Error())
				}

				if problems := shapeErrors(result.Tree, 0, result.Length); (len(problems) > 0) || (result.Error != "") {
					state.Fatalf("Fuzz of decode.Decode failed, the tree should fit its bytes, problems: %v, error: %s", problems, result.Error)
				}
			}
		}
	})
}
