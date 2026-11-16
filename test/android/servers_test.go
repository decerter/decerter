// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e_android

package android_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	_ "unsafe"
)

const (
	// the servers listen on the host's loopback only, the emulator reaches them as 10.0.2.2 through its user mode network
	listenAddress string = "127.0.0.1:0"
	echoPrefix    string = "echo "
	// a server answers this path with a page that loads chromeImagePath, the Chrome suite case rewrites the request to it and the image path in the page
	chromePagePath  string = "/chrome-up"
	chromeImagePath string = "/img-orig"
	// the image path the Chrome suite case rewrites the page's to, as long as the original
	chromeEditedImagePath string = "/img-down"
)

// crypto/tls has no setting for the TLS 1.3 suites, a suite case narrows its default lists to the one suite of the case; crypto/tls itself
// pushes both with a linkname directive (go.dev/issue/67401)
//
//go:linkname defaultCipherSuitesTLS13 crypto/tls.defaultCipherSuitesTLS13
var defaultCipherSuitesTLS13 []uint16

//go:linkname defaultCipherSuitesTLS13NoAES crypto/tls.defaultCipherSuitesTLS13NoAES
var defaultCipherSuitesTLS13NoAES []uint16

// what a test server saw of one request
type receivedRequest struct {
	Path        string
	Version     uint16
	CipherSuite uint16
}

// an HTTPS server with eproxy's RSA certificate that answers every request with its path; MaxVersion pins TLS 1.2 or allows 1.3,
// a non-empty AltSvc is sent as the Alt-Svc header of every answer; CipherSuite is the only suite of a server of a suite case, 0 for any
type httpsServer struct {
	Port        string
	MaxVersion  uint16
	AltSvc      string
	CipherSuite uint16
	requests    chan receivedRequest
}

// one suite of the Android suite cases: its IANA name, the TLS version and the certificate of assets the server has for it
type androidSuite struct {
	Name        string
	ID          uint16
	Version     uint16
	Certificate string
}

var (
	// the suites of the Android clients that decerter's record layer has: the TLS 1.3 ones, with the RSA and once with the ECDSA certificate, and the
	// TLS 1.2 ones of Conscrypt's default list, ECDHE with either certificate and RSA key exchange, AES-GCM, ChaCha20-Poly1305 and AES-CBC with SHA-1
	androidSuites = []androidSuite{
		newAndroidSuite(tls.TLS_AES_128_GCM_SHA256, "server_rsa"),
		newAndroidSuite(tls.TLS_AES_256_GCM_SHA384, "server_rsa"),
		newAndroidSuite(tls.TLS_CHACHA20_POLY1305_SHA256, "server_rsa"),
		newAndroidSuite(tls.TLS_AES_128_GCM_SHA256, "server_ecdsa"),
		newAndroidSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "server_ecdsa"),
		newAndroidSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "server_ecdsa"),
		newAndroidSuite(tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "server_ecdsa"),
		newAndroidSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "server_ecdsa"),
		newAndroidSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "server_ecdsa"),
		newAndroidSuite(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "server_rsa"),
		newAndroidSuite(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "server_rsa"),
		newAndroidSuite(tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "server_rsa"),
		newAndroidSuite(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "server_rsa"),
		newAndroidSuite(tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "server_rsa"),
		newAndroidSuite(tls.TLS_RSA_WITH_AES_128_GCM_SHA256, "server_rsa"),
		newAndroidSuite(tls.TLS_RSA_WITH_AES_256_GCM_SHA384, "server_rsa"),
		newAndroidSuite(tls.TLS_RSA_WITH_AES_128_CBC_SHA, "server_rsa"),
		newAndroidSuite(tls.TLS_RSA_WITH_AES_256_CBC_SHA, "server_rsa"),
	}
	// the suites of the Flutter and Chrome suite cases: the TLS 1.3 ones, and in TLS 1.2 AES-GCM with ECDSA, ChaCha20-Poly1305 and AES-CBC with SHA-1
	smallSuiteNames = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}
	// the ChromePublic suite case: TLS 1.2 and 1.3 with AES-128-GCM, and TLS_AES_256_GCM_SHA384
	chromiumSuiteNames = []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}
)

// a buffer two goroutines use: a server or a command writes into it, the test reads it
type lockedBuffer struct {
	mutex  *sync.Mutex
	buffer *bytes.Buffer
}

func newLockedBuffer() (locked lockedBuffer) {
	locked = lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}
	return
}

func (locked lockedBuffer) Write(data []byte) (count int, err error) {
	locked.mutex.Lock()
	defer locked.mutex.Unlock()
	count, err = locked.buffer.Write(data)
	return
}

func (locked lockedBuffer) String() (text string) {
	locked.mutex.Lock()
	defer locked.mutex.Unlock()
	text = locked.buffer.String()
	return
}

// a TLS 1.3 and a TLS 1.2 server, HTTP/1.1 only, both write the NSS key log of their sessions into keyLog; they are closed when the test ends
func startHTTPSServers(state *testing.T, keyLog io.Writer) (servers []httpsServer) {
	pair, loadErr := tls.LoadX509KeyPair(filepath.Join("..", "e2e", "assets", "server_rsa.crt"), filepath.Join("..", "e2e", "assets", "server_rsa.key"))

	if loadErr != nil {
		state.Fatalf("Could not load the server certificate, error: %s", loadErr.Error())
	}

	for _, maxVersion := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		servers = append(servers, startHTTPSServer(state, pair, maxVersion, keyLog))
	}

	return
}

func startHTTPSServer(state *testing.T, pair tls.Certificate, maxVersion uint16, keyLog io.Writer) (server httpsServer) {
	server = startHTTPSServerAt(state, pair, maxVersion, keyLog, listenAddress, "")
	return
}

// startHTTPSServer on address with an Alt-Svc header, empty is none
func startHTTPSServerAt(state *testing.T, pair tls.Certificate, maxVersion uint16, keyLog io.Writer, address string, altSvc string) (server httpsServer) {
	listener, listenErr := net.Listen("tcp", address)

	if listenErr != nil {
		state.Fatalf("Could not listen for the https server, error: %s", listenErr.Error())
	}

	_, port, splitErr := net.SplitHostPort(listener.Addr().String())

	if splitErr != nil {
		state.Fatalf("Could not read the port of the https server, error: %s", splitErr.Error())
	}

	server = httpsServer{Port: port, MaxVersion: maxVersion, AltSvc: altSvc, CipherSuite: 0, requests: make(chan receivedRequest, 16)}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   maxVersion,
		NextProtos:   []string{"http/1.1"},
		KeyLogWriter: keyLog,
	}
	serveHTTPS(state, server, listener, tlsConfig)
	return
}

// a server pinned to the version and suite, with the certificate of the suite; a TLS 1.3 suite becomes the only one of every Go server in the test
// process until the test ends
func startSuiteServer(state *testing.T, suite androidSuite) (server httpsServer) {
	pair, loadErr := tls.LoadX509KeyPair(filepath.Join("..", "e2e", "assets", suite.Certificate+".crt"), filepath.Join("..", "e2e", "assets", suite.Certificate+".key"))

	if loadErr != nil {
		state.Fatalf("Could not load the server certificate, error: %s", loadErr.Error())
	}

	listener, listenErr := net.Listen("tcp", listenAddress)

	if listenErr != nil {
		state.Fatalf("Could not listen for the https server, error: %s", listenErr.Error())
	}

	_, port, splitErr := net.SplitHostPort(listener.Addr().String())

	if splitErr != nil {
		state.Fatalf("Could not read the port of the https server, error: %s", splitErr.Error())
	}

	server = httpsServer{Port: port, MaxVersion: suite.Version, AltSvc: "", CipherSuite: suite.ID, requests: make(chan receivedRequest, 16)}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   suite.Version,
		MaxVersion:   suite.Version,
		NextProtos:   []string{"http/1.1"},
	}

	if suite.Version == tls.VersionTLS12 {
		tlsConfig.CipherSuites = []uint16{suite.ID}
	} else {
		defaultSuites, defaultSuitesNoAES := defaultCipherSuitesTLS13, defaultCipherSuitesTLS13NoAES
		defaultCipherSuitesTLS13, defaultCipherSuitesTLS13NoAES = []uint16{suite.ID}, []uint16{suite.ID}

		state.Cleanup(func() {
			defaultCipherSuitesTLS13, defaultCipherSuitesTLS13NoAES = defaultSuites, defaultSuitesNoAES
		})
	}

	serveHTTPS(state, server, listener, tlsConfig)
	return
}

// serve HTTP/1.1 over TLS on the listener until the test ends
func serveHTTPS(state *testing.T, server httpsServer, listener net.Listener, tlsConfig *tls.Config) {
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	httpServer := &http.Server{
		Handler:   http.HandlerFunc(server.handle),
		Protocols: protocols,
	}
	serveErrChannel := make(chan error, 1)

	// https server
	go func() {
		serveErrChannel <- httpServer.Serve(tls.NewListener(listener, tlsConfig))
	}()

	state.Cleanup(func() {
		closeErr := httpServer.Close()
		serveErr := <-serveErrChannel

		if !errors.Is(serveErr, http.ErrServerClosed) {
			closeErr = errors.Join(closeErr, serveErr)
		}

		if closeErr != nil {
			state.Errorf("Could not close the https server, error: %s", closeErr.Error())
		}
	})
}

// the request is recorded before the answer is written, so it is there once the client has the body
func (server httpsServer) handle(writer http.ResponseWriter, request *http.Request) {
	received := receivedRequest{Path: request.URL.Path, Version: 0, CipherSuite: 0}

	if request.TLS != nil {
		received.Version = request.TLS.Version
		received.CipherSuite = request.TLS.CipherSuite
	}

	select {
	case server.requests <- received:
	default:
	}

	if server.AltSvc != "" {
		writer.Header().Set("Alt-Svc", server.AltSvc)
	}

	answer := request.URL.Path

	// the page of the Chrome suite case
	if answer == chromePagePath {
		writer.Header().Set("Content-Type", "text/html")
		answer = `<!doctype html><html><body><img src="` + chromeImagePath + `"></body></html>`
	}

	_, err := writer.Write([]byte(answer))

	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

// the one request the server got since the last call, an error when there was none
func (server httpsServer) received() (request receivedRequest, err error) {
	select {
	case request = <-server.requests:
	default:
		err = fmt.Errorf("https server on port %s received no request", server.Port)
	}

	return
}

// the request is what the server of a suite case has to see: path, its version and, for a pinned server, its suite
func (server httpsServer) check(request receivedRequest, path string) (err error) {
	if (request.Path != path) || (request.Version != server.MaxVersion) || ((server.CipherSuite != 0) && (request.CipherSuite != server.CipherSuite)) {
		err = fmt.Errorf("the server on port %s should receive %s over %s with %s, request: %s over %s with %s", server.Port, path, tls.VersionName(server.MaxVersion), suiteName(server.CipherSuite), request.Path, tls.VersionName(request.Version), suiteName(request.CipherSuite))
	}

	return
}

// the IANA name of a suite, any for 0
func suiteName(id uint16) (name string) {
	name = "any suite"

	if id != 0 {
		name = tls.CipherSuiteName(id)
	}

	return
}

// the suites of androidSuites with the names, the RSA one of a name both certificates have; the test stops at a name the table does not have
func suitesOf(state *testing.T, names ...string) (suites []androidSuite) {
	for _, name := range names {
		index := slices.IndexFunc(androidSuites, func(suite androidSuite) (isSuite bool) {
			isSuite = (suite.Name == name)
			return
		})

		if index < 0 {
			state.Fatalf("No suite %s in the Android suite table", name)
		}

		suites = append(suites, androidSuites[index])
	}

	return
}

// a suite of the table: its IANA name from crypto/tls, TLS 1.2 for a suite with a key exchange in its name
func newAndroidSuite(id uint16, certificate string) (suite androidSuite) {
	suite = androidSuite{Name: tls.CipherSuiteName(id), ID: id, Version: tls.VersionTLS13, Certificate: certificate}

	if strings.Contains(suite.Name, "_WITH_") {
		suite.Version = tls.VersionTLS12
	}

	return
}

// the URL the device uses for path on this server
func (server httpsServer) url(path string) (address string) {
	address = "https://" + net.JoinHostPort(hostAddress, server.Port) + path
	return
}

// a TCP and a UDP echo server: each answers a line with echoPrefix and the line; they are closed when the test ends
func startEchoServers(state *testing.T) (tcpPort string, udpPort string) {
	listener, listenErr := net.Listen("tcp", listenAddress)

	if listenErr != nil {
		state.Fatalf("Could not listen for the tcp echo server, error: %s", listenErr.Error())
	}

	connection, packetErr := net.ListenPacket("udp", listenAddress)

	if packetErr != nil {
		state.Fatalf("Could not listen for the udp echo server, error: %s", packetErr.Error())
	}

	_, tcpPort, tcpErr := net.SplitHostPort(listener.Addr().String())
	_, udpPort, udpErr := net.SplitHostPort(connection.LocalAddr().String())

	if err := errors.Join(tcpErr, udpErr); err != nil {
		state.Fatalf("Could not read the ports of the echo servers, error: %s", err.Error())
	}

	waitGroup := &sync.WaitGroup{}

	// tcp echo server
	waitGroup.Go(func() {
		serveTCPEcho(state, listener)
	})

	// udp echo server
	waitGroup.Go(func() {
		serveUDPEcho(state, connection)
	})

	state.Cleanup(func() {
		closeErr := errors.Join(listener.Close(), connection.Close())
		waitGroup.Wait()

		if closeErr != nil {
			state.Errorf("Could not close the echo servers, error: %s", closeErr.Error())
		}
	})

	return
}

// one line per connection, until the listener is closed
func serveTCPEcho(state *testing.T, listener net.Listener) {
	for {
		connection, acceptErr := listener.Accept()

		if errors.Is(acceptErr, net.ErrClosed) {
			return
		}

		if acceptErr != nil {
			state.Errorf("Could not accept on the tcp echo server, error: %s", acceptErr.Error())
			return
		}

		line, readErr := bufio.NewReader(connection).ReadString('\n')

		if readErr == nil {
			_, readErr = io.WriteString(connection, echoPrefix+line)
		}

		if err := errors.Join(readErr, connection.Close()); err != nil {
			state.Errorf("Could not answer on the tcp echo server, error: %s", err.Error())
		}
	}
}

// one answer per datagram, until the socket is closed
func serveUDPEcho(state *testing.T, connection net.PacketConn) {
	buffer := make([]byte, 2048)

	for {
		count, source, readErr := connection.ReadFrom(buffer)

		if errors.Is(readErr, net.ErrClosed) {
			return
		}

		if readErr != nil {
			state.Errorf("Could not read on the udp echo server, error: %s", readErr.Error())
			return
		}

		_, writeErr := connection.WriteTo(append([]byte(echoPrefix), buffer[:count]...), source)

		if writeErr != nil {
			state.Errorf("Could not answer on the udp echo server, error: %s", writeErr.Error())
		}
	}
}
