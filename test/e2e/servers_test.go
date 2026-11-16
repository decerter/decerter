// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	// s_server prints this once it listens
	opensslServerReady string = "ACCEPT"
	// how often the output of an openssl peer is looked at
	opensslPollInterval time.Duration = 20 * time.Millisecond
)

// what a test server serves: plain HTTP when Certificate is nil, TLS pinned to Version and CipherSuite when they are set
// the server picks HTTP/2 through ALPN when HTTP2 is true, or with prior knowledge on plain HTTP; KeyLog gets the server's NSS key log lines, nil is none
// Frames counts the HTTP/2 frames of a plain server, nil counts none; Host is the loopback address it listens on, empty is 127.0.0.1
type serverConfig struct {
	Certificate *certificate
	Version     uint16
	CipherSuite uint16
	HTTP2       bool
	KeyLog      io.Writer
	Frames      *frameCounts
	Host        string
}

// what a test server saw of one request; Body and ContentLength only for the paths of the HTTP layer tests, the other tests compare the rest
// Grown is the length of the X-Decerter-Grown header field the split rule adds
type receivedRequest struct {
	Path          string
	Proto         string
	Version       uint16
	CipherSuite   uint16
	Body          string
	ContentLength int64
	Grown         int
}

type testServer struct {
	URL      string
	requests chan receivedRequest
}

// start a server on loopback that answers every request with the path it received, it is closed when the test ends
func startServer(state *testing.T, config serverConfig) (server testServer) {
	host := "127.0.0.1"

	if config.Host != "" {
		host = config.Host
	}

	listener, listenErr := net.Listen("tcp", net.JoinHostPort(host, "0"))

	if listenErr != nil {
		state.Fatalf("Could not listen for the test server, error: %s", listenErr.Error())
	}

	server = testServer{
		URL:      fmt.Sprintf("http://%s/", listener.Addr().String()),
		requests: make(chan receivedRequest, 16),
	}
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	httpServer := &http.Server{
		Handler:   http.HandlerFunc(server.handle),
		Protocols: protocols,
		// the cipher-suite matrix runs HTTP/2 over the CBC and RSA key exchange suites too, as eproxy's server allowed
		// a client that allows a larger HPACK table gets one, so the table size changes during a test
		HTTP2: &http.HTTP2Config{PermitProhibitedCipherSuites: true, MaxEncoderHeaderTableSize: 65536},
	}

	if config.Certificate != nil {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{config.Certificate.Pair},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"http/1.1"},
			KeyLogWriter: config.KeyLog,
		}

		if config.Version != 0 {
			tlsConfig.MinVersion = config.Version
			tlsConfig.MaxVersion = config.Version
		}

		// Go has no setting for the TLS 1.3 suites, curl pins those and the server checks what was negotiated
		if config.CipherSuite != 0 {
			tlsConfig.CipherSuites = []uint16{config.CipherSuite}
		}

		if config.HTTP2 {
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}
			protocols.SetHTTP2(true)
		}

		server.URL = fmt.Sprintf("https://%s/", listener.Addr().String())
		listener = tls.NewListener(listener, tlsConfig)
	} else if config.HTTP2 {
		protocols.SetUnencryptedHTTP2(true)

		if config.Frames != nil {
			listener = frameListener{Listener: listener, counts: config.Frames}
		}
	}

	serveErrChannel := make(chan error, 1)

	// test server
	go func() {
		serveErrChannel <- httpServer.Serve(listener)
	}()

	state.Cleanup(func() {
		closeErr := httpServer.Close()
		serveErr := <-serveErrChannel

		if !errors.Is(serveErr, http.ErrServerClosed) {
			closeErr = errors.Join(closeErr, serveErr)
		}

		if closeErr != nil {
			state.Errorf("Could not close test server, error: %s", closeErr.Error())
		}
	})

	return
}

// the request is recorded before the answer is written, so it is there once curl has the body
// /echo answers with the Content-Length and the body it got, /chunked with a chunked body whose word "world" is cut over two chunks, any other path with the path
func (server testServer) handle(writer http.ResponseWriter, request *http.Request) {
	received := receivedRequest{
		Path:          request.URL.Path,
		Proto:         request.Proto,
		Version:       0,
		CipherSuite:   0,
		Body:          "",
		ContentLength: 0,
		Grown:         len(request.Header.Get(grownHeaderName)),
	}

	if request.TLS != nil {
		received.Version = request.TLS.Version
		received.CipherSuite = request.TLS.CipherSuite
	}

	answer := []string{request.URL.Path}

	switch request.URL.Path {
	case "/echo":
		body, readErr := io.ReadAll(request.Body)

		if readErr != nil {
			http.Error(writer, readErr.Error(), http.StatusBadRequest)
			return
		}

		received.Body = string(body)
		received.ContentLength = request.ContentLength
		answer = []string{fmt.Sprintf("len=%d body=%s", request.ContentLength, body)}
	case "/chunked":
		answer = []string{"hello wor", "ld, chunked!"}
	case "/large":
		answer = largeBody()
	case grpcPath:
		server.answerGRPC(writer, request, received)
		return
	case grpcProtoPath:
		server.answerGRPCProto(writer, request, received)
		return
	default:
	}

	select {
	case server.requests <- received:
	default:
	}

	// a piece after the first is flushed on its own, so a response of more than one piece is chunked, one of a single piece has a Content-Length
	for index, piece := range answer {
		_, err := writer.Write([]byte(piece))

		if (err == nil) && (index < len(answer)-1) {
			err = http.NewResponseController(writer).Flush()
		}

		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// the one request the server got since the last call, an error when there was none
func (server testServer) received() (request receivedRequest, err error) {
	select {
	case request = <-server.requests:
	default:
		err = fmt.Errorf("server %s received no request", server.URL)
	}

	return
}

// a buffer two goroutines use: the command writes into it, the test reads it
type lockedBuffer struct {
	mutex  *sync.Mutex
	buffer *bytes.Buffer
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

// openssl s_server or s_client: output is everything it printed, the lines of its peer among them, and its stdin stays open until finish, both leave
// at the end of their input otherwise; Port is the port a server listens on
type opensslPeer struct {
	Port    string
	output  *lockedBuffer
	stdin   io.WriteCloser
	command *exec.Cmd
	exit    *peerExit
}

// the exit of a peer: done is closed once err is set
type peerExit struct {
	done chan struct{}
	err  error
}

// a session of the DTLS tests on 127.0.0.1 with eproxy's RSA certificate
func startDTLSServer(state *testing.T) (server opensslPeer) {
	server = startOpenSSLServer(state, true, "server_rsa", 1)
	return
}

// openssl s_server on a free loopback port for sessions connections, DTLS 1.2 when isDTLS, with the certificate and key of assets named certificate;
// it runs as root, so its socket is never redirected, and it is killed when the test ends; arguments go after the others
func startOpenSSLServer(state *testing.T, isDTLS bool, certificate string, sessions int, arguments ...string) (server opensslPeer) {
	port, portErr := freePort(isDTLS)

	if portErr != nil {
		state.Fatalf("Could not find a free port for the openssl server, error: %s", portErr.Error())
	}

	certificatePath, certificateErr := filepath.Abs(filepath.Join("assets", certificate+".crt"))
	keyPath, keyErr := filepath.Abs(filepath.Join("assets", certificate+".key"))

	if err := errors.Join(certificateErr, keyErr); err != nil {
		state.Fatalf("Could not find the server certificate, error: %s", err.Error())
	}

	serverArguments := []string{"s_server", "-accept", net.JoinHostPort(destinationPrefix.Addr().String(), port), "-cert", certificatePath, "-key", keyPath, "-naccept", strconv.Itoa(sessions)}

	if isDTLS {
		serverArguments = append(serverArguments, "-dtls1_2")
	}

	command := exec.CommandContext(state.Context(), "openssl", append(serverArguments, arguments...)...)
	server = startPeer(state, command, "server")
	server.Port = port
	_, isListening := server.waitFor(opensslServerReady, commandTimeout)

	if !isListening {
		state.Fatalf("Could not start the openssl server, output: %s", server.output.String())
	}

	return
}

// openssl s_client as runAs against the server, DTLS 1.2 when isDTLS; it is killed when the test ends, arguments go after the others
func startOpenSSLClient(state *testing.T, runAs account, server opensslPeer, isDTLS bool, arguments ...string) (client opensslPeer) {
	clientArguments := []string{"s_client", "-connect", net.JoinHostPort(destinationPrefix.Addr().String(), server.Port)}

	if isDTLS {
		clientArguments = append(clientArguments, "-dtls1_2")
	}

	command := exec.CommandContext(state.Context(), "openssl", append(clientArguments, arguments...)...)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: runAs.UID, Gid: runAs.GID, Groups: []uint32{}, NoSetGroups: false}}
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	client = startPeer(state, command, "client")
	return
}

// start the command with its stdin open and its output in a buffer, a cleanup kills it
func startPeer(state *testing.T, command *exec.Cmd, name string) (peer opensslPeer) {
	peer = opensslPeer{Port: "", output: &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}, stdin: nil, command: command, exit: &peerExit{done: make(chan struct{}), err: nil}}
	command.WaitDelay = time.Second
	command.Stdout = peer.output
	command.Stderr = peer.output
	stdin, stdinErr := command.StdinPipe()

	if stdinErr != nil {
		state.Fatalf("Could not open the stdin of the openssl %s, error: %s", name, stdinErr.Error())
	}

	peer.stdin = stdin
	startErr := command.Start()

	if startErr != nil {
		state.Fatalf("Could not start the openssl %s, error: %s", name, startErr.Error())
	}

	// openssl waiter, finish and the cleanup wait for its exit
	go func() {
		peer.exit.err = command.Wait()
		close(peer.exit.done)
	}()

	state.Cleanup(func() {
		// the peer is done or not needed any more, the context of the test is cancelled after the cleanups
		killErr := command.Process.Kill()

		if (killErr != nil) && !errors.Is(killErr, os.ErrProcessDone) {
			state.Errorf("Could not stop the openssl %s, error: %s", name, killErr.Error())
		}

		// the exit status of a killed peer says nothing
		select {
		case <-peer.exit.done:
		case <-time.After(commandTimeout):
		}

		if closeErr := stdin.Close(); (closeErr != nil) && !errors.Is(closeErr, os.ErrClosed) {
			state.Errorf("Could not close the stdin of the openssl %s, error: %s", name, closeErr.Error())
		}
	})

	return
}

// write a line to the peer's stdin
func (peer opensslPeer) send(line string) (err error) {
	_, err = io.WriteString(peer.stdin, line+"\n")
	return
}

// close the stdin, which ends the session, and wait for the exit of the peer
func (peer opensslPeer) finish() (err error) {
	// a server of one session leaves on its own, its stdin is closed then
	if closeErr := peer.stdin.Close(); !errors.Is(closeErr, os.ErrClosed) {
		err = closeErr
	}

	select {
	case <-peer.exit.done:
		err = errors.Join(err, peer.exit.err)
	case <-time.After(commandTimeout):
		err = errors.Join(err, fmt.Errorf("openssl did not leave in %s", commandTimeout))
	}

	if err != nil {
		err = fmt.Errorf("openssl %s: %w: %s", strings.Join(peer.command.Args[1:], " "), err, strings.TrimSpace(peer.output.String()))
	}

	return
}

// wait until the peer printed text, output is everything it printed so far
func (peer opensslPeer) waitFor(text string, timeout time.Duration) (output string, found bool) {
	deadline := time.Now().Add(timeout)

	for {
		output = peer.output.String()
		found = strings.Contains(output, text)

		if found || time.Now().After(deadline) {
			return
		}

		time.Sleep(opensslPollInterval)
	}
}

// wait until the peer printed text count times
func (peer opensslPeer) waitCount(text string, count int, timeout time.Duration) (isFound bool) {
	deadline := time.Now().Add(timeout)

	for {
		isFound = (strings.Count(peer.output.String(), text) >= count)

		if isFound || time.Now().After(deadline) {
			return
		}

		time.Sleep(opensslPollInterval)
	}
}

// a port of loopback no udp socket, or no tcp socket, has now, the server binds it right after
func freePort(isUDP bool) (port string, err error) {
	address := net.JoinHostPort(destinationPrefix.Addr().String(), "0")

	if !isUDP {
		listener, listenErr := net.Listen("tcp", address)

		if err = listenErr; err != nil {
			return
		}

		_, port, err = net.SplitHostPort(listener.Addr().String())
		err = errors.Join(err, listener.Close())
		return
	}

	connection, listenErr := net.ListenPacket("udp", address)

	if err = listenErr; err != nil {
		return
	}

	_, port, err = net.SplitHostPort(connection.LocalAddr().String())
	err = errors.Join(err, connection.Close())
	return
}
