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
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// s_server prints this once it listens
	dtlsServerReady string = "ACCEPT"
	// how often the output of the dtls server is looked at
	dtlsPollInterval time.Duration = 20 * time.Millisecond
)

// what a test server serves: plain HTTP when Certificate is nil, TLS pinned to Version and CipherSuite when they are set
// the server picks HTTP/2 through ALPN when HTTP2 is true, or with prior knowledge on plain HTTP; KeyLog gets the server's NSS key log lines, nil is none
type serverConfig struct {
	Certificate *certificate
	Version     uint16
	CipherSuite uint16
	HTTP2       bool
	KeyLog      io.Writer
}

// what a test server saw of one request; Body and ContentLength only for the paths of the HTTP layer tests, the other tests compare the rest
type receivedRequest struct {
	Path          string
	Proto         string
	Version       uint16
	CipherSuite   uint16
	Body          string
	ContentLength int64
}

type testServer struct {
	URL      string
	requests chan receivedRequest
}

// start a server on loopback that answers every request with the path it received, it is closed when the test ends
func startServer(state *testing.T, config serverConfig) (server testServer) {
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")

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
		HTTP2: &http.HTTP2Config{PermitProhibitedCipherSuites: true},
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

// openssl s_server -dtls1_2 on a free loopback port, run as root so its socket is never redirected; output is what it printed, the lines a client sent among them
type dtlsServer struct {
	Port   string
	output *lockedBuffer
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

// start the server for one session with eproxy's RSA certificate and wait until it listens, it is killed when the test ends
// its stdin stays open, s_server leaves at the end of its input otherwise
func startDTLSServer(state *testing.T) (server dtlsServer) {
	port, portErr := freeUDPPort()

	if portErr != nil {
		state.Fatalf("Could not find a free udp port for the dtls server, error: %s", portErr.Error())
	}

	server = dtlsServer{
		Port:   port,
		output: &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}},
	}
	certificatePath, certificateErr := filepath.Abs(filepath.Join("assets", "server_rsa.crt"))
	keyPath, keyErr := filepath.Abs(filepath.Join("assets", "server_rsa.key"))

	if err := errors.Join(certificateErr, keyErr); err != nil {
		state.Fatalf("Could not find the server certificate, error: %s", err.Error())
	}

	command := exec.CommandContext(state.Context(), "openssl", "s_server", "-dtls1_2", "-accept", net.JoinHostPort(destinationPrefix.Addr().String(), port), "-cert", certificatePath, "-key", keyPath, "-naccept", "1")
	command.WaitDelay = time.Second
	command.Stdout = server.output
	command.Stderr = server.output
	stdin, stdinErr := command.StdinPipe()

	if stdinErr != nil {
		state.Fatalf("Could not open the stdin of the dtls server, error: %s", stdinErr.Error())
	}

	startErr := command.Start()

	if startErr != nil {
		state.Fatalf("Could not start the dtls server, error: %s", startErr.Error())
	}

	state.Cleanup(func() {
		// the server is done or not needed any more, the context of the test is cancelled after the cleanups
		killErr := command.Process.Kill()

		if (killErr != nil) && !errors.Is(killErr, os.ErrProcessDone) {
			state.Errorf("Could not stop the dtls server, error: %s", killErr.Error())
		}

		// the exit status of a killed server says nothing
		_ = command.Wait()

		if closeErr := stdin.Close(); (closeErr != nil) && !errors.Is(closeErr, os.ErrClosed) {
			state.Errorf("Could not close the stdin of the dtls server, error: %s", closeErr.Error())
		}
	})

	_, isListening := server.waitFor(dtlsServerReady, commandTimeout)

	if !isListening {
		state.Fatalf("Could not start the dtls server, output: %s", server.output.String())
	}

	return
}

// wait until the server printed text, output is everything it printed so far
func (server dtlsServer) waitFor(text string, timeout time.Duration) (output string, found bool) {
	deadline := time.Now().Add(timeout)

	for {
		output = server.output.String()
		found = strings.Contains(output, text)

		if found || time.Now().After(deadline) {
			return
		}

		time.Sleep(dtlsPollInterval)
	}
}

// a port of loopback no udp socket has now, the server binds it right after
func freeUDPPort() (port string, err error) {
	connection, listenErr := net.ListenPacket("udp", net.JoinHostPort(destinationPrefix.Addr().String(), "0"))

	if err = listenErr; err != nil {
		return
	}

	_, port, err = net.SplitHostPort(connection.LocalAddr().String())
	err = errors.Join(err, connection.Close())
	return
}
