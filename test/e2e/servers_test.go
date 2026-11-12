// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
)

// what a test server serves: plain HTTP when Certificate is nil, TLS pinned to Version and CipherSuite when they are set
// the server picks HTTP/2 through ALPN when HTTP2 is true, or with prior knowledge on plain HTTP
type serverConfig struct {
	Certificate *certificate
	Version     uint16
	CipherSuite uint16
	HTTP2       bool
}

// what a test server saw of one request
type receivedRequest struct {
	Path        string
	Proto       string
	Version     uint16
	CipherSuite uint16
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
func (server testServer) handle(writer http.ResponseWriter, request *http.Request) {
	received := receivedRequest{
		Path:        request.URL.Path,
		Proto:       request.Proto,
		Version:     0,
		CipherSuite: 0,
	}

	if request.TLS != nil {
		received.Version = request.TLS.Version
		received.CipherSuite = request.TLS.CipherSuite
	}

	select {
	case server.requests <- received:
	default:
	}

	_, err := writer.Write([]byte(request.URL.Path))

	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
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
