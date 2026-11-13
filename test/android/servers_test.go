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
	"sync"
	"testing"
)

const (
	// the servers listen on the host's loopback only, the emulator reaches them as 10.0.2.2 through its user mode network
	listenAddress string = "127.0.0.1:0"
	echoPrefix    string = "echo "
)

// what a test server saw of one request
type receivedRequest struct {
	Path    string
	Version uint16
}

// an HTTPS server with eproxy's RSA certificate that answers every request with its path; MaxVersion pins TLS 1.2 or allows 1.3
type httpsServer struct {
	Port       string
	MaxVersion uint16
	requests   chan receivedRequest
}

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
	listener, listenErr := net.Listen("tcp", listenAddress)

	if listenErr != nil {
		state.Fatalf("Could not listen for the https server, error: %s", listenErr.Error())
	}

	_, port, splitErr := net.SplitHostPort(listener.Addr().String())

	if splitErr != nil {
		state.Fatalf("Could not read the port of the https server, error: %s", splitErr.Error())
	}

	server = httpsServer{Port: port, MaxVersion: maxVersion, requests: make(chan receivedRequest, 16)}
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	httpServer := &http.Server{
		Handler:   http.HandlerFunc(server.handle),
		Protocols: protocols,
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   maxVersion,
		NextProtos:   []string{"http/1.1"},
		KeyLogWriter: keyLog,
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

	return
}

// the request is recorded before the answer is written, so it is there once the client has the body
func (server httpsServer) handle(writer http.ResponseWriter, request *http.Request) {
	received := receivedRequest{Path: request.URL.Path, Version: 0}

	if request.TLS != nil {
		received.Version = request.TLS.Version
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
func (server httpsServer) received() (request receivedRequest, err error) {
	select {
	case request = <-server.requests:
	default:
		err = fmt.Errorf("https server on port %s received no request", server.Port)
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
