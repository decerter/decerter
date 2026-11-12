// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord_test

import (
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/decerter/decerter/internal/tlsrecord"
)

// Test if tlsrecord.ReadClientHello returns with the expected output.
func TestReadClientHelloPositive(state *testing.T) {
	positiveCases := []struct {
		MaxVersion uint16
		ServerName string
		Protocols  []string
		Expected   tlsrecord.Hello
	}{
		{MaxVersion: tls.VersionTLS13, ServerName: "example.com", Protocols: []string{"h2", "http/1.1"}, Expected: tlsrecord.Hello{Version: tlsrecord.VersionTLS13, ServerName: "example.com", Protocols: []string{"h2", "http/1.1"}}},
		{MaxVersion: tls.VersionTLS12, ServerName: "", Protocols: nil, Expected: tlsrecord.Hello{Version: tlsrecord.VersionTLS12, ServerName: "", Protocols: nil}},
	}

	for _, positive := range positiveCases {
		clientHello, err := goClientHello(&tls.Config{MaxVersion: positive.MaxVersion, ServerName: positive.ServerName, NextProtos: positive.Protocols, InsecureSkipVerify: true})

		if err != nil {
			state.Fatalf("Test of tlsrecord.ReadClientHello failed, cannot make a client hello, error: %s", err.Error())
		}

		// a ClientHello split over two segments is incomplete after the first
		_, isComplete, partErr := tlsrecord.ReadClientHello(clientHello[:len(clientHello)/2])

		if isComplete || (partErr != nil) {
			state.Errorf("Test of tlsrecord.ReadClientHello function failed, half a client hello should be incomplete without an error, complete: %v, error: %v", isComplete, partErr)
			return
		}

		hello, isComplete, err := tlsrecord.ReadClientHello(clientHello)

		if (err != nil) || !isComplete || !reflect.DeepEqual(hello, positive.Expected) {
			state.Errorf("Test of tlsrecord.ReadClientHello function failed, hello should be %+v, hello: %+v, complete: %v, error: %v", positive.Expected, hello, isComplete, err)
			return
		}
	}
}

// Test if tlsrecord.ReadClientHello returns with the expected errors.
func TestReadClientHelloNegative(state *testing.T) {
	negativeCases := [][]byte{
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{0x17, 0x03, 0x03, 0x00, 0x01, 0x00},
		{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
	}

	for _, negative := range negativeCases {
		_, isComplete, err := tlsrecord.ReadClientHello(negative)

		if isComplete || !errors.Is(err, tlsrecord.ErrUnexpectedRecord) {
			state.Errorf("Test of tlsrecord.ReadClientHello function failed, input: %q, error should be %v, error: %v", negative, tlsrecord.ErrUnexpectedRecord, err)
			return
		}
	}
}

// the first flight of a crypto/tls client, the handshake is left unfinished
func goClientHello(config *tls.Config) (clientHello []byte, err error) {
	clientSide, serverSide := net.Pipe()
	client := tls.Client(clientSide, config)
	handshakeErrChannel := make(chan error, 1)

	// client handshake, ends when the pipe is closed
	go func() {
		handshakeErrChannel <- client.Handshake()
	}()

	buffer := make([]byte, 16384)
	readCount, readErr := serverSide.Read(buffer)
	err = errors.Join(readErr, serverSide.Close(), clientSide.Close())
	<-handshakeErrChannel
	clientHello = buffer[:readCount]
	return
}
