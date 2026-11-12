// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord_test

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
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

// Test if tlsrecord.ReadDTLSClientHello returns with the expected output.
func TestReadDTLSClientHelloPositive(state *testing.T) {
	positiveCases := []struct {
		Datagram   []byte
		IsComplete bool
		Expected   tlsrecord.Hello
	}{
		{Datagram: dtlsClientHello("example.com", []string{"coap"}, 0), IsComplete: true, Expected: tlsrecord.Hello{Version: tlsrecord.VersionDTLS12, ServerName: "example.com", Protocols: []string{"coap"}}},
		{Datagram: dtlsClientHello("", nil, 0), IsComplete: true, Expected: tlsrecord.Hello{Version: tlsrecord.VersionDTLS12, ServerName: "", Protocols: nil}},
		// the first fragment of a ClientHello split over two datagrams
		{Datagram: dtlsClientHello("example.com", nil, 20), IsComplete: false, Expected: tlsrecord.Hello{}},
	}

	for _, positive := range positiveCases {
		hello, isComplete, err := tlsrecord.ReadDTLSClientHello(positive.Datagram)

		if (err != nil) || (isComplete != positive.IsComplete) || !reflect.DeepEqual(hello, positive.Expected) {
			state.Errorf("Test of tlsrecord.ReadDTLSClientHello function failed, hello should be %+v complete %v, hello: %+v, complete: %v, error: %v", positive.Expected, positive.IsComplete, hello, isComplete, err)
			return
		}
	}
}

// Test if tlsrecord.ReadDTLSClientHello returns with the expected errors.
func TestReadDTLSClientHelloNegative(state *testing.T) {
	clientHello := dtlsClientHello("example.com", nil, 0)
	// a record that ends inside the handshake header, and a ClientHello whose session id runs past its end
	shortRecord := append(bytes.Clone(clientHello[:13]), clientHello[13:20]...)
	binary.BigEndian.PutUint16(shortRecord[11:13], 7)
	brokenBody := bytes.Clone(clientHello)
	brokenBody[13+12+34] = 0xff
	negativeCases := []struct {
		Datagram []byte
		Err      error
	}{
		{Datagram: []byte("not a datagram of dtls"), Err: tlsrecord.ErrUnexpectedRecord},
		{Datagram: clientHello[:13], Err: tlsrecord.ErrUnexpectedRecord},
		{Datagram: shortRecord, Err: tlsrecord.ErrMalformedHandshake},
		{Datagram: brokenBody, Err: tlsrecord.ErrMalformedHandshake},
	}

	for _, negative := range negativeCases {
		_, isComplete, err := tlsrecord.ReadDTLSClientHello(negative.Datagram)

		if isComplete || !errors.Is(err, negative.Err) {
			state.Errorf("Test of tlsrecord.ReadDTLSClientHello function failed, input: %x, error should be %v, error: %v", negative.Datagram, negative.Err, err)
			return
		}
	}
}

// a DTLS 1.2 ClientHello in one record of epoch 0 (RFC 6347 section 4.2.2), fragmentLength above 0 sends only the start of the body
func dtlsClientHello(serverName string, protocols []string, fragmentLength int) (datagram []byte) {
	extensions := []byte{}

	if serverName != "" {
		name := append([]byte{0, byte(len(serverName))}, serverName...)
		list := append([]byte{0, byte(len(name) + 1), 0}, name...)
		extensions = append(extensions, 0, 0, 0, byte(len(list)))
		extensions = append(extensions, list...)
	}

	if len(protocols) != 0 {
		list := []byte{}

		for _, protocol := range protocols {
			list = append(list, byte(len(protocol)))
			list = append(list, protocol...)
		}

		extensions = append(extensions, 0, 16, 0, byte(len(list)+2), 0, byte(len(list)))
		extensions = append(extensions, list...)
	}

	// client_version, random, empty session id and cookie, one cipher suite, null compression, extensions
	body := append([]byte{0xfe, 0xfd}, bytes.Repeat([]byte{0x42}, 32)...)
	body = append(body, 0, 0, 0, 2, 0xc0, 0x2b, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	fragment := body

	if fragmentLength > 0 {
		fragment = body[:fragmentLength]
	}

	// message type, length, message sequence, fragment offset, fragment length
	message := []byte{1, 0, byte(len(body) >> 8), byte(len(body)), 0, 0, 0, 0, 0, 0, byte(len(fragment) >> 8), byte(len(fragment))}
	message = append(message, fragment...)
	// content type, version, epoch, sequence number, length
	datagram = []byte{22, 0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(len(message)))
	datagram = append(datagram, message...)
	return
}
