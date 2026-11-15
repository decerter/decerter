// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"testing"
)

// Test if tlsrecord.parseClientHello returns with the expected output.
func TestParseClientHelloPositive(state *testing.T) {
	random := [randomLength]byte(bytes.Repeat([]byte{0x42}, randomLength))
	positiveCases := []struct {
		Name       string
		Version    uint16
		HasCookie  bool
		Extensions []byte
		Expected   clientHello
	}{
		{Name: "no extension block", Version: VersionTLS12, HasCookie: false, Extensions: nil, Expected: clientHello{random: random, version: VersionTLS12, serverName: "", protocols: nil, earlyData: false}},
		{Name: "empty extension block", Version: VersionTLS12, HasCookie: false, Extensions: []byte{}, Expected: clientHello{random: random, version: VersionTLS12, serverName: "", protocols: nil, earlyData: false}},
		{Name: "server name, protocols and versions", Version: VersionTLS12, HasCookie: false, Extensions: slices.Concat(helloExtension(extensionServerName, serverNameData(serverNameHostName, "example.com")), helloExtension(extensionALPN, protocolsData("h2", "http/1.1")), helloExtension(extensionSupportedVersions, versionsData(VersionTLS12, VersionTLS13))), Expected: clientHello{random: random, version: VersionTLS13, serverName: "example.com", protocols: []string{"h2", "http/1.1"}, earlyData: false}},
		// a name of another type is skipped and only the first host name counts
		{Name: "more than one name", Version: VersionTLS12, HasCookie: false, Extensions: helloExtension(extensionServerName, slices.Concat([]byte{0, 31}, serverNameData(1, "x")[2:], serverNameData(serverNameHostName, "first.test")[2:], serverNameData(serverNameHostName, "second.test")[2:])), Expected: clientHello{random: random, version: VersionTLS12, serverName: "first.test", protocols: nil, earlyData: false}},
		{Name: "empty name list", Version: VersionTLS12, HasCookie: false, Extensions: helloExtension(extensionServerName, []byte{0, 0}), Expected: clientHello{random: random, version: VersionTLS12, serverName: "", protocols: nil, earlyData: false}},
		{Name: "grease versions around the real ones", Version: VersionTLS12, HasCookie: false, Extensions: helloExtension(extensionSupportedVersions, versionsData(0x0a0a, VersionTLS13, VersionTLS12, 0xfafa)), Expected: clientHello{random: random, version: VersionTLS13, serverName: "", protocols: nil, earlyData: false}},
		{Name: "only a grease version", Version: VersionTLS12, HasCookie: false, Extensions: helloExtension(extensionSupportedVersions, versionsData(0x1a1a)), Expected: clientHello{random: random, version: VersionTLS12, serverName: "", protocols: nil, earlyData: false}},
		// DTLS counts down, 0xfefc is DTLS 1.3
		{Name: "dtls versions", Version: VersionDTLS12, HasCookie: true, Extensions: helloExtension(extensionSupportedVersions, versionsData(VersionDTLS12, 0xfefc, 0xfeff)), Expected: clientHello{random: random, version: 0xfefc, serverName: "", protocols: nil, earlyData: false}},
		{Name: "early data and an extension that is not read", Version: VersionTLS12, HasCookie: false, Extensions: slices.Concat(helloExtension(extensionEarlyData, nil), helloExtension(0xff01, []byte{0})), Expected: clientHello{random: random, version: VersionTLS12, serverName: "", protocols: nil, earlyData: true}},
	}

	for _, positive := range positiveCases {
		hello, err := parseClientHello(clientHelloBody(positive.Version, random, positive.HasCookie, positive.Extensions), positive.HasCookie)

		if (err != nil) || !reflect.DeepEqual(hello, positive.Expected) {
			state.Errorf("Test of tlsrecord.parseClientHello function failed, case: %s, hello should be %+v, hello: %+v, error: %v", positive.Name, positive.Expected, hello, err)
			return
		}
	}
}

// Test if tlsrecord.parseClientHello returns with the expected errors.
func TestParseClientHelloNegative(state *testing.T) {
	random := [randomLength]byte{}
	whole := clientHelloBody(VersionTLS12, random, false, nil)
	negativeCases := []struct {
		Name      string
		Body      []byte
		HasCookie bool
	}{
		{Name: "no body", Body: nil, HasCookie: false},
		{Name: "ends in the random", Body: whole[:20], HasCookie: false},
		{Name: "ends in the cipher suites", Body: whole[:len(whole)-3], HasCookie: false},
		// the cookie length of DTLS is read as the start of the cipher suites
		{Name: "dtls hello without a cookie", Body: whole, HasCookie: true},
		{Name: "extension block longer than the hello", Body: append(bytes.Clone(whole), 0, 10, 0), HasCookie: false},
		{Name: "bytes behind the extension block", Body: append(clientHelloBody(VersionTLS12, random, false, helloExtension(extensionEarlyData, nil)), 0), HasCookie: false},
		{Name: "extension header cut", Body: clientHelloBody(VersionTLS12, random, false, []byte{0, 0, 0}), HasCookie: false},
		{Name: "extension data cut", Body: clientHelloBody(VersionTLS12, random, false, []byte{0, 0, 0, 5, 1}), HasCookie: false},
		{Name: "server name list cut", Body: clientHelloBody(VersionTLS12, random, false, helloExtension(extensionServerName, []byte{0, 9, 0})), HasCookie: false},
		{Name: "bytes behind the server name list", Body: clientHelloBody(VersionTLS12, random, false, helloExtension(extensionServerName, append(serverNameData(serverNameHostName, "a"), 0))), HasCookie: false},
		{Name: "server name cut", Body: clientHelloBody(VersionTLS12, random, false, helloExtension(extensionServerName, []byte{0, 2, 0, 0})), HasCookie: false},
		{Name: "protocol list cut", Body: clientHelloBody(VersionTLS12, random, false, helloExtension(extensionALPN, []byte{0, 9, 2, 'h'})), HasCookie: false},
		{Name: "protocol name cut", Body: clientHelloBody(VersionTLS12, random, false, helloExtension(extensionALPN, []byte{0, 2, 5, 'h'})), HasCookie: false},
		{Name: "version list cut", Body: clientHelloBody(VersionTLS12, random, false, helloExtension(extensionSupportedVersions, []byte{4, 3, 4})), HasCookie: false},
		{Name: "half a version", Body: clientHelloBody(VersionTLS12, random, false, helloExtension(extensionSupportedVersions, []byte{3, 3, 4, 3})), HasCookie: false},
	}

	for _, negative := range negativeCases {
		hello, err := parseClientHello(negative.Body, negative.HasCookie)

		if !errors.Is(err, ErrMalformedHandshake) {
			state.Errorf("Test of tlsrecord.parseClientHello function failed, case: %s, error should be %v, error: %v, hello: %+v", negative.Name, ErrMalformedHandshake, err, hello)
			return
		}
	}
}

// Test if tlsrecord.parseServerHello returns with the expected output.
func TestParseServerHelloPositive(state *testing.T) {
	random := [randomLength]byte(bytes.Repeat([]byte{0x24}, randomLength))
	positiveCases := []struct {
		Name       string
		Random     [randomLength]byte
		Extensions []byte
		Expected   serverHello
	}{
		{Name: "no extension block", Random: random, Extensions: nil, Expected: serverHello{random: random, version: VersionTLS12, cipherSuite: tlsECDHERSAWithAES128CBCSHA, protocol: "", encryptThenMAC: false, helloRetryRequest: false}},
		{Name: "tls 1.3 in supported versions", Random: random, Extensions: helloExtension(extensionSupportedVersions, []byte{3, 4}), Expected: serverHello{random: random, version: VersionTLS13, cipherSuite: tlsECDHERSAWithAES128CBCSHA, protocol: "", encryptThenMAC: false, helloRetryRequest: false}},
		{Name: "protocol and encrypt-then-MAC", Random: random, Extensions: slices.Concat(helloExtension(extensionALPN, protocolsData("h2")), helloExtension(extensionEncryptThenMAC, nil), helloExtension(0xff01, []byte{0})), Expected: serverHello{random: random, version: VersionTLS12, cipherSuite: tlsECDHERSAWithAES128CBCSHA, protocol: "h2", encryptThenMAC: true, helloRetryRequest: false}},
		{Name: "hello retry request", Random: helloRetryRequestRandom, Extensions: helloExtension(extensionSupportedVersions, []byte{3, 4}), Expected: serverHello{random: helloRetryRequestRandom, version: VersionTLS13, cipherSuite: tlsECDHERSAWithAES128CBCSHA, protocol: "", encryptThenMAC: false, helloRetryRequest: true}},
	}

	for _, positive := range positiveCases {
		hello, err := parseServerHello(serverHelloBody(VersionTLS12, positive.Random, tlsECDHERSAWithAES128CBCSHA, positive.Extensions))

		if (err != nil) || (hello != positive.Expected) {
			state.Errorf("Test of tlsrecord.parseServerHello function failed, case: %s, hello should be %+v, hello: %+v, error: %v", positive.Name, positive.Expected, hello, err)
			return
		}
	}
}

// Test if tlsrecord.parseServerHello returns with the expected errors.
func TestParseServerHelloNegative(state *testing.T) {
	random := [randomLength]byte{}
	whole := serverHelloBody(VersionTLS12, random, tlsECDHERSAWithAES128CBCSHA, nil)
	negativeCases := []struct {
		Name string
		Body []byte
	}{
		{Name: "no body", Body: nil},
		{Name: "ends in the cipher suite", Body: whole[:len(whole)-2]},
		{Name: "no compression method", Body: whole[:len(whole)-1]},
		{Name: "extension block cut", Body: append(bytes.Clone(whole), 0, 9)},
		{Name: "extension data cut", Body: serverHelloBody(VersionTLS12, random, tlsECDHERSAWithAES128CBCSHA, []byte{0, 43, 0, 2, 3})},
		{Name: "half a version", Body: serverHelloBody(VersionTLS12, random, tlsECDHERSAWithAES128CBCSHA, helloExtension(extensionSupportedVersions, []byte{3}))},
		{Name: "a version and a byte", Body: serverHelloBody(VersionTLS12, random, tlsECDHERSAWithAES128CBCSHA, helloExtension(extensionSupportedVersions, []byte{3, 4, 0}))},
		{Name: "two protocols", Body: serverHelloBody(VersionTLS12, random, tlsECDHERSAWithAES128CBCSHA, helloExtension(extensionALPN, protocolsData("h2", "http/1.1")))},
		{Name: "no protocol", Body: serverHelloBody(VersionTLS12, random, tlsECDHERSAWithAES128CBCSHA, helloExtension(extensionALPN, protocolsData()))},
		{Name: "protocol name cut", Body: serverHelloBody(VersionTLS12, random, tlsECDHERSAWithAES128CBCSHA, helloExtension(extensionALPN, []byte{0, 2, 5, 'h'}))},
	}

	for _, negative := range negativeCases {
		hello, err := parseServerHello(negative.Body)

		if !errors.Is(err, ErrMalformedHandshake) {
			state.Errorf("Test of tlsrecord.parseServerHello function failed, case: %s, error should be %v, error: %v, hello: %+v", negative.Name, ErrMalformedHandshake, err, hello)
			return
		}
	}
}

// Test if tlsrecord.parseEncryptedExtensions returns with the expected output.
func TestParseEncryptedExtensionsPositive(state *testing.T) {
	positiveCases := []struct {
		Name     string
		Body     []byte
		Protocol string
	}{
		{Name: "no body", Body: nil, Protocol: ""},
		{Name: "empty extension block", Body: []byte{0, 0}, Protocol: ""},
		{Name: "no protocol", Body: extensionBlock(helloExtension(extensionServerName, nil)), Protocol: ""},
		{Name: "protocol", Body: extensionBlock(slices.Concat(helloExtension(extensionServerName, nil), helloExtension(extensionALPN, protocolsData("http/1.1")))), Protocol: "http/1.1"},
	}

	for _, positive := range positiveCases {
		protocol, err := parseEncryptedExtensions(positive.Body)

		if (err != nil) || (protocol != positive.Protocol) {
			state.Errorf("Test of tlsrecord.parseEncryptedExtensions function failed, case: %s, protocol should be %q, protocol: %q, error: %v", positive.Name, positive.Protocol, protocol, err)
			return
		}
	}
}

// Test if tlsrecord.parseEncryptedExtensions returns with the expected errors.
func TestParseEncryptedExtensionsNegative(state *testing.T) {
	negativeCases := []struct {
		Name string
		Body []byte
	}{
		{Name: "extension block cut", Body: []byte{0, 5, 0}},
		{Name: "bytes behind the extension block", Body: []byte{0, 0, 0}},
		{Name: "extension header cut", Body: extensionBlock([]byte{0, 16, 0})},
		{Name: "two protocols", Body: extensionBlock(helloExtension(extensionALPN, protocolsData("h2", "http/1.1")))},
		{Name: "protocol list cut", Body: extensionBlock(helloExtension(extensionALPN, []byte{0, 9, 2, 'h'}))},
	}

	for _, negative := range negativeCases {
		protocol, err := parseEncryptedExtensions(negative.Body)

		if !errors.Is(err, ErrMalformedHandshake) {
			state.Errorf("Test of tlsrecord.parseEncryptedExtensions function failed, case: %s, error should be %v, error: %v, protocol: %q", negative.Name, ErrMalformedHandshake, err, protocol)
			return
		}
	}
}

// Test if tlsrecord.ReadClientHello returns with the expected output for a ClientHello that takes more than one record.
func TestReadClientHelloRecordsPositive(state *testing.T) {
	random := [randomLength]byte(bytes.Repeat([]byte{0x42}, randomLength))
	message := handshakeMessage(handshakeClientHello, clientHelloBody(VersionTLS12, random, false, slices.Concat(helloExtension(extensionServerName, serverNameData(serverNameHostName, "example.com")), helloExtension(extensionALPN, protocolsData("h2")), helloExtension(extensionSupportedVersions, versionsData(VersionTLS13, VersionTLS12)))))
	expected := Hello{Version: VersionTLS13, ServerName: "example.com", Protocols: []string{"h2"}, ClientRandom: random}
	// where the message is cut into records: inside its header, inside its body, and both
	positiveCases := [][]int{
		{},
		{2},
		{handshakeHeaderLength},
		{40},
		{1, 3, 50, len(message) - 1},
	}

	for _, positive := range positiveCases {
		var data []byte
		start := 0

		for _, end := range append(slices.Clone(positive), len(message)) {
			// every record but the last one leaves the hello incomplete
			if start != 0 {
				_, isComplete, partErr := ReadClientHello(data)

				if isComplete || (partErr != nil) {
					state.Errorf("Test of tlsrecord.ReadClientHello function failed, cuts: %v, %d bytes of the hello should be incomplete without an error, complete: %v, error: %v", positive, start, isComplete, partErr)
					return
				}
			}

			data = append(data, plainRecord(HandshakeContentType, message[start:end])...)
			start = end
		}

		// what follows the hello is not read
		data = append(data, plainRecord(ApplicationDataContentType, []byte("early"))...)
		hello, isComplete, err := ReadClientHello(data)

		if (err != nil) || !isComplete || !reflect.DeepEqual(hello, expected) {
			state.Errorf("Test of tlsrecord.ReadClientHello function failed, cuts: %v, hello should be %+v, hello: %+v, complete: %v, error: %v", positive, expected, hello, isComplete, err)
			return
		}
	}
}

// Test if tlsrecord.ReadClientHello returns with the expected errors for a ClientHello that takes more than one record.
func TestReadClientHelloRecordsNegative(state *testing.T) {
	message := handshakeMessage(handshakeClientHello, clientHelloBody(VersionTLS12, [randomLength]byte{}, false, nil))
	negativeCases := []struct {
		Name string
		Data []byte
		Err  error
	}{
		{Name: "hello longer than a message that is read", Data: plainRecord(HandshakeContentType, []byte{handshakeClientHello, 1, 0, 1, 3, 3}), Err: ErrRecordOverflow},
		{Name: "hello that ends in its random", Data: plainRecord(HandshakeContentType, handshakeMessage(handshakeClientHello, message[handshakeHeaderLength:30])), Err: ErrMalformedHandshake},
		{Name: "alert inside the hello", Data: slices.Concat(plainRecord(HandshakeContentType, message[:10]), plainRecord(AlertContentType, []byte{2, 40})), Err: ErrUnexpectedRecord},
		{Name: "server hello behind half a header", Data: slices.Concat(plainRecord(HandshakeContentType, []byte{handshakeServerHello, 0}), plainRecord(HandshakeContentType, []byte{0, 0})), Err: ErrUnexpectedRecord},
		{Name: "record of another protocol version", Data: []byte{byte(HandshakeContentType), 2, 0, 0, 1, handshakeClientHello}, Err: ErrUnexpectedRecord},
		{Name: "record longer than any", Data: []byte{byte(HandshakeContentType), 3, 1, 0x48, 0x01, handshakeClientHello}, Err: ErrRecordOverflow},
	}

	for _, negative := range negativeCases {
		hello, isComplete, err := ReadClientHello(negative.Data)

		if isComplete || !errors.Is(err, negative.Err) {
			state.Errorf("Test of tlsrecord.ReadClientHello function failed, case: %s, error should be %v, error: %v, complete: %v, hello: %+v", negative.Name, negative.Err, err, isComplete, hello)
			return
		}
	}
}

// a record without protection
func plainRecord(contentType ContentType, fragment []byte) (record []byte) {
	record = newRecord(contentType, [2]byte{3, 3}, len(fragment))
	record = append(record, fragment...)
	setRecordLength(record, len(fragment))
	return
}

// one extension of a hello: its type, the length of its data and the data
func helloExtension(extensionType uint16, data []byte) (extension []byte) {
	extension = binary.BigEndian.AppendUint16(nil, extensionType)
	extension = binary.BigEndian.AppendUint16(extension, uint16(len(data)))
	extension = append(extension, data...)
	return
}

// the extensions with their length in front, as they end a hello
func extensionBlock(extensions []byte) (block []byte) {
	block = binary.BigEndian.AppendUint16(nil, uint16(len(extensions)))
	block = append(block, extensions...)
	return
}

// the data of server_name with one name
func serverNameData(nameType uint8, name string) (data []byte) {
	data = binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
	data = append(data, nameType)
	data = binary.BigEndian.AppendUint16(data, uint16(len(name)))
	data = append(data, name...)
	return
}

// the data of application_layer_protocol_negotiation
func protocolsData(protocols ...string) (data []byte) {
	list := []byte{}

	for _, protocol := range protocols {
		list = append(list, byte(len(protocol)))
		list = append(list, protocol...)
	}

	data = extensionBlock(list)
	return
}

// the data of supported_versions of a ClientHello
func versionsData(versions ...uint16) (data []byte) {
	data = []byte{byte(2 * len(versions))}

	for _, version := range versions {
		data = binary.BigEndian.AppendUint16(data, version)
	}

	return
}

// the body of a ClientHello: version, random, empty session id, the empty cookie of DTLS, one cipher suite, the null compression and the extensions, without a block when they are nil
func clientHelloBody(version uint16, random [randomLength]byte, hasCookie bool, extensions []byte) (body []byte) {
	body = binary.BigEndian.AppendUint16(nil, version)
	body = append(body, random[:]...)
	body = append(body, 0)

	if hasCookie {
		body = append(body, 0)
	}

	body = append(body, 0, 2, byte(tlsAES128GCMSHA256>>8), byte(tlsAES128GCMSHA256&0xff), 1, 0)

	if extensions != nil {
		body = append(body, extensionBlock(extensions)...)
	}

	return
}

// the body of a ServerHello: version, random, empty session id, the cipher suite, the null compression and the extensions, without a block when they are nil
func serverHelloBody(version uint16, random [randomLength]byte, cipherSuite uint16, extensions []byte) (body []byte) {
	body = binary.BigEndian.AppendUint16(nil, version)
	body = append(body, random[:]...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, cipherSuite)
	body = append(body, 0)

	if extensions != nil {
		body = append(body, extensionBlock(extensions)...)
	}

	return
}
