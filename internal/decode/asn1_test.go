// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"

	v1 "github.com/decerter/decerter/api"
)

// DER as encoding/asn1 writes it: the oracle of the tests
func der(state *testing.T, value any) (data []byte) {
	data, err := asn1.Marshal(value)

	if err != nil {
		state.Fatalf("Could not marshal %T: %v", value, err)
	}

	return
}

// an element of a class and tag around contents, constructed
func tagged(state *testing.T, class int, tag int, contents ...[]byte) (data []byte) {
	data = der(state, asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: join(contents...)})
	return
}

// a primitive element of a class and tag
func primitive(state *testing.T, class int, tag int, contents []byte) (data []byte) {
	data = der(state, asn1.RawValue{Class: class, Tag: tag, IsCompound: false, Bytes: contents})
	return
}

func sequence(state *testing.T, contents ...[]byte) (data []byte) {
	data = tagged(state, asn1.ClassUniversal, asn1.TagSequence, contents...)
	return
}

// a Kerberos PrincipalName of a name type and its parts in GeneralStrings
func principal(state *testing.T, nameType int, parts ...string) (data []byte) {
	names := [][]byte{}

	for _, part := range parts {
		names = append(names, primitive(state, asn1.ClassUniversal, asn1.TagGeneralString, []byte(part)))
	}

	data = sequence(state, tagged(state, asn1.ClassContextSpecific, 0, der(state, nameType)), tagged(state, asn1.ClassContextSpecific, 1, sequence(state, names...)))
	return
}

// Test if decode.Decode returns with the expected output for BER: the universal types encoding/asn1 writes (an OID it reads the same, a big INTEGER,
// a negative one, times, strings), an indefinite length with its end-of-contents octets and a high tag number.
func TestBERPositive(state *testing.T) {
	oid := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	huge, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	data := sequence(state, der(state, true), der(state, -129), der(state, huge), der(state, oid), der(state, asn1.Enumerated(7)), der(state, []byte("bytes")),
		der(state, asn1.BitString{Bytes: []byte{0xf0}, BitLength: 4}), der(state, asn1.NullRawValue), primitive(state, asn1.ClassUniversal, asn1.TagUTF8String, []byte("text")),
		tagged(state, asn1.ClassContextSpecific, 3, der(state, 1)))
	result := mustDecode(state, data, streamContext(9999, v1.UpDirection, true), berProtocol)

	if (len(errorsOf(result.Tree)) != 0) || (result.Summary != "BER SEQUENCE, "+itoaOf(len(data))+" bytes") {
		state.Errorf("Test of BER failed, the elements should decode, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the BER elements", result, map[string]string{
		"ber.boolean": "TRUE", "ber.integer#0": "-129", "ber.integer#1": huge.String(), "ber.object_identifier": oid.String(), "ber.enumerated": "7",
		"ber.octet_string": `"bytes"`, "ber.bit_string": "4 unused bits, f0", "ber.null": "NULL", "ber.utf8string": `"text"`, "ber.context": "1 elements", "ber.integer#2": "1",
	})
	indefinite := []byte{0x30, 0x80, 0x02, 0x01, 0x05, 0x5f, 0x81, 0x00, 0x01, 0xaa, 0x00, 0x00, 0x02, 0x01, 0x06}
	result = mustDecode(state, indefinite, streamContext(9999, v1.UpDirection, true), berProtocol)

	if (len(result.Tree) != 2) || (len(errorsOf(result.Tree)) != 0) || (result.Tree[0].Length != 12) || (result.Tree[0].Children[1].Label != "[APPLICATION 128]") {
		state.Errorf("Test of BER failed, the indefinite length should end at its zero bytes, tree: %+v, errors: %v", result.Tree, errorsOf(result.Tree))
	}
}

// Test if decode.Decode returns with the expected errors for BER: contents past their parent, a length of 5 bytes, an indefinite primitive, elements
// nested past berMaxDepth and an indefinite length without its end.
func TestBERNegative(state *testing.T) {
	deep := []byte{0x02, 0x01, 0x01}

	for range berMaxDepth + 2 {
		deep = sequence(state, deep)
	}

	negativeCases := map[string]struct {
		data     []byte
		expected string
	}{
		"past":       {data: []byte{0x30, 0x05, 0x04, 0x09, 'a', 'b', 'c'}, expected: "the contents run past their parent: 3 of their 9 bytes are there"},
		"length":     {data: []byte{0x30, 0x85, 1, 1, 1, 1, 1}, expected: "the bytes are no ASN.1 BER element"},
		"primitive":  {data: []byte{0x30, 0x04, 0x04, 0x80, 0x00, 0x00}, expected: "a primitive element has an indefinite length"},
		"deep":       {data: deep, expected: "the elements nest more than 24 deep"},
		"indefinite": {data: []byte{0x30, 0x80, 0x02, 0x01, 0x05}, expected: "the stream ends inside the element"},
	}

	for name, negative := range negativeCases {
		result := mustDecode(state, negative.data, streamContext(9999, v1.UpDirection, true), berProtocol)

		if !strings.Contains(strings.Join(errorsOf(result.Tree), "; "), negative.expected) {
			state.Errorf("Test of BER failed, %s should have the error %q, errors: %v", name, negative.expected, errorsOf(result.Tree))
		}
	}
}

// Test if decode.Decode returns with the expected output for LDAP: a bind, a search and an unbind by sniffing, the server's answers with result codes,
// StartTLS that switches both directions to TLS, and a search entry of 100 KiB in a joined stream.
func TestLDAPPositive(state *testing.T) {
	message := func(identifier int, operation []byte) (data []byte) {
		data = sequence(state, der(state, identifier), operation)
		return
	}
	bind := message(1, tagged(state, asn1.ClassApplication, 0, der(state, 3), der(state, []byte("cn=admin,dc=example,dc=org")), primitive(state, asn1.ClassContextSpecific, 0, []byte("secret"))))
	search := message(2, tagged(state, asn1.ClassApplication, 3, der(state, []byte("dc=example,dc=org")), der(state, asn1.Enumerated(2)), der(state, asn1.Enumerated(0)),
		der(state, 0), der(state, 0), der(state, false), primitive(state, asn1.ClassContextSpecific, 7, []byte("objectClass")), sequence(state, der(state, []byte("cn")))))
	unbind := message(3, primitive(state, asn1.ClassApplication, 2, nil))
	result := mustDecode(state, join(bind, search, unbind), streamContext(9999, v1.UpDirection, false), "")
	expected := `LDAP bindRequest(1) v3 "cn=admin,dc=example,dc=org" simple; LDAP searchRequest(2) "dc=example,dc=org" wholeSubtree; LDAP unbindRequest(3)`

	if (result.Protocol != ldapProtocol) || (len(errorsOf(result.Tree)) != 0) || (result.Summary != expected) {
		state.Errorf("Test of LDAP failed, the requests should sniff as LDAP, summary: %s, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	checkValues(state, "the LDAP requests", result, map[string]string{"ldap.messageID": "1", "ldap.protocolOp": "3 elements", "ldap.messageID#1": "2"})
	large := strings.Repeat("z", 100<<10)
	entry := message(2, tagged(state, asn1.ClassApplication, 4, der(state, []byte("cn=big,dc=example,dc=org")), sequence(state, sequence(state, der(state, []byte("description")), tagged(state, asn1.ClassUniversal, asn1.TagSet, der(state, []byte(large)))))))
	done := message(2, tagged(state, asn1.ClassApplication, 5, der(state, asn1.Enumerated(32)), der(state, []byte("dc=example,dc=org")), der(state, []byte("no such entry"))))
	result = mustDecode(state, join(entry, done), streamContext(389, v1.DownDirection, true), "")
	expected = `LDAP searchResEntry(2) "cn=big,dc=example,dc=org"; LDAP searchResDone(2) noSuchObject "dc=example,dc=org" "no such entry"`

	if (len(result.Tree) != 2) || (len(errorsOf(result.Tree)) != 0) || (result.Summary != expected) || (result.Tree[0].Length != len(entry)) {
		state.Errorf("Test of LDAP failed, the large entry should be one message, summary: %s, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	checkValues(state, "the LDAP answers", result, map[string]string{"ldap.resultCode": "32"})
	hello := tlsRecord(22, 0x0301, handshakeMessage(1, make([]byte, 40)))
	startTLS := message(1, tagged(state, asn1.ClassApplication, 23, primitive(state, asn1.ClassContextSpecific, 0, []byte(ldapStartTLS))))
	result = mustDecode(state, join(startTLS, hello), streamContext(389, v1.UpDirection, true), "")

	if (len(result.Tree) != 2) || (result.Summary != `LDAP extendedReq(1) 1.3.6.1.4.1.1466.20037 (StartTLS); TLS`) {
		state.Errorf("Test of LDAP failed, StartTLS should switch to TLS, result: %+v", result)
	}

	answer := message(1, tagged(state, asn1.ClassApplication, 24, der(state, asn1.Enumerated(0)), der(state, []byte{}), der(state, []byte{})))
	result = mustDecode(state, join(answer, hello), streamContext(389, v1.DownDirection, true), "")

	if (len(result.Tree) != 2) || (result.Summary != `LDAP extendedResp(1) success; TLS`) {
		state.Errorf("Test of LDAP failed, the StartTLS answer should switch to TLS, result: %+v", result)
	}
}

// Test if decode.Decode returns with the expected output for Kerberos: an AS-REQ over UDP by sniffing, an AS-REP and a KRB-ERROR over TCP with their record
// marks, and an AP-REQ.
func TestKerberosPositive(state *testing.T) {
	explicit := func(tag int, contents ...[]byte) (data []byte) {
		data = tagged(state, asn1.ClassContextSpecific, tag, contents...)
		return
	}
	general := func(text string) (data []byte) {
		data = primitive(state, asn1.ClassUniversal, asn1.TagGeneralString, []byte(text))
		return
	}
	body := sequence(state, explicit(0, der(state, asn1.BitString{Bytes: []byte{0x40, 0x81, 0, 0x10}, BitLength: 32})), explicit(1, principal(state, 1, "alice")),
		explicit(2, general("EXAMPLE.COM")), explicit(3, principal(state, 2, "krbtgt", "EXAMPLE.COM")), explicit(7, der(state, 12345)), explicit(8, sequence(state, der(state, 18), der(state, 17))))
	request := tagged(state, asn1.ClassApplication, 10, sequence(state, explicit(1, der(state, 5)), explicit(2, der(state, 10)), explicit(4, body)))
	udp := Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 9988, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	result := mustDecode(state, request, udp, "")

	if (result.Protocol != kerberosProtocol) || (len(errorsOf(result.Tree)) != 0) || (result.Summary != `Kerberos AS-REQ realm "EXAMPLE.COM" cname "alice" sname "krbtgt/EXAMPLE.COM"`) {
		state.Errorf("Test of Kerberos failed, the AS-REQ should sniff as Kerberos, summary: %s, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	checkValues(state, "the AS-REQ", result, map[string]string{"kerberos.pvno": "1 elements", "kerberos.nonce": "1 elements", "kerberos.realm": "1 elements"})
	reply := tagged(state, asn1.ClassApplication, 11, sequence(state, explicit(0, der(state, 5)), explicit(1, der(state, 11)), explicit(3, general("EXAMPLE.COM")), explicit(4, principal(state, 1, "alice")),
		explicit(5, tagged(state, asn1.ClassApplication, 1, sequence(state, explicit(0, der(state, 5))))), explicit(6, sequence(state, explicit(0, der(state, 18)), explicit(2, der(state, []byte{1, 2, 3}))))))
	failure := tagged(state, asn1.ClassApplication, 30, sequence(state, explicit(0, der(state, 5)), explicit(1, der(state, 30)), explicit(4, primitive(state, asn1.ClassUniversal, asn1.TagGeneralizedTime, []byte("20261116120000Z"))),
		explicit(5, der(state, 0)), explicit(6, der(state, 25)), explicit(9, general("EXAMPLE.COM")), explicit(10, principal(state, 2, "krbtgt", "EXAMPLE.COM"))))
	tcp := join(be32(uint32(len(reply))), reply, be32(uint32(len(failure))), failure)
	result = mustDecode(state, tcp, streamContext(88, v1.DownDirection, true), "")
	expected := `Kerberos AS-REP realm "EXAMPLE.COM" cname "alice"; Kerberos KRB-ERROR KDC_ERR_PREAUTH_REQUIRED realm "EXAMPLE.COM" sname "krbtgt/EXAMPLE.COM"`

	if (len(result.Tree) != 2) || (len(errorsOf(result.Tree)) != 0) || (result.Summary != expected) {
		state.Errorf("Test of Kerberos failed, the TCP messages should decode, summary: %s, errors: %v", result.Summary, errorsOf(result.Tree))
	}

	checkValues(state, "the KRB-ERROR", result, map[string]string{"kerberos.rm.length": itoaOf(len(reply)), "ber.generalizedtime": `"20261116120000Z"`})
}

// Test if decode.Decode returns with the expected errors for Kerberos and LDAP: a TCP record mark with its top bit set, an LDAP message with an indefinite
// length, and a message cut in one read.
func TestKerberosNegative(state *testing.T) {
	negativeCases := map[string]struct {
		data     []byte
		as       string
		isJoined bool
		expected string
	}{
		"mark":       {data: []byte{0x80, 0, 0, 4, 1, 2, 3, 4}, as: kerberosProtocol, isJoined: true, expected: "the bytes are no Kerberos message"},
		"indefinite": {data: []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x42, 0x00, 0x00, 0x00}, as: ldapProtocol, isJoined: true, expected: "the bytes are no Lightweight Directory Access Protocol message"},
		"cut":        {data: []byte{0x30, 0x20, 0x02, 0x01, 0x01}, as: ldapProtocol, isJoined: false, expected: "the message continues in the next read: 5 of its 34 bytes are here"},
	}

	for name, negative := range negativeCases {
		result := mustDecode(state, negative.data, streamContext(9999, v1.UpDirection, negative.isJoined), negative.as)

		if !strings.Contains(strings.Join(errorsOf(result.Tree), "; "), negative.expected) {
			state.Errorf("Test of Kerberos failed, %s should have the error %q, errors: %v", name, negative.expected, errorsOf(result.Tree))
		}
	}
}

func itoaOf(value int) (text string) {
	text = big.NewInt(int64(value)).String()
	return
}

// Fuzz if decode.Decode never fails on any bytes as BER, LDAP and Kerberos, over a stream and a datagram.
func FuzzASN1(fuzz *testing.F) {
	fuzz.Add([]byte{0x30, 0x80, 0x02, 0x01, 0x05, 0x5f, 0x81, 0x00, 0x01, 0xaa, 0x00, 0x00})
	fuzz.Add([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00})
	fuzz.Add([]byte{0x00, 0x00, 0x00, 0x0c, 0x6a, 0x0a, 0x30, 0x08, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x01, 0x0a})
	fuzz.Add([]byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b})
	udp := Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 88, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	contexts := []Context{udp, streamContext(389, v1.UpDirection, false), streamContext(88, v1.DownDirection, true), streamContext(389, v1.DownDirection, true)}

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		fuzzDecodes(state, data, contexts, []string{"", berProtocol, ldapProtocol, kerberosProtocol})
	})
}
