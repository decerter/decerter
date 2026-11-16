// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	v1 "github.com/decerter/decerter/api"
)

// a tcp read and a joined stream of a direction to a port
func streamContext(port uint16, direction v1.Direction, isJoined bool) (context Context) {
	context = Context{Transport: StreamTransport, Layer: v1.TCPLayer, Direction: direction, ServerPort: port, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: isJoined}
	return
}

// a command as RESP: an array of bulk strings
func respCommand(words ...string) (data []byte) {
	data = []byte("*" + strconv.Itoa(len(words)) + "\r\n")

	for _, word := range words {
		data = append(data, "$"+strconv.Itoa(len(word))+"\r\n"+word+"\r\n"...)
	}

	return
}

// Test if decode.Decode returns with the expected output for RESP: commands of a client by sniffing, a bulk string of 100 KiB in a joined stream as
// one value, the replies of RESP2 and RESP3, an inline command, and a bulk string cut short in one read.
func TestRESPPositive(state *testing.T) {
	commands := join(respCommand("SET", "key", "value"), respCommand("GET", "key"))
	result := mustDecode(state, commands, streamContext(7000, v1.UpDirection, false), "")

	if (result.Protocol != respProtocol) || (result.Summary != `Redis SET "key" "value"; Redis GET "key"`) || (len(result.Tree) != 2) || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of RESP failed, two commands should sniff as RESP, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	large := strings.Repeat("v", 100<<10)
	result = mustDecode(state, respCommand("SET", "big", large), streamContext(6379, v1.UpDirection, true), "")
	value := findAll(result.Tree, "resp.bulk_string")

	if (len(result.Tree) != 1) || (len(value) != 3) || (value[2].Value != "102400 bytes") || (len(errorsOf(result.Tree)) != 0) || !strings.HasPrefix(result.Summary, `Redis SET "big" "vvv`) {
		state.Errorf("Test of RESP failed, the large bulk string should be one value, value: %+v, errors: %v", value, errorsOf(result.Tree))
	}

	// the same value in one read of the flow goes on in the next one
	result = mustDecode(state, respCommand("SET", "big", large)[:40000], streamContext(6379, v1.UpDirection, false), "")

	if errors := strings.Join(errorsOf(result.Tree), "; "); !strings.Contains(errors, "the value continues in the next read") || !strings.Contains(errors, "the string goes on past the bytes: 39969 of its 102400 bytes are there") {
		state.Errorf("Test of RESP failed, a cut bulk string should continue in the next read, errors: %s", errors)
	}

	replies := []byte("+OK\r\n-ERR unknown command 'FOO'\r\n:42\r\n$-1\r\n$5\r\nhello\r\n*2\r\n:1\r\n$1\r\nx\r\n%1\r\n+key\r\n#t\r\n_\r\n,3.14\r\n=15\r\ntxt:Some string\r\n")
	result = mustDecode(state, replies, streamContext(6379, v1.DownDirection, true), "")

	if (len(result.Tree) != 10) || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of RESP failed, the replies should be 10 values, tree: %+v, errors: %v", result.Tree, errorsOf(result.Tree))
	}

	checkValues(state, "the RESP replies", result, map[string]string{
		"resp.simple_string#0": `"OK"`, "resp.error": `"ERR unknown command 'FOO'"`, "resp.integer#0": `"42"`, "resp.bulk_string#0": "null", "resp.data#0": `"hello"`,
		"resp.map": "1 elements", "resp.boolean": "true", "resp.null": "null", "resp.double": `"3.14"`, "resp.data#2": `"txt:Some string"`,
	})

	result = mustDecode(state, []byte("PING\r\n"), streamContext(6379, v1.UpDirection, false), "")

	if (result.Protocol != respProtocol) || (result.Summary != "Redis inline PING") {
		state.Errorf("Test of RESP failed, an inline command should decode, result: %+v", result)
	}
}

// Test if decode.Decode returns with the expected errors for RESP: a bad length, an unknown type inside an array, a boolean that is neither t nor f, and
// arrays nested deeper than respMaxDepth.
func TestRESPNegative(state *testing.T) {
	negativeCases := map[string]struct {
		data     []byte
		expected string
	}{
		"length":  {data: []byte("$x\r\nabc\r\n"), expected: "the bytes are no Redis Serialization Protocol value"},
		"element": {data: []byte("*1\r\n?\r\n"), expected: "the bytes are no Redis Serialization Protocol value"},
		"boolean": {data: []byte("#x\r\n"), expected: "a boolean is t or f"},
		"deep":    {data: join(bytes.Repeat([]byte("*1\r\n"), respMaxDepth+2), []byte(":1\r\n")), expected: "the bytes are no Redis Serialization Protocol value"},
		"crlf":    {data: []byte("$3\r\nabcde"), expected: "the string does not end with CRLF"},
	}

	for name, negative := range negativeCases {
		result := mustDecode(state, negative.data, streamContext(6379, v1.DownDirection, true), respProtocol)

		if !strings.Contains(strings.Join(errorsOf(result.Tree), "; "), negative.expected) {
			state.Errorf("Test of RESP failed, %s should have the error %q, errors: %v", name, negative.expected, errorsOf(result.Tree))
		}
	}
}

// an MQTT packet: the first byte, the remaining length and the body
func mqttPacket(first byte, body []byte) (data []byte) {
	length := len(body)
	data = []byte{first}

	for {
		part := byte(length & 0x7f)
		length >>= 7

		if length > 0 {
			part |= 0x80
		}

		data = append(data, part)

		if length == 0 {
			break
		}
	}

	data = append(data, body...)
	return
}

func mqttText(text string) (data []byte) {
	data = join(be16(uint16(len(text))), []byte(text))
	return
}

// Test if decode.Decode returns with the expected output for MQTT: a 3.1.1 CONNECT with a will, user name and password by sniffing and the packets after
// it, a 5.0 CONNECT and PUBLISH with properties in a joined stream, the server's CONNACK of 5.0, and a PUBLISH of 200 KiB with a remaining length of 3 bytes.
func TestMQTTPositive(state *testing.T) {
	connect := mqttPacket(0x10, join(mqttText("MQTT"), []byte{4, 0xc6}, be16(60), mqttText("client-1"), mqttText("will/topic"), mqttText("bye"), mqttText("user"), mqttText("secret")))
	publish := mqttPacket(0x32, join(mqttText("a/b"), be16(7), []byte("hello")))
	subscribe := mqttPacket(0x82, join(be16(8), mqttText("a/#"), []byte{1}))
	result := mustDecode(state, join(connect, publish, subscribe, mqttPacket(0xc0, nil)), streamContext(9000, v1.UpDirection, false), "")

	if (result.Protocol != mqttProtocol) || (len(result.Tree) != 4) || (len(errorsOf(result.Tree)) != 0) ||
		(result.Summary != `MQTT CONNECT "MQTT" level 4 client "client-1"; MQTT PUBLISH "a/b" id=7; MQTT SUBSCRIBE id=8 "a/#"; MQTT PINGREQ`) {
		state.Errorf("Test of MQTT failed, the packets should sniff as MQTT, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the MQTT 3.1.1 packets", result, map[string]string{
		"mqtt.ver": "MQTT v3.1.1 (4)", "mqtt.conflag.uname": "yes", "mqtt.conflag.qos": "0", "mqtt.willtopic": `"will/topic"`, "mqtt.username": `"user"`,
		"mqtt.qos": "1", "mqtt.msg": `"hello"`, "mqtt.sub.qos": "0x01 QoS 1", "mqtt.kalive": "60",
	})
	properties := join([]byte{8}, []byte{0x11}, be32(3600), []byte{0x21}, be16(10))
	connect5 := mqttPacket(0x10, join(mqttText("MQTT"), []byte{5, 0x02}, be16(30), properties, mqttText("c5")))
	payload := strings.Repeat("p", 200<<10)
	publishProperties := join([]byte{16}, []byte{0x26}, mqttText("k"), mqttText("v"), []byte{0x03}, mqttText("txt"), []byte{0x23}, be16(1))
	publish5 := mqttPacket(0x30, join(mqttText("t"), publishProperties, []byte(payload)))
	result = mustDecode(state, join(connect5, publish5), streamContext(1883, v1.UpDirection, true), "")

	if (len(result.Tree) != 2) || (len(errorsOf(result.Tree)) != 0) || (result.Tree[1].Length != len(publish5)) {
		state.Errorf("Test of MQTT failed, the 5.0 packets should decode whole, tree: %+v, errors: %v", result.Tree, errorsOf(result.Tree))
	}

	checkValues(state, "the MQTT 5.0 packets", result, map[string]string{"mqtt.ver": "MQTT v5.0 (5)", "mqtt.property.uint32": "3600", "mqtt.property#2": `"k"="v"`, "mqtt.property#3": `"txt"`, "mqtt.len#1": strconv.Itoa(len(publish5) - 4)})
	connack := mqttPacket(0x20, join([]byte{0, 0x00}, []byte{3, 0x21}, be16(20)))
	result = mustDecode(state, connack, streamContext(1883, v1.DownDirection, true), "")

	if (result.Summary != "MQTT CONNACK Success") || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of MQTT failed, the CONNACK of 5.0 should have its properties, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}
}

// Test if decode.Decode returns with the expected errors for MQTT: a remaining length of 5 bytes, a string past its packet, an unknown 5.0 property.
func TestMQTTNegative(state *testing.T) {
	negativeCases := map[string]struct {
		data     []byte
		expected string
	}{
		"length":   {data: []byte{0x30, 0xff, 0xff, 0xff, 0xff, 0x01}, expected: "the bytes are no MQ Telemetry Transport Protocol packet"},
		"string":   {data: mqttPacket(0x30, join(be16(40), []byte("abc"))), expected: "Topic: the field runs past the end"},
		"property": {data: join(mqttPacket(0x10, join(mqttText("MQTT"), []byte{5, 0}, be16(1), []byte{2, 0x7f, 0}, mqttText("c")))), expected: "an unknown property"},
	}

	for name, negative := range negativeCases {
		result := mustDecode(state, negative.data, streamContext(1883, v1.UpDirection, true), mqttProtocol)

		if !strings.Contains(strings.Join(errorsOf(result.Tree), "; "), negative.expected) {
			state.Errorf("Test of MQTT failed, %s should have the error %q, errors: %v", name, negative.expected, errorsOf(result.Tree))
		}
	}
}

// Test if decode.Decode returns with the expected output for SMTP, IMAP and POP3: a client's session with mail data and a server's replies of several lines,
// the TLS records after STARTTLS, an IMAP FETCH answer with a literal split in a joined stream, and a POP3 response of several lines.
func TestMailPositive(state *testing.T) {
	session := "EHLO client.example\r\nMAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.com>\r\nDATA\r\nSubject: hello\r\nFrom: a@example.com\r\n\r\nbody line\r\n..dot\r\n.\r\nQUIT\r\n"
	result := mustDecode(state, []byte(session), streamContext(25, v1.UpDirection, true), "")

	if (result.Protocol != smtpProtocol) || (len(result.Tree) != 6) || (len(errorsOf(result.Tree)) != 0) ||
		(result.Summary != `SMTP EHLO "client.example"; SMTP MAIL "FROM:<a@example.com>"; SMTP RCPT "TO:<b@example.com>"; SMTP DATA; SMTP mail data, 60 bytes; SMTP QUIT`) {
		state.Errorf("Test of SMTP failed, the session should be 6 PDUs, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the SMTP session", result, map[string]string{"imf.header#0": `"hello"`, "imf.body": `"body line\r\n..dot\r\n"`, "smtp.req.parameter#0": `"client.example"`})
	hello := tlsRecord(22, 0x0301, handshakeMessage(1, make([]byte, 40)))
	replies := join([]byte("220 mail.example ESMTP ready\r\n250-mail.example\r\n250-SIZE 1000\r\n250 STARTTLS\r\n220 go ahead\r\n"), hello)
	result = mustDecode(state, replies, streamContext(25, v1.DownDirection, true), "")

	if (len(result.Tree) != 4) || (result.Tree[3].Name != "smtp.tls") || (findNode(result.Tree, "tls.handshake.type") == nil) || (result.Summary != `SMTP reply 220 "mail.example ESMTP ready"; SMTP reply 250 "mail.example" (3 lines); SMTP reply 220 "go ahead"; TLS`) {
		state.Errorf("Test of SMTP failed, the replies should end with TLS, result: %+v", result)
	}

	fetch := "* 1 FETCH (BODY[] {12}\r\nhello\r\nworld)\r\na1 OK done\r\n"
	result = mustDecode(state, []byte(fetch), streamContext(143, v1.DownDirection, true), "")

	if (result.Protocol != imapProtocol) || (len(result.Tree) != 2) || (len(errorsOf(result.Tree)) != 0) || (result.Summary != `IMAP response "*" "1"; IMAP response "a1" "OK"`) {
		state.Errorf("Test of IMAP failed, the literal should stay inside its response, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the IMAP literal", result, map[string]string{"imap.literal": `"hello\r\nworld"`})
	result = mustDecode(state, []byte("a1 LOGIN user pass\r\n"), streamContext(9143, v1.UpDirection, false), imapProtocol)
	checkValues(state, "the IMAP login", result, map[string]string{"imap.request.tag": `"a1"`, "imap.request.command": `"LOGIN"`})
	pop := "+OK POP3 ready\r\n+OK 2 messages\r\n1 120\r\n2 200\r\n.\r\n-ERR no such message\r\n"
	result = mustDecode(state, []byte(pop), streamContext(110, v1.DownDirection, true), "")

	if (result.Protocol != popProtocol) || (len(result.Tree) != 3) || (findNode(result.Tree, "pop.data") == nil) || (result.Summary != `POP +OK "POP3 ready"; POP +OK "2 messages"; POP -ERR "no such message"`) {
		state.Errorf("Test of POP3 failed, the responses should be 3 PDUs, result: %+v", result)
	}

	result = mustDecode(state, []byte("USER bob\r\nSTLS\r\n"), streamContext(110, v1.UpDirection, false), "")
	checkValues(state, "the POP3 commands", result, map[string]string{"pop.request.command#1": `"STLS"`, "pop.request.parameter": `"bob"`})
}

// Test if decode.Decode returns with the expected errors for the mail protocols: a line without its end in a read and in a joined stream, mail data without
// its lone dot.
func TestMailNegative(state *testing.T) {
	result := mustDecode(state, []byte("EHLO cut"), streamContext(25, v1.UpDirection, false), smtpProtocol)

	if errors := errorsOf(result.Tree); (len(errors) != 1) || !strings.Contains(errors[0], "the line continues in the next read, 8 bytes of it are here") {
		state.Errorf("Test of SMTP failed, a cut line should continue in the next read, errors: %v", errors)
	}

	result = mustDecode(state, []byte("DATA\r\nSubject: x\r\n\r\nno end"), streamContext(25, v1.UpDirection, true), smtpProtocol)

	if errors := errorsOf(result.Tree); (len(errors) != 1) || !strings.Contains(errors[0], "the stream ends inside the line") {
		state.Errorf("Test of SMTP failed, mail data without its dot should end with the stream, errors: %v", errors)
	}
}

// Test if decode.Decode returns with the expected output for the second review of the text protocols: an IMAP literal and RESP lengths near MaxInt64 are
// cut short, not a panic; a lone +OK of a read is a whole POP3 line; SMTP and IMAP lines without a word the sniff knows are taken by their port.
func TestTextReviewPositive(state *testing.T) {
	huge := []struct {
		data     []byte
		port     uint16
		protocol string
	}{
		{data: []byte("a1 APPEND inbox {9223372036854775807}\r\nabc\r\n"), port: 143, protocol: imapProtocol},
		{data: []byte("* 1 FETCH (BODY[] {9223372036854775800}\r\nabc)\r\n"), port: 143, protocol: imapProtocol},
		{data: []byte("*2\r\n$9223372036854775780\r\nabc\r\n"), port: 6379, protocol: respProtocol},
		{data: []byte("$9223372036854775800\r\nabc\r\n"), port: 6379, protocol: respProtocol},
	}

	for _, testCase := range huge {
		for _, isJoined := range []bool{false, true} {
			for _, as := range []string{"", testCase.protocol} {
				result := mustDecode(state, testCase.data, streamContext(testCase.port, v1.UpDirection, isJoined), as)
				errors := strings.Join(errorsOf(result.Tree), "; ")
				isShort := strings.Contains(errors, "inside the") || strings.Contains(errors, "continues in the next read") || strings.Contains(errors, "goes on past the bytes")

				if (result.Error != "") || (result.Protocol != testCase.protocol) || !isShort {
					state.Errorf("Test of the huge sizes failed, %q should be %s cut short, protocol: %s, error: %s, errors: %v", testCase.data, testCase.protocol, result.Protocol, result.Error, errorsOf(result.Tree))
				}
			}
		}
	}

	for _, line := range []string{"+OK POP3 server ready\r\n", "+OK\r\n", "+OK bye\r\n"} {
		if result := mustDecode(state, []byte(line), streamContext(110, v1.DownDirection, false), ""); (result.Protocol != popProtocol) || (len(errorsOf(result.Tree)) != 0) {
			state.Errorf("Test of POP3 failed, a lone %q should be a whole line, protocol: %s, errors: %v", line, result.Protocol, errorsOf(result.Tree))
		}
	}

	// lines after the +OK without their dot are a response that goes on
	if result := mustDecode(state, []byte("+OK 2 messages\r\n1 120\r\n"), streamContext(110, v1.DownDirection, false), ""); !strings.Contains(strings.Join(errorsOf(result.Tree), "; "), "continues in the next read") {
		state.Errorf("Test of POP3 failed, a listing without its dot should go on in the next read, errors: %v", errorsOf(result.Tree))
	}

	for _, testCase := range []struct {
		data      string
		port      uint16
		direction v1.Direction
		protocol  string
	}{
		{data: "MAIL FROM:<a@example.com>\r\n", port: 25, direction: v1.UpDirection, protocol: smtpProtocol},
		{data: "QUIT\r\n", port: 587, direction: v1.UpDirection, protocol: smtpProtocol},
		{data: "Subject: hello\r\n\r\nbody\r\n", port: 25, direction: v1.UpDirection, protocol: smtpProtocol},
		{data: "a1 OK LOGIN completed\r\n", port: 143, direction: v1.DownDirection, protocol: imapProtocol},
		{data: "+ ready for literal data\r\n", port: 143, direction: v1.DownDirection, protocol: imapProtocol},
		{data: "a2 APPEND inbox {3}\r\nabc\r\n", port: 143, direction: v1.UpDirection, protocol: imapProtocol},
	} {
		if result := mustDecode(state, []byte(testCase.data), streamContext(testCase.port, testCase.direction, false), ""); (result.Protocol != testCase.protocol) || (result.Candidates[0].Basis != v1.PortDecodeBasis) {
			state.Errorf("Test of the line sniffs failed, %q on port %d should be %s by the port, candidates: %+v", testCase.data, testCase.port, testCase.protocol, result.Candidates)
		}
	}
}

// Fuzz if decode.Decode never fails on any bytes as RESP, MQTT, SMTP, IMAP and POP3, over a read and a joined stream each way.
func FuzzText(fuzz *testing.F) {
	fuzz.Add(join(respCommand("SET", "k", "v"), []byte("+OK\r\n%1\r\n+a\r\n*1\r\n$1\r\nb\r\n")))
	fuzz.Add(mqttPacket(0x10, join(mqttText("MQTT"), []byte{5, 0xc6}, be16(60), []byte{3, 0x21, 0, 1}, mqttText("c"), []byte{0}, mqttText("w"), mqttText("m"), mqttText("u"), mqttText("p"))))
	fuzz.Add([]byte("EHLO a\r\nDATA\r\nx: y\r\n\r\nz\r\n.\r\nBDAT 3 LAST\r\nabcQUIT\r\n"))
	fuzz.Add([]byte("* 1 FETCH (BODY[] {3}\r\nabc)\r\na OK\r\n"))
	fuzz.Add([]byte("+OK\r\na\r\n.\r\n-ERR x\r\n"))
	fuzz.Add([]byte("a1 APPEND inbox {9223372036854775807}\r\nabc\r\n"))
	fuzz.Add([]byte("*2\r\n$9223372036854775780\r\nabc\r\n"))
	fuzz.Add(mqttPacket(0x10, join(mqttText("MQTT"), []byte{4, 0xc2}, be16(60), mqttText("client"), mqttText("user"), mqttText("pass"))))
	contexts := []Context{}

	for _, direction := range []v1.Direction{v1.UpDirection, v1.DownDirection} {
		for _, isJoined := range []bool{false, true} {
			contexts = append(contexts, streamContext(1883, direction, isJoined), streamContext(25, direction, isJoined), streamContext(143, direction, isJoined), streamContext(110, direction, isJoined))
		}
	}

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		fuzzDecodes(state, data, contexts, []string{"", respProtocol, mqttProtocol, smtpProtocol, imapProtocol, popProtocol})
	})
}
