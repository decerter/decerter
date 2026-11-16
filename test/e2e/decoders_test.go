// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// the gRPC call whose messages are Protocol Buffers: field 1 the text, field 2 150; the answer's field 1 is "echo: " and the text
	grpcProtoPath string = "/decerter.test.Echo/Proto"
	grpcProtoText string = "hello protobuf"
	// what the WebSocket client and server say
	websocketWelcome string = "welcome"
	websocketText    string = "hello websocket"
	websocketBinary  string = "binary protobuf"
	websocketGUID    string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	// how long a case waits for the messages of a WebSocket flow
	websocketWaitTimeout time.Duration = 5 * time.Second
)

// a protobuf field of wire type LEN with a text of at most 127 bytes
func protoString(number byte, text string) (field []byte) {
	field = append([]byte{number<<3 | 2, byte(len(text))}, text...)
	return
}

// the request of the protobuf call: field 1 the text, field 2 the varint 150
func protoRequest() (message []byte) {
	message = append(protoString(1, grpcProtoText), 0x10, 0x96, 0x01)
	return
}

// a gRPC unary call whose request is a protobuf message with its text in field 1: the answer is one message with "echo: " and the text in field 1
func (server testServer) answerGRPCProto(writer http.ResponseWriter, request *http.Request, received receivedRequest) {
	body, readErr := io.ReadAll(request.Body)

	if (readErr != nil) || (len(body) < 7) || (int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5) || (body[5] != 0x0a) || (int(body[6]) > len(body)-7) {
		http.Error(writer, "no protobuf grpc message", http.StatusBadRequest)
		return
	}

	received.Body = string(body[7 : 7+int(body[6])])

	select {
	case server.requests <- received:
	default:
	}

	writer.Header().Set("Content-Type", "application/grpc+proto")
	writer.Header().Set("Trailer", "Grpc-Status")
	_, err := writer.Write(grpcFrame(string(protoString(1, "echo: "+received.Body))))

	if err != nil {
		return
	}

	writer.Header().Set("Grpc-Status", "0")
}

// the errors of a decode tree with the names of their nodes
func decodeErrors(nodes []v1.DecodeNode) (errs []string) {
	for _, node := range nodes {
		if node.Error != "" {
			errs = append(errs, node.Name+": "+node.Error)
		}

		errs = append(errs, decodeErrors(node.Children)...)
	}

	return
}

// a decode tool's metadata and tree from the marker id; the tree is the API's when isSame
func mcpDecode(state *testing.T, session *sdk.ClientSession, tool string, arguments map[string]any, marker string, decoded v1.Decode) (metadata mcp.DecodeResult, isSame bool) {
	text, isError := callTool(state, session, tool, arguments, &metadata)
	tree := mcp.DecodeTree{}
	treeErr := json.Unmarshal([]byte(inMarker(text, marker)), &tree)
	isSame = !isError && (treeErr == nil) && !metadata.Cut && reflect.DeepEqual(tree.Tree, decoded.Tree) && (tree.Summary == decoded.Summary)

	if !isSame {
		state.Logf("%s %v: metadata: %+v, error: %v, text: %.2000s", tool, arguments, metadata, treeErr, text)
	}

	return
}

// Test if a gRPC call of curl over TLS 1.3 and TLS 1.2 with ALPN h2 decodes as gRPC with the protobuf fields of both messages, and the handshake decerter kept of
// its flow as TLS each way: the ClientHello with JA3 and JA4, the server's flight with its certificate and, decrypted, the TLS 1.3 messages and both Finished;
// over the API and the same trees over MCP.
func TestDecodeGRPCHandshakePositive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	session := startMCP(state, client.socket, state.TempDir(), false)
	configs := []serverConfig{
		{Certificate: &ecdsaCertificate, Version: tls.VersionTLS13, HTTP2: true},
		{Certificate: &rsaCertificate, Version: tls.VersionTLS12, HTTP2: true},
	}

	for _, config := range configs {
		server := startServer(state, config)
		testCase := curlCase{Name: server.URL, Server: config, Suite: "", Expected: receivedRequest{}}
		arguments := append([]string{"-q", "--silent", "--show-error", "--max-time", curlMaxTime}, curlArguments(testCase, strings.TrimSuffix(server.URL, "/")+grpcProtoPath)...)
		arguments = append(arguments, "--header", "content-type: application/grpc", "--header", "te: trailers", "--data-binary", "@-")
		output, err := runAsUser(state.Context(), testUser, string(grpcFrame(string(protoRequest()))), curlPath, arguments...)
		received, receivedErr := server.received()

		if err = errors.Join(err, receivedErr); (err != nil) || (output != string(grpcFrame(string(protoString(1, "echo: "+grpcProtoText))))) || (received.Body != grpcProtoText) {
			state.Errorf("Test of the gRPC decode failed, %s, the call should get its answer, output: %q, received: %+v, error: %v", server.URL, output, received, err)
			continue
		}

		flowID, exchanges, err := flowExchanges(state, client, server, 1)

		if (err != nil) || (len(exchanges) != 1) {
			state.Errorf("Test of the gRPC decode failed, %s, the call should be one exchange, exchanges: %+v, error: %v", server.URL, exchanges, err)
			continue
		}

		testGRPCDecode(state, client, session, exchanges[0].ID)
		testHandshakeDecode(state, client, session, flowID, config.Version)
	}
}

// both sides of the call decode as gRPC by their content type with the protobuf fields at body offsets
func testGRPCDecode(state *testing.T, client apiClient, session *sdk.ClientSession, exchangeID uint64) {
	expected := map[v1.Side]struct {
		reason  string
		summary string
		text    string
	}{
		v1.RequestSide:  {reason: "content type application/grpc is gRPC", summary: "gRPC request " + grpcProtoPath + ", 1 message", text: `"` + grpcProtoText + `"`},
		v1.ResponseSide: {reason: "content type application/grpc+proto is gRPC", summary: "gRPC response, 1 message", text: `"echo: ` + grpcProtoText + `"`},
	}

	for side, want := range expected {
		decoded := v1.Decode{}
		status, err := client.call(state.Context(), http.MethodGet, fmt.Sprintf("/exchanges/%d/decode?side=%s", exchangeID, side), nil, &decoded)
		text := findDecodeNode(decoded.Tree, "protobuf.field.string")

		if (err != nil) || (status != http.StatusOK) || (decoded.Protocol != "grpc") || (decoded.Candidates[0].Reason != want.reason) || (decoded.Summary != want.summary) || (text == nil) || (text.Value != want.text) ||
			(text.Offset != 7) || (len(decodeErrors(decoded.Tree)) > 0) {
			state.Errorf("Test of the gRPC decode failed, the %s of exchange %d should be gRPC with protobuf fields, status: %d, decode: %+v, error: %v", side, exchangeID, status, decoded, err)
			continue
		}

		if (side == v1.RequestSide) && (findDecodeNode(decoded.Tree, "protobuf.field.varint") == nil || findDecodeNode(decoded.Tree, "protobuf.field.varint").Value != "150") {
			state.Errorf("Test of the gRPC decode failed, field 2 of the request should be 150, tree: %+v", decoded.Tree)
		}

		if _, isSame := mcpDecode(state, session, "decode_exchange_body", map[string]any{"id": exchangeID, "side": string(side)}, fmt.Sprintf("x%d-%s-decode", exchangeID, side), decoded); !isSame {
			state.Errorf("Test of decode_exchange_body failed, the %s of exchange %d should be the API's tree", side, exchangeID)
		}
	}
}

// the handshake of the flow decodes as TLS each way, all of its bytes, with what each side sent
func testHandshakeDecode(state *testing.T, client apiClient, session *sdk.ClientSession, flowID uint64, version uint16) {
	flow := v1.Flow{}
	_, err := client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d", flowID), nil, &flow)

	if (err != nil) || (flow.Up.HandshakeBytes == 0) || (flow.Down.HandshakeBytes == 0) {
		state.Errorf("Test of the handshake decode failed, flow %d should have kept its handshake both ways, flow: %+v, error: %v", flowID, flow, err)
		return
	}

	parts := map[v1.Direction][]string{
		v1.UpDirection:   {"Client Hello", "ALPN h2,http/1.1", "Finished"},
		v1.DownDirection: {"Server Hello TLS 1.3", "Encrypted Extensions", "Certificate ", "Certificate Verify", "Finished"},
	}
	// curl sends no server name to an address; the server's ALPN is in the EncryptedExtensions of TLS 1.3, in the ServerHello of TLS 1.2
	nodes := map[v1.Direction][]string{v1.UpDirection: {"tls.handshake.ja3", "tls.handshake.ja4", "tls.handshake.extensions_alpn_str"}, v1.DownDirection: {"tls.handshake.ja3s", "tls.handshake.extensions_alpn_str", "x509.subject", "x509.not_after"}}

	if version == tls.VersionTLS12 {
		parts[v1.UpDirection] = []string{"Client Hello", "Client Key Exchange", "Change Cipher Spec", "Finished"}
		parts[v1.DownDirection] = []string{"Server Hello TLS 1.2", "Certificate ", "Server Key Exchange", "Server Hello Done", "Change Cipher Spec", "Finished"}
	}

	for direction, kept := range map[v1.Direction]int{v1.UpDirection: flow.Up.HandshakeBytes, v1.DownDirection: flow.Down.HandshakeBytes} {
		decoded := v1.Decode{}
		status, err := client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/decode?part=handshake&direction=%s", flowID, direction), nil, &decoded)
		isComplete := (err == nil) && (status == http.StatusOK) && (decoded.Protocol == "tls") && (decoded.Source == v1.HandshakeDecodeSource) && (decoded.FlowID == flowID) && (decoded.Data != nil) &&
			(decoded.Data.Total == kept) && !decoded.Cut && (len(decodeErrors(decoded.Tree)) == 0) && (decoded.Candidates[0].Reason == "the handshake records decerter kept of the TLS flow")

		for _, part := range parts[direction] {
			isComplete = isComplete && strings.Contains(decoded.Summary, part)
		}

		for _, name := range nodes[direction] {
			isComplete = isComplete && (findDecodeNode(decoded.Tree, name) != nil)
		}

		if !isComplete {
			state.Errorf("Test of the handshake decode failed, flow %d going %s should decode as TLS with %v and %v, status: %d, summary: %q, errors: %v, decode: %.300v, error: %v", flowID, direction, parts[direction], nodes[direction], status,
				decoded.Summary, decodeErrors(decoded.Tree), decoded, err)
			continue
		}

		if subject := findDecodeNode(decoded.Tree, "x509.subject"); (direction == v1.DownDirection) && !strings.Contains(subject.Value, "O=Internet Widgits Pty Ltd") {
			state.Errorf("Test of the handshake decode failed, the certificate should be the server's, subject: %q", subject.Value)
		}

		metadata, isSame := mcpDecode(state, session, "decode_flow", map[string]any{"id": flowID, "direction": string(direction)}, fmt.Sprintf("f%d-%s-decode", flowID, direction), decoded)

		if !isSame || (metadata.Source != v1.HandshakeDecodeSource) || (metadata.FlowID != flowID) || (metadata.Data != nil) {
			state.Errorf("Test of decode_flow failed, flow %d going %s should be the API's tree without the bytes, metadata: %+v", flowID, direction, metadata)
		}
	}
}

// a WebSocket frame, FIN set; a client masks it with a random key
func writeWebSocketFrame(writer io.Writer, opcode byte, payload []byte, isMasked bool) (err error) {
	header := []byte{0x80 | opcode}
	maskFlag := byte(0)

	if isMasked {
		maskFlag = 0x80
	}

	if len(payload) <= 125 {
		header = append(header, maskFlag|byte(len(payload)))
	} else {
		header = binary.BigEndian.AppendUint16(append(header, maskFlag|126), uint16(len(payload)))
	}

	body := append([]byte{}, payload...)

	if isMasked {
		key := make([]byte, 4)
		_, err = rand.Read(key)

		if err != nil {
			return
		}

		header = append(header, key...)

		for index := range body {
			body[index] ^= key[index%4]
		}
	}

	_, err = writer.Write(append(header, body...))
	return
}

// the next frame, unmasked; frames of one message only, lengths up to 16 bits
func readWebSocketFrame(reader *bufio.Reader) (opcode byte, payload []byte, err error) {
	header := make([]byte, 2)
	_, err = io.ReadFull(reader, header)

	if err != nil {
		return
	}

	opcode, length := header[0]&0x0f, int(header[1]&0x7f)

	if length == 126 {
		extended := make([]byte, 2)
		_, err = io.ReadFull(reader, extended)
		length = int(binary.BigEndian.Uint16(extended))
	}

	key := make([]byte, 4)

	if (err == nil) && (header[1]&0x80 != 0) {
		_, err = io.ReadFull(reader, key)
	}

	if err != nil {
		return
	}

	payload = make([]byte, length)
	_, err = io.ReadFull(reader, payload)

	if header[1]&0x80 != 0 {
		for index := range payload {
			payload[index] ^= key[index%4]
		}
	}

	return
}

func websocketAccept(key string) (accept string) {
	sum := sha1.Sum([]byte(key + websocketGUID))
	accept = base64.StdEncoding.EncodeToString(sum[:])
	return
}

// a WebSocket server on loopback: the 101 goes out with a first text frame in one write, then it echoes text and binary messages, answers a ping with a pong
// and a close with a close
func startWebSocketServer(state *testing.T) (address string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		state.Fatalf("Could not listen for the WebSocket server, error: %s", err.Error())
	}

	httpServer := &http.Server{Handler: http.HandlerFunc(serveWebSocket), ReadHeaderTimeout: commandTimeout}
	serveErrChannel := make(chan error, 1)

	// WebSocket server
	go func() {
		serveErrChannel <- httpServer.Serve(listener)
	}()

	state.Cleanup(func() {
		closeErr := httpServer.Close()

		if serveErr := <-serveErrChannel; !errors.Is(serveErr, http.ErrServerClosed) {
			closeErr = errors.Join(closeErr, serveErr)
		}

		if closeErr != nil {
			state.Errorf("Could not close the WebSocket server, error: %s", closeErr.Error())
		}
	})

	address = listener.Addr().String()
	return
}

func serveWebSocket(writer http.ResponseWriter, request *http.Request) {
	key := request.Header.Get("Sec-WebSocket-Key")

	if !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") || (key == "") {
		http.Error(writer, "not a WebSocket upgrade", http.StatusBadRequest)
		return
	}

	conn, buffered, err := http.NewResponseController(writer).Hijack()

	if err != nil {
		return
	}

	defer func() { _ = conn.Close() }()
	welcome := &strings.Builder{}
	fmt.Fprintf(welcome, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", websocketAccept(key))
	frame := &strings.Builder{}
	err = writeWebSocketFrame(frame, 1, []byte(websocketWelcome), false)

	if err == nil {
		_, err = conn.Write([]byte(welcome.String() + frame.String()))
	}

	for err == nil {
		_ = conn.SetDeadline(time.Now().Add(commandTimeout))
		opcode, payload, readErr := readWebSocketFrame(buffered.Reader)

		if readErr != nil {
			return
		}

		switch opcode {
		case 1, 2:
			err = writeWebSocketFrame(conn, opcode, payload, false)
		case 9:
			err = writeWebSocketFrame(conn, 10, payload, false)
		case 8:
			_ = writeWebSocketFrame(conn, 8, payload, false)
			return
		}
	}
}

// the test binary as the test user's WebSocket client of host:port: the upgrade, then a text and a binary protobuf message, a ping and a close, each answered;
// it prints what came back
func talkWebSocket(address string) (report string, err error) {
	conn, err := net.DialTimeout("tcp", address, commandTimeout)

	if err != nil {
		return
	}

	defer func() { err = errors.Join(err, conn.Close()) }()
	err = conn.SetDeadline(time.Now().Add(commandTimeout))

	if err != nil {
		return
	}

	key := base64.StdEncoding.EncodeToString([]byte("decerter e2e key 16b"))
	_, err = fmt.Fprintf(conn, "GET /chat HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", address, key)

	if err != nil {
		return
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)

	if err != nil {
		return
	}

	// a 101 has no body, the frames come after its head on the same reader
	err = response.Body.Close()

	if err != nil {
		return
	}

	if (response.StatusCode != http.StatusSwitchingProtocols) || (response.Header.Get("Sec-WebSocket-Accept") != websocketAccept(key)) {
		err = fmt.Errorf("the server did not switch to WebSocket: %s", response.Status)
		return
	}

	answers := []string{}
	_, welcome, err := readWebSocketFrame(reader)
	answers = append(answers, string(welcome))
	sends := []struct {
		opcode  byte
		payload []byte
	}{
		{opcode: 1, payload: []byte(websocketText)},
		{opcode: 2, payload: protoString(1, websocketBinary)},
		{opcode: 9, payload: []byte("p")},
		{opcode: 8, payload: append(binary.BigEndian.AppendUint16(nil, 1000), "bye"...)},
	}

	for _, send := range sends {
		if err != nil {
			return
		}

		err = writeWebSocketFrame(conn, send.opcode, send.payload, true)

		if err != nil {
			return
		}

		opcode, payload, readErr := readWebSocketFrame(reader)
		err = readErr
		answers = append(answers, fmt.Sprintf("%d:%q", opcode, payload))
		// one frame each, so the reads of the flow are one frame or a few
		time.Sleep(20 * time.Millisecond)
	}

	report = strings.Join(answers, " ")
	return
}

// Test if the frames of the test user's WebSocket client and of the server after the HTTP/1.1 Upgrade decode as WebSocket by the Upgrade of the flow's
// exchange: the client's masked, the server's not, its first frame in the read of the 101, a binary message as protobuf, ping, pong and close; over the
// API and the same trees over MCP.
func TestDecodeWebSocketPositive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	session := startMCP(state, client.socket, state.TempDir(), false)
	clientPath := copyClient(state)
	address := startWebSocketServer(state)
	output, err := runGoClient(state.Context(), clientPath, "websocket", address)
	expected := fmt.Sprintf("%s 1:%q 2:%q 10:\"p\" 8:\"\\x03\\xe8bye\"", websocketWelcome, websocketText, protoString(1, websocketBinary))

	if (err != nil) || (output != expected) {
		state.Fatalf("Test of the WebSocket decode failed, the client should get every answer, output: %s, expected: %s, error: %v", output, expected, err)
	}

	_, port, _ := net.SplitHostPort(address)
	summaries, err := websocketSummaries(state, client, session, port)

	if err != nil {
		state.Fatalf("Test of the WebSocket decode failed, error: %s", err.Error())
	}

	parts := map[v1.Direction][]string{
		v1.UpDirection:   {`Text "` + websocketText + `"`, fmt.Sprintf("Binary %d bytes (protobuf)", len(protoString(1, websocketBinary))), "Ping", "Close 1000 Normal Closure"},
		v1.DownDirection: {`Text "` + websocketWelcome + `"`, `Text "` + websocketText + `"`, "Binary", "Pong", "Close 1000 Normal Closure"},
	}

	for direction, expectedParts := range parts {
		for _, part := range expectedParts {
			if !strings.Contains(summaries[direction], part) {
				state.Errorf("Test of the WebSocket decode failed, the frames going %s should have %q, summaries: %s", direction, part, summaries[direction])
			}
		}
	}
}

// the summaries of the WebSocket messages of the newest flow to port each way, once its close went both ways; every message after the upgrade request is WebSocket,
// the client's frames masked, and MCP gives the same tree
func websocketSummaries(state *testing.T, client apiClient, session *sdk.ClientSession, port string) (summaries map[v1.Direction]string, err error) {
	deadline := time.Now().Add(websocketWaitTimeout)
	messages := []v1.Message{}
	flowID := uint64(0)

	for time.Now().Before(deadline) {
		flows := v1.FlowList{}
		_, err = client.call(state.Context(), http.MethodGet, "/flows?limit=1&filter="+url.QueryEscape("tcp.dstport == "+port), nil, &flows)

		if (err == nil) && (len(flows.Flows) == 1) && (flows.Flows[0].State == v1.ClosedFlowState) {
			flowID = flows.Flows[0].ID
			list := v1.MessageList{}
			_, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/messages", flowID), nil, &list)
			messages = list.Messages
			break
		}

		time.Sleep(50 * time.Millisecond)
	}

	if (err != nil) || (len(messages) < 3) {
		err = fmt.Errorf("the flow to port %s should close with its messages, messages: %+v: %w", port, messages, errors.Join(err, os.ErrDeadlineExceeded))
		return
	}

	summaries = map[v1.Direction]string{}

	for index, message := range messages {
		decoded := v1.Decode{}
		status, callErr := client.call(state.Context(), http.MethodGet, fmt.Sprintf("/messages/%d/decode", message.ID), nil, &decoded)

		// the upgrade request goes before the exchange's 101
		if (callErr == nil) && (index == 0) && (message.Direction == v1.UpDirection) && (decoded.Protocol != "websocket") {
			continue
		}

		masks := map[string]bool{}

		for _, root := range decoded.Tree {
			if mask := findDecodeNode(root.Children, "websocket.mask"); mask != nil {
				masks[mask.Value] = true
			}
		}

		if (callErr != nil) || (status != http.StatusOK) || (decoded.Protocol != "websocket") || (decoded.Candidates[0].Reason != "the flow switched to WebSocket with an HTTP Upgrade") || (len(decodeErrors(decoded.Tree)) > 0) ||
			(len(masks) != 1) || !masks[map[v1.Direction]string{v1.UpDirection: "yes", v1.DownDirection: "no"}[message.Direction]] {
			err = errors.Join(err, fmt.Errorf("message %d going %s should be WebSocket, masked when the client sent it, status: %d, masks: %v, errors: %v, decode: %.300v, error: %w", message.ID, message.Direction, status, masks,
				decodeErrors(decoded.Tree), decoded, callErr))
			continue
		}

		summaries[message.Direction] += decoded.Summary + "; "

		if _, isSame := mcpDecode(state, session, "decode_message", map[string]any{"id": message.ID}, fmt.Sprintf("m%d-decode", message.ID), decoded); !isSame {
			err = errors.Join(err, fmt.Errorf("decode_message of message %d should be the API's tree", message.ID))
		}
	}

	return
}
