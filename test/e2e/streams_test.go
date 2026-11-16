// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/jackc/pgx/v5/pgproto3"
)

const (
	// the value of the Redis client: a bulk string of 100 KiB, written in pieces of 4 KiB with a pause, so decerter reads the command in many messages
	redisValueBytes int           = 100 << 10
	redisWriteBytes int           = 4 << 10
	redisWritePause time.Duration = 3 * time.Millisecond
	// the STUN magic cookie of RFC 8489
	stunCookie uint32 = 0x2112a442
	// how long a case waits for the flow of a client
	streamWaitTimeout time.Duration = 10 * time.Second
	// what the fake PostgreSQL server answers to its one query
	pgsqlQuery  string = "SELECT 1 AS one"
	pgsqlAnswer string = "1"
)

// Test if the test user's clients of Redis, SMTP and PostgreSQL through decerter decode as their protocol in the flow stream view, a Redis command of 100 KiB
// split over many reads as one value, and the same trees over MCP; and if a STUN binding over UDP decodes per message.
func TestDecodeStreamPositive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	session := startMCP(state, client.socket, state.TempDir(), false)
	clientPath := copyClient(state)
	cases := []struct {
		Name     string
		Mode     string
		Address  string
		Expected string
		Protocol string
		Up       []string
		Down     []string
	}{
		{Name: "redis", Mode: "redis", Address: startStreamServer(state, serveRedis), Expected: fmt.Sprintf("OK %d", redisValueBytes), Protocol: "resp",
			Up: []string{`Redis SET "big" "vvvv`, `Redis GET "big"`, "Redis QUIT"}, Down: []string{`Redis simple string "OK"`, "Redis bulk string 102400 bytes"}},
		{Name: "smtp", Mode: "smtp", Address: startStreamServer(state, serveSMTP), Expected: "sent", Protocol: "smtp",
			Up: []string{`SMTP EHLO "localhost"`, `SMTP MAIL "FROM:<a@example.com>`, "SMTP DATA", "SMTP mail data", "SMTP QUIT"}, Down: []string{`SMTP reply 220 "decerter.test ESMTP ready"`, "SMTP reply 250", "SMTP reply 354", "SMTP reply 221"}},
		{Name: "pgsql", Mode: "pgsql", Address: startStreamServer(state, servePostgres), Expected: "row " + pgsqlAnswer, Protocol: "pgsql",
			Up:   []string{`PostgreSQL StartupMessage 3.0 user="decerter"`, `PostgreSQL Query "` + pgsqlQuery + `"`, "PostgreSQL Terminate"},
			Down: []string{"PostgreSQL Authentication request Success", `PostgreSQL Row description 1 columns "one"`, "PostgreSQL Data row 1 columns", `PostgreSQL Command completion "SELECT 1"`, "PostgreSQL Ready for query idle"}},
	}

	for _, testCase := range cases {
		output, err := runGoClient(state.Context(), clientPath, testCase.Mode, testCase.Address)

		if (err != nil) || (output != testCase.Expected) {
			state.Errorf("Test of the %s stream failed, the client should get its answers, output: %q, error: %v", testCase.Name, output, err)
			continue
		}

		_, port, _ := net.SplitHostPort(testCase.Address)
		flowID, err := closedFlow(state, client, "tcp.dstport == "+port)

		if err != nil {
			state.Errorf("Test of the %s stream failed, error: %s", testCase.Name, err.Error())
			continue
		}

		for direction, parts := range map[v1.Direction][]string{v1.UpDirection: testCase.Up, v1.DownDirection: testCase.Down} {
			decoded := v1.Decode{}
			status, callErr := client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/decode?part=stream&direction=%s", flowID, direction), nil, &decoded)

			if (callErr != nil) || (status != http.StatusOK) || (decoded.Protocol != testCase.Protocol) || (decoded.Source != v1.StreamDecodeSource) || decoded.Cut || (len(decodeErrors(decoded.Tree)) > 0) {
				state.Errorf("Test of the %s stream failed, going %s it should decode as %s without errors, status: %d, errors: %v, decode: %.600v, error: %v", testCase.Name, direction, testCase.Protocol, status,
					decodeErrors(decoded.Tree), decoded, callErr)
				continue
			}

			for _, part := range parts {
				if !strings.Contains(decoded.Summary, part) {
					state.Errorf("Test of the %s stream failed, the summary going %s should have %q, summary: %s", testCase.Name, direction, part, decoded.Summary)
				}
			}

			if _, isSame := mcpDecode(state, session, "decode_flow", map[string]any{"id": flowID, "part": "stream", "direction": string(direction)}, fmt.Sprintf("f%d-%s-decode", flowID, direction), decoded); !isSame {
				state.Errorf("Test of the %s stream failed, decode_flow going %s should give the API's tree", testCase.Name, direction)
			}

			if (testCase.Name == "redis") && (direction == v1.UpDirection) {
				testSplitCommand(state, client, decoded)
			}
		}
	}

	testSTUN(state, client, clientPath)
}

// the Redis SET of 100 KiB came in several messages: in the stream it is one root over more than one segment, the first message alone goes on in the next read
func testSplitCommand(state *testing.T, client apiClient, decoded v1.Decode) {
	if (len(decoded.Tree) == 0) || (len(decoded.Segments) < 3) {
		state.Errorf("Test of the split Redis command failed, the stream should have the messages as segments, segments: %+v", decoded.Segments)
		return
	}

	root := decoded.Tree[0]
	covered := 0

	for _, segment := range decoded.Segments {
		if segment.Offset < root.Offset+root.Length {
			covered++
		}
	}

	if (root.Length <= redisValueBytes) || (covered < 2) || (findDecodeNode(root.Children, "resp.bulk_string") == nil) {
		state.Errorf("Test of the split Redis command failed, the SET should be one value over several messages, root: %s %d+%d, messages: %d", root.Name, root.Offset, root.Length, covered)
		return
	}

	first := v1.Decode{}
	_, err := client.call(state.Context(), http.MethodGet, fmt.Sprintf("/messages/%d/decode", decoded.Segments[0].MessageID), nil, &first)

	if (err != nil) || !strings.Contains(strings.Join(decodeErrors(first.Tree), "; "), "continues in the next read") {
		state.Errorf("Test of the split Redis command failed, the first message alone should go on in the next read, errors: %v, error: %v", decodeErrors(first.Tree), err)
	}
}

// a STUN Binding Request of the test user and the server's answer each decode as STUN, the answer with the XOR-MAPPED-ADDRESS of the client
func testSTUN(state *testing.T, client apiClient, clientPath string) {
	address := startSTUNServer(state)
	output, err := runGoClient(state.Context(), clientPath, "stun", address)

	if (err != nil) || !strings.HasPrefix(output, "mapped 127.0.0.1:") {
		state.Errorf("Test of STUN failed, the client should get its mapped address, output: %q, error: %v", output, err)
		return
	}

	_, port, _ := net.SplitHostPort(address)
	messages, err := messagesBothWays(state, client, "udp.dstport == "+port+" && proc.uid == "+strconv.Itoa(int(testUser.UID)))

	if err != nil {
		state.Errorf("Test of STUN failed, error: %s", err.Error())
		return
	}

	for _, message := range messages {
		decoded := v1.Decode{}
		_, callErr := client.call(state.Context(), http.MethodGet, fmt.Sprintf("/messages/%d/decode", message.ID), nil, &decoded)
		expected := map[v1.Direction]string{v1.UpDirection: "STUN Binding Request", v1.DownDirection: "STUN Binding Success Response " + strings.TrimPrefix(output, "mapped ")}[message.Direction]

		if (callErr != nil) || (decoded.Protocol != "stun") || (len(decodeErrors(decoded.Tree)) > 0) || !strings.HasPrefix(decoded.Summary, expected) {
			state.Errorf("Test of STUN failed, message %d going %s should decode as %q, summary: %s, errors: %v, error: %v", message.ID, message.Direction, expected, decoded.Summary, decodeErrors(decoded.Tree), callErr)
		}
	}
}

// the messages of the newest flow the filter takes, once it has one each way
func messagesBothWays(state *testing.T, client apiClient, filter string) (messages []v1.Message, err error) {
	deadline := time.Now().Add(streamWaitTimeout)

	for time.Now().Before(deadline) {
		flows := v1.FlowList{}
		_, err = client.call(state.Context(), http.MethodGet, "/flows?limit=1&filter="+url.QueryEscape(filter), nil, &flows)

		if (err == nil) && (len(flows.Flows) == 1) && (flows.Flows[0].Up.Messages > 0) && (flows.Flows[0].Down.Messages > 0) {
			list := v1.MessageList{}
			_, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/messages", flows.Flows[0].ID), nil, &list)
			messages = list.Messages
			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	err = fmt.Errorf("no flow %q with messages both ways within %s: %w", filter, streamWaitTimeout, errors.Join(os.ErrDeadlineExceeded, err))
	return
}

// the id of the newest flow the filter takes once it closed
func closedFlow(state *testing.T, client apiClient, filter string) (flowID uint64, err error) {
	deadline := time.Now().Add(streamWaitTimeout)

	for time.Now().Before(deadline) {
		flows := v1.FlowList{}
		_, err = client.call(state.Context(), http.MethodGet, "/flows?limit=1&filter="+url.QueryEscape(filter), nil, &flows)

		if (err == nil) && (len(flows.Flows) == 1) && (flows.Flows[0].State == v1.ClosedFlowState) {
			flowID = flows.Flows[0].ID
			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	err = fmt.Errorf("no closed flow %q within %s: %w", filter, streamWaitTimeout, errors.Join(os.ErrDeadlineExceeded, err))
	return
}

// a tcp server on 127.0.0.1 that serves each connection with serve until the test ends
func startStreamServer(state *testing.T, serve func(connection net.Conn) (err error)) (address string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		state.Fatalf("Could not listen, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil {
			state.Logf("Could not close the listener, error: %s", closeErr.Error())
		}
	})

	// accept loop
	go func() {
		for {
			connection, acceptErr := listener.Accept()

			if acceptErr != nil {
				return
			}

			// one connection
			go func() {
				serveErr := serve(connection)

				if closeErr := connection.Close(); (serveErr != nil) || (closeErr != nil) {
					state.Logf("The stream server stopped, error: %v", errors.Join(serveErr, closeErr))
				}
			}()
		}
	}()

	address = listener.Addr().String()
	return
}

// a command of RESP: an array of bulk strings
func respArray(words ...string) (data []byte) {
	data = []byte("*" + strconv.Itoa(len(words)) + "\r\n")

	for _, word := range words {
		data = append(data, "$"+strconv.Itoa(len(word))+"\r\n"+word+"\r\n"...)
	}

	return
}

// write data in pieces with a pause between them
func writePieces(writer io.Writer, data []byte) (err error) {
	for offset := 0; offset < len(data); offset += redisWriteBytes {
		if _, err = writer.Write(data[offset:min(len(data), offset+redisWriteBytes)]); err != nil {
			return
		}

		time.Sleep(redisWritePause)
	}

	return
}

// one array of bulk strings from the reader
func readRESPArray(reader *bufio.Reader) (words []string, err error) {
	line, err := reader.ReadString('\n')

	if err != nil {
		return
	}

	count, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))

	if err != nil {
		return
	}

	for range count {
		header, headerErr := reader.ReadString('\n')

		if err = headerErr; err != nil {
			return
		}

		size, sizeErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(header, "$")))

		if err = sizeErr; err != nil {
			return
		}

		word := make([]byte, size+2)

		if _, err = io.ReadFull(reader, word); err != nil {
			return
		}

		words = append(words, string(word[:size]))
	}

	return
}

// a Redis server of SET, GET and QUIT; the GET answer goes out in pieces too
func serveRedis(connection net.Conn) (err error) {
	reader := bufio.NewReader(connection)
	values := map[string]string{}

	for {
		words, readErr := readRESPArray(reader)

		if err = readErr; err != nil {
			return
		}

		switch strings.ToUpper(words[0]) {
		case "SET":
			values[words[1]] = words[2]
			_, err = io.WriteString(connection, "+OK\r\n")
		case "GET":
			value := values[words[1]]
			err = writePieces(connection, []byte("$"+strconv.Itoa(len(value))+"\r\n"+value+"\r\n"))
		case "QUIT":
			_, err = io.WriteString(connection, "+OK\r\n")
			return
		default:
			_, err = io.WriteString(connection, "-ERR unknown command\r\n")
		}

		if err != nil {
			return
		}
	}
}

// the Redis client: SET of 100 KiB in pieces, GET of it, QUIT; prints OK and the length it got back
func talkRedis(address string) (report string, err error) {
	connection, err := net.DialTimeout("tcp", address, commandTimeout)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, connection.Close())
	}()

	reader := bufio.NewReader(connection)
	value := strings.Repeat("v", redisValueBytes)

	if err = writePieces(connection, respArray("SET", "big", value)); err != nil {
		return
	}

	if line, readErr := reader.ReadString('\n'); (readErr != nil) || (line != "+OK\r\n") {
		err = fmt.Errorf("SET answered %q: %w", line, readErr)
		return
	}

	if _, err = connection.Write(respArray("GET", "big")); err != nil {
		return
	}

	header, err := reader.ReadString('\n')

	if err != nil {
		return
	}

	size, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(header, "$")))

	if err != nil {
		return
	}

	answer := make([]byte, size+2)

	if _, err = io.ReadFull(reader, answer); err != nil {
		return
	}

	if _, err = connection.Write(respArray("QUIT")); err != nil {
		return
	}

	if line, readErr := reader.ReadString('\n'); (readErr != nil) || (line != "+OK\r\n") {
		err = fmt.Errorf("QUIT answered %q: %w", line, readErr)
		return
	}

	report = fmt.Sprintf("OK %d", size)
	return
}

// an SMTP server that takes one mail
func serveSMTP(connection net.Conn) (err error) {
	reader := bufio.NewReader(connection)
	reply := func(text string) (replyErr error) {
		_, replyErr = io.WriteString(connection, text+"\r\n")
		return
	}

	if err = reply("220 decerter.test ESMTP ready"); err != nil {
		return
	}

	for {
		line, readErr := reader.ReadString('\n')

		if err = readErr; err != nil {
			return
		}

		command, _, _ := strings.Cut(strings.ToUpper(strings.TrimSpace(line)), " ")

		switch command {
		case "EHLO":
			err = reply("250-decerter.test\r\n250-SIZE 10485760\r\n250 8BITMIME")
		case "MAIL", "RCPT":
			err = reply("250 OK")
		case "DATA":
			if err = reply("354 end with a lone dot"); err != nil {
				return
			}

			for {
				body, bodyErr := reader.ReadString('\n')

				if err = bodyErr; err != nil {
					return
				}

				if body == ".\r\n" {
					break
				}
			}

			err = reply("250 OK queued")
		case "QUIT":
			err = reply("221 bye")
			return
		default:
			err = reply("502 not implemented")
		}

		if err != nil {
			return
		}
	}
}

// the SMTP client of net/smtp: one mail with a few header fields
func talkSMTP(address string) (report string, err error) {
	connection, err := net.DialTimeout("tcp", address, commandTimeout)

	if err != nil {
		return
	}

	mail, err := smtp.NewClient(connection, "decerter.test")

	if err != nil {
		err = errors.Join(err, connection.Close())
		return
	}

	// QUIT closes the connection, a failure before it closes it here
	defer func() {
		if err != nil {
			err = errors.Join(err, mail.Close())
		}
	}()

	if err = mail.Hello("localhost"); err != nil {
		return
	}

	if err = mail.Mail("a@example.com"); err != nil {
		return
	}

	if err = mail.Rcpt("b@example.com"); err != nil {
		return
	}

	body, err := mail.Data()

	if err != nil {
		return
	}

	if _, err = io.WriteString(body, "Subject: stream test\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nhello through decerter\r\n.dot line\r\n"); err != nil {
		return
	}

	if err = body.Close(); err != nil {
		return
	}

	if err = mail.Quit(); err != nil {
		return
	}

	report = "sent"
	return
}

// a PostgreSQL server of pgproto3: trust auth, one query with one row
func servePostgres(connection net.Conn) (err error) {
	backend := pgproto3.NewBackend(connection, connection)

	if _, err = backend.ReceiveStartupMessage(); err != nil {
		return
	}

	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.2"})
	backend.Send(&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: []byte{1, 2, 3, 4}})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	if err = backend.Flush(); err != nil {
		return
	}

	for {
		message, receiveErr := backend.Receive()

		if err = receiveErr; err != nil {
			return
		}

		switch message.(type) {
		case *pgproto3.Query:
			backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("one"), TableOID: 0, TableAttributeNumber: 0, DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1, Format: 0}}})
			backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte(pgsqlAnswer)}})
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			err = backend.Flush()
		case *pgproto3.Terminate:
			return
		}

		if err != nil {
			return
		}
	}
}

// the PostgreSQL client of pgproto3: startup, one simple query, terminate; prints the row it got
func talkPostgres(address string) (report string, err error) {
	connection, err := net.DialTimeout("tcp", address, commandTimeout)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, connection.Close())
	}()

	if err = connection.SetDeadline(time.Now().Add(commandTimeout)); err != nil {
		return
	}

	frontend := pgproto3.NewFrontend(connection, connection)
	frontend.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "decerter"}})

	if err = frontend.Flush(); err != nil {
		return
	}

	if err = waitReady(frontend, nil); err != nil {
		return
	}

	frontend.Send(&pgproto3.Query{String: pgsqlQuery})

	if err = frontend.Flush(); err != nil {
		return
	}

	rows := []string{}

	if err = waitReady(frontend, &rows); err != nil {
		return
	}

	frontend.Send(&pgproto3.Terminate{})

	if err = frontend.Flush(); err != nil {
		return
	}

	report = "row " + strings.Join(rows, ",")
	return
}

// the server's messages up to ReadyForQuery, the first value of each DataRow into rows
func waitReady(frontend *pgproto3.Frontend, rows *[]string) (err error) {
	for {
		message, receiveErr := frontend.Receive()

		if err = receiveErr; err != nil {
			return
		}

		switch received := message.(type) {
		case *pgproto3.DataRow:
			if (rows != nil) && (len(received.Values) > 0) {
				*rows = append(*rows, string(received.Values[0]))
			}
		case *pgproto3.ErrorResponse:
			err = fmt.Errorf("the server answered an error: %s", received.Message)
			return
		case *pgproto3.ReadyForQuery:
			return
		}
	}
}

// a STUN server on udp 127.0.0.1 that answers each Binding Request with the sender's XOR-MAPPED-ADDRESS
func startSTUNServer(state *testing.T) (address string) {
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")

	if err != nil {
		state.Fatalf("Could not listen on udp, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if closeErr := connection.Close(); closeErr != nil {
			state.Logf("Could not close the STUN server, error: %s", closeErr.Error())
		}
	})

	// answer loop
	go func() {
		buffer := make([]byte, 1500)

		for {
			count, peer, readErr := connection.ReadFrom(buffer)

			if readErr != nil {
				return
			}

			if (count < 20) || (binary.BigEndian.Uint16(buffer) != 0x0001) {
				continue
			}

			sender := peer.(*net.UDPAddr)
			attribute := binary.BigEndian.AppendUint16(nil, 0x0020)
			attribute = binary.BigEndian.AppendUint16(attribute, 8)
			attribute = append(attribute, 0, 1)
			attribute = binary.BigEndian.AppendUint16(attribute, uint16(sender.Port)^uint16(stunCookie>>16))
			attribute = binary.BigEndian.AppendUint32(attribute, binary.BigEndian.Uint32(sender.IP.To4())^stunCookie)
			answer := binary.BigEndian.AppendUint16(nil, 0x0101)
			answer = binary.BigEndian.AppendUint16(answer, uint16(len(attribute)))
			answer = append(answer, buffer[4:20]...)
			answer = append(answer, attribute...)

			if _, writeErr := connection.WriteTo(answer, peer); writeErr != nil {
				return
			}
		}
	}()

	address = connection.LocalAddr().String()
	return
}

// the STUN client: one Binding Request, prints the mapped address of the answer
func talkSTUN(address string) (report string, err error) {
	connection, err := net.DialTimeout("udp", address, commandTimeout)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, connection.Close())
	}()

	if err = connection.SetDeadline(time.Now().Add(commandTimeout)); err != nil {
		return
	}

	transaction := make([]byte, 12)

	if _, err = rand.Read(transaction); err != nil {
		return
	}

	request := binary.BigEndian.AppendUint16(nil, 0x0001)
	request = binary.BigEndian.AppendUint16(request, 0)
	request = binary.BigEndian.AppendUint32(request, stunCookie)
	request = append(request, transaction...)

	if _, err = connection.Write(request); err != nil {
		return
	}

	answer := make([]byte, 1500)
	count, err := connection.Read(answer)

	if err != nil {
		return
	}

	if (count < 32) || (binary.BigEndian.Uint16(answer) != 0x0101) || (string(answer[8:20]) != string(transaction)) || (binary.BigEndian.Uint16(answer[20:]) != 0x0020) {
		err = fmt.Errorf("no Binding Success Response with XOR-MAPPED-ADDRESS: %x", answer[:count])
		return
	}

	port := binary.BigEndian.Uint16(answer[26:]) ^ uint16(stunCookie>>16)
	ip := binary.BigEndian.AppendUint32(nil, binary.BigEndian.Uint32(answer[28:])^stunCookie)
	report = "mapped " + net.JoinHostPort(net.IP(ip).String(), strconv.Itoa(int(port)))
	return
}
