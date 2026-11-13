// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/intercept"
)

const (
	// the test binary runs as the Go HTTP/2 client when this names a mode: large or grpc
	clientCommandEnvironment string = "DECERTER_E2E_CLIENT"
	// the gRPC unary call of the test server and the message the clients send
	grpcPath    string = "/decerter.test.Echo/Say"
	grpcRequest string = "hello grpc"
	// /large answers this many bytes in pieces of largePiece, each flushed on its own
	largeBytes int = 2 << 20
	largePiece int = 64 << 10
	// a field curl sends in every request: after the first, the dynamic table carries it
	repeatedField string = "x-decerter-repeat"
	repeatedValue string = "one value for every request"
)

// the HTTP/2 frames of the connections of a plain test server: WINDOW_UPDATEs it read, DATA frames it wrote
type frameCounts struct {
	windowUpdates atomic.Int64
	data          atomic.Int64
}

// a listener whose connections count their frames
type frameListener struct {
	net.Listener
	counts *frameCounts
}

// the frame headers of one direction of a connection: buffer holds what came of the next frame, skip the bytes of the preface still to come
type frameTap struct {
	buffer []byte
	skip   int
}

// a connection that counts the frames it reads and writes, each direction is used by one goroutine
type frameConn struct {
	net.Conn
	counts  *frameCounts
	read    frameTap
	written frameTap
}

func (listener frameListener) Accept() (conn net.Conn, err error) {
	inner, err := listener.Listener.Accept()

	if err != nil {
		return
	}

	conn = &frameConn{Conn: inner, counts: listener.counts, read: frameTap{buffer: nil, skip: len(http2.ClientPreface)}, written: frameTap{buffer: nil, skip: 0}}
	return
}

func (conn *frameConn) Read(buffer []byte) (count int, err error) {
	count, err = conn.Conn.Read(buffer)

	for _, frameType := range conn.read.feed(buffer[:count]) {
		if frameType == http2.FrameWindowUpdate {
			conn.counts.windowUpdates.Add(1)
		}
	}

	return
}

func (conn *frameConn) Write(buffer []byte) (count int, err error) {
	count, err = conn.Conn.Write(buffer)

	for _, frameType := range conn.written.feed(buffer[:count]) {
		if frameType == http2.FrameData {
			conn.counts.data.Add(1)
		}
	}

	return
}

// the types of the frames the bytes complete
func (tap *frameTap) feed(data []byte) (types []http2.FrameType) {
	tap.buffer = append(tap.buffer, data...)
	skipped := min(tap.skip, len(tap.buffer))
	tap.buffer = tap.buffer[skipped:]
	tap.skip -= skipped

	for len(tap.buffer) >= 9 {
		length := int(tap.buffer[0])<<16 | int(tap.buffer[1])<<8 | int(tap.buffer[2])

		if len(tap.buffer) < 9+length {
			return
		}

		types = append(types, http2.FrameType(tap.buffer[3]))
		tap.buffer = tap.buffer[9+length:]
	}

	return
}

// the pieces of /large
func largeBody() (pieces []string) {
	piece := strings.Repeat("0123456789abcdef", largePiece/16)

	for range largeBytes / largePiece {
		pieces = append(pieces, piece)
	}

	return
}

// a gRPC message with its 5-byte prefix, not compressed
func grpcFrame(message string) (frame []byte) {
	frame = binary.BigEndian.AppendUint32([]byte{0}, uint32(len(message)))
	frame = append(frame, message...)
	return
}

// a gRPC unary call: the request is one message, the answer one message "echo: " and the request's, grpc-status 0 in the trailers
func (server testServer) answerGRPC(writer http.ResponseWriter, request *http.Request, received receivedRequest) {
	body, readErr := io.ReadAll(request.Body)

	if (readErr != nil) || (len(body) < 5) || (int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5) {
		http.Error(writer, "no grpc message", http.StatusBadRequest)
		return
	}

	received.Body = string(body[5:])

	select {
	case server.requests <- received:
	default:
	}

	writer.Header().Set("Content-Type", "application/grpc")
	writer.Header().Set("Trailer", "Grpc-Status")
	_, err := writer.Write(grpcFrame("echo: " + received.Body))

	if err != nil {
		return
	}

	writer.Header().Set("Grpc-Status", "0")
}

// the test binary as the test user's Go HTTP/2 client of one URL, or its udp client of one host:port: large prints the protocol, length and SHA-256 of the body, grpc makes the unary call and prints the answer and grpc-status
// 64 KiB windows and 16 KiB frames make a large body many DATA frames and WINDOW_UPDATEs, a 64 KiB HPACK table makes the server's table grow
func runClient(mode string, arguments []string) (code int) {
	if len(arguments) != 1 {
		fmt.Fprintln(os.Stderr, "usage: the URL of the server")
		code = 2
		return
	}

	target := arguments[0]

	// the udp mode sends datagrams, not http
	if mode == "udp" {
		fmt.Print(sendUDP(target))
		return
	}

	protocols := &http.Protocols{}

	if strings.HasPrefix(target, "https:") {
		protocols.SetHTTP2(true)
	} else {
		protocols.SetUnencryptedHTTP2(true)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		Protocols:       protocols,
		HTTP2:           &http.HTTP2Config{MaxReceiveBufferPerConnection: 65535, MaxReceiveBufferPerStream: 65535, MaxReadFrameSize: 16384, MaxDecoderHeaderTableSize: 65536},
	}
	client := &http.Client{Transport: transport, Timeout: commandTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	output := ""
	var err error

	switch mode {
	case "large":
		output, err = getLarge(ctx, client, target)
	case "grpc":
		output, err = callGRPC(ctx, client, target)
	case "edit":
		output, err = getEdits(ctx, client, target)
	default:
		err = fmt.Errorf("unknown client mode %q", mode)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		code = 1
		return
	}

	fmt.Print(output)
	return
}

func getLarge(ctx context.Context, client *http.Client, target string) (output string, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)

	if err != nil {
		return
	}

	response, err := client.Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	hash := sha256.New()
	length, err := io.Copy(hash, response.Body)

	if err != nil {
		return
	}

	output = fmt.Sprintf("%s %d %x", response.Proto, length, hash.Sum(nil))
	return
}

func callGRPC(ctx context.Context, client *http.Client, target string) (output string, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(grpcFrame(grpcRequest)))

	if err != nil {
		return
	}

	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("Te", "trailers")
	response, err := client.Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return
	}

	if len(body) < 5 {
		err = fmt.Errorf("no grpc message in %q", body)
		return
	}

	output = fmt.Sprintf("%s %s status=%s", response.Proto, body[5:], response.Trailer.Get("Grpc-Status"))
	return
}

// the test binary copied where the test user may run it, removed when the test ends
func copyClient(state *testing.T) (path string) {
	executable, err := os.Executable()

	if err != nil {
		state.Fatalf("Could not find the test binary, error: %s", err.Error())
	}

	directory, err := os.MkdirTemp("", "decerter-e2e-client-")

	if err != nil {
		state.Fatalf("Could not make a directory for the client, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if removeErr := os.RemoveAll(directory); removeErr != nil {
			state.Errorf("Could not remove the client, error: %s", removeErr.Error())
		}
	})

	path = filepath.Join(directory, "client")
	data, err := os.ReadFile(executable)

	if err == nil {
		err = errors.Join(os.Chmod(directory, 0o755), os.WriteFile(path, data, 0o755))
	}

	if err != nil {
		state.Fatalf("Could not copy the client, error: %s", err.Error())
	}

	return
}

// run the Go client as the test user
func runGoClient(ctx context.Context, path string, mode string, target string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, path, target)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: testUser.UID, Gid: testUser.GID, Groups: []uint32{}, NoSetGroups: false}}
	command.Dir = "/"
	command.Env = []string{clientCommandEnvironment + "=" + mode, "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()

	if err != nil {
		err = fmt.Errorf("go client %s %s: %w: %s", mode, target, err, strings.TrimSpace(stderr.String()))
		return
	}

	output = stdout.String()
	return
}

// the newest flow to the server with one complete exchange: its only exchange
func lastExchange(state *testing.T, client apiClient, server testServer) (exchange v1.Exchange, err error) {
	_, exchanges, err := flowExchanges(state, client, server, 1)

	if (err == nil) && (len(exchanges) != 1) {
		err = fmt.Errorf("the flow should have one exchange, exchanges: %+v", exchanges)
	}

	if err == nil {
		exchange = exchanges[0]
	}

	return
}

func headerOf(headers []v1.Header, name string) (value string) {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			value = header.Value
			return
		}
	}

	return
}

// Test if the API shows HTTP/2 as exchanges over TLS 1.2 and 1.3 with ALPN h2 and over h2c with prior knowledge: curl's three parallel requests on one connection with a field
// the dynamic table repeats, a 2 MiB response over many DATA frames and WINDOW_UPDATEs, and a gRPC unary call (curl over TLS, the Go client over h2c, since Go's own TLS gives
// decerter no secrets); a rule of layer http that finds nothing changes none of it, though every message goes through it.
func TestHTTP2Positive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	events := client.subscribe(state)
	clientPath := copyClient(state)
	ruleRequest := v1.RuleRequest{Filter: "", Direction: v1.UpDirection, Layer: v1.HTTPLayer, Find: v1.Value{Type: v1.TextValueType, Value: "/nowhere"}, Replace: v1.Value{Type: v1.TextValueType, Value: "/z"}}
	status, err := client.call(state.Context(), http.MethodPost, "/rules", ruleRequest, nil)

	if (err != nil) || (status != http.StatusCreated) {
		state.Fatalf("Test of the http/2 view failed, cannot add the rule, status: %d, error: %v", status, err)
	}

	large := sha256.Sum256([]byte(strings.Join(largeBody(), "")))
	configs := []serverConfig{
		{Certificate: &rsaCertificate, Version: tls.VersionTLS12, HTTP2: true},
		{Certificate: &ecdsaCertificate, Version: tls.VersionTLS13, HTTP2: true},
		{Certificate: nil, HTTP2: true, Frames: &frameCounts{}},
	}

	for _, config := range configs {
		server := startServer(state, config)
		testCase := curlCase{Name: server.URL, Server: config, Suite: "", Expected: receivedRequest{}}
		scheme := strings.SplitN(server.URL, ":", 2)[0]
		host := strings.TrimSuffix(strings.SplitN(server.URL, "//", 2)[1], "/")

		// three requests at once, multiplexed on one connection
		arguments := append(curlArguments(testCase, server.URL+"a"), "--parallel", "--header", repeatedField+": "+repeatedValue, server.URL+"b", server.URL+"c")
		output, err := runCurl(state.Context(), testUser, arguments)
		paths := []string{}

		for range 3 {
			request, receivedErr := server.received()
			err = errors.Join(err, receivedErr)
			paths = append(paths, request.Path)

			if request.Proto != "HTTP/2.0" {
				err = errors.Join(err, fmt.Errorf("the server got %s", request.Proto))
			}
		}

		slices.Sort(paths)

		if (err != nil) || (len(output) != 6) || !slices.Equal(paths, []string{"/a", "/b", "/c"}) {
			state.Errorf("Test of the http/2 view failed, %s, three parallel requests should reach the server unchanged, curl: %q, server: %v, error: %v", server.URL, output, paths, err)
			return
		}

		flowID, exchanges, err := flowExchanges(state, client, server, 3)
		streams := []uint32{}

		for _, exchange := range exchanges {
			request, response := exchange.Request, exchange.Response
			streams = append(streams, exchange.StreamID)

			if (err == nil) && ((exchange.Protocol != "HTTP/2") || (exchange.StreamID%2 != 1) || (request == nil) || (response == nil) || (request.Method != "GET") || (request.URL != scheme+"://"+host+request.Target) ||
				(headerOf(request.Headers, repeatedField) != repeatedValue) || (headerOf(request.Headers, ":authority") != host) || (response.Status != 200) || (response.BodyLength != len(request.Target)) ||
				(response.Framing != v1.FramesFraming) || (request.State != v1.CompleteHTTPState) || (response.State != v1.CompleteHTTPState) || request.Edited || (request.Note != "")) {
				err = fmt.Errorf("exchange %+v, request: %+v, response: %+v", exchange, request, response)
			}
		}

		slices.Sort(streams)

		if (err != nil) || (len(exchanges) != 3) || (len(slices.Compact(streams)) != 3) {
			state.Errorf("Test of the http/2 view failed, %s, flow %d should have the three streams as exchanges, streams: %v, error: %v", server.URL, flowID, streams, err)
			return
		}

		// a large response and a gRPC call: the Go client on h2c, curl over TLS (it prints the answer's message with its prefix, the history has its trailers)
		largeOutput, grpcOutput := "", ""
		expectedLarge, expectedGRPC := fmt.Sprintf("HTTP/2.0 %d %x", largeBytes, large), "HTTP/2.0 echo: "+grpcRequest+" status=0"
		var largeErr, grpcErr error

		if config.Certificate == nil {
			largeOutput, largeErr = runGoClient(state.Context(), clientPath, "large", server.URL+"large")
			grpcOutput, grpcErr = runGoClient(state.Context(), clientPath, "grpc", strings.TrimSuffix(server.URL, "/")+grpcPath)
		} else {
			body, curlErr := runCurl(state.Context(), testUser, curlArguments(testCase, server.URL+"large"))
			largeOutput, largeErr = fmt.Sprintf("HTTP/2.0 %d %x", len(body), sha256.Sum256([]byte(body))), curlErr
			grpcArguments := append([]string{"-q", "--silent", "--show-error", "--max-time", curlMaxTime}, curlArguments(testCase, strings.TrimSuffix(server.URL, "/")+grpcPath)...)
			grpcArguments = append(grpcArguments, "--header", "content-type: application/grpc", "--header", "te: trailers", "--data-binary", "@-")
			grpcOutput, grpcErr = runAsUser(state.Context(), testUser, string(grpcFrame(grpcRequest)), curlPath, grpcArguments...)
			expectedGRPC = string(grpcFrame("echo: " + grpcRequest))
		}

		if (largeErr != nil) || (grpcErr != nil) || (largeOutput != expectedLarge) || (grpcOutput != expectedGRPC) {
			state.Errorf("Test of the http/2 view failed, %s, large: %q, grpc: %q, error: %v", server.URL, largeOutput, grpcOutput, errors.Join(largeErr, grpcErr))
			return
		}

		// the requests of the large body and of the call reached the server in order
		_, receivedErr := server.received()
		grpcReceived, grpcReceivedErr := server.received()

		if err = errors.Join(receivedErr, grpcReceivedErr); (err != nil) || (grpcReceived.Body != grpcRequest) {
			state.Errorf("Test of the http/2 view failed, %s, the server should get the call, request: %+v, error: %v", server.URL, grpcReceived, err)
			return
		}

		if config.Frames != nil && ((config.Frames.windowUpdates.Load() < 16) || (config.Frames.data.Load() < 100)) {
			state.Errorf("Test of the http/2 view failed, %s, the large body should take many frames, WINDOW_UPDATE: %d, DATA: %d", server.URL, config.Frames.windowUpdates.Load(), config.Frames.data.Load())
			return
		}

		// the exchanges: the large body counted whole and kept up to the flow's limit, the call with its messages and trailers
		exchange, err := lastExchange(state, client, server)

		if (err != nil) || (exchange.Request == nil) || (exchange.Request.Target != grpcPath) || (exchange.Response == nil) {
			state.Errorf("Test of the http/2 view failed, %s, the gRPC call should be an exchange, exchange: %+v, error: %v", server.URL, exchange, err)
			return
		}

		request, response := exchange.Request, exchange.Response

		if !slices.Equal(request.GRPCMessages, []v1.GRPCMessage{{Offset: 0, Length: uint32(len(grpcRequest)), Compressed: false}}) || !slices.Equal(response.GRPCMessages, []v1.GRPCMessage{{Offset: 0, Length: uint32(len("echo: " + grpcRequest)), Compressed: false}}) ||
			(headerOf(response.Trailers, "grpc-status") != "0") || (response.State != v1.CompleteHTTPState) || (request.BodyLength != 5+len(grpcRequest)) {
			state.Errorf("Test of the http/2 view failed, %s, the gRPC call should list its messages, request: %+v, response: %+v", server.URL, request, response)
			return
		}

		flows := v1.FlowList{}
		_, err = client.call(state.Context(), http.MethodGet, "/flows?filter="+url.QueryEscape(fmt.Sprintf(`tcp.dstport == %s && http.request.uri == "/large"`, serverPortOf(server))), nil, &flows)
		exchanges = nil

		if (err == nil) && (len(flows.Flows) == 1) {
			list := v1.ExchangeList{}
			_, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/exchanges", flows.Flows[0].ID), nil, &list)
			exchanges = list.Exchanges
		}

		if (err != nil) || (len(exchanges) != 1) || (exchanges[0].Response == nil) || (exchanges[0].Response.BodyLength != largeBytes) || (exchanges[0].Response.StoredLength == 0) ||
			(exchanges[0].Response.StoredLength >= largeBytes) || (exchanges[0].Response.State != v1.CompleteHTTPState) {
			state.Errorf("Test of the http/2 view failed, %s, the large response should be counted whole, flows: %+v, exchanges: %+v, error: %v", server.URL, flows, exchanges, err)
			return
		}
	}

	if len(events.wait(state, v1.ExchangeEventType, 15)) < 15 {
		state.Errorf("Test of the http/2 view failed, the event stream should tell the exchanges")
		return
	}

	// the three parallel flows by their stream and path, and the rule changed nothing
	for filterText, expected := range map[string]int{`http2.streamid == 5 && http.request.uri in {"/a" "/b" "/c"} && http.user_agent contains "curl"`: len(configs), `http.request.uri == "/z"`: 0} {
		flows := v1.FlowList{}
		_, err = client.call(state.Context(), http.MethodGet, "/flows?filter="+url.QueryEscape(filterText), nil, &flows)

		if (err != nil) || (len(flows.Flows) != expected) {
			state.Errorf("Test of the http/2 view failed, the filter %s should take %d flows, flows: %d, error: %v", filterText, expected, len(flows.Flows), err)
			return
		}
	}
}

// Test if --decrypt shows the exchanges of an HTTP/2 flow over TLS 1.3, read from the observed copies.
func TestHTTP2DecryptPositive(state *testing.T) {
	client := startAPIDecerter(state, DecryptDecerterMode, nil)
	config := serverConfig{Certificate: &ecdsaCertificate, Version: tls.VersionTLS13, HTTP2: true}
	err := testCurl(state, testUser, curlCase{Name: "decrypt h2", Server: config, Suite: "", Expected: receivedRequest{Path: "/", Proto: "HTTP/2.0", Version: tls.VersionTLS13, CipherSuite: 0}})

	if err != nil {
		state.Fatalf("Test of the http/2 view with --decrypt failed, error: %s", err.Error())
	}

	flows := v1.FlowList{}
	_, err = client.call(state.Context(), http.MethodGet, "/flows?filter="+url.QueryEscape(`tls.alpn == "h2"`), nil, &flows)

	if (err != nil) || (len(flows.Flows) != 1) {
		state.Fatalf("Test of the http/2 view with --decrypt failed, one flow should be listed, flows: %+v, error: %v", flows, err)
	}

	deadline := time.Now().Add(holdArrival)
	exchanges := v1.ExchangeList{}

	for time.Now().Before(deadline) {
		_, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/exchanges", flows.Flows[0].ID), nil, &exchanges)

		if (err == nil) && (len(exchanges.Exchanges) == 1) && (exchanges.Exchanges[0].Response != nil) && (exchanges.Exchanges[0].Response.State == v1.CompleteHTTPState) {
			break
		}

		time.Sleep(holdPoll)
	}

	if (err != nil) || (len(exchanges.Exchanges) != 1) || (exchanges.Exchanges[0].Protocol != "HTTP/2") || (exchanges.Exchanges[0].StreamID != 1) || (exchanges.Exchanges[0].Request.Method != "GET") ||
		(exchanges.Exchanges[0].Response == nil) || (exchanges.Exchanges[0].Response.Status != 200) || (exchanges.Exchanges[0].Response.BodyLength != 1) || (exchanges.Exchanges[0].Request.Note != "") {
		state.Errorf("Test of the http/2 view with --decrypt failed, the flow should have its exchange, exchanges: %+v, error: %v", exchanges, err)
		return
	}
}

// Test if HTTP/1.1 to a server that offers h2 stays HTTP/1.1 without a stream, http2.streamid does not take it, and another user's HTTP/2 flow is not in the history.
func TestHTTP2Negative(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	config := serverConfig{Certificate: &rsaCertificate, Version: tls.VersionTLS13, HTTP2: true}
	server := startServer(state, config)
	output, err := runCurl(state.Context(), testUser, curlArguments(curlCase{Name: "http/1.1", Server: serverConfig{Certificate: config.Certificate, Version: config.Version}, Suite: "", Expected: receivedRequest{}}, server.URL+"one"))
	_, receivedErr := server.received()

	if err = errors.Join(err, receivedErr); (err != nil) || (output != "/one") {
		state.Fatalf("Test of the http/2 view failed, curl --http1.1 should work, output: %q, error: %v", output, err)
	}

	exchange, err := lastExchange(state, client, server)

	if (err != nil) || (exchange.Protocol != "HTTP/1.1") || (exchange.StreamID != 0) || (exchange.Request.Version != "HTTP/1.1") {
		state.Errorf("Test of the http/2 view failed, an http/1.1 flow should stay HTTP/1.1, exchange: %+v, error: %v", exchange, err)
		return
	}

	flows := v1.FlowList{}
	_, err = client.call(state.Context(), http.MethodGet, "/flows?filter="+url.QueryEscape("http2.streamid"), nil, &flows)

	if (err != nil) || (len(flows.Flows) != 0) {
		state.Errorf("Test of the http/2 view failed, http2.streamid should not take an HTTP/1.1 flow, flows: %+v, error: %v", flows, err)
		return
	}

	// a user decerter does not select
	output, err = runCurl(state.Context(), otherUser, curlArguments(curlCase{Name: "other user", Server: config, Suite: "", Expected: receivedRequest{}}, server.URL+"two"))
	_, receivedErr = server.received()
	_, flowsErr := client.call(state.Context(), http.MethodGet, "/flows?filter="+url.QueryEscape("http2.streamid"), nil, &flows)

	if err = errors.Join(err, receivedErr, flowsErr); (err != nil) || (output != "/two") || (len(flows.Flows) != 0) {
		state.Errorf("Test of the http/2 view failed, another user's flow should not be read, output: %q, flows: %+v, error: %v", output, flows, err)
		return
	}
}
