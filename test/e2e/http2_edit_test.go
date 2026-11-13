// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/intercept"
)

const (
	// the test binary runs as the root's Go h2c server of the edit cases when this is 1, it prints its URL and serves until stdin ends
	serverCommandEnvironment string = "DECERTER_E2E_SERVER"
	// the requests of the hold cases on one connection, three at a time; one response grows by growBytes, one shrinks to shrunkBody
	editRequests int    = 20
	growBytes    int    = 200 << 10
	shrunkBody   string = "ten bytes!"
	// /shrink answers this many bytes
	shrinkBytes int = 300 << 10
)

// what a peer's GODEBUG=http2debug=2 log may not say
var protocolErrorPattern = regexp.MustCompile(`(?i)PROTOCOL_ERROR|FLOW_CONTROL_ERROR|COMPRESSION_ERROR|protocol error`)

// the test binary as an h2c server: /test answers "reached /test", /grow "GROW", /shrink shrinkBytes of z, any other path the path
func runServer() (code int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		code = 1
		return
	}

	protocols := &http.Protocols{}
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Handler: http.HandlerFunc(answerEdit), Protocols: protocols}
	fmt.Printf("http://%s/\n", listener.Addr().String())

	// stdin ends when the test is done
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		_ = server.Close()
	}()

	if err = server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err.Error())
		code = 1
	}

	return
}

func answerEdit(writer http.ResponseWriter, request *http.Request) {
	answer := request.URL.Path

	switch request.URL.Path {
	case "/test":
		answer = "reached /test"
	case "/grow":
		answer = "GROW"
	case "/shrink":
		answer = strings.Repeat("z", shrinkBytes)
	default:
	}

	if _, err := writer.Write([]byte(answer)); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

// the Go client of the edit cases: /old, then /grow, /shrink and more paths, three at a time on its one connection; one line per path with the length of its body, sorted
func getEdits(ctx context.Context, client *http.Client, target string) (output string, err error) {
	paths := []string{"/grow", "/shrink"}

	for index := range editRequests - 2 {
		paths = append(paths, fmt.Sprintf("/par/%d", index))
	}

	body, err := getBody(ctx, client, target+"old")

	if err != nil {
		return
	}

	lines := []string{"/old " + body}
	mutex := &sync.Mutex{}
	waitGroup := sync.WaitGroup{}
	slots := make(chan struct{}, 3)

	for _, path := range paths {
		slots <- struct{}{}

		// one request of three at a time
		waitGroup.Go(func() {
			defer func() {
				<-slots
			}()

			pathBody, getErr := getBody(ctx, client, strings.TrimSuffix(target, "/")+path)
			mutex.Lock()
			defer mutex.Unlock()
			err = errors.Join(err, getErr)
			lines = append(lines, fmt.Sprintf("%s %d", path, len(pathBody)))
		})
	}

	waitGroup.Wait()
	slices.Sort(lines)
	output = strings.Join(lines, "\n")
	return
}

func getBody(ctx context.Context, client *http.Client, target string) (body string, err error) {
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

	data, err := io.ReadAll(response.Body)

	if (err == nil) && (response.ContentLength >= 0) && (response.ContentLength != int64(len(data))) {
		err = fmt.Errorf("%s: content-length %d, body %d bytes", target, response.ContentLength, len(data))
	}

	body = string(data)
	return
}

// the test binary as the root's h2c server with GODEBUG=http2debug=2: its URL, and its log once stop returned
func startGoServer(state *testing.T) (target string, log *lockedBuffer, stop func() error) {
	executable, err := os.Executable()

	if err != nil {
		state.Fatalf("Could not find the test binary, error: %s", err.Error())
	}

	command := exec.Command(executable)
	command.Env = []string{serverCommandEnvironment + "=1", "GODEBUG=http2debug=2", "PATH=/usr/local/bin:/usr/bin:/bin", "LC_ALL=C"}
	log = &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}
	command.Stderr = log
	stdin, stdinErr := command.StdinPipe()
	stdout, stdoutErr := command.StdoutPipe()

	if err = errors.Join(stdinErr, stdoutErr); err == nil {
		err = command.Start()
	}

	if err != nil {
		state.Fatalf("Could not start the go server, error: %s", err.Error())
	}

	line, err := bufio.NewReader(stdout).ReadString('\n')

	if err != nil {
		state.Fatalf("Could not read the go server's URL, error: %v, log: %s", err, log.String())
	}

	target = strings.TrimSpace(line)
	stop = func() (stopErr error) {
		stopErr = errors.Join(stdin.Close(), command.Wait())
		return
	}
	return
}

// run the Go client as the test user with GODEBUG=http2debug=2, its log too
func runGoClientLogged(ctx context.Context, path string, mode string, target string) (output string, log string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, path, target)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: testUser.UID, Gid: testUser.GID, Groups: []uint32{}, NoSetGroups: false}}
	command.Dir = "/"
	command.Env = []string{clientCommandEnvironment + "=" + mode, "GODEBUG=http2debug=2", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	output, log = stdout.String(), stderr.String()

	if err != nil {
		err = fmt.Errorf("go client %s %s: %w", mode, target, err)
	}

	return
}

// the rules of the edit cases: :path / and /old become /test, GROW grows by growBytes, a run of z becomes shrunkBody
func addEditRules(state *testing.T, client apiClient) {
	rules := []v1.RuleRequest{
		{Filter: "", Direction: v1.UpDirection, Layer: v1.HTTPLayer, Find: v1.Value{Type: v1.RegexValueType, Value: `:path: /(old)?\r\n`}, Replace: v1.Value{Type: v1.TextValueType, Value: ":path: /test\r\n"}},
		{Filter: "", Direction: v1.DownDirection, Layer: v1.HTTPLayer, Find: v1.Value{Type: v1.TextValueType, Value: "\r\n\r\nGROW"}, Replace: v1.Value{Type: v1.TextValueType, Value: "\r\n\r\nGROW" + strings.Repeat("g", growBytes)}},
		{Filter: "", Direction: v1.DownDirection, Layer: v1.HTTPLayer, Find: v1.Value{Type: v1.RegexValueType, Value: `\r\n\r\nz+$`}, Replace: v1.Value{Type: v1.TextValueType, Value: "\r\n\r\n" + shrunkBody}},
	}

	for _, rule := range rules {
		code, err := client.call(state.Context(), http.MethodPost, "/rules", rule, nil)

		if (err != nil) || (code != http.StatusCreated) {
			state.Fatalf("Could not add the rule %+v, status: %d, error: %v", rule, code, err)
		}
	}
}

// Test if rules of layer http edit HTTP/2: curl --http2 over TLS 1.2, TLS 1.3 and h2c reaches /test when a rule rewrites :path, and a Go h2c client and server with
// GODEBUG=http2debug=2 log no protocol error while their 21 requests on one connection, three at a time, have :path rewritten and bodies grown by 200 KiB past 64 KiB windows and shrunk.
func TestHTTP2EditPositive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	addEditRules(state, client)

	for _, config := range []serverConfig{{Certificate: &rsaCertificate, Version: tls.VersionTLS12, HTTP2: true}, {Certificate: &ecdsaCertificate, Version: tls.VersionTLS13, HTTP2: true}, {Certificate: nil, HTTP2: true}} {
		server := startServer(state, config)
		testCase := curlCase{Name: server.URL, Server: config, Suite: "", Expected: receivedRequest{}}
		output, err := runCurl(state.Context(), testUser, curlArguments(testCase, server.URL))
		request, receivedErr := server.received()

		if err = errors.Join(err, receivedErr); (err != nil) || (output != "/test") || (request.Path != "/test") || (request.Proto != "HTTP/2.0") {
			state.Errorf("Test of http/2 editing failed, %s, the rewritten :path should reach /test, curl: %q, server: %+v, error: %v", server.URL, output, request, err)
			return
		}

		exchange, err := lastExchange(state, client, server)

		if (err != nil) || (exchange.Request == nil) || !exchange.Request.Edited || (exchange.Request.Original == nil) || (exchange.Request.Target != "/test") || (exchange.Request.Original.Target != "/") {
			state.Errorf("Test of http/2 editing failed, %s, the exchange should show the edit, exchange: %+v, error: %v", server.URL, exchange, err)
			return
		}
	}

	// the Go client and server
	target, serverLog, stop := startGoServer(state)
	output, clientLog, err := runGoClientLogged(state.Context(), copyClient(state), "edit", target)
	err = errors.Join(err, stop())
	lines := []string{"/old reached /test", "/grow " + strconv.Itoa(len("GROW")+growBytes), "/shrink " + strconv.Itoa(len(shrunkBody))}

	for index := range editRequests - 2 {
		lines = append(lines, fmt.Sprintf("/par/%d %d", index, len(fmt.Sprintf("/par/%d", index))))
	}

	slices.Sort(lines)
	logs := clientLog + serverLog.String()

	if (err != nil) || (output != strings.Join(lines, "\n")) || protocolErrorPattern.MatchString(logs) || !strings.Contains(clientLog, "http2: Transport") || !strings.Contains(serverLog.String(), "http2: server") {
		state.Errorf("Test of http/2 editing failed, the go client should get every edit without a protocol error, output: %q, errors in the logs: %q, error: %v", output, protocolErrorPattern.FindAllString(logs, 5), err)
		return
	}
}

// Test if holds of layer http take HTTP/2 responses one stream at a time: curl's 20 requests on one connection, three at a time, over TLS 1.2, TLS 1.3 and h2c, each response held
// and forwarded, one grown by 200 KiB and one shrunk to 10 bytes, all complete without a FLOW_CONTROL_ERROR or COMPRESSION_ERROR.
func TestHTTP2HoldPositive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	status, err := client.call(state.Context(), http.MethodPut, "/intercept", v1.InterceptRequest{Enabled: true, Filter: `http.request.uri contains "/h/" && proc.comm == "curl"`, Direction: v1.DownDirection, Layer: v1.HTTPLayer}, nil)

	if (err != nil) || (status != http.StatusOK) {
		state.Fatalf("Test of http/2 holds failed, cannot hold http messages, status: %d, error: %v", status, err)
	}

	for _, config := range []serverConfig{{Certificate: &rsaCertificate, Version: tls.VersionTLS12, HTTP2: true}, {Certificate: &ecdsaCertificate, Version: tls.VersionTLS13, HTTP2: true}, {Certificate: nil, HTTP2: true}} {
		server := startServer(state, config)
		testCase := curlCase{Name: server.URL, Server: config, Suite: "", Expected: receivedRequest{}}
		arguments := append(curlArguments(testCase, server.URL+"h/0"), "--parallel", "--parallel-max", "3", "--write-out", `%{url} %{http_code} %{size_download} %{num_connects}\n`, "--output", "/dev/null")

		for index := 1; index < editRequests; index++ {
			arguments = append(arguments, "--output", "/dev/null", fmt.Sprintf("%sh/%d", server.URL, index))
		}

		resultChannel := curlAsync(state.Context(), arguments)
		err = forwardHolds(state.Context(), client, editRequests)
		result := <-resultChannel
		sizes, connections, parseErr := curlSizes(result.output, server.URL)

		if err = errors.Join(err, result.err, parseErr); (err != nil) || (len(sizes) != editRequests) || (connections != 1) {
			state.Errorf("Test of http/2 holds failed, %s, every held response should arrive on one connection, curl: %q, error: %v", server.URL, result.output, err)
			return
		}

		for index := range editRequests {
			path := fmt.Sprintf("/h/%d", index)
			expected := len(path)

			switch index {
			case 3:
				expected += growBytes
			case 7:
				expected = len(shrunkBody)
			default:
			}

			if sizes[path] != expected {
				state.Errorf("Test of http/2 holds failed, %s, %s should have %d bytes, sizes: %v", server.URL, path, expected, sizes)
				return
			}
		}

		for range editRequests {
			_, _ = server.received()
		}
	}
}

// forward count held messages as they come: the body of /h/3 grows by growBytes, the one of /h/7 becomes shrunkBody, content-length is left to decerter
func forwardHolds(ctx context.Context, client apiClient, count int) (err error) {
	for range count {
		held, waitErr := client.waitHeld(ctx)

		if err = waitErr; err != nil {
			return
		}

		payload, decodeErr := hex.DecodeString(held.Payload.Hex)

		if err = decodeErr; err != nil {
			return
		}

		edited := payload

		switch {
		case bytes.HasSuffix(payload, []byte("\r\n\r\n/h/3")):
			edited = append(bytes.Clone(payload), strings.Repeat("g", growBytes)...)
		case bytes.HasSuffix(payload, []byte("\r\n\r\n/h/7")):
			edited = append(bytes.Clone(payload[:bytes.Index(payload, []byte("\r\n\r\n"))+4]), shrunkBody...)
		default:
		}

		if !bytes.Equal(edited, payload) {
			_, err = client.call(ctx, http.MethodPut, fmt.Sprintf("/holds/%d", held.ID), v1.EditRequest{Payload: v1.Value{Type: v1.HexValueType, Value: hex.EncodeToString(edited)}}, nil)

			if err != nil {
				return
			}
		}

		code := 0
		code, err = client.call(ctx, http.MethodPost, fmt.Sprintf("/holds/%d/forward", held.ID), nil, nil)

		if (err == nil) && (code != http.StatusNoContent) {
			err = fmt.Errorf("forward of hold %d: status %d", held.ID, code)
		}

		if err != nil {
			return
		}
	}

	return
}

// curl's --write-out lines: the size of each path, and the connections it made in all
func curlSizes(output string, base string) (sizes map[string]int, connections int, err error) {
	sizes = map[string]int{}

	for line := range strings.Lines(output) {
		fields := strings.Fields(line)

		if (len(fields) != 4) || (fields[1] != "200") {
			err = errors.Join(err, fmt.Errorf("line %q", line))
			continue
		}

		size, sizeErr := strconv.Atoi(fields[2])
		connects, connectsErr := strconv.Atoi(fields[3])
		err = errors.Join(err, sizeErr, connectsErr)
		sizes["/"+strings.TrimPrefix(fields[0], base)] = size
		connections += connects
	}

	return
}
