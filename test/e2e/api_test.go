// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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
	"sync"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/api"
	"github.com/decerter/decerter/internal/intercept"
)

const (
	// how often the held messages are looked at, and how long a request may take to be held
	holdPoll    time.Duration = 20 * time.Millisecond
	holdArrival time.Duration = 10 * time.Second
	// curl's limit for a request that is dropped
	dropMaxTime string = "2"
	// the client port of the udp session that is held
	heldUDPPort string = "40001"
)

// a client of the control API on its unix socket
type apiClient struct {
	client *http.Client
	socket string
}

// what curl printed, or why it failed
type curlResult struct {
	output string
	err    error
}

// the events of one stream, collected until the test ends
type eventLog struct {
	mutex  *sync.Mutex
	events []v1.Event
	raw    []string
}

// Test if a request held over the API can be edited and forwarded (GET / to GET /test), dropped, left to its timeout, and let go by turning intercept off, over plain HTTP and TLS 1.3, while the flow is listed open and the event stream tells every step.
func TestAPIHoldPositive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	events := client.subscribe(state)
	interceptState := v1.InterceptState{}
	status, err := client.call(state.Context(), http.MethodPut, "/intercept", v1.InterceptRequest{Enabled: true, Filter: `proc.comm == "curl"`, Direction: ""}, &interceptState)

	if (err != nil) || (status != http.StatusOK) || !interceptState.Enabled || (interceptState.Direction != v1.UpDirection) || (interceptState.HoldTimeoutSeconds != apiHoldTimeout.Seconds()) {
		state.Fatalf("Test of the api hold failed, cannot turn intercept on, status: %d, state: %+v, error: %v", status, interceptState, err)
	}

	for _, config := range []serverConfig{{Certificate: nil}, {Certificate: &rsaCertificate, Version: tls.VersionTLS13}} {
		server := startServer(state, config)
		testCase := curlCase{Name: server.URL, Server: config, Suite: "", Expected: receivedRequest{}}

		// edit and forward: the server gets /test
		resultChannel := curlAsync(state.Context(), curlArguments(testCase, server.URL))
		held, err := client.waitHeld(state.Context())

		if err != nil {
			state.Fatalf("Test of the api hold failed, %s, error: %s", server.URL, err.Error())
		}

		flow := v1.Flow{}
		status, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d", held.FlowID), nil, &flow)

		if (err != nil) || (status != http.StatusOK) || (flow.State != v1.OpenFlowState) || (flow.Process.Comm != "curl") || (flow.Process.UID != testUser.UID) {
			state.Errorf("Test of the api hold failed, %s, the held flow should be listed open, flow: %+v, error: %v", server.URL, flow, err)
			return
		}

		payload, err := hex.DecodeString(held.Payload.Hex)

		if (err != nil) || !bytes.HasPrefix(payload, []byte("GET / HTTP/1.1\r\n")) {
			state.Fatalf("Test of the api hold failed, %s, the held request should start with GET /, payload: %q, error: %v", server.URL, payload, err)
		}

		edited := v1.Hold{}
		status, err = client.call(state.Context(), http.MethodPut, fmt.Sprintf("/holds/%d", held.ID), v1.EditRequest{Payload: v1.Value{Type: v1.TextValueType, Value: strings.Replace(string(payload), "GET / ", "GET /test ", 1)}}, &edited)

		if (err != nil) || (status != http.StatusOK) || !edited.Edited || !strings.HasPrefix(edited.Payload.Escaped, `GET /test HTTP/1.1\r\n`) {
			state.Fatalf("Test of the api hold failed, %s, cannot edit, status: %d, hold: %+v, error: %v", server.URL, status, edited, err)
		}

		status, err = client.call(state.Context(), http.MethodPost, fmt.Sprintf("/holds/%d/forward", held.ID), nil, nil)
		result := <-resultChannel
		request, receivedErr := server.received()

		if (err != nil) || (status != http.StatusNoContent) || (result.err != nil) || (result.output != "/test") || (receivedErr != nil) || (request.Path != "/test") {
			state.Errorf("Test of the api hold failed, %s, the edited request should reach the server, status: %d, curl: %+v, server: %+v, error: %v", server.URL, status, result, request, errors.Join(err, receivedErr))
			return
		}

		// drop: the server gets nothing, curl waits for an answer until its own limit
		resultChannel = curlAsync(state.Context(), append([]string{"--max-time", dropMaxTime}, curlArguments(testCase, server.URL)...))
		held, err = client.waitHeld(state.Context())

		if err != nil {
			state.Fatalf("Test of the api hold failed, %s, error: %s", server.URL, err.Error())
		}

		status, err = client.call(state.Context(), http.MethodPost, fmt.Sprintf("/holds/%d/drop", held.ID), nil, nil)
		result = <-resultChannel
		_, receivedErr = server.received()

		if (err != nil) || (status != http.StatusNoContent) || (result.err == nil) || !strings.Contains(result.err.Error(), "exit status 28") || (receivedErr == nil) {
			state.Errorf("Test of the api hold failed, %s, a dropped request should time out in curl and never reach the server, status: %d, curl: %+v, error: %v", server.URL, status, result, err)
			return
		}

		// nobody decides: the request goes on unchanged after the hold timeout
		start := time.Now()
		resultChannel = curlAsync(state.Context(), curlArguments(testCase, server.URL))
		_, err = client.waitHeld(state.Context())

		if err != nil {
			state.Fatalf("Test of the api hold failed, %s, error: %s", server.URL, err.Error())
		}

		result = <-resultChannel

		if (result.err != nil) || (result.output != "/") || (time.Since(start) < apiHoldTimeout) {
			state.Errorf("Test of the api hold failed, %s, an undecided request should go on unchanged after %s, curl: %+v, after: %s", server.URL, apiHoldTimeout, result, time.Since(start))
			return
		}

		// intercept off lets the held request go on unchanged at once, then it is turned on again
		resultChannel = curlAsync(state.Context(), curlArguments(testCase, server.URL))
		_, err = client.waitHeld(state.Context())

		if err != nil {
			state.Fatalf("Test of the api hold failed, %s, error: %s", server.URL, err.Error())
		}

		start = time.Now()
		status, err = client.call(state.Context(), http.MethodPut, "/intercept", v1.InterceptRequest{Enabled: false, Filter: "", Direction: ""}, nil)
		result = <-resultChannel

		if (err != nil) || (status != http.StatusOK) || (result.err != nil) || (result.output != "/") || (time.Since(start) >= apiHoldTimeout) {
			state.Errorf("Test of the api hold failed, %s, intercept off should forward the held request, status: %d, curl: %+v, error: %v", server.URL, status, result, err)
			return
		}

		status, err = client.call(state.Context(), http.MethodPut, "/intercept", v1.InterceptRequest{Enabled: true, Filter: `proc.comm == "curl"`, Direction: v1.UpDirection}, nil)

		if (err != nil) || (status != http.StatusOK) {
			state.Fatalf("Test of the api hold failed, cannot turn intercept on again, status: %d, error: %v", status, err)
		}
	}

	// every step is in the event stream, without a payload
	reasons := map[string]int{}
	types := map[v1.EventType]int{}

	events.wait(state, v1.FlowClosedEventType, 8)

	for _, event := range events.wait(state, v1.InterceptChangedEventType, 5) {
		types[event.Type]++

		if event.Type == v1.HoldReleasedEventType {
			reasons[event.Reason]++
		}
	}

	for _, reason := range []intercept.ReleaseReason{intercept.ForwardReleaseReason, intercept.DropReleaseReason, intercept.TimeoutReleaseReason, intercept.InterceptOffReleaseReason} {
		if reasons[string(reason)] != 2 {
			state.Errorf("Test of the api event stream failed, two holds should be released with reason %s, reasons: %v", reason, reasons)
			return
		}
	}

	if (types[v1.HeldEventType] != 8) || (types[v1.HoldEditedEventType] != 2) || (types[v1.FlowOpenedEventType] < 8) || (types[v1.MessageEventType] < 14) || (types[v1.InterceptChangedEventType] != 5) || events.hasPayload() {
		state.Errorf("Test of the api event stream failed, event counts: %v, payload in an event: %v", types, events.hasPayload())
		return
	}
}

// Test if a plain udp datagram held over the API holds only its own session: another session goes on meanwhile, the held one goes on when forwarded.
func TestAPIUDPHoldPositive(state *testing.T) {
	socatPath, err := exec.LookPath("socat")

	if err != nil {
		state.Skipf("Skipping the api udp hold, it needs socat: %s", err.Error())
	}

	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	port, received := startUDPEchoServer(state)
	status, err := client.call(state.Context(), http.MethodPut, "/intercept", v1.InterceptRequest{Enabled: true, Filter: "udp.srcport == " + heldUDPPort, Direction: v1.UpDirection}, nil)

	if (err != nil) || (status != http.StatusOK) {
		state.Fatalf("Test of the api udp hold failed, cannot turn intercept on, status: %d, error: %v", status, err)
	}

	heldChannel := runAsync(func() (output string, err error) {
		output, err = runAsUser(state.Context(), testUser, "held", socatPath, "-t", "4", "-", "UDP:"+net.JoinHostPort(destinationPrefix.Addr().String(), port)+",sourceport="+heldUDPPort)
		return
	})
	held, err := client.waitHeld(state.Context())

	if err != nil {
		state.Fatalf("Test of the api udp hold failed, error: %s", err.Error())
	}

	// the reader of the proxy socket goes on: another session gets its echo while the first datagram waits
	output, err := runAsUser(state.Context(), testUser, "free", socatPath, "-t", "1", "-", "UDP:"+net.JoinHostPort(destinationPrefix.Addr().String(), port))
	holds := v1.HoldList{}
	_, listErr := client.call(state.Context(), http.MethodGet, "/holds", nil, &holds)

	if (err != nil) || (output != "free") || (listErr != nil) || (len(holds.Holds) != 1) || (<-received != "free") {
		state.Errorf("Test of the api udp hold failed, another session should get its echo while one datagram is held, output: %q, holds: %d, error: %v", output, len(holds.Holds), errors.Join(err, listErr))
		return
	}

	status, err = client.call(state.Context(), http.MethodPost, fmt.Sprintf("/holds/%d/forward", held.ID), nil, nil)
	result := <-heldChannel

	if (err != nil) || (status != http.StatusNoContent) || (held.Layer != v1.UDPLayer) || (result.err != nil) || (result.output != "held") || (<-received != "held") {
		state.Errorf("Test of the api udp hold failed, the forwarded datagram should get its echo, status: %d, hold: %+v, result: %+v, error: %v", status, held, result, err)
		return
	}
}

// Test if a rule added over the API rewrites the next request over plain HTTP, TLS 1.2 and TLS 1.3, a regex rule expands its groups, a filter limits a rule, and a deleted rule changes nothing any more.
func TestAPIRulePositive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	events := client.subscribe(state)
	configs := []serverConfig{{Certificate: nil}, {Certificate: &rsaCertificate, Version: tls.VersionTLS12}, {Certificate: &ecdsaCertificate, Version: tls.VersionTLS13}}
	rule := v1.Rule{}
	status, err := client.call(state.Context(), http.MethodPost, "/rules", v1.RuleRequest{Filter: "", Direction: v1.UpDirection, Layer: "", Find: v1.Value{Type: v1.TextValueType, Value: "GET / "}, Replace: v1.Value{Type: v1.TextValueType, Value: "GET /test "}}, &rule)

	if (err != nil) || (status != http.StatusCreated) || (rule.ID == 0) {
		state.Fatalf("Test of the api rules failed, cannot add a rule, status: %d, error: %v", status, err)
	}

	for _, config := range configs {
		err = testCurl(state, testUser, curlCase{Name: "rule", Server: config, Suite: "", Expected: receivedRequest{Path: "/test", Proto: "HTTP/1.1", Version: config.Version, CipherSuite: 0}})

		if err != nil {
			state.Errorf("Test of the api rules failed, the rule should rewrite the request, error: %s", err.Error())
			return
		}
	}

	rules := v1.RuleList{}
	_, err = client.call(state.Context(), http.MethodGet, "/rules", nil, &rules)

	if (err != nil) || (len(rules.Rules) != 1) || (rules.Rules[0].Hits != uint64(len(configs))) {
		state.Errorf("Test of the api rules failed, the rule should have %d hits, rules: %+v, error: %v", len(configs), rules, err)
		return
	}

	status, err = client.call(state.Context(), http.MethodDelete, fmt.Sprintf("/rules/%d", rule.ID), nil, nil)

	if (err != nil) || (status != http.StatusNoContent) {
		state.Fatalf("Test of the api rules failed, cannot delete the rule, status: %d, error: %v", status, err)
	}

	for _, config := range configs {
		err = testCurl(state, testUser, curlCase{Name: "deleted", Server: config, Suite: "", Expected: receivedRequest{Path: "/", Proto: "HTTP/1.1", Version: config.Version, CipherSuite: 0}})

		if err != nil {
			state.Errorf("Test of the api rules failed, a deleted rule should change nothing, error: %s", err.Error())
			return
		}
	}

	// a regex rule for TLS flows only: the group goes into the new path, plain HTTP stays as it is
	status, err = client.call(state.Context(), http.MethodPost, "/rules", v1.RuleRequest{Filter: "tls", Direction: v1.UpDirection, Layer: v1.TLSLayer, Find: v1.Value{Type: v1.RegexValueType, Value: `GET /(\w+) `}, Replace: v1.Value{Type: v1.TextValueType, Value: "GET /test/$1 "}}, nil)

	if (err != nil) || (status != http.StatusCreated) {
		state.Fatalf("Test of the api rules failed, cannot add the regex rule, status: %d, error: %v", status, err)
	}

	for index, config := range configs {
		expected := "/test/abc"

		if index == 0 {
			expected = "/abc"
		}

		server := startServer(state, config)
		output, curlErr := runCurl(state.Context(), testUser, curlArguments(curlCase{Name: "regex", Server: config, Suite: "", Expected: receivedRequest{}}, server.URL+"abc"))

		if (curlErr != nil) || (output != expected) {
			state.Errorf("Test of the api rules failed, %s should be %s, output: %q, error: %v", server.URL, expected, output, curlErr)
			return
		}
	}

	added := 0

	for _, event := range events.wait(state, v1.RuleAddedEventType, 2) {
		if (event.Type == v1.RuleAddedEventType) || (event.Type == v1.RuleDeletedEventType) {
			added++
		}
	}

	if added != 3 {
		state.Errorf("Test of the api event stream failed, two rules added and one deleted should be 3 events, events: %d", added)
		return
	}
}

// Test if the API lists the relayed flows with their TLS ClientHello but no payloads, takes a filter on them, and exports key log lines equal to the test server's key log.
func TestAPIFlowsPositive(state *testing.T) {
	client := startAPIDecerter(state, RelayDecerterMode, nil)
	keyLog := &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}
	configs := []serverConfig{{Certificate: nil}, {Certificate: &rsaCertificate, Version: tls.VersionTLS12, KeyLog: keyLog}, {Certificate: &rsaCertificate, Version: tls.VersionTLS13, KeyLog: keyLog}}

	for _, config := range configs {
		err := testCurl(state, testUser, curlCase{Name: "relay", Server: config, Suite: "", Expected: receivedRequest{Path: "/", Proto: "HTTP/1.1", Version: config.Version, CipherSuite: 0}})

		if err != nil {
			state.Fatalf("Test of the api flows failed, error: %s", err.Error())
		}
	}

	status := v1.Status{}
	_, err := client.call(state.Context(), http.MethodGet, "/status", nil, &status)

	if (err != nil) || (status.Processing != v1.RelayProcessing) || status.Intercept.Available || (status.History.Flows != len(configs)) {
		state.Fatalf("Test of the api flows failed, status: %+v, error: %v", status, err)
	}

	positiveCases := []struct {
		Filter string
		Flows  int
		TLS    bool
	}{
		{Filter: `proc.comm == "curl"`, Flows: 3, TLS: false},
		{Filter: "tls", Flows: 2, TLS: true},
		{Filter: "!tls && tcp", Flows: 1, TLS: false},
		{Filter: "tls.version == 0x0303", Flows: 1, TLS: true},
	}

	for _, positive := range positiveCases {
		flows := v1.FlowList{}
		_, err = client.call(state.Context(), http.MethodGet, "/flows?filter="+url.QueryEscape(positive.Filter), nil, &flows)

		if (err != nil) || (len(flows.Flows) != positive.Flows) {
			state.Errorf("Test of the api flows failed, filter %q should take %d flows, flows: %d, error: %v", positive.Filter, positive.Flows, len(flows.Flows), err)
			return
		}

		for _, flow := range flows.Flows {
			if (flow.State != v1.ClosedFlowState) || (flow.Up.Messages != 0) || (flow.Up.Bytes == 0) || (positive.TLS && ((flow.TLS == nil) || (len(flow.TLS.ClientRandom) != 64))) {
				state.Errorf("Test of the api flows failed, filter %q, a relayed flow should be closed with bytes, no messages and its client random, flow: %+v", positive.Filter, flow)
				return
			}
		}
	}

	exported, err := client.text(state.Context(), "/keylog?filter=tls")
	exportedLines := keyLogLines(exported)
	serverLines := keyLogLines(keyLog.String())
	slices.Sort(exportedLines)
	slices.Sort(serverLines)

	// TLS 1.2 has one CLIENT_RANDOM line, TLS 1.3 four traffic secret lines
	if (err != nil) || (len(exportedLines) != 5) || !slices.Equal(exportedLines, serverLines) {
		state.Errorf("Test of the api key log failed, the export should be the server's key log, export: %q, server: %q, error: %v", exportedLines, serverLines, err)
		return
	}
}

// Test if the history of --decrypt has the decrypted request of a TLS flow, as observed copies, and holding and rules are refused.
func TestAPIDecryptPositive(state *testing.T) {
	client := startAPIDecerter(state, DecryptDecerterMode, nil)
	config := serverConfig{Certificate: &ecdsaCertificate, Version: tls.VersionTLS13}
	err := testCurl(state, testUser, curlCase{Name: "decrypt", Server: config, Suite: "", Expected: receivedRequest{Path: "/", Proto: "HTTP/1.1", Version: tls.VersionTLS13, CipherSuite: 0}})

	if err != nil {
		state.Fatalf("Test of the api decrypt history failed, error: %s", err.Error())
	}

	flows := v1.FlowList{}
	_, err = client.call(state.Context(), http.MethodGet, "/flows?filter=tls", nil, &flows)

	if (err != nil) || (len(flows.Flows) != 1) || (flows.Flows[0].TLS.Version != "TLS1.3") || (flows.Flows[0].Layer != v1.TLSLayer) {
		state.Fatalf("Test of the api decrypt history failed, one TLS 1.3 flow should be listed, flows: %+v, error: %v", flows, err)
	}

	messages := v1.MessageList{}
	_, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/messages", flows.Flows[0].ID), nil, &messages)

	if (err != nil) || (len(messages.Messages) < 2) || (messages.Messages[0].Origin != v1.ObservedOrigin) || (messages.Messages[0].Direction != v1.UpDirection) {
		state.Fatalf("Test of the api decrypt history failed, the flow should have observed messages, messages: %+v, error: %v", messages, err)
	}

	detail := v1.MessageDetail{}
	_, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/messages/%d?length=16", messages.Messages[0].ID), nil, &detail)

	if (err != nil) || (detail.Payload.Escaped != `GET / HTTP/1.1\r\n`) || (detail.Payload.Total <= 16) || (detail.Original != nil) {
		state.Errorf("Test of the api decrypt history failed, the request should be in the history, message: %+v, error: %v", detail, err)
		return
	}

	// the HTTP layer reads the observed records too; the flow may still be closing, the exchange is complete once curl has its answer
	exchanges := v1.ExchangeList{}
	_, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/exchanges", flows.Flows[0].ID), nil, &exchanges)

	if (err != nil) || (len(exchanges.Exchanges) != 1) || (exchanges.Exchanges[0].Request == nil) || (exchanges.Exchanges[0].Request.Method != "GET") || (exchanges.Exchanges[0].Response == nil) || (exchanges.Exchanges[0].Response.Status != 200) {
		state.Errorf("Test of the api decrypt history failed, the flow should have its exchange, exchanges: %+v, error: %v", exchanges, err)
		return
	}

	for path, request := range map[string]any{"/intercept": v1.InterceptRequest{Enabled: true}, "/rules": v1.RuleRequest{Find: v1.Value{Type: v1.TextValueType, Value: "a"}, Replace: v1.Value{Type: v1.TextValueType, Value: "b"}}} {
		method := http.MethodPut

		if path == "/rules" {
			method = http.MethodPost
		}

		status, callErr := client.call(state.Context(), method, path, request, nil)

		if (callErr != nil) || (status != http.StatusConflict) {
			state.Errorf("Test of the api decrypt history failed, %s should be refused without --intercept, status: %d, error: %v", path, status, callErr)
			return
		}
	}
}

// Test if the api socket refuses a user who is not root, and a path that is not a socket stops decerter before it starts.
func TestAPINegative(state *testing.T) {
	client := startAPIDecerter(state, RelayDecerterMode, nil)
	// the directories of the test may be entered, the socket's own mode keeps the test user out
	err := errors.Join(os.Chmod(filepath.Dir(client.socket), 0o755), os.Chmod(filepath.Dir(filepath.Dir(client.socket)), 0o755))

	if err != nil {
		state.Fatalf("Test of the api socket failed, cannot open its directory, error: %s", err.Error())
	}

	_, err = runCurl(state.Context(), testUser, []string{"--unix-socket", client.socket, "http://" + v1.HostName + v1.BasePath + "/status"})

	if (err == nil) || !strings.Contains(err.Error(), "exit status 7") {
		state.Errorf("Test of the api socket failed, the test user should not connect, error: %v", err)
		return
	}

	// a regular file where the socket should be
	filePath := filepath.Join(state.TempDir(), "api.sock")
	err = os.WriteFile(filePath, nil, 0o600)

	if err != nil {
		state.Fatalf("Test of the api socket failed, cannot write a file, error: %s", err.Error())
	}

	decerter := newAPIDecerter(state, RelayDecerterMode, "", nil, testFlags(), "", filePath)
	startErr := decerter.Start()
	shutdownErr := decerter.Shutdown()
	_, statErr := os.Stat(filePath)

	if !errors.Is(startErr, api.ErrNotSocket) || (shutdownErr != nil) || (statErr != nil) {
		state.Errorf("Test of the api socket failed, start should fail with %v and leave the file, error: %v, shutdown: %v, stat: %v", api.ErrNotSocket, startErr, shutdownErr, statErr)
		return
	}
}

// decerter in mode with the control API on a socket in the test's directory
func startAPIDecerter(state *testing.T, mode decerterMode, rules []intercept.Rule) (client apiClient) {
	socket := filepath.Join(state.TempDir(), "api.sock")
	decerter := newAPIDecerter(state, mode, "", rules, testFlags(), "", socket)
	startApp(state, &decerter, mode)
	client = apiClient{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					dialer := net.Dialer{}
					return dialer.DialContext(ctx, "unix", socket)
				},
			},
		},
		socket: socket,
	}
	return
}

// one request with a JSON body, nil sends none; result nil reads no answer
func (client apiClient) call(ctx context.Context, method string, path string, body any, result any) (status int, err error) {
	var reader io.Reader = http.NoBody

	if body != nil {
		encoded, encodeErr := json.Marshal(body)

		if err = encodeErr; err != nil {
			return
		}

		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, "http://"+v1.HostName+v1.BasePath+path, reader)

	if err != nil {
		return
	}

	response, err := client.client.Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	status = response.StatusCode
	answer, err := io.ReadAll(response.Body)

	if (err != nil) || (result == nil) || (status >= 300) {
		return
	}

	err = json.Unmarshal(answer, result)
	return
}

// a plain text answer
func (client apiClient) text(ctx context.Context, path string) (text string, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+v1.HostName+v1.BasePath+path, http.NoBody)

	if err != nil {
		return
	}

	response, err := client.client.Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	answer, err := io.ReadAll(response.Body)
	text = string(answer)

	if (err == nil) && (response.StatusCode != http.StatusOK) {
		err = fmt.Errorf("status %d: %s", response.StatusCode, text)
	}

	return
}

// the first held message, it comes once curl sent its request
func (client apiClient) waitHeld(ctx context.Context) (held v1.Hold, err error) {
	deadline := time.Now().Add(holdArrival)

	for time.Now().Before(deadline) {
		holds := v1.HoldList{}
		_, err = client.call(ctx, http.MethodGet, "/holds", nil, &holds)

		if err != nil {
			return
		}

		if len(holds.Holds) > 0 {
			held = holds.Holds[0]
			return
		}

		time.Sleep(holdPoll)
	}

	err = fmt.Errorf("no message was held in %s", holdArrival)
	return
}

// read the event stream until the test ends, the first comment line tells the stream is subscribed
func (client apiClient) subscribe(state *testing.T) (log *eventLog) {
	log = &eventLog{mutex: &sync.Mutex{}, events: nil, raw: nil}
	request, err := http.NewRequestWithContext(state.Context(), http.MethodGet, "http://"+v1.HostName+v1.BasePath+"/events", http.NoBody)

	if err != nil {
		state.Fatalf("Could not make the event request, error: %s", err.Error())
	}

	response, err := client.client.Do(request)

	if err != nil {
		state.Fatalf("Could not subscribe to the events, error: %s", err.Error())
	}

	reader := bufio.NewReader(response.Body)
	_, err = reader.ReadString('\n')

	if err != nil {
		state.Fatalf("Could not read the event stream, error: %s", err.Error())
	}

	doneChannel := make(chan struct{})

	// event stream reader, ends when the test's context closes the stream
	go func() {
		defer close(doneChannel)

		for {
			line, readErr := reader.ReadString('\n')

			if readErr != nil {
				return
			}

			data, isData := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "data: ")

			if !isData {
				continue
			}

			event := v1.Event{}

			if json.Unmarshal([]byte(data), &event) == nil {
				log.add(event, data)
			}
		}
	}()

	state.Cleanup(func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			state.Errorf("Could not close the event stream, error: %s", closeErr.Error())
		}

		<-doneChannel
	})

	return
}

func (log *eventLog) add(event v1.Event, raw string) {
	log.mutex.Lock()
	defer log.mutex.Unlock()
	log.events = append(log.events, event)
	log.raw = append(log.raw, raw)
}

// the events so far once count events of the type are there; the stream lags behind the answers of the API a little
func (log *eventLog) wait(state *testing.T, eventType v1.EventType, count int) (events []v1.Event) {
	deadline := time.Now().Add(holdArrival)

	for {
		log.mutex.Lock()
		events = slices.Clone(log.events)
		log.mutex.Unlock()
		found := 0

		for _, event := range events {
			if event.Type == eventType {
				found++
			}
		}

		if (found >= count) || time.Now().After(deadline) {
			return
		}

		time.Sleep(holdPoll)
	}
}

// a payload must never be in an event
func (log *eventLog) hasPayload() (hasPayload bool) {
	log.mutex.Lock()
	defer log.mutex.Unlock()
	hasPayload = slices.ContainsFunc(log.raw, func(raw string) bool {
		return strings.Contains(raw, `"payload"`) || strings.Contains(raw, "GET /")
	})
	return
}

// curl as the test user in the background
func curlAsync(ctx context.Context, arguments []string) (result chan curlResult) {
	result = runAsync(func() (output string, err error) {
		output, err = runCurl(ctx, testUser, arguments)
		return
	})
	return
}

func runAsync(run func() (output string, err error)) (result chan curlResult) {
	result = make(chan curlResult, 1)

	// the client in the background
	go func() {
		output, err := run()
		result <- curlResult{output: output, err: err}
	}()

	return
}

// run a tool as runAs with input on stdin, like runCurl
func runAsUser(ctx context.Context, runAs account, input string, name string, arguments ...string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, name, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: runAs.UID, Gid: runAs.GID, Groups: []uint32{}, NoSetGroups: false}}
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	command.Stdin = strings.NewReader(input)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()

	if err != nil {
		err = fmt.Errorf("%s %s: %w: %s", name, strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()))
		return
	}

	output = stdout.String()
	return
}

// a udp server on loopback, run as root so it is not redirected, that echoes every datagram and tells what it got; socat sends an empty datagram at the end of its input, that one is not told
func startUDPEchoServer(state *testing.T) (port string, received chan string) {
	connection, err := net.ListenPacket("udp", net.JoinHostPort(destinationPrefix.Addr().String(), "0"))

	if err != nil {
		state.Fatalf("Could not listen for the udp echo server, error: %s", err.Error())
	}

	_, port, err = net.SplitHostPort(connection.LocalAddr().String())

	if err != nil {
		state.Fatalf("Could not read the port of the udp echo server, error: %s", err.Error())
	}

	received = make(chan string, 16)
	doneChannel := make(chan struct{})

	// udp echo server
	go func() {
		defer close(doneChannel)
		buffer := make([]byte, 65535)

		for {
			count, peer, readErr := connection.ReadFrom(buffer)

			if readErr != nil {
				return
			}

			if count > 0 {
				received <- string(buffer[:count])
			}

			_, writeErr := connection.WriteTo(buffer[:count], peer)

			if writeErr != nil {
				return
			}
		}
	}()

	state.Cleanup(func() {
		if closeErr := connection.Close(); closeErr != nil {
			state.Errorf("Could not close the udp echo server, error: %s", closeErr.Error())
		}

		<-doneChannel
	})

	return
}

// the non-empty lines of a key log, without comments
func keyLogLines(text string) (lines []string) {
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)

		if (line != "") && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return
}
