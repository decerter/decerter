// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/intercept"
)

var (
	// plain HTTP, TLS 1.2 and TLS 1.3, curl talks HTTP/1.1 to each
	httpConfigs = []serverConfig{{Certificate: nil}, {Certificate: &rsaCertificate, Version: tls.VersionTLS12}, {Certificate: &ecdsaCertificate, Version: tls.VersionTLS13}}
)

// Test if the API shows curl's HTTP/1.1 exchanges over plain HTTP, TLS 1.2 and TLS 1.3, three keep-alive requests stay in step while rules of layer http change
// a request head and a response body of different lengths, and a rule replaces a word that the server's chunks cut in two.
func TestHTTPRulesPositive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	events := client.subscribe(state)
	ruleRequests := []v1.RuleRequest{
		{Filter: `http.request.uri == "/b"`, Direction: v1.UpDirection, Layer: v1.HTTPLayer, Find: v1.Value{Type: v1.TextValueType, Value: "GET /b "}, Replace: v1.Value{Type: v1.TextValueType, Value: "GET /bee "}},
		{Filter: `http.request.uri == "/a" && http.response.code == 200`, Direction: v1.DownDirection, Layer: v1.HTTPLayer, Find: v1.Value{Type: v1.TextValueType, Value: "/a"}, Replace: v1.Value{Type: v1.TextValueType, Value: "/apple"}},
		{Filter: `http.request.uri == "/chunked"`, Direction: v1.DownDirection, Layer: v1.HTTPLayer, Find: v1.Value{Type: v1.TextValueType, Value: "world"}, Replace: v1.Value{Type: v1.TextValueType, Value: "planet"}},
	}

	for _, ruleRequest := range ruleRequests {
		status, err := client.call(state.Context(), http.MethodPost, "/rules", ruleRequest, nil)

		if (err != nil) || (status != http.StatusCreated) {
			state.Fatalf("Test of the http layer failed, cannot add rule %+v, status: %d, error: %v", ruleRequest, status, err)
		}
	}

	for _, config := range httpConfigs {
		server := startServer(state, config)
		testCase := curlCase{Name: server.URL, Server: config, Suite: "", Expected: receivedRequest{}}
		arguments := curlArguments(testCase, server.URL+"a")
		arguments = append(arguments, server.URL+"b", server.URL+"c")
		output, err := runCurl(state.Context(), testUser, arguments)
		paths := []string{}

		for range 3 {
			request, receivedErr := server.received()
			err = errors.Join(err, receivedErr)
			paths = append(paths, request.Path)
		}

		if (err != nil) || (output != "/apple/bee/c") || !slices.Equal(paths, []string{"/a", "/bee", "/c"}) {
			state.Errorf("Test of the http layer failed, %s, three keep-alive requests should stay in step, curl: %q, server: %v, error: %v", server.URL, output, paths, err)
			return
		}

		flowID, exchanges, err := flowExchanges(state, client, server, 3)

		if err != nil {
			state.Errorf("Test of the http layer failed, %s, error: %s", server.URL, err.Error())
			return
		}

		scheme := strings.SplitN(server.URL, ":", 2)[0]
		host := strings.TrimSuffix(strings.SplitN(server.URL, "//", 2)[1], "/")

		for index, expected := range []struct {
			Target string
			Body   int
			Edited [2]bool
		}{{Target: "/a", Body: len("/apple"), Edited: [2]bool{false, true}}, {Target: "/bee", Body: len("/bee"), Edited: [2]bool{true, false}}, {Target: "/c", Body: len("/c"), Edited: [2]bool{false, false}}} {
			exchange := exchanges[index]
			request, response := exchange.Request, exchange.Response

			if (request == nil) || (response == nil) || (request.Method != "GET") || (request.Target != expected.Target) || (request.URL != scheme+"://"+host+expected.Target) || (response.Status != 200) || (response.BodyLength != expected.Body) ||
				(request.Edited != expected.Edited[0]) || (response.Edited != expected.Edited[1]) || (request.State != v1.CompleteHTTPState) || (response.State != v1.CompleteHTTPState) || (response.Framing != v1.LengthFraming) {
				state.Errorf("Test of the http layer failed, %s, exchange %d of flow %d should be %+v, request: %+v, response: %+v", server.URL, index, flowID, expected, request, response)
				return
			}
		}

		// the original head of the edited request, the header fields as curl sent them
		original := exchanges[1].Request.Original

		if (original == nil) || (original.Target != "/b") || !slices.ContainsFunc(original.Headers, func(header v1.Header) bool { return header.Name == "User-Agent" }) {
			state.Errorf("Test of the http layer failed, %s, the edited request should keep its original head, request: %+v", server.URL, exchanges[1].Request)
			return
		}

		// a word cut over two chunks of the server
		output, err = runCurl(state.Context(), testUser, curlArguments(testCase, server.URL+"chunked"))

		if (err != nil) || (output != "hello planet, chunked!") {
			state.Errorf("Test of the http layer failed, %s, the rule should replace the word across the chunks, curl: %q, error: %v", server.URL, output, err)
			return
		}

		_, receivedErr := server.received()
		_, exchanges, err = flowExchanges(state, client, server, 1)
		body := v1.ExchangeBody{}

		if err == nil {
			_, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/exchanges/%d/body?side=response", exchanges[0].ID), nil, &body)
		}

		if err = errors.Join(err, receivedErr); (err != nil) || (exchanges[0].Response.Framing != v1.ChunkedFraming) || !exchanges[0].Response.Edited || (body.Payload.Escaped != "hello planet, chunked!") || (body.Original == nil) || (body.Original.Escaped != "hello world, chunked!") {
			state.Errorf("Test of the http layer failed, %s, the chunked response should be edited in the history, exchange: %+v, body: %+v, error: %v", server.URL, exchanges, body, err)
			return
		}
	}

	if len(events.wait(state, v1.ExchangeEventType, 12)) < 12 {
		state.Errorf("Test of the http layer failed, the event stream should tell the exchanges")
		return
	}

	// the flows of the history by their exchanges
	flows := v1.FlowList{}
	_, err := client.call(state.Context(), http.MethodGet, "/flows?filter="+url.QueryEscape(`http.request.uri == "/chunked" && http.response.code == 200 && http.user_agent contains "curl"`), nil, &flows)

	if (err != nil) || (len(flows.Flows) != len(httpConfigs)) {
		state.Errorf("Test of the http layer failed, the filter should take the three chunked flows, flows: %d, error: %v", len(flows.Flows), err)
		return
	}
}

// Test if a POST held as a whole HTTP message through decerter ui, the way the page does it, can be edited to a longer body and reaches the server with the right Content-Length, over plain HTTP, TLS 1.2 and TLS 1.3.
func TestHTTPHoldPositive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	browser := startUI(state, client.socket)
	interceptState := v1.InterceptState{}
	err := browser.call(state.Context(), http.MethodPut, "/intercept", v1.InterceptRequest{Enabled: true, Filter: `http.request.method == "POST" && proc.comm == "curl"`, Direction: v1.UpDirection, Layer: v1.HTTPLayer}, http.StatusOK, &interceptState)

	if (err != nil) || !interceptState.Enabled || (interceptState.Layer != v1.HTTPLayer) {
		state.Fatalf("Test of the http hold failed, cannot hold http messages, state: %+v, error: %v", interceptState, err)
	}

	page, err := browser.text(state.Context(), http.MethodGet, "/", nil, http.StatusOK)

	if (err != nil) || !strings.Contains(page, `id="exchanges-table"`) || !strings.Contains(page, `id="intercept-layer"`) {
		state.Fatalf("Test of the http hold failed, the page should have the exchanges and the layer, error: %v", err)
	}

	for _, config := range httpConfigs {
		server := startServer(state, config)
		testCase := curlCase{Name: server.URL, Server: config, Suite: "", Expected: receivedRequest{}}
		// a GET before the POST on the same connection (curl --next keeps it) is not held, the POST is
		arguments := append(curlArguments(testCase, server.URL+"first"), "--next")
		echoArguments := curlArguments(testCase, server.URL+"echo")
		arguments = append(arguments, echoArguments[:len(echoArguments)-1]...)
		arguments = append(arguments, "--data-binary", "short", server.URL+"echo")
		resultChannel := curlAsync(state.Context(), arguments)
		held, err := browser.waitHeld(state.Context())

		if err != nil {
			state.Fatalf("Test of the http hold failed, %s, error: %s", server.URL, err.Error())
		}

		payload, err := hex.DecodeString(held.Payload.Hex)

		if (err != nil) || (held.Layer != v1.HTTPLayer) || (held.ExchangeID == 0) || !bytes.HasPrefix(payload, []byte("POST /echo HTTP/1.1\r\n")) || !bytes.Contains(payload, []byte("\r\nContent-Length: 5\r\n")) || !bytes.HasSuffix(payload, []byte("\r\n\r\nshort")) {
			state.Fatalf("Test of the http hold failed, %s, the held message should be the whole POST, hold: %+v, payload: %q, error: %v", server.URL, held, payload, err)
		}

		// the page edits the escaped text and sends the bytes as hex
		edited := bytes.Replace(payload, []byte("\r\n\r\nshort"), []byte("\r\n\r\na much longer body"), 1)
		hold := v1.Hold{}
		err = browser.call(state.Context(), http.MethodPut, fmt.Sprintf("/holds/%d", held.ID), v1.EditRequest{Payload: v1.Value{Type: v1.HexValueType, Value: hex.EncodeToString(edited)}}, http.StatusOK, &hold)

		if err == nil {
			err = browser.call(state.Context(), http.MethodPost, fmt.Sprintf("/holds/%d/forward", held.ID), nil, http.StatusNoContent, nil)
		}

		result := <-resultChannel
		first, firstErr := server.received()
		request, receivedErr := server.received()

		if err = errors.Join(err, result.err, firstErr, receivedErr); (err != nil) || (result.output != "/firstlen=18 body=a much longer body") || (first.Path != "/first") || (request.ContentLength != 18) || (request.Body != "a much longer body") {
			state.Errorf("Test of the http hold failed, %s, the longer body should reach the server with its length, curl: %q, server: %+v, error: %v", server.URL, result.output, request, err)
			return
		}

		// the exchange through the page: the edited request with its original head and body
		exchange := v1.Exchange{}
		body := v1.ExchangeBody{}
		err = browser.call(state.Context(), http.MethodGet, fmt.Sprintf("/exchanges/%d", held.ExchangeID), nil, http.StatusOK, &exchange)

		if err == nil {
			err = browser.call(state.Context(), http.MethodGet, fmt.Sprintf("/exchanges/%d/body?side=request", held.ExchangeID), nil, http.StatusOK, &body)
		}

		if (err != nil) || (exchange.Request == nil) || !exchange.Request.Edited || (exchange.Request.Original == nil) || (exchange.Request.BodyLength != 18) || (exchange.Request.OriginalBodyLength != 5) || (body.Payload.Escaped != "a much longer body") || (body.Original == nil) || (body.Original.Escaped != "short") || (exchange.Response == nil) || (exchange.Response.Status != 200) {
			state.Errorf("Test of the http hold failed, %s, the exchange should show the edit, exchange: %+v, body: %+v, error: %v", server.URL, exchange, body, err)
			return
		}

		exchanges := v1.ExchangeList{}
		err = browser.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/exchanges", exchange.FlowID), nil, http.StatusOK, &exchanges)

		if (err != nil) || (len(exchanges.Exchanges) != 2) || (exchanges.Exchanges[0].Request.Target != "/first") || exchanges.Exchanges[0].Request.Edited {
			state.Errorf("Test of the http hold failed, %s, the flow should have the GET and the POST, exchanges: %+v, error: %v", server.URL, exchanges, err)
			return
		}
	}
}

// Test if the HTTP layer returns with the expected errors: a held request nobody decides goes on unchanged after the hold timeout, a request with
// Expect: 100-continue that is not whole goes on as it came after the assembly timeout, a capture filter on an http field is refused, and a message
// larger than the body limit goes on as it came with a note.
func TestHTTPNegative(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	status, err := client.call(state.Context(), http.MethodPut, "/intercept", v1.InterceptRequest{Enabled: true, Filter: `http.request.uri == "/echo"`, Direction: v1.UpDirection, Layer: v1.HTTPLayer}, nil)

	if (err != nil) || (status != http.StatusOK) {
		state.Fatalf("Test of the http layer failed, cannot hold http messages, status: %d, error: %v", status, err)
	}

	config := httpConfigs[2]
	server := startServer(state, config)
	testCase := curlCase{Name: server.URL, Server: config, Suite: "", Expected: receivedRequest{}}
	start := time.Now()
	output, err := runCurl(state.Context(), testUser, append(curlArguments(testCase, server.URL+"echo"), "--data-binary", "short"))
	request, receivedErr := server.received()

	if err = errors.Join(err, receivedErr); (err != nil) || (output != "len=5 body=short") || (request.ContentLength != 5) || (time.Since(start) < apiHoldTimeout) {
		state.Errorf("Test of the http layer failed, an undecided request should go on unchanged after %s, curl: %q after %s, error: %v", apiHoldTimeout, output, time.Since(start), err)
		return
	}

	// Expect: 100-continue: curl sends the body only after the server's 100, and the server only sees the kept head after the assembly timeout, well
	// before the hold timeout and curl's own expect timeout
	start = time.Now()
	output, err = runCurl(state.Context(), testUser, append(curlArguments(testCase, server.URL+"echo"), "-H", "Expect: 100-continue", "--expect100-timeout", "15", "--data-binary", "slow"))
	request, receivedErr = server.received()
	elapsed := time.Since(start)
	_, exchanges, exchangesErr := flowExchanges(state, client, server, 1)

	if err = errors.Join(err, receivedErr, exchangesErr); (err != nil) || (output != "len=4 body=slow") || (request.ContentLength != 4) || (elapsed < apiAssemblyTimeout) || (elapsed >= apiHoldTimeout) || !strings.Contains(exchanges[0].Request.Note, "not whole after "+apiAssemblyTimeout.String()) {
		state.Errorf("Test of the http layer failed, a request that is not whole should go on as it came after the assembly timeout %s, curl: %q after %s, exchanges: %+v, error: %v", apiAssemblyTimeout, output, elapsed, exchanges, err)
		return
	}

	// 2 MiB: over the limit of a whole message, the record layer takes it as it came
	large := strings.Repeat("x", 2<<20)
	arguments := append([]string{"-q", "--silent", "--show-error", "--max-time", curlMaxTime, "-H", "Expect:", "--data-binary", "@-"}, curlArguments(testCase, server.URL+"echo")...)
	output, err = runAsUser(state.Context(), testUser, large, curlPath, arguments...)
	request, receivedErr = server.received()
	_, exchanges, exchangesErr = flowExchanges(state, client, server, 1)

	if err = errors.Join(err, receivedErr, exchangesErr); (err != nil) || (output != "len=2097152 body="+large) || (len(request.Body) != len(large)) || !strings.Contains(exchanges[0].Request.Note, "larger than") || exchanges[0].Request.Edited {
		state.Errorf("Test of the http layer failed, a large request should go on with a note, curl: %d bytes, exchanges: %+v, error: %v", len(output), exchanges, err)
		return
	}

	status, err = client.call(state.Context(), http.MethodPost, "/captures", v1.CaptureRequest{Filter: `http.host == "a"`, Plaintext: false}, nil)

	if (err != nil) || (status != http.StatusBadRequest) {
		state.Errorf("Test of the http layer failed, a capture filter on an http field should be refused, status: %d, error: %v", status, err)
		return
	}
}

// the exchanges of the newest flow to the server, once count of them have their response complete
func flowExchanges(state *testing.T, client apiClient, server testServer, count int) (flowID uint64, exchanges []v1.Exchange, err error) {
	port := serverPortOf(server)
	deadline := time.Now().Add(holdArrival)

	for time.Now().Before(deadline) {
		flows := v1.FlowList{}
		_, err = client.call(state.Context(), http.MethodGet, "/flows?limit=1&filter="+url.QueryEscape("tcp.dstport == "+port), nil, &flows)

		if (err != nil) || (len(flows.Flows) == 0) {
			time.Sleep(holdPoll)
			continue
		}

		flowID = flows.Flows[0].ID
		list := v1.ExchangeList{}
		_, err = client.call(state.Context(), http.MethodGet, fmt.Sprintf("/flows/%d/exchanges", flowID), nil, &list)
		exchanges = list.Exchanges
		complete := 0

		for _, exchange := range exchanges {
			if (exchange.Response != nil) && (exchange.Response.State == v1.CompleteHTTPState) {
				complete++
			}
		}

		if (err == nil) && (complete >= count) {
			return
		}

		time.Sleep(holdPoll)
	}

	err = errors.Join(err, fmt.Errorf("flow %d to port %s should have %d complete exchanges, exchanges: %+v", flowID, port, count, exchanges))
	return
}
