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
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/ui"
)

// the browser side of decerter ui: the cookie of the first load goes with every request under the secret path base, a change carries the page's Origin
type uiBrowser struct {
	client *http.Client
	host   string
	base   string
	cookie *http.Cookie
}

// Test if a request held through decerter ui, the way the page does it, can be edited from GET / to GET /test and forwarded, plain and over TLS 1.3, while the flow list and the event stream come through the proxy.
func TestUIHoldPositive(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	browser := startUI(state, client.socket)
	page, err := browser.text(state.Context(), http.MethodGet, "/", nil, http.StatusOK)

	if (err != nil) || !strings.Contains(page, `<script type="module" src="app.js"></script>`) {
		state.Fatalf("Test of the ui failed, the page should load with the cookie, page: %q, error: %v", page, err)
	}

	flows := v1.FlowList{}
	err = browser.call(state.Context(), http.MethodGet, "/flows", nil, http.StatusOK, &flows)

	if err != nil {
		state.Fatalf("Test of the ui failed, cannot list the flows, error: %s", err.Error())
	}

	events := browser.subscribe(state)
	interceptState := v1.InterceptState{}
	err = browser.call(state.Context(), http.MethodPut, "/intercept", v1.InterceptRequest{Enabled: true, Filter: `proc.comm == "curl"`, Direction: v1.UpDirection}, http.StatusOK, &interceptState)

	if (err != nil) || !interceptState.Enabled {
		state.Fatalf("Test of the ui failed, cannot turn intercept on, state: %+v, error: %v", interceptState, err)
	}

	for _, config := range []serverConfig{{Certificate: nil}, {Certificate: &rsaCertificate, Version: tls.VersionTLS13}} {
		server := startServer(state, config)
		testCase := curlCase{Name: server.URL, Server: config, Suite: "", Expected: receivedRequest{}}
		resultChannel := curlAsync(state.Context(), curlArguments(testCase, server.URL))
		held, err := browser.waitHeld(state.Context())

		if err != nil {
			state.Fatalf("Test of the ui failed, %s, error: %s", server.URL, err.Error())
		}

		// the page edits the escaped text and sends the bytes as hex
		payload, err := hex.DecodeString(held.Payload.Hex)

		if (err != nil) || !bytes.HasPrefix(payload, []byte("GET / HTTP/1.1\r\n")) {
			state.Fatalf("Test of the ui failed, %s, the held request should start with GET /, payload: %q, error: %v", server.URL, payload, err)
		}

		edited := v1.Hold{}
		err = browser.call(state.Context(), http.MethodPut, fmt.Sprintf("/holds/%d", held.ID), v1.EditRequest{Payload: v1.Value{Type: v1.HexValueType, Value: hex.EncodeToString(bytes.Replace(payload, []byte("GET / "), []byte("GET /test "), 1))}}, http.StatusOK, &edited)

		if (err != nil) || !edited.Edited {
			state.Fatalf("Test of the ui failed, %s, cannot edit, hold: %+v, error: %v", server.URL, edited, err)
		}

		err = browser.call(state.Context(), http.MethodPost, fmt.Sprintf("/holds/%d/forward", held.ID), nil, http.StatusNoContent, nil)
		result := <-resultChannel
		request, receivedErr := server.received()

		if (err != nil) || (result.err != nil) || (result.output != "/test") || (receivedErr != nil) || (request.Path != "/test") {
			state.Errorf("Test of the ui failed, %s, the edited request should reach the server, curl: %+v, server: %+v, error: %v", server.URL, result, request, errors.Join(err, receivedErr))
			return
		}

		// the flow list with a filter and the message as the history kept it
		err = browser.call(state.Context(), http.MethodGet, "/flows?filter="+url.QueryEscape(`proc.comm == "curl"`), nil, http.StatusOK, &flows)

		if (err != nil) || (len(flows.Flows) == 0) || (flows.Flows[0].ID != held.FlowID) {
			state.Errorf("Test of the ui failed, %s, the filtered flow list should start with the held flow %d, flows: %+v, error: %v", server.URL, held.FlowID, flows, err)
			return
		}

		detail := v1.MessageDetail{}
		err = browser.call(state.Context(), http.MethodGet, fmt.Sprintf("/messages/%d?offset=4&length=5", held.ID), nil, http.StatusOK, &detail)

		if (err != nil) || !detail.Edited || (detail.Payload.Escaped != "/test") || (detail.Original == nil) || !strings.HasPrefix(detail.Original.Escaped, "/ HTT") {
			state.Errorf("Test of the ui failed, %s, the message should be edited, detail: %+v, error: %v", server.URL, detail, err)
			return
		}
	}

	// the stream through the proxy told every hold and its forward
	streamed := events.wait(state, v1.HoldReleasedEventType, 2)
	held, released := 0, 0

	for _, event := range streamed {
		switch event.Type {
		case v1.HeldEventType:
			held++
		case v1.HoldReleasedEventType:
			if event.Reason == string(intercept.ForwardReleaseReason) {
				released++
			}
		default:
		}
	}

	if (held != 2) || (released != 2) {
		state.Errorf("Test of the ui event stream failed, two holds should be streamed and forwarded, held: %d, forwarded: %d", held, released)
		return
	}
}

// Test if decerter ui answers 403 without the cookie, to another Host and to a change from another Origin, and such a change does not reach decerter.
func TestUINegative(state *testing.T) {
	client := startAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{intercept.IdentityRule{}})
	browser := startUI(state, client.socket)
	off := v1.InterceptRequest{Enabled: false, Filter: "", Direction: ""}
	on := v1.InterceptRequest{Enabled: true, Filter: "", Direction: ""}
	negativeCases := []struct {
		Name   string
		Method string
		Path   string
		Body   any
		Change func(request *http.Request)
	}{
		{Name: "no cookie", Method: http.MethodGet, Path: "/", Change: func(request *http.Request) { request.Header.Del("Cookie") }},
		{Name: "no cookie for the api", Method: http.MethodGet, Path: v1.BasePath + "/flows", Change: func(request *http.Request) { request.Header.Del("Cookie") }},
		{Name: "a wrong token", Method: http.MethodGet, Path: "/?token=" + strings.Repeat("x", 43), Change: func(request *http.Request) { request.Header.Del("Cookie") }},
		{Name: "another Host", Method: http.MethodGet, Path: v1.BasePath + "/flows", Change: func(request *http.Request) { request.Host = "rebind.example:" + request.URL.Port() }},
		{Name: "localhost", Method: http.MethodGet, Path: "/", Change: func(request *http.Request) { request.Host = "localhost:" + request.URL.Port() }},
		{Name: "the api outside the secret path", Method: http.MethodGet, Path: v1.BasePath + "/flows", Change: func(request *http.Request) { request.URL.Path = v1.BasePath + "/flows" }},
		{Name: "a code decerter ui never made", Method: http.MethodGet, Path: "/", Change: func(request *http.Request) {
			request.URL.Path = "/"
			request.URL.RawQuery = "code=" + strings.Repeat("y", 43)
			request.Header.Del("Cookie")
		}},
		{Name: "another Origin", Method: http.MethodPut, Path: v1.BasePath + "/intercept", Body: on, Change: func(request *http.Request) { request.Header.Set("Origin", "http://127.0.0.1:1") }},
		{Name: "no Origin", Method: http.MethodPut, Path: v1.BasePath + "/intercept", Body: on, Change: func(request *http.Request) {
			request.Header.Del("Origin")
			request.Header.Del("Sec-Fetch-Site")
		}},
		{Name: "another site", Method: http.MethodPut, Path: v1.BasePath + "/intercept", Body: on, Change: func(request *http.Request) { request.Header.Set("Sec-Fetch-Site", "same-site") }},
	}

	err := browser.call(state.Context(), http.MethodPut, "/intercept", off, http.StatusOK, nil)

	if err != nil {
		state.Fatalf("Test of the ui failed, cannot turn intercept off, error: %s", err.Error())
	}

	for _, negative := range negativeCases {
		request, err := browser.request(state.Context(), negative.Method, negative.Path, negative.Body)

		if err != nil {
			state.Fatalf("Could not make the request, error: %s", err.Error())
		}

		negative.Change(request)
		status, body, err := browser.send(request)

		if (err != nil) || (status != http.StatusForbidden) || (strings.TrimSpace(body) != "forbidden") {
			state.Errorf("Test of the ui failed, %s should be 403, status: %d, body: %q, error: %v", negative.Name, status, body, err)
			return
		}
	}

	status := v1.Status{}
	code, err := client.call(state.Context(), http.MethodGet, "/status", nil, &status)

	if (err != nil) || (code != http.StatusOK) || status.Intercept.Enabled {
		state.Errorf("Test of the ui failed, a refused change should not reach decerter, status: %d, intercept: %+v, error: %v", code, status.Intercept, err)
		return
	}
}

// decerter ui in this process for the api on socket, stopped with the test; the browser has made its first load and has the cookie
func startUI(state *testing.T, socket string) (browser uiBrowser) {
	target, err := ui.ParseTarget(socket)

	if err != nil {
		state.Fatalf("Could not parse the api socket, error: %s", err.Error())
	}

	_, err = ui.Check(state.Context(), target)

	if err != nil {
		state.Fatalf("Could not reach the api, error: %s", err.Error())
	}

	credentials, err := ui.NewCredentials()

	if err != nil {
		state.Fatalf("Could not make the token, error: %s", err.Error())
	}

	listener, host, err := ui.Listen()

	if err != nil {
		state.Fatalf("Could not listen for the ui, error: %s", err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())
	doneChannel := make(chan error, 1)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// ui server
	go func() {
		doneChannel <- ui.Serve(ctx, listener, ui.Handler(target, credentials, host, logger), logger)
	}()

	transport := &http.Transport{}
	state.Cleanup(func() {
		transport.CloseIdleConnections()
		cancel()

		if serveErr := <-doneChannel; serveErr != nil {
			state.Errorf("Could not serve the ui, error: %s", serveErr.Error())
		}
	})

	browser = uiBrowser{
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		host:   host,
		base:   "",
		cookie: nil,
	}

	// the first load of the printed URL: a cookie for the secret path and a redirect there without the token
	response, err := browser.client.Get(ui.URL(host, credentials.Token))

	if err != nil {
		state.Fatalf("Could not load the ui, error: %s", err.Error())
	}

	if closeErr := response.Body.Close(); closeErr != nil {
		state.Fatalf("Could not close the answer, error: %s", closeErr.Error())
	}

	cookies := response.Cookies()

	location := response.Header.Get("Location")

	if (response.StatusCode != http.StatusSeeOther) || (location != "/"+credentials.Prefix+"/") || (len(cookies) != 1) || !cookies[0].HttpOnly || (cookies[0].SameSite != http.SameSiteStrictMode) || (cookies[0].Path != location) {
		state.Fatalf("Test of the ui failed, the first load should set the cookie for the secret path and redirect there, status: %d, location: %q, cookies: %v", response.StatusCode, location, cookies)
	}

	browser.base = strings.TrimSuffix(location, "/")
	browser.cookie = cookies[0]
	return
}

// a request the way the page sends it: the cookie, and the page's Origin for a change
func (browser uiBrowser) request(ctx context.Context, method string, path string, body any) (request *http.Request, err error) {
	var reader io.Reader = http.NoBody

	if body != nil {
		encoded, encodeErr := json.Marshal(body)

		if err = encodeErr; err != nil {
			return
		}

		reader = bytes.NewReader(encoded)
	}

	request, err = http.NewRequestWithContext(ctx, method, "http://"+browser.host+browser.base+path, reader)

	if err != nil {
		return
	}

	request.AddCookie(browser.cookie)
	request.Header.Set("Sec-Fetch-Site", "same-origin")

	if (method != http.MethodGet) && (method != http.MethodHead) {
		request.Header.Set("Origin", "http://"+browser.host)
		request.Header.Set("Content-Type", "application/json")
	}

	return
}

func (browser uiBrowser) send(request *http.Request) (status int, body string, err error) {
	response, err := browser.client.Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	content, err := io.ReadAll(response.Body)
	status, body = response.StatusCode, string(content)
	return
}

// a page path, an error unless the answer has the expected status
func (browser uiBrowser) text(ctx context.Context, method string, path string, body any, expected int) (text string, err error) {
	request, err := browser.request(ctx, method, path, body)

	if err != nil {
		return
	}

	status, text, err := browser.send(request)

	if (err == nil) && (status != expected) {
		err = fmt.Errorf("status %d: %s", status, text)
	}

	return
}

// an api path under /api/v1 through the ui; result nil reads no answer
func (browser uiBrowser) call(ctx context.Context, method string, path string, body any, expected int, result any) (err error) {
	text, err := browser.text(ctx, method, v1.BasePath+path, body, expected)

	if (err != nil) || (result == nil) {
		return
	}

	err = json.Unmarshal([]byte(text), result)
	return
}

// the first held message, as the page's held list shows it
func (browser uiBrowser) waitHeld(ctx context.Context) (held v1.Hold, err error) {
	deadline := time.Now().Add(holdArrival)

	for time.Now().Before(deadline) {
		holds := v1.HoldList{}
		err = browser.call(ctx, http.MethodGet, "/holds", nil, http.StatusOK, &holds)

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

// the event stream through the ui, read until the test ends
func (browser uiBrowser) subscribe(state *testing.T) (log *eventLog) {
	log = &eventLog{mutex: &sync.Mutex{}, events: nil, raw: nil}
	request, err := browser.request(state.Context(), http.MethodGet, v1.BasePath+"/events", nil)

	if err != nil {
		state.Fatalf("Could not make the event request, error: %s", err.Error())
	}

	response, err := browser.client.Do(request)

	if err != nil {
		state.Fatalf("Could not subscribe to the events through the ui, error: %s", err.Error())
	}

	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')

	if (err != nil) || (response.StatusCode != http.StatusOK) || (first != ": decerter events\n") {
		state.Fatalf("Could not read the event stream through the ui, status: %d, first line: %q, error: %v", response.StatusCode, first, err)
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
