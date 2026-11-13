// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package ui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
)

const (
	// how long the test waits for the fake api to see a closed stream
	streamCloseTimeout time.Duration = 2 * time.Second
)

// a control API on a unix socket that records what it got; the event stream sends one event, a second one when release is closed, and reports when its client went away
type fakeAPI struct {
	target   Target
	mutex    *sync.Mutex
	requests []*http.Request
	release  chan struct{}
	closed   chan struct{}
}

// a running decerter ui in front of a fake API
type testUI struct {
	api    *fakeAPI
	host   string
	token  string
	client *http.Client
}

// what the ui answered, the body is read and closed
type uiAnswer struct {
	StatusCode int
	Header     http.Header
	Cookies    []*http.Cookie
}

// one request to the ui: Host empty is the listener's, Cookie the cookie value under Name (empty Name is the listener's cookie)
type uiRequest struct {
	Method     string
	Path       string
	Host       string
	CookieName string
	Cookie     string
	Headers    map[string]string
	Body       string
}

// Test if the first load with the token sets the cookie and redirects to / without it, and the page, its files and the api are served with the cookie, the right Host and, for a change, the Origin.
func TestGuardPositive(state *testing.T) {
	current := startUI(state)
	response, body := current.do(state, uiRequest{Method: http.MethodGet, Path: "/?token=" + current.token, Cookie: "-"})
	cookies := response.Cookies

	if (response.StatusCode != http.StatusSeeOther) || (response.Header.Get("Location") != "/") || (len(cookies) != 1) || strings.Contains(body, current.token) {
		state.Fatalf("Test of the ui token failed, the first load should redirect to / without the token and set one cookie, status: %d, location: %q, cookies: %v, body: %q", response.StatusCode, response.Header.Get("Location"), cookies, body)
	}

	cookie := cookies[0]

	if (cookie.Name != cookieNameOf(current.host)) || (cookie.Value != current.token) || !cookie.HttpOnly || (cookie.SameSite != http.SameSiteStrictMode) || (cookie.Path != "/") || cookie.Secure || (cookie.MaxAge != 0) || !hasSecurityHeaders(response.Header) {
		state.Fatalf("Test of the ui token failed, the cookie should be HttpOnly, SameSite=Strict, Path=/ and not Secure, cookie: %+v, headers: %v", cookie, response.Header)
	}

	positiveCases := []struct {
		Request     uiRequest
		ContentType string
		Text        string
	}{
		{Request: uiRequest{Method: http.MethodGet, Path: "/"}, ContentType: "text/html", Text: `<script type="module" src="app.js"></script>`},
		{Request: uiRequest{Method: http.MethodGet, Path: "/app.js"}, ContentType: "text/javascript", Text: "new EventSource("},
		{Request: uiRequest{Method: http.MethodGet, Path: "/app.css"}, ContentType: "text/css", Text: "--background"},
		// the browser's own request, typed into the address bar or a reload
		{Request: uiRequest{Method: http.MethodGet, Path: "/", Headers: map[string]string{"Sec-Fetch-Site": "none"}}, ContentType: "text/html", Text: "<title>decerter</title>"},
		{Request: uiRequest{Method: http.MethodGet, Path: "/api/v1/status", Headers: map[string]string{"Origin": "http://" + current.host, "Referer": "http://" + current.host + "/", "Sec-Fetch-Site": "same-origin"}}, ContentType: "application/json", Text: `"mode":"run"`},
		{Request: uiRequest{Method: http.MethodPut, Path: "/api/v1/intercept", Headers: map[string]string{"Origin": "http://" + current.host}, Body: `{"enabled": true}`}, ContentType: "application/json", Text: `"enabled": true`},
		{Request: uiRequest{Method: http.MethodPost, Path: "/api/v1/holds/1/forward", Headers: map[string]string{"Sec-Fetch-Site": "same-origin"}}, ContentType: "application/json", Text: `"forwarded"`},
	}

	for _, positive := range positiveCases {
		response, body = current.do(state, positive.Request)

		if (response.StatusCode != http.StatusOK) || !strings.HasPrefix(response.Header.Get("Content-Type"), positive.ContentType) || !strings.Contains(body, positive.Text) || !hasSecurityHeaders(response.Header) {
			state.Errorf("Test of the ui guard failed, %s %s should be served, status: %d, headers: %v, body: %q", positive.Request.Method, positive.Request.Path, response.StatusCode, response.Header, body)
			return
		}
	}

	// the api gets no cookie, Origin or Referer, and its own host name
	for _, request := range current.api.seen() {
		if (request.Header.Get("Cookie") != "") || (request.Header.Get("Origin") != "") || (request.Header.Get("Referer") != "") || (request.Host != v1.HostName) {
			state.Errorf("Test of the ui proxy failed, the api should get no cookie, Origin or Referer and the host %s, %s %s, host %q, headers: %v", v1.HostName, request.Method, request.URL.Path, request.Host, request.Header)
			return
		}
	}

	if len(current.api.seen()) != 3 {
		state.Errorf("Test of the ui proxy failed, the api should get three requests, requests: %d", len(current.api.seen()))
		return
	}
}

// Test if a request without the token cookie, with another Host, with a wrong token, from another site or port, or a change without the right Origin gets 403 and never reaches the api.
func TestGuardNegative(state *testing.T) {
	current := startUI(state)
	_, port, err := net.SplitHostPort(current.host)

	if err != nil {
		state.Fatalf("Could not split the ui host, error: %s", err.Error())
	}

	otherHost := "127.0.0.1:1"

	if port == "1" {
		otherHost = "127.0.0.1:2"
	}

	negativeCases := []uiRequest{
		// no cookie
		{Method: http.MethodGet, Path: "/", Cookie: "-"},
		{Method: http.MethodGet, Path: "/app.js", Cookie: "-"},
		{Method: http.MethodGet, Path: "/api/v1/status", Cookie: "-"},
		{Method: http.MethodGet, Path: "/api/v1/events", Cookie: "-"},
		{Method: http.MethodPut, Path: "/api/v1/intercept", Cookie: "-", Headers: map[string]string{"Origin": "http://" + current.host}, Body: `{"enabled": true}`},
		// a wrong token, the token anywhere but a GET of /, the cookie of another port
		{Method: http.MethodGet, Path: "/?token=" + otherToken(current.token), Cookie: "-"},
		{Method: http.MethodGet, Path: "/?token=", Cookie: "-"},
		{Method: http.MethodGet, Path: "/api/v1/status?token=" + current.token, Cookie: "-"},
		{Method: http.MethodPost, Path: "/?token=" + current.token, Cookie: "-", Headers: map[string]string{"Origin": "http://" + current.host}},
		{Method: http.MethodGet, Path: "/", Cookie: otherToken(current.token)},
		{Method: http.MethodGet, Path: "/", CookieName: cookiePrefix + "1"},
		// another Host: DNS rebinding, localhost, another port
		{Method: http.MethodGet, Path: "/", Host: "rebind.example:" + port},
		{Method: http.MethodGet, Path: "/api/v1/status", Host: "localhost:" + port},
		{Method: http.MethodGet, Path: "/", Host: otherHost},
		{Method: http.MethodGet, Path: "/?token=" + current.token, Host: "localhost:" + port, Cookie: "-"},
		// another site, or another port of 127.0.0.1, which is the same site to the browser
		{Method: http.MethodGet, Path: "/api/v1/status", Headers: map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{Method: http.MethodGet, Path: "/api/v1/status", Headers: map[string]string{"Sec-Fetch-Site": "same-site"}},
		// a change without its Origin
		{Method: http.MethodPut, Path: "/api/v1/intercept", Headers: map[string]string{"Origin": "http://" + otherHost}, Body: `{"enabled": true}`},
		{Method: http.MethodPut, Path: "/api/v1/intercept", Headers: map[string]string{"Origin": "http://localhost:" + port}, Body: `{"enabled": true}`},
		{Method: http.MethodPut, Path: "/api/v1/intercept", Headers: map[string]string{"Origin": "null"}, Body: `{"enabled": true}`},
		{Method: http.MethodPut, Path: "/api/v1/intercept", Body: `{"enabled": true}`},
		{Method: http.MethodPost, Path: "/api/v1/holds/1/forward", Headers: map[string]string{"Origin": "http://" + current.host, "Sec-Fetch-Site": "cross-site"}},
		{Method: http.MethodDelete, Path: "/api/v1/rules/1", Headers: map[string]string{"Sec-Fetch-Site": "none"}},
	}

	for _, negative := range negativeCases {
		response, body := current.do(state, negative)

		if (response.StatusCode != http.StatusForbidden) || (len(response.Cookies) != 0) || !hasSecurityHeaders(response.Header) || strings.Contains(body, "<") {
			state.Errorf("Test of the ui guard failed, %s %s with host %q, cookie %q and headers %v should be 403 without a cookie, status: %d, headers: %v", negative.Method, negative.Path, negative.Host, negative.Cookie, negative.Headers, response.StatusCode, response.Header)
			return
		}
	}

	if len(current.api.seen()) != 0 {
		state.Errorf("Test of the ui guard failed, no refused request should reach the api, requests: %d", len(current.api.seen()))
		return
	}
}

// Test if the proxy forwards only clean paths under /api/v1/, and nothing else of the ui reaches the api.
func TestProxyPathNegative(state *testing.T) {
	current := startUI(state)
	proxy := newProxy(current.api.target, slog.New(slog.DiscardHandler))

	for _, target := range []string{"/api/v2/status", "/api/v1", "/api/v1/../v2/status", "/api/v1/%2e%2e/x", "/api/v1/holds%2F1", "/api/v1/./status", "/api/v1//status", "/status", "/api/v1x/status"} {
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, http.NoBody))

		if recorder.Code != http.StatusNotFound {
			state.Errorf("Test of the ui proxy failed, %s should not be forwarded, status: %d", target, recorder.Code)
			return
		}
	}

	// through the whole ui: the mux cleans the path with a redirect, files of the page are not the api
	for _, path := range []string{"/api/v1/../../etc/passwd", "/api/v2/status", "/api/v1", "/index.html/../api/v1/status"} {
		response, _ := current.do(state, uiRequest{Method: http.MethodGet, Path: path})

		if (response.StatusCode == http.StatusOK) || (response.StatusCode == http.StatusForbidden) {
			state.Errorf("Test of the ui proxy failed, %s should be redirected or not found, status: %d", path, response.StatusCode)
			return
		}
	}

	response, _ := current.do(state, uiRequest{Method: http.MethodPatch, Path: "/api/v1/intercept", Headers: map[string]string{"Origin": "http://" + current.host}})

	if (response.StatusCode != http.StatusMethodNotAllowed) || (len(current.api.seen()) != 0) {
		state.Errorf("Test of the ui proxy failed, PATCH should not be forwarded and nothing should reach the api, status: %d, requests: %d", response.StatusCode, len(current.api.seen()))
		return
	}
}

// Test if the event stream goes through the proxy one event at a time, and a client that goes away closes the stream to the api.
func TestProxyStreamPositive(state *testing.T) {
	current := startUI(state)
	ctx, cancel := context.WithCancel(state.Context())
	defer cancel()
	request, err := current.request(ctx, uiRequest{Method: http.MethodGet, Path: "/api/v1/events"})

	if err != nil {
		state.Fatalf("Could not make the stream request, error: %s", err.Error())
	}

	response, err := current.client.Do(request)

	if err != nil {
		state.Fatalf("Test of the ui stream failed, error: %s", err.Error())
	}

	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			state.Errorf("Could not close the stream, error: %s", closeErr.Error())
		}
	}()

	if (response.StatusCode != http.StatusOK) || (response.Header.Get("Content-Type") != "text/event-stream") || !hasSecurityHeaders(response.Header) || (len(response.Header.Values("Cache-Control")) != 1) {
		state.Fatalf("Test of the ui stream failed, status: %d, headers: %v", response.StatusCode, response.Header)
	}

	// the first event arrives while the api still holds the stream open: nothing waits for more
	reader := bufio.NewReader(response.Body)
	first, err := readEvent(reader)

	if (err != nil) || !strings.Contains(first, "event: flow_opened") {
		state.Fatalf("Test of the ui stream failed, the first event should arrive at once, event: %q, error: %v", first, err)
	}

	close(current.api.release)
	second, err := readEvent(reader)

	if (err != nil) || !strings.Contains(second, "event: held") {
		state.Fatalf("Test of the ui stream failed, the second event should follow, event: %q, error: %v", second, err)
	}

	cancel()

	select {
	case <-current.api.closed:
	case <-time.After(streamCloseTimeout):
		state.Errorf("Test of the ui stream failed, the api stream should end when the browser goes away")
		return
	}
}

// Test if ParseTarget returns with the expected target for paths, abstract sockets and loopback addresses.
func TestParseTargetPositive(state *testing.T) {
	positiveCases := map[string]Target{
		"/run/decerter/api.sock":      {Network: UnixNetwork, Address: "/run/decerter/api.sock"},
		"api.sock":                {Network: UnixNetwork, Address: "api.sock"},
		"./127.0.0.1:8080":        {Network: UnixNetwork, Address: "./127.0.0.1:8080"},
		"@decerter-api":               {Network: UnixNetwork, Address: "@decerter-api"},
		"127.0.0.1:8080":          {Network: TCPNetwork, Address: "127.0.0.1:8080"},
		"127.1.2.3:8080":          {Network: TCPNetwork, Address: "127.1.2.3:8080"},
		"[::1]:8080":              {Network: TCPNetwork, Address: "[::1]:8080"},
		"[::ffff:127.0.0.1]:8080": {Network: TCPNetwork, Address: "127.0.0.1:8080"},
	}

	for value, expected := range positiveCases {
		target, err := ParseTarget(value)

		if (err != nil) || (target != expected) {
			state.Errorf("Test of ParseTarget failed, %q should be %+v, target: %+v, error: %v", value, expected, target, err)
			return
		}
	}
}

// Test if ParseTarget returns with the expected errors for an empty address and TCP addresses that are not loopback.
func TestParseTargetNegative(state *testing.T) {
	negativeCases := map[string]error{
		"":                 ErrAPIAddress,
		"@":                ErrAPIAddress,
		"10.0.0.1:8080":    ErrNotLoopback,
		"0.0.0.0:8080":     ErrNotLoopback,
		"[::]:8080":        ErrNotLoopback,
		"localhost:8080":   ErrNotLoopback,
		"example.com:8080": ErrNotLoopback,
		"127.0.0.1:0":      ErrAPIAddress,
		"[fe80::1%lo]:80":  ErrNotLoopback,
		"127.0.0.1:99999":  ErrAPIAddress,
		"127.0.0.1:http":   ErrAPIAddress,
	}

	for value, expected := range negativeCases {
		_, err := ParseTarget(value)

		if !errors.Is(err, expected) {
			state.Errorf("Test of ParseTarget failed, %q should fail with %v, error: %v", value, expected, err)
			return
		}
	}
}

// Test if Check returns with the status of a running api on a socket file and on a loopback port, the host side of adb forward, and the proxy reaches the port too.
func TestCheckPositive(state *testing.T) {
	api := startFakeAPI(state)
	tcpTarget := startFakeTCPAPI(state, api)

	for _, target := range []Target{api.target, tcpTarget} {
		status, err := Check(state.Context(), target)

		if (err != nil) || (status.Mode != "run") || (status.Processing != v1.InterceptProcessing) {
			state.Errorf("Test of Check failed, %s, status: %+v, error: %v", target, status, err)
			return
		}
	}

	recorder := httptest.NewRecorder()
	newProxy(tcpTarget, slog.New(slog.DiscardHandler)).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/status", http.NoBody))

	if (recorder.Code != http.StatusOK) || !strings.Contains(recorder.Body.String(), `"mode":"run"`) {
		state.Errorf("Test of the ui proxy failed, the api on %s should answer, status: %d, body: %q", tcpTarget, recorder.Code, recorder.Body.String())
		return
	}
}

// Test if Check returns with an error that says what to do for a missing socket, a socket the user may not open, an abstract socket nobody listens on, a closed port and a server that refuses the user.
func TestCheckNegative(state *testing.T) {
	directory := state.TempDir()
	missing := filepath.Join(directory, "missing.sock")
	refusing := startRefusingServer(state)
	negativeCases := []struct {
		Target   Target
		Expected error
	}{
		{Target: Target{Network: UnixNetwork, Address: missing}, Expected: ErrNoSocket},
		{Target: Target{Network: UnixNetwork, Address: fmt.Sprintf("@decerter-ui-test-%d", os.Getpid())}, Expected: ErrNoServer},
		{Target: Target{Network: TCPNetwork, Address: closedPort(state)}, Expected: ErrNoServer},
		{Target: refusing, Expected: ErrRefused},
	}

	// root opens every socket file
	if os.Geteuid() != 0 {
		api := startFakeAPI(state)
		err := os.Chmod(api.target.Address, 0o600)

		if err == nil {
			err = os.Chmod(filepath.Dir(api.target.Address), 0o000)
		}

		if err != nil {
			state.Fatalf("Could not take the socket away, error: %s", err.Error())
		}

		state.Cleanup(func() {
			if chmodErr := os.Chmod(filepath.Dir(api.target.Address), 0o700); chmodErr != nil {
				state.Errorf("Could not give the socket back, error: %s", chmodErr.Error())
			}
		})

		negativeCases = append(negativeCases, struct {
			Target   Target
			Expected error
		}{Target: api.target, Expected: ErrSocketPermission})
	}

	for _, negative := range negativeCases {
		_, err := Check(state.Context(), negative.Target)

		if !errors.Is(err, negative.Expected) {
			state.Errorf("Test of Check failed, %s should fail with %v, error: %v", negative.Target, negative.Expected, err)
			return
		}
	}

	_, err := Check(state.Context(), Target{Network: UnixNetwork, Address: missing})

	if (err == nil) || !strings.Contains(err.Error(), "decerter run --api-socket") {
		state.Errorf("Test of Check failed, the error should say how to start decerter, error: %v", err)
		return
	}

	if !strings.Contains(ErrSocketPermission.Error(), "groupadd decerter") || !strings.Contains(ErrSocketPermission.Error(), "usermod -aG decerter") {
		state.Errorf("Test of Check failed, the permission error should name groupadd and usermod, error: %v", ErrSocketPermission)
		return
	}
}

// Test if NewToken returns with 32 random bytes in base64url, and URL puts it into the query.
func TestTokenPositive(state *testing.T) {
	first, err := NewToken()

	if err != nil {
		state.Fatalf("Test of NewToken failed, error: %s", err.Error())
	}

	second, err := NewToken()

	if (err != nil) || (len(first) != 43) || (first == second) || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(first) {
		state.Errorf("Test of NewToken failed, tokens should be 43 base64url characters and differ, tokens: %q %q, error: %v", first, second, err)
		return
	}

	if URL("127.0.0.1:4242", first) != "http://127.0.0.1:4242/?token="+first {
		state.Errorf("Test of URL failed, URL: %s", URL("127.0.0.1:4242", first))
		return
	}
}

// Test if the page has its SPDX line, no inline script, style or event handler, and its script never writes HTML.
func TestWebPositive(state *testing.T) {
	forbidden := map[string]*regexp.Regexp{
		"web/index.html": regexp.MustCompile(`<script(\s[^>]*)?>[^<]|<script(?:\s+type="module")?>|\sstyle=|\son[a-z]+=|<style|javascript:`),
		"web/app.js":     regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setAttribute\(\s*'on|\.style\.|setAttribute\(\s*'style`),
		"web/app.css":    regexp.MustCompile(`@import|url\(`),
	}

	for name, pattern := range forbidden {
		content, err := webFiles.ReadFile(name)

		if err != nil {
			state.Fatalf("Could not read %s, error: %s", name, err.Error())
		}

		if !strings.Contains(strings.Join(strings.SplitN(string(content), "\n", 3)[:2], "\n"), "SPDX-License-Identifier: AGPL-3.0-only") {
			state.Errorf("Test of the page failed, %s should have its SPDX line", name)
			return
		}

		if match := pattern.Find(content); match != nil {
			state.Errorf("Test of the page failed, %s has %q", name, match)
			return
		}
	}
}

// a decerter ui on 127.0.0.1 in front of a fake api, stopped with the test; the client follows no redirect
func startUI(state *testing.T) (current testUI) {
	api := startFakeAPI(state)
	token, err := NewToken()

	if err != nil {
		state.Fatalf("Could not make a token, error: %s", err.Error())
	}

	listener, host, err := Listen()

	if err != nil {
		state.Fatalf("Could not listen, error: %s", err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())
	doneChannel := make(chan error, 1)
	logger := slog.New(slog.DiscardHandler)

	// ui server
	go func() {
		doneChannel <- Serve(ctx, listener, Handler(api.target, token, host, logger), logger)
	}()

	transport := &http.Transport{}
	state.Cleanup(func() {
		transport.CloseIdleConnections()
		cancel()

		if serveErr := <-doneChannel; serveErr != nil {
			state.Errorf("Could not serve the ui, error: %s", serveErr.Error())
		}
	})

	current = testUI{
		api:   api,
		host:  host,
		token: token,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	return
}

func (current testUI) request(ctx context.Context, test uiRequest) (request *http.Request, err error) {
	request, err = http.NewRequestWithContext(ctx, test.Method, "http://"+current.host+test.Path, strings.NewReader(test.Body))

	if err != nil {
		return
	}

	request.Host = current.host

	if test.Host != "" {
		request.Host = test.Host
	}

	cookieName := cookieNameOf(current.host)

	if test.CookieName != "" {
		cookieName = test.CookieName
	}

	cookie := current.token

	if test.Cookie != "" {
		cookie = test.Cookie
	}

	if cookie != "-" {
		request.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	}

	for name, value := range test.Headers {
		request.Header.Set(name, value)
	}

	return
}

// the answer and its body
func (current testUI) do(state *testing.T, test uiRequest) (answer uiAnswer, body string) {
	request, err := current.request(state.Context(), test)

	if err != nil {
		state.Fatalf("Could not make request %s %s, error: %s", test.Method, test.Path, err.Error())
	}

	response, err := current.client.Do(request)

	if err != nil {
		state.Fatalf("Could not send request %s %s, error: %s", test.Method, test.Path, err.Error())
	}

	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			state.Errorf("Could not close the body, error: %s", closeErr.Error())
		}
	}()

	content, err := io.ReadAll(response.Body)

	if err != nil {
		state.Fatalf("Could not read the body of %s %s, error: %s", test.Method, test.Path, err.Error())
	}

	answer = uiAnswer{StatusCode: response.StatusCode, Header: response.Header, Cookies: response.Cookies()}
	body = string(content)
	return
}

// the token with its last character changed
func otherToken(token string) (other string) {
	last := "A"

	if strings.HasSuffix(token, last) {
		last = "B"
	}

	other = token[:len(token)-1] + last
	return
}

func hasSecurityHeaders(header http.Header) (hasHeaders bool) {
	hasHeaders = (header.Get("Content-Security-Policy") == contentSecurityPolicy) && (header.Get("X-Content-Type-Options") == "nosniff") && (header.Get("Referrer-Policy") == "no-referrer") && (header.Get("Cache-Control") == "no-store")
	return
}

// one server-sent event, up to its empty line
func readEvent(reader *bufio.Reader) (event string, err error) {
	for {
		line, readErr := reader.ReadString('\n')

		if err = readErr; err != nil {
			return
		}

		if line == "\n" {
			return
		}

		event += line
	}
}

// the fake api on a socket file in the test's directory
func startFakeAPI(state *testing.T) (api *fakeAPI) {
	directory, err := os.MkdirTemp("", "decerter-ui-")

	if err != nil {
		state.Fatalf("Could not make a directory, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if removeErr := os.RemoveAll(directory); removeErr != nil {
			state.Errorf("Could not remove %s, error: %s", directory, removeErr.Error())
		}
	})

	socket := filepath.Join(directory, "api.sock")
	listener, err := net.Listen("unix", socket)

	if err != nil {
		state.Fatalf("Could not listen on %s, error: %s", socket, err.Error())
	}

	api = &fakeAPI{
		target:   Target{Network: UnixNetwork, Address: socket},
		mutex:    &sync.Mutex{},
		requests: nil,
		release:  make(chan struct{}),
		closed:   make(chan struct{}),
	}
	server := &http.Server{Handler: http.HandlerFunc(api.handle), ReadHeaderTimeout: readHeaderTimeout}

	// fake api server
	go func() {
		if serveErr := server.Serve(listener); !errors.Is(serveErr, http.ErrServerClosed) {
			state.Errorf("Could not serve the fake api, error: %v", serveErr)
		}
	}()

	state.Cleanup(func() {
		if closeErr := server.Close(); closeErr != nil {
			state.Errorf("Could not close the fake api, error: %s", closeErr.Error())
		}
	})

	return
}

// the handler of api on a loopback port as well
func startFakeTCPAPI(state *testing.T, api *fakeAPI) (target Target) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")

	if err != nil {
		state.Fatalf("Could not listen, error: %s", err.Error())
	}

	server := &http.Server{Handler: http.HandlerFunc(api.handle), ReadHeaderTimeout: readHeaderTimeout}

	// fake api server on tcp
	go func() {
		if serveErr := server.Serve(listener); !errors.Is(serveErr, http.ErrServerClosed) {
			state.Errorf("Could not serve the fake api, error: %v", serveErr)
		}
	}()

	state.Cleanup(func() {
		if closeErr := server.Close(); closeErr != nil {
			state.Errorf("Could not close the fake api, error: %s", closeErr.Error())
		}
	})

	target, err = ParseTarget(listener.Addr().String())

	if err != nil {
		state.Fatalf("Could not parse %s, error: %s", listener.Addr().String(), err.Error())
	}

	return
}

func (api *fakeAPI) handle(writer http.ResponseWriter, request *http.Request) {
	api.mutex.Lock()
	api.requests = append(api.requests, request.Clone(context.Background()))
	api.mutex.Unlock()
	body, err := io.ReadAll(request.Body)

	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	writer.Header().Set("Content-Type", "application/json")

	switch request.Method + " " + request.URL.Path {
	case "GET /api/v1/status":
		_, err = fmt.Fprint(writer, `{"mode":"run","processing":"intercept","version":"test"}`)
	case "PUT /api/v1/intercept":
		_, err = writer.Write(body)
	case "POST /api/v1/holds/1/forward":
		_, err = fmt.Fprint(writer, `{"forwarded":true}`)
	case "GET /api/v1/events":
		api.stream(writer, request)
		return
	default:
		writer.WriteHeader(http.StatusNotFound)
	}

	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
	}
}

// one event, a second once released, then open until the client goes away
func (api *fakeAPI) stream(writer http.ResponseWriter, request *http.Request) {
	defer close(api.closed)
	controller := http.NewResponseController(writer)
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)
	_, err := fmt.Fprint(writer, "id: 1\nevent: flow_opened\ndata: {\"seq\":1}\n\n")

	if err == nil {
		err = controller.Flush()
	}

	if err != nil {
		return
	}

	select {
	case <-api.release:
	case <-request.Context().Done():
		return
	}

	_, err = fmt.Fprint(writer, "id: 2\nevent: held\ndata: {\"seq\":2}\n\n")

	if err == nil {
		err = controller.Flush()
	}

	if err != nil {
		return
	}

	<-request.Context().Done()
}

func (api *fakeAPI) seen() (requests []*http.Request) {
	api.mutex.Lock()
	defer api.mutex.Unlock()
	requests = append(requests, api.requests...)
	return
}

// a socket that closes every connection at once, the way the api refuses a peer of an abstract socket
func startRefusingServer(state *testing.T) (target Target) {
	name := fmt.Sprintf("@decerter-ui-refuse-%d", os.Getpid())
	listener, err := net.Listen("unix", name)

	if err != nil {
		state.Fatalf("Could not listen on %s, error: %s", name, err.Error())
	}

	state.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil {
			state.Errorf("Could not close %s, error: %s", name, closeErr.Error())
		}
	})

	// refusing server
	go func() {
		for {
			connection, acceptErr := listener.Accept()

			if acceptErr != nil {
				return
			}

			if closeErr := connection.Close(); closeErr != nil {
				return
			}
		}
	}()

	target = Target{Network: UnixNetwork, Address: name}
	return
}

// a loopback port nothing listens on
func closedPort(state *testing.T) (address string) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")

	if err != nil {
		state.Fatalf("Could not listen, error: %s", err.Error())
	}

	address = listener.Addr().String()

	if closeErr := listener.Close(); closeErr != nil {
		state.Fatalf("Could not close the listener, error: %s", closeErr.Error())
	}

	return
}
