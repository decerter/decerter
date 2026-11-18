// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package ui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/api"
	"github.com/decerter/decerter/internal/history"
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
	api         *fakeAPI
	host        string
	credentials *Credentials
	client      *http.Client
}

// what the ui answered, the body is read and closed
type uiAnswer struct {
	StatusCode int
	Header     http.Header
	Cookies    []*http.Cookie
}

// one request to the ui: Path is under the secret path unless IsRoot, Host empty is the listener's, Cookie the cookie value under Name (empty Name is the listener's cookie)
type uiRequest struct {
	Method     string
	Path       string
	IsRoot     bool
	Host       string
	CookieName string
	Cookie     string
	Headers    map[string]string
	Body       string
}

// Test if the first load with the token, or once with the code, sets the cookie for the secret path and redirects there without them, and the page, its files and the api are served there with the cookie, the right Host and, for a change, the Origin.
func TestGuardPositive(state *testing.T) {
	current := startUI(state)
	code, err := current.credentials.NewCode()

	if err != nil {
		state.Fatalf("Could not make a code, error: %s", err.Error())
	}

	base := "/" + current.credentials.Prefix + "/"

	for _, first := range []string{"/?token=" + current.credentials.Token, "/?code=" + code, "/?token=" + current.credentials.Token} {
		response, body := current.do(state, uiRequest{Method: http.MethodGet, Path: first, IsRoot: true, Cookie: "-"})
		cookies := response.Cookies

		if (response.StatusCode != http.StatusSeeOther) || (response.Header.Get("Location") != base) || (len(cookies) != 1) || strings.Contains(body, current.credentials.Token) || strings.Contains(body, code) {
			state.Fatalf("Test of the ui token failed, the first load %s should redirect to the secret path without the token and set one cookie, status: %d, location: %q, cookies: %v, body: %q", first, response.StatusCode, response.Header.Get("Location"), cookies, body)
		}

		cookie := cookies[0]

		if (cookie.Name != cookieNameOf(current.host)) || (cookie.Value != current.credentials.Token) || !cookie.HttpOnly || (cookie.SameSite != http.SameSiteStrictMode) || (cookie.Path != base) || cookie.Secure || (cookie.MaxAge != 0) || !hasSecurityHeaders(response.Header) {
			state.Fatalf("Test of the ui token failed, the cookie should be HttpOnly, SameSite=Strict, for the secret path and not Secure, cookie: %+v, headers: %v", cookie, response.Header)
		}
	}

	var response uiAnswer
	var body string

	positiveCases := []struct {
		Request     uiRequest
		ContentType string
		Text        string
	}{
		{Request: uiRequest{Method: http.MethodGet, Path: "/"}, ContentType: "text/html", Text: `<script type="module" src="app.js"></script>`},
		{Request: uiRequest{Method: http.MethodGet, Path: "/app.js"}, ContentType: "text/javascript", Text: "new EventSource("},
		{Request: uiRequest{Method: http.MethodGet, Path: "/app.css"}, ContentType: "text/css", Text: "--background"},
		{Request: uiRequest{Method: http.MethodGet, Path: "/favicon.svg"}, ContentType: "image/svg+xml", Text: "<svg "},
		{Request: uiRequest{Method: http.MethodGet, Path: "/fonts/inter-400-700-latin.woff2"}, ContentType: "font/woff2", Text: "wOF2"},
		{Request: uiRequest{Method: http.MethodGet, Path: "/fonts/OFL.txt"}, ContentType: "text/plain", Text: "SIL OPEN FONT LICENSE"},
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

	// the api gets no cookie, Origin, Referer or Sec-Fetch-Site, and its own host name
	for _, request := range current.api.seen() {
		if (request.Header.Get("Cookie") != "") || (request.Header.Get("Origin") != "") || (request.Header.Get("Referer") != "") || (request.Header.Get("Sec-Fetch-Site") != "") || (request.Host != v1.HostName) {
			state.Errorf("Test of the ui proxy failed, the api should get no cookie, Origin, Referer or Sec-Fetch-Site and the host %s, %s %s, host %q, headers: %v", v1.HostName, request.Method, request.URL.Path, request.Host, request.Header)
			return
		}
	}

	if len(current.api.seen()) != 3 {
		state.Errorf("Test of the ui proxy failed, the api should get three requests, requests: %d", len(current.api.seen()))
		return
	}
}

// Test if a request without the token cookie, outside the secret path, with another Host, with a wrong token or a code that is used, expired or never made, from another site or port, or a change without the right Origin gets 403 and never reaches the api.
func TestGuardNegative(state *testing.T) {
	current := startUI(state)
	token := current.credentials.Token
	code, err := current.credentials.NewCode()

	if err != nil {
		state.Fatalf("Could not make a code, error: %s", err.Error())
	}

	response, _ := current.do(state, uiRequest{Method: http.MethodGet, Path: "/?code=" + code, IsRoot: true, Cookie: "-"})

	if response.StatusCode != http.StatusSeeOther {
		state.Fatalf("Test of the ui code failed, the first use of the code should be served, status: %d", response.StatusCode)
	}

	expired, err := current.credentials.NewCode()

	if err != nil {
		state.Fatalf("Could not make a code, error: %s", err.Error())
	}

	current.credentials.mutex.Lock()
	current.credentials.codeDeadline = time.Now().Add(-time.Second)
	current.credentials.mutex.Unlock()
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
		{Method: http.MethodGet, Path: "/favicon.svg", Cookie: "-"},
		{Method: http.MethodGet, Path: "/fonts/kode-mono-700-latin.woff2", Cookie: "-"},
		{Method: http.MethodGet, Path: "/api/v1/status", Cookie: "-"},
		{Method: http.MethodGet, Path: "/api/v1/events", Cookie: "-"},
		{Method: http.MethodPut, Path: "/api/v1/intercept", Cookie: "-", Headers: map[string]string{"Origin": "http://" + current.host}, Body: `{"enabled": true}`},
		// a wrong token, the token anywhere but a GET of /, the cookie of another port
		{Method: http.MethodGet, Path: "/?token=" + otherToken(token), IsRoot: true, Cookie: "-"},
		{Method: http.MethodGet, Path: "/?token=", IsRoot: true, Cookie: "-"},
		{Method: http.MethodGet, Path: "/api/v1/status?token=" + token, Cookie: "-"},
		{Method: http.MethodGet, Path: "/?token=" + token, Cookie: "-"},
		{Method: http.MethodPost, Path: "/?token=" + token, IsRoot: true, Cookie: "-", Headers: map[string]string{"Origin": "http://" + current.host}},
		{Method: http.MethodGet, Path: "/", Cookie: otherToken(token)},
		{Method: http.MethodGet, Path: "/", CookieName: cookiePrefix + "1"},
		// a code that was used, expired, never made, or next to the token
		{Method: http.MethodGet, Path: "/?code=" + code, IsRoot: true, Cookie: "-"},
		{Method: http.MethodGet, Path: "/?code=" + expired, IsRoot: true, Cookie: "-"},
		{Method: http.MethodGet, Path: "/?code=" + token, IsRoot: true, Cookie: "-"},
		{Method: http.MethodGet, Path: "/?code=", IsRoot: true, Cookie: "-"},
		{Method: http.MethodGet, Path: "/?code=" + code + "&token=" + token, IsRoot: true, Cookie: "-"},
		// the cookie outside the secret path: the root, the api at the root, another path
		{Method: http.MethodGet, Path: "/", IsRoot: true},
		{Method: http.MethodGet, Path: "/app.js", IsRoot: true},
		{Method: http.MethodGet, Path: "/api/v1/status", IsRoot: true},
		{Method: http.MethodGet, Path: "/" + otherToken(current.credentials.Prefix) + "/", IsRoot: true},
		{Method: http.MethodGet, Path: "/" + current.credentials.Prefix, IsRoot: true},
		// another Host: DNS rebinding, localhost, another port
		{Method: http.MethodGet, Path: "/", Host: "rebind.example:" + port},
		{Method: http.MethodGet, Path: "/api/v1/status", Host: "localhost:" + port},
		{Method: http.MethodGet, Path: "/", Host: otherHost},
		{Method: http.MethodGet, Path: "/?token=" + token, IsRoot: true, Host: "localhost:" + port, Cookie: "-"},
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

// Test if a browser's cookie jar, which keeps cookies apart by host but not by port, sends the token cookie to the page of decerter ui and to no other server on 127.0.0.1.
func TestCookieScopePositive(state *testing.T) {
	current := startUI(state)
	cookies := make(chan string, 4)
	other := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookies <- request.Header.Get("Cookie")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer other.Close()
	jar, err := cookiejar.New(nil)

	if err != nil {
		state.Fatalf("Could not make a cookie jar, error: %s", err.Error())
	}

	browser := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	response, err := browser.Get(URL(current.host, current.credentials.Token))

	if err != nil {
		state.Fatalf("Could not load the ui, error: %s", err.Error())
	}

	if closeErr := response.Body.Close(); closeErr != nil {
		state.Fatalf("Could not close the body, error: %s", closeErr.Error())
	}

	if (response.StatusCode != http.StatusOK) || (response.Request.URL.Path != current.credentials.base()) {
		state.Fatalf("Test of the ui cookie failed, the first load should end on the page under the secret path, status: %d, URL: %s", response.StatusCode, response.Request.URL)
	}

	// another port of the same host, at its root and at the path of the API
	for _, path := range []string{"/", v1.BasePath + "/status", "/favicon.ico"} {
		response, err = browser.Get(other.URL + path)

		if err != nil {
			state.Fatalf("Could not reach the other server, error: %s", err.Error())
		}

		if closeErr := response.Body.Close(); closeErr != nil {
			state.Fatalf("Could not close the body, error: %s", closeErr.Error())
		}

		if cookie := <-cookies; strings.Contains(cookie, current.credentials.Token) {
			state.Errorf("Test of the ui cookie failed, another server on 127.0.0.1 should not get the token, %s got cookie: %q", path, cookie)
			return
		}
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
		"/run/decerter/api.sock":  {Network: UnixNetwork, Address: "/run/decerter/api.sock"},
		"api.sock":                {Network: UnixNetwork, Address: "api.sock"},
		"./127.0.0.1:8080":        {Network: UnixNetwork, Address: "./127.0.0.1:8080"},
		"@decerter-api":           {Network: UnixNetwork, Address: "@decerter-api"},
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

// Test if Check returns with an error that says what to do for a missing socket, a socket the user may not open, an abstract socket nobody listens on, a closed port, a server that refuses the user
// and a tcp address that accepts and closes at once like adb forward without decerter on the device.
func TestCheckNegative(state *testing.T) {
	directory := state.TempDir()
	missing := filepath.Join(directory, "missing.sock")
	refusing := startRefusingServer(state, UnixNetwork)
	forwarded := startRefusingServer(state, TCPNetwork)
	negativeCases := []struct {
		Target   Target
		Expected error
	}{
		{Target: Target{Network: UnixNetwork, Address: missing}, Expected: ErrNoSocket},
		{Target: Target{Network: UnixNetwork, Address: fmt.Sprintf("@decerter-ui-test-%d", os.Getpid())}, Expected: ErrNoServer},
		{Target: Target{Network: TCPNetwork, Address: closedPort(state)}, Expected: ErrNoServer},
		{Target: refusing, Expected: ErrRefused},
		{Target: forwarded, Expected: ErrNotListening},
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

	_, err = Check(state.Context(), forwarded)

	if (err == nil) || !strings.Contains(err.Error(), "nothing is listening") || strings.Contains(err.Error(), "does not let this user in") {
		state.Errorf("Test of Check failed, an adb forward without decerter on the device should say that nothing listens yet, error: %v", err)
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

	if CodeURL("127.0.0.1:4242", second) != "http://127.0.0.1:4242/?code="+second {
		state.Errorf("Test of CodeURL failed, URL: %s", CodeURL("127.0.0.1:4242", second))
		return
	}

	credentials, err := NewCredentials()

	if (err != nil) || (len(credentials.Token) != 43) || (len(credentials.Prefix) != 43) || (credentials.Token == credentials.Prefix) || (credentials.base() != "/"+credentials.Prefix+"/") {
		state.Errorf("Test of NewCredentials failed, the token and the path should be two different tokens, credentials: %+v, error: %v", credentials, err)
		return
	}
}

// Test if the page has its SPDX line, no inline script, style or event handler, its script never writes HTML, its style loads nothing but its own fonts, and the favicon is a plain image.
func TestWebPositive(state *testing.T) {
	forbidden := map[string]*regexp.Regexp{
		"web/index.html":  regexp.MustCompile(`<script(\s[^>]*)?>[^<]|<script(?:\s+type="module")?>|\sstyle=|\son[a-z]+=|<style|javascript:`),
		"web/app.js":      regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setAttribute\(\s*'on|\.style\.|setAttribute\(\s*'style`),
		"web/app.css":     regexp.MustCompile(`@import|url\(`),
		"web/favicon.svg": regexp.MustCompile(`(?i)<script|\son[a-z]+=|href=|url\(|<style|\sstyle=|<image|<foreignObject|<use|<text|@import|data:`),
	}
	// the stylesheet names the embedded fonts, a file of the page each
	fontURL := regexp.MustCompile(`url\("(fonts/[a-z0-9-]+\.woff2)"\) format\("woff2"\)`)

	for name, pattern := range forbidden {
		content, err := webFiles.ReadFile(name)

		if err != nil {
			state.Fatalf("Could not read %s, error: %s", name, err.Error())
		}

		if name == "web/app.css" {
			for _, font := range fontURL.FindAllSubmatch(content, -1) {
				if !slices.ContainsFunc(pageFiles, func(file pageFile) bool { return file.Name == string(font[1]) }) {
					state.Errorf("Test of the page failed, app.css loads %s, which the page does not serve", font[1])
					return
				}
			}

			content = fontURL.ReplaceAll(content, nil)
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

// Test if every file of the web directory is a file of the page and served at its own path, each font is WOFF2 and its license names the three fonts.
func TestPageFilesPositive(state *testing.T) {
	var embedded []string
	err := fs.WalkDir(webFiles, webDirectory, func(name string, entry fs.DirEntry, walkErr error) (err error) {
		if err = walkErr; err != nil {
			return
		}

		if !entry.IsDir() {
			embedded = append(embedded, strings.TrimPrefix(name, webDirectory+"/"))
		}

		return
	})

	if err != nil {
		state.Fatalf("Could not walk the web directory, error: %s", err.Error())
	}

	var served []string

	for _, file := range pageFiles {
		served = append(served, file.Name)

		if (file.Name != "index.html") && (file.Path != "/"+file.Name) {
			state.Errorf("Test of the page files failed, %s should be served at /%s, path: %s", file.Name, file.Name, file.Path)
			return
		}

		content, readErr := webFiles.ReadFile(webDirectory + "/" + file.Name)

		if err = readErr; err != nil {
			state.Fatalf("Could not read %s, error: %s", file.Name, err.Error())
		}

		if strings.HasSuffix(file.Name, ".woff2") && ((file.ContentType != "font/woff2") || !strings.HasPrefix(string(content), "wOF2")) {
			state.Errorf("Test of the page files failed, %s should be WOFF2 served as font/woff2, type: %s, start: %q", file.Name, file.ContentType, content[:min(4, len(content))])
			return
		}
	}

	slices.Sort(embedded)
	slices.Sort(served)

	if !slices.Equal(embedded, served) {
		state.Errorf("Test of the page files failed, every embedded file should be served, embedded: %v, served: %v", embedded, served)
		return
	}

	license, err := webFiles.ReadFile(webDirectory + "/fonts/OFL.txt")

	if err != nil {
		state.Fatalf("Could not read the font license, error: %s", err.Error())
	}

	for _, text := range []string{"SIL OPEN FONT LICENSE Version 1.1", "Copyright 2023 The Kode Mono Project Authors", "Copyright (c) 2016 The Inter Project Authors", "Copyright 2020 The JetBrains Mono Project Authors"} {
		if !strings.Contains(string(license), text) {
			state.Errorf("Test of the page files failed, fonts/OFL.txt should have %q", text)
			return
		}
	}
}

// Test if the intercept form offers every layer PUT /intercept takes and the page names each of them in its state text.
func TestInterceptLayersPositive(state *testing.T) {
	page, err := webFiles.ReadFile("web/index.html")

	if err != nil {
		state.Fatalf("Could not read index.html, error: %s", err.Error())
	}

	script, err := webFiles.ReadFile("web/app.js")

	if err != nil {
		state.Fatalf("Could not read app.js, error: %s", err.Error())
	}

	selectMatch := regexp.MustCompile(`(?s)<select id="intercept-layer"[^>]*>(.*?)</select>`).FindSubmatch(page)

	if selectMatch == nil {
		state.Fatalf("Test of the page failed, index.html has no intercept-layer select")
	}

	offered := []string{}

	for _, option := range regexp.MustCompile(`<option value="([^"]*)">`).FindAllSubmatch(selectMatch[1], -1) {
		offered = append(offered, string(option[1]))
	}

	labels := regexp.MustCompile(`(?s)const interceptLayers = \{(.*?)\};`).FindSubmatch(script)

	if labels == nil {
		state.Fatalf("Test of the page failed, app.js has no interceptLayers")
	}

	for _, layer := range []v1.Layer{"", v1.TCPLayer, v1.TLSLayer, v1.UDPLayer, v1.DTLSLayer, v1.HTTPLayer} {
		key := string(layer) + ":"

		if layer == "" {
			key = "'':"
		}

		if !slices.Contains(offered, string(layer)) || !strings.Contains(string(labels[1]), "\n  "+key) {
			state.Errorf("Test of the page failed, layer %q should be offered and named, offered: %q", layer, offered)
		}
	}
}

// Test if the page pages the exchanges of a flow like its messages and caps what live events add to the lists: the flows, the messages and the exchanges;
// the cap on the flows never trims the rows More read or the selected one, and moves More's cursor only while no page of More was read.
func TestListBoundsPositive(state *testing.T) {
	page, err := webFiles.ReadFile("web/index.html")

	if err != nil {
		state.Fatalf("Could not read index.html, error: %s", err.Error())
	}

	script, err := webFiles.ReadFile("web/app.js")

	if err != nil {
		state.Fatalf("Could not read app.js, error: %s", err.Error())
	}

	// the body of a function of app.js, up to the next line that closes a top-level block
	bodyOf := func(name string) (body string) {
		match := regexp.MustCompile(`(?s)\n(?:async )?function ` + name + `\(.*?\n\}\n`).Find(script)
		body = string(match)
		return
	}
	expected := []struct {
		name    string
		text    string
		pattern string
	}{
		{name: "a button for the next page of exchanges", text: string(page), pattern: `<button id="more-exchanges" type="button" hidden>`},
		{name: "a cap on the rows", text: string(script), pattern: `const maxListRows = 1000;`},
		{name: "the next page of exchanges by the cursor", text: string(script), pattern: `/flows/\$\{state.flowId\}/exchanges\?cursor=\$\{encodeURIComponent\(state.exchangesCursor\)\}`},
		{name: "the button shown while there is a next page", text: string(script), pattern: `byId\('more-exchanges'\).hidden = !state.exchangesCursor;`},
		{name: "flow events trim the flows", text: bodyOf("onFlow"), pattern: `trimFlows\(\);`},
		{name: "the rows More read and the selected one kept", text: bodyOf("trimFlows"), pattern: `filter\(\(id\) => !state\.pagedFlows\.has\(id\) && id !== state\.flowId\)`},
		{name: "the cursor moved only without rows of More", text: bodyOf("trimFlows"), pattern: `if \(state\.pagedFlows\.size === 0\) \{\n    state\.flowsCursor = `},
		{name: "the rows More read marked", text: bodyOf("moreFlows"), pattern: `state\.pagedFlows\.add\(flow\.id\);`},
		{name: "the marks cleared with the list", text: bodyOf("loadFlows"), pattern: `state\.flows\.clear\(\);\n    state\.pagedFlows\.clear\(\);`},
		{name: "message events stop at the cap", text: bodyOf("onMessage"), pattern: `state.messages.length >= maxListRows`},
		{name: "exchange events stop at the cap", text: bodyOf("onExchange"), pattern: `state.exchanges.length >= maxListRows`},
	}

	for _, check := range expected {
		if !regexp.MustCompile(check.pattern).MatchString(check.text) {
			state.Errorf("Test of the page failed, it should have %s, %q", check.name, check.pattern)
		}
	}

	// no single page of 1000 exchanges read again on every event
	if strings.Contains(string(script), "exchanges?limit=1000") || strings.Contains(bodyOf("onExchange"), "loadExchanges") {
		state.Errorf("Test of the page failed, the exchanges should be paged and updated from their events")
	}
}

// a decerter ui on 127.0.0.1 in front of a fake api, stopped with the test; the client follows no redirect
func startUI(state *testing.T) (current testUI) {
	api := startFakeAPI(state)
	credentials, err := NewCredentials()

	if err != nil {
		state.Fatalf("Could not make the credentials, error: %s", err.Error())
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
		doneChannel <- Serve(ctx, listener, Handler(api.target, credentials, host, logger), logger)
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
		api:         api,
		host:        host,
		credentials: credentials,
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
	path := test.Path

	if !test.IsRoot {
		path = "/" + current.credentials.Prefix + path
	}

	request, err = http.NewRequestWithContext(ctx, test.Method, "http://"+current.host+path, strings.NewReader(test.Body))

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

	cookie := current.credentials.Token

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
func startRefusingServer(state *testing.T, network Network) (target Target) {
	name := fmt.Sprintf("@decerter-ui-refuse-%d", os.Getpid())

	// adb forward on the host while nothing listens on the device
	if network == TCPNetwork {
		name = "127.0.0.1:0"
	}

	listener, err := net.Listen(string(network), name)

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

	target = Target{Network: network, Address: listener.Addr().String()}
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

// Test if decerter ui returns with the expected output for an api over TCP, as adb forward has it: the start check and the proxy send the loopback ip:port as Host,
// which the api takes there, not decerter, which it takes only on its socket.
func TestTCPHostPositive(state *testing.T) {
	backend := api.NewBackend(api.Info{Mode: v1.RunMode}, history.DefaultLimits(), nil)
	server := httptest.NewServer(api.Handler(backend, slog.New(slog.DiscardHandler)))
	defer server.Close()
	target, err := ParseTarget(strings.TrimPrefix(server.URL, "http://"))

	if err != nil {
		state.Fatalf("Could not parse the target, error: %s", err.Error())
	}

	status, err := Check(state.Context(), target)

	if (err != nil) || (status.Mode != v1.RunMode) || (target.Host() != target.Address) || (Target{Network: UnixNetwork, Address: "/run/decerter/api.sock"}.Host() != v1.HostName) {
		state.Errorf("Test of ui.Check failed, the api over TCP should answer, host: %q, status: %+v, error: %v", target.Host(), status, err)
		return
	}

	recorder := httptest.NewRecorder()
	newProxy(target, slog.New(slog.DiscardHandler)).ServeHTTP(recorder, httptest.NewRequestWithContext(state.Context(), http.MethodGet, "http://127.0.0.1:1/api/v1/status", http.NoBody))

	if (recorder.Code != http.StatusOK) || !strings.Contains(recorder.Body.String(), `"mode":"run"`) {
		state.Errorf("Test of the ui proxy failed, the api over TCP should answer, status: %d, body: %s", recorder.Code, recorder.Body.String())
	}
}
