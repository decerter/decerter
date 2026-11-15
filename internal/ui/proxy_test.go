// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package ui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// a control API on a socket file that answers every request with handler
// the directory is short: a socket path has at most 107 bytes and the test's own directory can be longer
func startHandlerAPI(state *testing.T, handler http.HandlerFunc) (target Target) {
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

	server := httptest.NewUnstartedServer(handler)
	closeErr := server.Listener.Close()

	if closeErr != nil {
		state.Fatalf("Could not close the fake api's tcp listener, error: %s", closeErr.Error())
	}

	server.Listener = listener
	server.Start()
	state.Cleanup(server.Close)
	target = Target{Network: UnixNetwork, Address: socket}
	return
}

// a response writer whose body can't be written
type failingWriter struct {
	header http.Header
	status int
}

func (writer *failingWriter) Header() (header http.Header) {
	header = writer.header
	return
}

func (writer *failingWriter) WriteHeader(status int) {
	writer.status = status
}

func (writer *failingWriter) Write(data []byte) (written int, err error) {
	err = errors.New("connection reset by the browser")
	return
}

// Test if Check returns with the expected errors: an api that answers another status than 200, broken JSON or a body cut short.
func TestCheckAnswerNegative(state *testing.T) {
	starting := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)

		if _, writeErr := io.WriteString(writer, " starting \n"); writeErr != nil {
			state.Errorf("Could not write the fake api answer, error: %s", writeErr.Error())
		}
	})
	broken := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		if _, writeErr := io.WriteString(writer, `{"mode": `); writeErr != nil {
			state.Errorf("Could not write the fake api answer, error: %s", writeErr.Error())
		}
	})
	cut := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		connection, buffered, err := http.NewResponseController(writer).Hijack()

		if err != nil {
			state.Errorf("Could not hijack the fake api connection, error: %s", err.Error())
			return
		}

		body := `{"mode": "run"`
		_, err = buffered.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)+100) + "\r\n\r\n" + body)

		if err == nil {
			err = buffered.Flush()
		}

		if err = errors.Join(err, connection.Close()); err != nil {
			state.Errorf("Could not write the cut answer, error: %s", err.Error())
		}
	})
	negativeCases := []struct {
		Name     string
		Target   Target
		Expected error
		Text     string
	}{
		{Name: "status 503", Target: starting, Expected: ErrAPI, Text: "status 503: starting"},
		{Name: "broken JSON", Target: broken, Expected: ErrAPI, Text: "unexpected end of JSON input"},
		{Name: "cut body", Target: cut, Expected: io.ErrUnexpectedEOF, Text: ""},
	}

	for _, negative := range negativeCases {
		status, err := Check(state.Context(), negative.Target)

		if !errors.Is(err, negative.Expected) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of ui.Check function failed, %s, error should be %v with %q, status: %+v, error: %v", negative.Name, negative.Expected, negative.Text, status, err)
			return
		}
	}
}

// Test if Explain returns with the expected output: an error it has no reason for comes back as it is.
func TestExplainPositive(state *testing.T) {
	other := errors.New("something else")
	explained := Explain(other, Target{Network: UnixNetwork, Address: "/run/decerter/api.sock"})

	if !errors.Is(explained, other) || (explained.Error() != other.Error()) {
		state.Errorf("Test of ui.Explain function failed, an unknown error should stay as it is, error: %v", explained)
		return
	}
}

// Test if the proxy returns with the expected errors: 502 with the reason when the api can't be reached, 502 without a body when the browser went away.
func TestProxyNegative(state *testing.T) {
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxy := newProxy(Target{Network: UnixNetwork, Address: filepath.Join(state.TempDir(), "missing.sock")}, logger)
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/status", http.NoBody))

	if (recorder.Code != http.StatusBadGateway) || (recorder.Header().Get("Content-Type") != "application/json") || !strings.Contains(recorder.Body.String(), "there is no api socket at this path") || !strings.Contains(logs.String(), `"msg":"Could not reach the control api"`) {
		state.Errorf("Test of the ui proxy failed, an api that can't be reached should be 502 with the reason, status: %d, body: %q, logs: %s", recorder.Code, recorder.Body.String(), logs.String())
		return
	}

	ctx, cancel := context.WithCancel(state.Context())
	cancel()
	logs.Reset()
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/status", http.NoBody).WithContext(ctx))

	if (recorder.Code != http.StatusBadGateway) || (recorder.Body.Len() != 0) || !strings.Contains(logs.String(), `"msg":"Ui api request cancelled"`) {
		state.Errorf("Test of the ui proxy failed, a browser that went away should be 502 without a body, status: %d, body: %q, logs: %s", recorder.Code, recorder.Body.String(), logs.String())
		return
	}
}

// Test if writeError returns with the expected output: a body that can't be written is only logged, the status is set.
func TestWriteErrorPositive(state *testing.T) {
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	writer := &failingWriter{header: http.Header{}, status: 0}
	writeError(writer, http.StatusNotFound, ErrPath, logger)

	if (writer.status != http.StatusNotFound) || (writer.header.Get("Content-Type") != "application/json") || !strings.Contains(logs.String(), `"msg":"Could not write ui error"`) {
		state.Errorf("Test of ui.writeError function failed, status should be %d and the write error logged, status: %d, logs: %s", http.StatusNotFound, writer.status, logs.String())
		return
	}
}

// Test if cookieNameOf returns with the expected output: the port of the host in the name, none for a host without a port.
func TestCookieNameOfPositive(state *testing.T) {
	positiveCases := map[string]string{
		"127.0.0.1:4242": "decerter-ui-4242",
		"localhost":      "decerter-ui-",
	}

	for host, expected := range positiveCases {
		name := cookieNameOf(host)

		if name != expected {
			state.Errorf("Test of ui.cookieNameOf function failed, host %s, name should be %s, name: %s", host, expected, name)
			return
		}
	}
}
