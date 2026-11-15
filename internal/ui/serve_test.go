// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package ui

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Test if the ui answers the browser's own favicon request with 204 and no body.
func TestFaviconPositive(state *testing.T) {
	current := startUI(state)
	answer, body := current.do(state, uiRequest{Method: http.MethodGet, Path: "/favicon.ico"})

	if (answer.StatusCode != http.StatusNoContent) || (body != "") || !hasSecurityHeaders(answer.Header) {
		state.Errorf("Test of the ui favicon failed, status should be %d without a body, status: %d, body: %q", http.StatusNoContent, answer.StatusCode, body)
		return
	}
}

// Test if Serve returns with the expected errors: a listener that is closed already is an error at once.
func TestServeNegative(state *testing.T) {
	listener, _, err := Listen()

	if err != nil {
		state.Fatalf("Could not listen, error: %s", err.Error())
	}

	err = listener.Close()

	if err != nil {
		state.Fatalf("Could not close the listener, error: %s", err.Error())
	}

	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	err = Serve(state.Context(), listener, http.NotFoundHandler(), logger)

	if !errors.Is(err, net.ErrClosed) || !strings.Contains(logs.String(), `"msg":"Could not serve the ui"`) {
		state.Errorf("Test of ui.Serve function failed, a closed listener should be %v, error: %v, logs: %s", net.ErrClosed, err, logs.String())
		return
	}
}

// Test if Serve returns with the expected output: a request that does not finish within the shutdown time is closed, and Serve still returns without an error.
func TestServeShutdownPositive(state *testing.T) {
	listener, host, err := Listen()

	if err != nil {
		state.Fatalf("Could not listen, error: %s", err.Error())
	}

	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		<-release
	})
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(state.Context())
	defer cancel()
	serveErrChannel := make(chan error, 1)

	// ui server
	go func() {
		serveErrChannel <- Serve(ctx, listener, handler, logger)
	}()

	requestErrChannel := make(chan error, 1)

	// a request that hangs in the handler
	go func() {
		response, requestErr := http.Get("http://" + host + "/")

		if requestErr == nil {
			requestErr = errors.Join(errors.New("the hanging request got an answer"), response.Body.Close())
		}

		requestErrChannel <- requestErr
	}()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		state.Fatalf("Test of ui.Serve function failed, the request did not reach the handler")
	}

	cancel()

	select {
	case err = <-serveErrChannel:
	case <-time.After(10 * time.Second):
		state.Fatalf("Test of ui.Serve function failed, it did not stop")
	}

	requestErr := <-requestErrChannel

	if (err != nil) || (requestErr == nil) || !strings.Contains(logs.String(), `"msg":"Could not shut the ui down in time, closing it"`) {
		state.Errorf("Test of ui.Serve function failed, a hanging request should be closed after the shutdown time, error: %v, request: %v, logs: %s", err, requestErr, logs.String())
		return
	}
}
