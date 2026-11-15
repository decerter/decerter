// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/ui"
	"github.com/decerter/decerter/pkg/internal/logging"
)

// a control api on a socket file that only answers the status, the target of decerter ui and decerter mcp
// the directory is short: a socket path has at most 107 bytes and the test's own directory can be longer
func startFakeAPI(state *testing.T) (target ui.Target) {
	directory, err := os.MkdirTemp("", "decerter-cmd-")

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot make a directory, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if removeErr := os.RemoveAll(directory); removeErr != nil {
			state.Errorf("Test of cmd failed, cannot remove %s, error: %s", directory, removeErr.Error())
		}
	})

	socket := filepath.Join(directory, "api.sock")
	listener, err := net.Listen("unix", socket)

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot listen on %s, error: %s", socket, err.Error())
	}

	target = ui.Target{Network: ui.UnixNetwork, Address: socket}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+v1.BasePath+"/status", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		encodeErr := json.NewEncoder(writer).Encode(v1.Status{Mode: v1.RunMode, Processing: v1.InterceptProcessing, Version: "test", Platform: "linux", Scope: "", TLSSecrets: false, Started: time.Time{}, Intercept: v1.InterceptState{}, Rules: 0, History: v1.HistoryStatus{}, Captures: v1.CaptureStatus{}})

		if encodeErr != nil {
			state.Errorf("Test of cmd failed, cannot write the status, error: %s", encodeErr.Error())
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: waitTimeout}
	serveDone := make(chan struct{})

	// fake api server
	go func() {
		defer close(serveDone)

		if serveErr := server.Serve(listener); !errors.Is(serveErr, http.ErrServerClosed) {
			state.Errorf("Test of cmd failed, cannot serve the fake api, error: %v", serveErr)
		}
	}()

	state.Cleanup(func() {
		if closeErr := server.Close(); closeErr != nil {
			state.Errorf("Test of cmd failed, cannot close the fake api, error: %s", closeErr.Error())
		}

		<-serveDone
	})

	return
}

// a target whose socket file does not exist
func missingAPI(state *testing.T) (target ui.Target) {
	target = ui.Target{Network: ui.UnixNetwork, Address: filepath.Join(state.TempDir(), "api.sock")}
	return
}

// os.Stdout is a file opened read only while the test runs, every write to it fails
func readOnlyStdout(state *testing.T) {
	path := filepath.Join(state.TempDir(), "stdout")
	err := os.WriteFile(path, nil, 0o600)

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot write %s, error: %s", path, err.Error())
	}

	file, err := os.Open(path)

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot open %s, error: %s", path, err.Error())
	}

	original := os.Stdout
	os.Stdout = file

	state.Cleanup(func() {
		os.Stdout = original

		if closeErr := file.Close(); closeErr != nil {
			state.Errorf("Test of cmd failed, cannot close %s, error: %s", path, closeErr.Error())
		}
	})
}

// Test if cmd.UI returns with the expected output: it prints the URL with the token, serves the page behind it and stops without an error on a shutdown signal.
func TestUIPositive(state *testing.T) {
	target := startFakeAPI(state)
	stdout := redirectStdout(state)
	logs := newLockedBuffer()
	logger := logging.New(logs, slog.LevelDebug)
	errChannel := make(chan error, 1)
	lineChannel := make(chan string, 1)

	// decerter ui
	go func() {
		errChannel <- UI(target, false, &logger)
	}()

	// the printed URL
	go func() {
		line, readErr := bufio.NewReader(stdout.reader).ReadString('\n')

		if readErr != nil {
			line = ""
		}

		lineChannel <- strings.TrimSpace(line)
	}()

	address := ""

	select {
	case address = <-lineChannel:
	case err := <-errChannel:
		state.Fatalf("Test of cmd.UI function failed, it returned before it printed the URL, error: %v, logs: %s", err, logs.String())
	case <-time.After(waitTimeout):
		state.Fatalf("Test of cmd.UI function failed, no URL after %s, logs: %s", waitTimeout, logs.String())
	}

	if !strings.HasPrefix(address, "http://127.0.0.1:") || !strings.Contains(address, "/?token=") {
		state.Errorf("Test of cmd.UI function failed, the URL should have the loopback address and the token, URL: %q", address)
	}

	// the first load sets the cookie and redirects to / without the token
	client := &http.Client{
		CheckRedirect: func(request *http.Request, via []*http.Request) (err error) {
			err = http.ErrUseLastResponse
			return
		},
		Timeout: waitTimeout,
	}
	response, getErr := client.Get(address)

	if getErr != nil {
		state.Errorf("Test of cmd.UI function failed, cannot load the URL, error: %s", getErr.Error())
	} else {
		if response.StatusCode != http.StatusSeeOther {
			state.Errorf("Test of cmd.UI function failed, the first load should be %d, status: %d", http.StatusSeeOther, response.StatusCode)
		}

		if closeErr := response.Body.Close(); closeErr != nil {
			state.Errorf("Test of cmd.UI function failed, cannot close the answer, error: %s", closeErr.Error())
		}
	}

	signalSelf(state, syscall.SIGINT)

	select {
	case err := <-errChannel:
		if (err != nil) || !strings.Contains(logs.String(), `"msg":"Got shutdown signal"`) || !strings.Contains(logs.String(), `"mode":"run"`) {
			state.Errorf("Test of cmd.UI function failed, a signal should stop it without an error, error: %v, logs: %s", err, logs.String())
			return
		}
	case <-time.After(waitTimeout):
		state.Fatalf("Test of cmd.UI function failed, it did not stop after the signal, logs: %s", logs.String())
	}
}

// Test if cmd.UI returns with the expected errors: an api that can't be reached, a stdout the URL can't be written to.
func TestUINegative(state *testing.T) {
	logs := &bytes.Buffer{}
	logger := logging.New(logs, slog.LevelInfo)
	err := UI(missingAPI(state), false, &logger)

	if !errors.Is(err, ui.ErrNoSocket) || !strings.Contains(logs.String(), `"msg":"Could not reach the control api"`) {
		state.Errorf("Test of cmd.UI function failed, a missing socket should be %v, error: %v, logs: %s", ui.ErrNoSocket, err, logs.String())
		return
	}

	target := startFakeAPI(state)
	readOnlyStdout(state)
	logs.Reset()
	err = UI(target, false, &logger)

	if !errors.Is(err, syscall.EBADF) || !strings.Contains(logs.String(), `"msg":"Could not print the ui address"`) {
		state.Errorf("Test of cmd.UI function failed, a stdout that can't be written should be %v, error: %v, logs: %s", syscall.EBADF, err, logs.String())
		return
	}
}

// Test if cmd.UI with --open hands the browser opener a URL with a code that works once and not the token, so a command line other users can read holds no credential that still works.
func TestUIOpenPositive(state *testing.T) {
	target := startFakeAPI(state)
	directory := state.TempDir()
	argumentsPath := filepath.Join(directory, "arguments")
	err := os.WriteFile(filepath.Join(directory, "xdg-open"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+argumentsPath+".tmp && mv "+argumentsPath+".tmp "+argumentsPath+"\n"), 0o700)

	if err != nil {
		state.Fatalf("Test of cmd.UI function failed, cannot write the opener, error: %s", err.Error())
	}

	state.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	stdout := redirectStdout(state)
	logs := newLockedBuffer()
	logger := logging.New(logs, slog.LevelDebug)
	errChannel := make(chan error, 1)
	lineChannel := make(chan string, 1)

	// decerter ui --open
	go func() {
		errChannel <- UI(target, true, &logger)
	}()

	// the printed URL
	go func() {
		line, readErr := bufio.NewReader(stdout.reader).ReadString('\n')

		if readErr != nil {
			line = ""
		}

		lineChannel <- strings.TrimSpace(line)
	}()

	printed := ""

	select {
	case printed = <-lineChannel:
	case err = <-errChannel:
		state.Fatalf("Test of cmd.UI function failed, it returned before it printed the URL, error: %v, logs: %s", err, logs.String())
	case <-time.After(waitTimeout):
		state.Fatalf("Test of cmd.UI function failed, no URL after %s, logs: %s", waitTimeout, logs.String())
	}

	defer func() {
		signalSelf(state, syscall.SIGINT)

		select {
		case stopErr := <-errChannel:
			if stopErr != nil {
				state.Errorf("Test of cmd.UI function failed, a signal should stop it without an error, error: %v, logs: %s", stopErr, logs.String())
			}
		case <-time.After(waitTimeout):
			state.Errorf("Test of cmd.UI function failed, it did not stop after the signal, logs: %s", logs.String())
		}
	}()

	_, token, _ := strings.Cut(printed, "/?token=")
	opened := []byte{}
	deadline := time.Now().Add(waitTimeout)

	for time.Now().Before(deadline) {
		opened, err = os.ReadFile(argumentsPath)

		if err == nil {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	address := strings.TrimSpace(string(opened))
	prefix, _, _ := strings.Cut(printed, "/?token=")

	if (err != nil) || (token == "") || strings.Contains(address, token) || !strings.HasPrefix(address, prefix+"/?code=") || strings.Contains(address, "\n") {
		state.Errorf("Test of cmd.UI function failed, the opener should get one URL with a code and without the token, printed: %q, opened: %q, error: %v", printed, address, err)
		return
	}

	client := &http.Client{
		CheckRedirect: func(request *http.Request, via []*http.Request) (err error) {
			err = http.ErrUseLastResponse
			return
		},
		Timeout: waitTimeout,
	}

	// the code works for the first load and never again
	for _, expected := range []int{http.StatusSeeOther, http.StatusForbidden} {
		response, getErr := client.Get(address)

		if getErr != nil {
			state.Errorf("Test of cmd.UI function failed, cannot load the opened URL, error: %s", getErr.Error())
			return
		}

		if closeErr := response.Body.Close(); closeErr != nil {
			state.Errorf("Test of cmd.UI function failed, cannot close the answer, error: %s", closeErr.Error())
			return
		}

		if (response.StatusCode != expected) || ((expected == http.StatusSeeOther) && (len(response.Cookies()) != 1)) {
			state.Errorf("Test of cmd.UI function failed, the opened URL should answer %d, status: %d, cookies: %v", expected, response.StatusCode, response.Cookies())
			return
		}
	}
}
