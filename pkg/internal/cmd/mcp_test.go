// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package cmd

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/mcp"
	"github.com/decerter/decerter/internal/ui"
	"github.com/decerter/decerter/pkg/internal/logging"
)

const (
	// the first request of an MCP client, its answer goes to stdout
	initializeRequest string = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}` + "\n"
)

// os.Stdin is a pipe while the test runs, closing the writer is the MCP client going away
func redirectStdin(state *testing.T) (writer *os.File) {
	reader, writer, err := os.Pipe()

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot make a pipe for stdin, error: %s", err.Error())
	}

	original := os.Stdin
	os.Stdin = reader

	state.Cleanup(func() {
		os.Stdin = original

		// the test closes the writer itself to end the session
		if closeErr := writer.Close(); (closeErr != nil) && !errors.Is(closeErr, os.ErrClosed) {
			state.Errorf("Test of cmd failed, cannot close the stdin pipe, error: %s", closeErr.Error())
		}

		// the SDK closes stdin at the end of the session
		if closeErr := reader.Close(); (closeErr != nil) && !errors.Is(closeErr, os.ErrClosed) {
			state.Errorf("Test of cmd failed, cannot close the stdin pipe, error: %s", closeErr.Error())
		}
	})

	return
}

// Test if cmd.MCP returns with the expected output: the session ends without an error when the client closes stdin, also while the api can't be reached, and on a shutdown signal.
func TestMCPPositive(state *testing.T) {
	positiveCases := []struct {
		Name       string
		Target     ui.Target
		AllowWrite bool
		Level      slog.Level
		Signal     bool
		Text       string
	}{
		{Name: "api reached, stdin closed", Target: startFakeAPI(state), AllowWrite: false, Level: slog.LevelInfo, Signal: false, Text: `"msg":"Control api reached"`},
		{Name: "api missing, debug logs, stdin closed", Target: missingAPI(state), AllowWrite: true, Level: slog.LevelDebug, Signal: false, Text: `"msg":"MCP client went away"`},
		{Name: "shutdown signal", Target: startFakeAPI(state), AllowWrite: true, Level: slog.LevelInfo, Signal: true, Text: `"msg":"Got shutdown signal"`},
	}

	for _, positive := range positiveCases {
		stdin := redirectStdin(state)
		logs := newLockedBuffer()
		logger := logging.New(logs, positive.Level)
		errChannel := make(chan error, 1)

		// decerter mcp
		go func() {
			errChannel <- MCP(positive.Target, state.TempDir(), positive.AllowWrite, &logger)
		}()

		// the signal only after shutdownContext is registered, which is long before the server serves
		if !logs.waitFor(`"msg":"MCP server on stdio"`) {
			state.Fatalf("Test of cmd.MCP function failed, %s, the server did not start, logs: %s", positive.Name, logs.String())
		}

		if positive.Signal {
			signalSelf(state, syscall.SIGTERM)
		} else if closeErr := stdin.Close(); closeErr != nil {
			state.Fatalf("Test of cmd.MCP function failed, %s, cannot close stdin, error: %s", positive.Name, closeErr.Error())
		}

		select {
		case err := <-errChannel:
			if (err != nil) || !strings.Contains(logs.String(), positive.Text) {
				state.Errorf("Test of cmd.MCP function failed, %s, it should end without an error and log %q, error: %v, logs: %s", positive.Name, positive.Text, err, logs.String())
				return
			}
		case <-time.After(waitTimeout):
			state.Fatalf("Test of cmd.MCP function failed, %s, it did not stop, logs: %s", positive.Name, logs.String())
		}
	}
}

// Test if cmd.MCP returns with the expected errors: an output directory that does not exist stops it before it serves, a stdout the answer can't be written to ends the session.
func TestMCPNegative(state *testing.T) {
	logs := &bytes.Buffer{}
	logger := logging.New(logs, slog.LevelInfo)
	err := MCP(startFakeAPI(state), filepath.Join(state.TempDir(), "missing"), false, &logger)

	if !errors.Is(err, mcp.ErrOutputDirectory) || !strings.Contains(logs.String(), `"msg":"Could not open the output directory"`) {
		state.Errorf("Test of cmd.MCP function failed, a missing output directory should be %v, error: %v, logs: %s", mcp.ErrOutputDirectory, err, logs.String())
		return
	}

	stdin := redirectStdin(state)
	readOnlyStdout(state)
	serveLogs := newLockedBuffer()
	serveLogger := logging.New(serveLogs, slog.LevelInfo)
	errChannel := make(chan error, 1)

	// decerter mcp
	go func() {
		errChannel <- MCP(startFakeAPI(state), state.TempDir(), false, &serveLogger)
	}()

	if !serveLogs.waitFor(`"msg":"MCP server on stdio"`) {
		state.Fatalf("Test of cmd.MCP function failed, the server did not start, logs: %s", serveLogs.String())
	}

	_, err = stdin.WriteString(initializeRequest)

	if err != nil {
		state.Fatalf("Test of cmd.MCP function failed, cannot write the initialize request, error: %s", err.Error())
	}

	select {
	case err = <-errChannel:
		if (err == nil) || !strings.Contains(serveLogs.String(), `"msg":"Could not serve MCP"`) {
			state.Errorf("Test of cmd.MCP function failed, an answer that can't be written should end the session with an error, error: %v, logs: %s", err, serveLogs.String())
			return
		}
	case <-time.After(waitTimeout):
		state.Fatalf("Test of cmd.MCP function failed, it did not stop, logs: %s", serveLogs.String())
	}
}
