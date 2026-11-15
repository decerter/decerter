// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/android"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/tls/openssl"
	"github.com/decerter/decerter/internal/ui"
	internal "github.com/decerter/decerter/pkg/internal/cmd"
)

// os.Stdout and os.Stdin are files of the test while it runs: stdout what the commands print, stdin empty, so decerter mcp sees its client go away at once
func redirectStdio(state *testing.T) (stdoutPath string) {
	directory := state.TempDir()
	stdoutPath = filepath.Join(directory, "stdout")
	stdinPath := filepath.Join(directory, "stdin")
	err := os.WriteFile(stdinPath, nil, 0o600)

	if err != nil {
		state.Fatalf("Test of decerter failed, cannot write %s, error: %s", stdinPath, err.Error())
	}

	stdout, err := os.Create(stdoutPath)

	if err != nil {
		state.Fatalf("Test of decerter failed, cannot create %s, error: %s", stdoutPath, err.Error())
	}

	stdin, err := os.Open(stdinPath)

	if err != nil {
		state.Fatalf("Test of decerter failed, cannot open %s, error: %s", stdinPath, err.Error())
	}

	originalStdout, originalStdin := os.Stdout, os.Stdin
	os.Stdout, os.Stdin = stdout, stdin

	state.Cleanup(func() {
		os.Stdout, os.Stdin = originalStdout, originalStdin

		// the MCP SDK closes stdin at the end of its session
		for _, file := range []*os.File{stdout, stdin} {
			if closeErr := file.Close(); (closeErr != nil) && !errors.Is(closeErr, os.ErrClosed) {
				state.Errorf("Test of decerter failed, cannot close %s, error: %s", file.Name(), closeErr.Error())
			}
		}
	})

	return
}

// Test if decerter returns with the expected errors for flag values the parsers refuse.
func TestFlagValuesNegative(state *testing.T) {
	negativeCases := []struct {
		Args []string
		Text string
	}{
		{Args: []string{"run", "--pid", "x"}, Text: `invalid pid "x"`},
		{Args: []string{"run", "--uid", "1001", "--port", "x"}, Text: `invalid port "x"`},
		{Args: []string{"capture", "-w", "-", "--uid", "1001", "--snaplen", "x"}, Text: `invalid snaplen "x"`},
		{Args: []string{"android", "setup", "--port", "x"}, Text: `invalid port "x"`},
		// layer http is decided per message, not per flow
		{Args: []string{"run", "--uid", "1001", "--filter", `http.request.method == "GET"`}, Text: "invalid filter: "},
	}

	for _, negative := range negativeCases {
		_, err := execute(state, negative.Args)

		if (err == nil) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of decerter %s failed, error should contain %q, error: %v", strings.Join(negative.Args, " "), negative.Text, err)
			return
		}
	}
}

// Test if the commands return with the expected errors when they run and fail before anything is loaded: no device for android setup, outside of Android for restore and tls,
// a missing --libssl for keylog, a missing api socket for ui.
func TestCommandsNegative(state *testing.T) {
	stdoutPath := redirectStdio(state)
	adb := filepath.Join(state.TempDir(), "adb")
	err := os.WriteFile(adb, []byte("#!/bin/sh\necho 'List of devices attached'\necho\n"), 0o700)

	if err != nil {
		state.Fatalf("Test of decerter failed, cannot write the fake adb, error: %s", err.Error())
	}

	state.Setenv("ADB", adb)
	isAndroid := platform.Detect("/").Type == platform.AndroidType
	negativeCases := []struct {
		Args     []string
		Expected error
		Skip     bool
	}{
		{Args: []string{"android", "setup"}, Expected: android.ErrNoDevice, Skip: os.Geteuid() == 0},
		{Args: []string{"android", "setup", "--remove"}, Expected: android.ErrNoDevice, Skip: os.Geteuid() == 0},
		{Args: []string{"android", "restore"}, Expected: internal.ErrNotAndroid, Skip: isAndroid},
		{Args: []string{"android", "tls", "--package", "com.example.app"}, Expected: internal.ErrNotAndroid, Skip: isAndroid},
		{Args: []string{"keylog", "--uid", "1001", "--libssl", filepath.Join(state.TempDir(), "libssl.so.3")}, Expected: openssl.ErrLibraryNotFound, Skip: false},
		{Args: []string{"ui", "--api-socket", filepath.Join(state.TempDir(), "api.sock")}, Expected: ui.ErrNoSocket, Skip: false},
	}

	for _, negative := range negativeCases {
		if negative.Skip {
			continue
		}

		_, err = execute(state, negative.Args)

		if !errors.Is(err, negative.Expected) {
			state.Errorf("Test of decerter %s failed, error should be %v, error: %v", strings.Join(negative.Args, " "), negative.Expected, err)
			return
		}
	}

	printed, err := os.ReadFile(stdoutPath)

	if err != nil {
		state.Fatalf("Test of decerter failed, cannot read %s, error: %s", stdoutPath, err.Error())
	}

	if (os.Geteuid() != 0) && !strings.Contains(string(printed), adb) {
		state.Errorf("Test of decerter android setup failed, it should print the adb it found, stdout: %q", printed)
		return
	}
}

// Test if decerter mcp returns with the expected output: with the default api socket and output directory it serves until its client closes stdin, whether the api runs or not.
func TestMCPCommandPositive(state *testing.T) {
	redirectStdio(state)
	state.Chdir(state.TempDir())
	_, err := execute(state, []string{"mcp"})

	if err != nil {
		state.Errorf("Test of decerter mcp failed, a client that closes stdin should end it without an error, error: %v", err)
		return
	}

	entries, err := os.ReadDir(".")

	if (err != nil) || (len(entries) != 0) {
		state.Errorf("Test of decerter mcp failed, nothing should be written into the output directory, entries: %v, error: %v", entries, err)
		return
	}
}
