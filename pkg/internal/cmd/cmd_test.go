// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package cmd

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/tls/openssl"
	"github.com/decerter/decerter/pkg/internal/logging"
)

const (
	// how long a test waits for a log line or a command to return
	waitTimeout time.Duration = 10 * time.Second
)

// the logs of a command that runs in another goroutine
type lockedBuffer struct {
	mutex  *sync.Mutex
	buffer *bytes.Buffer
}

func newLockedBuffer() (buffer lockedBuffer) {
	buffer = lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}
	return
}

func (buffer lockedBuffer) Write(data []byte) (written int, err error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	written, err = buffer.buffer.Write(data)
	return
}

func (buffer lockedBuffer) String() (text string) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	text = buffer.buffer.String()
	return
}

// poll the logs until they contain text, false after waitTimeout
func (buffer lockedBuffer) waitFor(text string) (found bool) {
	deadline := time.Now().Add(waitTimeout)

	for time.Now().Before(deadline) {
		if strings.Contains(buffer.String(), text) {
			found = true
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	return
}

// os.Stdout is a pipe while the test runs, read closes the writing end and returns what was written
type testStdout struct {
	reader *os.File
	writer *os.File
}

func redirectStdout(state *testing.T) (stdout testStdout) {
	reader, writer, err := os.Pipe()

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot make a pipe for stdout, error: %s", err.Error())
	}

	original := os.Stdout
	os.Stdout = writer
	stdout = testStdout{reader: reader, writer: writer}

	state.Cleanup(func() {
		os.Stdout = original

		// the writer is closed already after read
		if closeErr := writer.Close(); (closeErr != nil) && !errors.Is(closeErr, os.ErrClosed) {
			state.Errorf("Test of cmd failed, cannot close the stdout pipe, error: %s", closeErr.Error())
		}

		if closeErr := reader.Close(); closeErr != nil {
			state.Errorf("Test of cmd failed, cannot close the stdout pipe, error: %s", closeErr.Error())
		}
	})

	return
}

func (stdout testStdout) read(state *testing.T) (text string) {
	err := stdout.writer.Close()

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot close the stdout pipe, error: %s", err.Error())
	}

	data, err := io.ReadAll(stdout.reader)

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot read stdout, error: %s", err.Error())
	}

	text = string(data)
	return
}

// the signal goes to this process; only send it while a shutdownContext is registered for it, otherwise it ends the test binary
func signalSelf(state *testing.T, signal syscall.Signal) {
	err := syscall.Kill(os.Getpid(), signal)

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot send %s, error: %s", signal, err.Error())
	}
}

// a socket path under a regular file, so the api can't listen and the start fails before anything is loaded, whatever groups the host has
func unusableSocket(state *testing.T) (socket string) {
	file := filepath.Join(state.TempDir(), "file")
	err := os.WriteFile(file, nil, 0o600)

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot write %s, error: %s", file, err.Error())
	}

	socket = filepath.Join(file, "api.sock")
	return
}

// Test if cmd.Run returns with the expected errors: a package on Linux before anything starts, an api socket that can't be made stops the start and the shutdown still runs.
func TestRunNegative(state *testing.T) {
	negativeCases := []struct {
		Name      string
		Packages  []string
		Socket    string
		Intercept bool
		Expected  error
		Text      string
	}{
		{Name: "package on Linux", Packages: []string{"com.example.app"}, Socket: "", Intercept: false, Expected: ErrPackageNotAndroid, Text: "Could not select packages"},
		{Name: "api socket under a file", Packages: nil, Socket: unusableSocket(state), Intercept: false, Expected: syscall.ENOTDIR, Text: "Could not create api socket"},
		{Name: "intercept with the api socket under a file", Packages: nil, Socket: unusableSocket(state), Intercept: true, Expected: syscall.ENOTDIR, Text: "Could not create api socket"},
	}

	for _, negative := range negativeCases {
		logs := &bytes.Buffer{}
		logger := logging.New(logs, slog.LevelDebug)
		err := Run(redirect.Filter{UIDs: []uint32{1001}}, negative.Packages, nil, 0, time.Second, false, false, false, negative.Intercept, negative.Socket, time.Second, time.Second, "", &logger)

		if !errors.Is(err, negative.Expected) || !strings.Contains(logs.String(), negative.Text) {
			state.Errorf("Test of cmd.Run function failed, %s, error should be %v with the log %q, error: %v, logs: %s", negative.Name, negative.Expected, negative.Text, err, logs.String())
			return
		}

		// serve logs its end after a failed start too
		if (negative.Packages == nil) && !strings.Contains(logs.String(), `"msg":"Stopped"`) {
			state.Errorf("Test of cmd.Run function failed, %s, the shutdown should be logged, logs: %s", negative.Name, logs.String())
			return
		}
	}
}

// Test if cmd.Capture returns with the expected errors: a package on Linux before anything starts, an api socket that can't be made stops the start.
func TestCaptureNegative(state *testing.T) {
	negativeCases := []struct {
		Name     string
		Packages []string
		Socket   string
		Expected error
		Text     string
	}{
		{Name: "package on Linux", Packages: []string{"com.example.app"}, Socket: "", Expected: ErrPackageNotAndroid, Text: "Could not select packages"},
		{Name: "api socket under a file", Packages: nil, Socket: unusableSocket(state), Expected: syscall.ENOTDIR, Text: "Could not create api socket"},
	}

	for _, negative := range negativeCases {
		logs := &bytes.Buffer{}
		logger := logging.New(logs, slog.LevelDebug)
		err := Capture(redirect.Filter{UIDs: []uint32{1001}}, negative.Packages, nil, "", negative.Socket, false, 1500, false, false, "", 0, &logger)

		if !errors.Is(err, negative.Expected) || !strings.Contains(logs.String(), negative.Text) {
			state.Errorf("Test of cmd.Capture function failed, %s, error should be %v with the log %q, error: %v, logs: %s", negative.Name, negative.Expected, negative.Text, err, logs.String())
			return
		}
	}
}

// Test if cmd.Keylog returns with the expected errors: a package on Linux before anything starts, a --libssl that does not exist stops the start before the uprobe is loaded.
func TestKeylogNegative(state *testing.T) {
	negativeCases := []struct {
		Name     string
		Packages []string
		Libssl   string
		Text     string
	}{
		{Name: "package on Linux", Packages: []string{"com.example.app"}, Libssl: "", Text: "Could not select packages"},
		{Name: "missing libssl", Packages: nil, Libssl: filepath.Join(state.TempDir(), "libssl.so.3"), Text: `"msg":"Could not`},
	}

	for _, negative := range negativeCases {
		logs := &bytes.Buffer{}
		logger := logging.New(logs, slog.LevelDebug)
		err := Keylog(redirect.Filter{UIDs: []uint32{1001}}, negative.Packages, negative.Libssl, &logger)

		// an architecture without the uprobe fails before the library is looked at
		isExpected := errors.Is(err, ErrPackageNotAndroid)

		if negative.Packages == nil {
			isExpected = errors.Is(err, openssl.ErrLibraryNotFound) || errors.Is(err, secrets.ErrUnsupportedArchitecture)
		}

		if !isExpected || !strings.Contains(logs.String(), negative.Text) {
			state.Errorf("Test of cmd.Keylog function failed, %s, error should be set with the log %q, error: %v, logs: %s", negative.Name, negative.Text, err, logs.String())
			return
		}
	}
}
