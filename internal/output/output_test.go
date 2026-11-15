// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package output_test

import (
	"errors"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/decerter/decerter/internal/output"
)

// a pipe whose reader is closed, SIGPIPE is ignored until the test ends so the write fails with EPIPE
func closedPipe(state *testing.T) (writer *os.File) {
	signal.Ignore(syscall.SIGPIPE)
	reader, writer, err := os.Pipe()

	if err != nil {
		state.Fatalf("Could not make a pipe, error: %s", err.Error())
	}

	state.Cleanup(func() {
		signal.Reset(syscall.SIGPIPE)

		if closeErr := writer.Close(); closeErr != nil {
			state.Errorf("Could not close the writer of the pipe, error: %s", closeErr.Error())
		}
	})

	err = reader.Close()

	if err != nil {
		state.Fatalf("Could not close the reader of the pipe, error: %s", err.Error())
	}

	return
}

// Test if output.EscapeField returns with the expected output: a comm a process set to a terminal escape sequence or a line break comes out escaped.
func TestEscapeFieldPositive(state *testing.T) {
	positiveCases := map[string]string{
		"":                        "",
		"curl":                    "curl",
		"Web Content":             "Web Content",
		"\x1b":                    "\\x1b",
		"\x1b]0;owned\x07\x1b[2J": "\\x1b]0;owned\\x07\\x1b[2J",
		"a\nudp pid=1":            "a\\x0audp pid=1",
		"\xffa\\":                 "\\xffa\\\\",
	}

	for field, expected := range positiveCases {
		text := output.EscapeField(field)

		if text != expected {
			state.Errorf("Test of output.EscapeField function failed, field: %q, result should be %q, result: %q", field, expected, text)
			return
		}
	}
}

// Test if output.Writer returns with the expected output: writes to a reader that is there go through and call nothing.
func TestWriterPositive(state *testing.T) {
	reader, file, err := os.Pipe()

	if err != nil {
		state.Fatalf("Could not make a pipe, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if closeErr := errors.Join(reader.Close(), file.Close()); closeErr != nil {
			state.Errorf("Could not close the pipe, error: %s", closeErr.Error())
		}
	})

	calls := atomic.Int32{}
	writer := output.NewWriter(file)
	writer.OnGone(func() {
		calls.Add(1)
	})
	_, err = writer.Write([]byte("one\n"))

	if err == nil {
		_, err = writer.WriteString("two\n")
	}

	buffer := make([]byte, 16)
	length, readErr := reader.Read(buffer)

	if (err != nil) || (readErr != nil) || (string(buffer[:length]) != "one\ntwo\n") || (calls.Load() != 0) {
		state.Errorf("Test of output.Writer failed, both writes should arrive, read: %q, calls: %d, error: %v, read error: %v", buffer[:length], calls.Load(), err, readErr)
		return
	}
}

// Test if output.Writer returns with the expected errors: a write after the reader went away fails with EPIPE and calls the OnGone function once,
// also when OnGone comes after the failed write.
func TestWriterNegative(state *testing.T) {
	calls := atomic.Int32{}
	writer := output.NewWriter(closedPipe(state))
	writer.OnGone(func() {
		calls.Add(1)
	})
	_, err := writer.WriteString("line\n")
	_, secondErr := writer.Write([]byte("line\n"))

	if !errors.Is(err, syscall.EPIPE) || !output.IsGone(secondErr) || (calls.Load() != 1) {
		state.Errorf("Test of output.Writer failed, the writes should fail with EPIPE and call OnGone once, calls: %d, error: %v, second error: %v", calls.Load(), err, secondErr)
		return
	}

	lateCalls := atomic.Int32{}
	lateWriter := output.NewWriter(closedPipe(state))
	_, err = lateWriter.WriteString("line\n")
	lateWriter.OnGone(func() {
		lateCalls.Add(1)
	})

	if !output.IsGone(err) || (lateCalls.Load() != 1) {
		state.Errorf("Test of output.Writer failed, OnGone after the failed write should call at once, calls: %d, error: %v", lateCalls.Load(), err)
		return
	}

	if output.IsGone(errors.New("other")) || output.IsGone(nil) {
		state.Errorf("Test of output.IsGone failed, only EPIPE and EIO mean the reader is gone")
		return
	}
}
