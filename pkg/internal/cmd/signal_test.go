// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	// set in the environment of the test binary that runs as a child: the name of what it does instead of the tests
	childEnvironment string = "DECERTER_CMD_TEST_CHILD"
	// the child writes to a stdout whose reader is gone
	closedStdoutChild string = "closed-stdout"
)

// the test binary runs as a child of a test when childEnvironment is set
func TestMain(m *testing.M) {
	if os.Getenv(childEnvironment) == closedStdoutChild {
		os.Exit(writeClosedStdout())
	}

	os.Exit(m.Run())
}

// shutdownContext, then a write to stdout: without SIGPIPE ignored the Go runtime kills the process at the write, with it the write fails with EPIPE
func writeClosedStdout() (code int) {
	_, cancel := shutdownContext()
	defer cancel()
	_, err := fmt.Fprintln(os.Stdout, "tcp pid=1 uid=1001 comm=curl 127.0.0.1:443")

	if !errors.Is(err, syscall.EPIPE) {
		code = 1
	}

	_, printErr := fmt.Fprintf(os.Stderr, "write error: %v\n", err)

	if printErr != nil {
		code = 1
	}

	return
}

// Test if cmd.shutdownContext returns with the expected output: SIGINT, SIGTERM and SIGHUP each cancel the context, and the context is not done before.
func TestShutdownContextPositive(state *testing.T) {
	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		ctx, cancel := shutdownContext()

		if ctx.Err() != nil {
			cancel()
			state.Errorf("Test of cmd.shutdownContext function failed, the context should not be done before %s, error: %v", signal, ctx.Err())
			return
		}

		signalSelf(state, signal)

		select {
		case <-ctx.Done():
		case <-time.After(waitTimeout):
		}

		err := ctx.Err()
		cancel()

		if !errors.Is(err, context.Canceled) {
			state.Errorf("Test of cmd.shutdownContext function failed, %s should cancel the context, error: %v", signal, err)
			return
		}
	}
}

// Test if cmd.shutdownContext returns with the expected output: a process whose stdout reader is gone gets EPIPE from its write and goes on, it is not killed by SIGPIPE.
func TestShutdownContextClosedStdoutPositive(state *testing.T) {
	executable, err := os.Executable()

	if err != nil {
		state.Fatalf("Could not find the test binary, error: %s", err.Error())
	}

	reader, writer, err := os.Pipe()

	if err != nil {
		state.Fatalf("Could not make a pipe, error: %s", err.Error())
	}

	err = reader.Close()

	if err != nil {
		state.Fatalf("Could not close the reader of the pipe, error: %s", err.Error())
	}

	defer func() {
		if closeErr := writer.Close(); closeErr != nil {
			state.Errorf("Could not close the writer of the pipe, error: %s", closeErr.Error())
		}
	}()

	ctx, cancel := context.WithTimeout(state.Context(), waitTimeout)
	defer cancel()
	stderr := &bytes.Buffer{}
	command := exec.CommandContext(ctx, executable)
	command.Env = append(os.Environ(), childEnvironment+"="+closedStdoutChild)
	command.Stdout = writer
	command.Stderr = stderr
	err = command.Run()

	if (err != nil) || !strings.Contains(stderr.String(), "broken pipe") {
		state.Errorf("Test of cmd.shutdownContext function failed, the write should fail with EPIPE and the process exit on its own, error: %v, state: %v, stderr: %q", err, command.ProcessState, stderr.String())
		return
	}
}
