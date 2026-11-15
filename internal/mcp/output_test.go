// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package mcp

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/ui"
)

// a reader that gives some bytes, then fails with err
type failingReader struct {
	data string
	err  error
}

func (reader *failingReader) Read(data []byte) (read int, err error) {
	if reader.data == "" {
		err = reader.err
		return
	}

	read = copy(data, reader.data)
	reader.data = reader.data[read:]
	return
}

func openTestOutput(state *testing.T, directory string) (output Output) {
	output, err := OpenOutput(directory)

	if err != nil {
		state.Fatalf("Could not open the output directory, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if closeErr := output.Close(); closeErr != nil {
			state.Errorf("Could not close the output directory, error: %s", closeErr.Error())
		}
	})

	return
}

// Test if mcp.Output.save returns with the expected output: a second file of the same millisecond gets the next free name.
func TestSavePositive(state *testing.T) {
	directory := state.TempDir()
	output := openTestOutput(state, directory)

	// both files of one pair usually fall into the same millisecond, the name of the second depends on it
	for range 20 {
		first, err := output.save("keylog", "txt", strings.NewReader("first"))

		if err != nil {
			state.Fatalf("Test of mcp.Output.save function failed, error: %s", err.Error())
		}

		second, err := output.save("keylog", "txt", strings.NewReader("second"))

		if err != nil {
			state.Fatalf("Test of mcp.Output.save function failed, error: %s", err.Error())
		}

		firstName := strings.TrimSuffix(filepath.Base(first.Path), ".txt")
		secondName := strings.TrimSuffix(filepath.Base(second.Path), ".txt")

		if first.Path == second.Path {
			state.Errorf("Test of mcp.Output.save function failed, two files should have two names, path: %s", first.Path)
			return
		}

		if !strings.HasPrefix(secondName, firstName) {
			continue
		}

		if (secondName != firstName+"-2") || (second.Size != 6) {
			state.Errorf("Test of mcp.Output.save function failed, the second file of a millisecond should be %s-2, path: %s, size: %d", firstName, second.Path, second.Size)
			return
		}

		return
	}
}

// Test if mcp.Output.save returns with the expected errors: a reader error stays the reader's, an error that names a path is the file's, and neither leaves a file.
func TestSaveNegative(state *testing.T) {
	directory := state.TempDir()
	output := openTestOutput(state, directory)
	readErr := errors.New("connection reset")
	pathErr := &fs.PathError{Op: "write", Path: "decerter-keylog.txt", Err: errors.New("no space left on device")}
	negativeCases := []struct {
		Name      string
		Err       error
		IsFileErr bool
		IsReadErr bool
		IsPathErr bool
	}{
		{Name: "reader error", Err: readErr, IsFileErr: false, IsReadErr: true, IsPathErr: false},
		{Name: "path error", Err: pathErr, IsFileErr: true, IsReadErr: false, IsPathErr: true},
	}

	for _, negative := range negativeCases {
		result, err := output.save("keylog", "txt", &failingReader{data: "partial", err: negative.Err})
		entries, listErr := os.ReadDir(directory)

		if (errors.Is(err, ErrOutputFile) != negative.IsFileErr) || (errors.Is(err, readErr) != negative.IsReadErr) || (errors.Is(err, pathErr) != negative.IsPathErr) || (result.Path != "") || (listErr != nil) || (len(entries) != 0) {
			state.Errorf("Test of mcp.Output.save function failed, %s, file error should be %v, error: %v, result: %+v, entries: %v, list: %v", negative.Name, negative.IsFileErr, err, result, entries, listErr)
			return
		}
	}
}

// Test if mcp.OpenOutput returns with the expected errors: a relative directory when the working directory is gone.
func TestOpenOutputNegative(state *testing.T) {
	gone := filepath.Join(state.TempDir(), "gone")
	err := os.Mkdir(gone, 0o700)

	if err != nil {
		state.Fatalf("Could not make %s, error: %s", gone, err.Error())
	}

	state.Chdir(gone)
	state.Setenv("PWD", "")
	err = os.Remove(gone)

	if err != nil {
		state.Fatalf("Could not remove %s, error: %s", gone, err.Error())
	}

	_, err = OpenOutput("exports")

	if !errors.Is(err, ErrOutputDirectory) {
		state.Errorf("Test of mcp.OpenOutput function failed, a relative directory without a working directory should be %v, error: %v", ErrOutputDirectory, err)
		return
	}
}

// Test if mcp.Serve returns with the expected output: no error when the client closes stdin, and none when ctx is done.
func TestServePositive(state *testing.T) {
	for _, isCancelled := range []bool{false, true} {
		reader, writer, err := os.Pipe()

		if err != nil {
			state.Fatalf("Could not make a pipe for stdin, error: %s", err.Error())
		}

		original := os.Stdin
		os.Stdin = reader
		output := openTestOutput(state, state.TempDir())
		server, err := NewServer(NewClient(ui.Target{Network: ui.UnixNetwork, Address: filepath.Join(state.TempDir(), "api.sock")}), output, false, slog.New(slog.DiscardHandler))

		if err != nil {
			os.Stdin = original
			state.Fatalf("Could not make the mcp server, error: %s", err.Error())
		}

		ctx, cancel := context.WithCancel(state.Context())
		errChannel := make(chan error, 1)

		// mcp server on the pipe
		go func() {
			errChannel <- Serve(ctx, server)
		}()

		if isCancelled {
			cancel()
		} else {
			err = writer.Close()
		}

		select {
		case serveErr := <-errChannel:
			err = errors.Join(err, serveErr)
		case <-time.After(10 * time.Second):
			err = errors.Join(err, errors.New("serve did not return"))
		}

		cancel()
		os.Stdin = original

		// the SDK closes stdin at the end of the session
		for _, file := range []*os.File{writer, reader} {
			if closeErr := file.Close(); (closeErr != nil) && !errors.Is(closeErr, os.ErrClosed) {
				err = errors.Join(err, closeErr)
			}
		}

		if err != nil {
			state.Errorf("Test of mcp.Serve function failed, cancelled %v, it should end without an error, error: %v", isCancelled, err)
			return
		}
	}
}
