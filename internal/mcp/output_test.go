// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// a raw JSON-RPC client of serve on two pipes: lines go to the server, answers come back one per line
type rawClient struct {
	input   *io.PipeWriter
	answers *bufio.Scanner
}

// serve on pipes with the server for target, until ctx is done or the client closes its input; errChannel gets serve's error
func startRawServe(state *testing.T, ctx context.Context, target ui.Target) (client rawClient, errChannel chan error) {
	server, err := NewServer(NewClient(target), openTestOutput(state, state.TempDir()), false, slog.New(slog.DiscardHandler))

	if err != nil {
		state.Fatalf("Could not make the mcp server, error: %s", err.Error())
	}

	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	errChannel = make(chan error, 1)

	// mcp server on the pipes
	go func() {
		errChannel <- serve(ctx, server, inputReader, outputWriter)
		_ = outputWriter.Close()
	}()

	client = rawClient{input: inputWriter, answers: bufio.NewScanner(outputReader)}
	client.answers.Buffer(make([]byte, 0, 1<<16), 1<<24)
	state.Cleanup(func() {
		_ = inputWriter.Close()
		_ = outputReader.Close()
	})
	return
}

// send one line and read the next answer
func (client rawClient) exchange(state *testing.T, line string) (answer map[string]any) {
	client.send(state, line)

	if !client.answers.Scan() {
		state.Fatalf("Could not read an answer to %q, error: %v", line, client.answers.Err())
	}

	if err := json.Unmarshal(client.answers.Bytes(), &answer); err != nil {
		state.Fatalf("Could not decode the answer %q, error: %s", client.answers.Text(), err.Error())
	}

	return
}

func (client rawClient) send(state *testing.T, line string) {
	if _, err := io.WriteString(client.input, line+"\n"); err != nil {
		state.Fatalf("Could not send %q, error: %s", line, err.Error())
	}
}

// the session's start: initialize and its notification
func (client rawClient) initialize(state *testing.T) {
	answer := client.exchange(state, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)

	if answer["result"] == nil {
		state.Fatalf("Could not initialize, answer: %v", answer)
	}

	client.send(state, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

// Test if mcp.serve returns with the expected output: a line that is no JSON or no JSON-RPC message gets an error answer with its id, and the server answers the next request.
func TestServeLinesPositive(state *testing.T) {
	client, errChannel := startRawServe(state, state.Context(), ui.Target{Network: ui.UnixNetwork, Address: filepath.Join(state.TempDir(), "api.sock")})
	client.initialize(state)
	positiveCases := []struct {
		Line string
		Code float64
		ID   any
	}{
		{Line: `{"jsonrpc":"2.0","id":2,"method":"tools/list"`, Code: -32700, ID: nil},
		{Line: `not json at all`, Code: -32700, ID: nil},
		{Line: `{"jsonrpc":"1.0","id":"three","method":"tools/list"}`, Code: -32600, ID: "three"},
		{Line: `{"id":4}`, Code: -32600, ID: float64(4)},
		{Line: `[]`, Code: -32600, ID: nil},
		{Line: `[{"jsonrpc":"2.0","id":5,"method":"tools/list"},{"bad":true}]`, Code: -32600, ID: nil},
		{Line: `{"jsonrpc":"2.0","id":{"x":1},"method":"tools/list"}`, Code: -32600, ID: nil},
	}

	for _, positive := range positiveCases {
		answer := client.exchange(state, positive.Line)
		answerErr, _ := answer["error"].(map[string]any)

		if (answerErr == nil) || (answerErr["code"] != positive.Code) || (answer["id"] != positive.ID) || (answer["jsonrpc"] != "2.0") {
			state.Errorf("Test of mcp.serve function failed, %q should be answered with %v and id %v, answer: %v", positive.Line, positive.Code, positive.ID, answer)
			return
		}

		// the session goes on
		answer = client.exchange(state, `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`)

		if (answer["result"] == nil) || (answer["id"] != float64(9)) {
			state.Errorf("Test of mcp.serve function failed, after %q the server should answer tools/list, answer: %v", positive.Line, answer)
			return
		}
	}

	// an empty line is no message and gets no answer, the end of stdin ends the session without an error
	client.send(state, "   ")

	if err := client.input.Close(); err != nil {
		state.Fatalf("Could not close the input, error: %s", err.Error())
	}

	select {
	case serveErr := <-errChannel:
		if serveErr != nil {
			state.Errorf("Test of mcp.serve function failed, the end of stdin should end it without an error, error: %v", serveErr)
		}
	case <-time.After(10 * time.Second):
		state.Errorf("Test of mcp.serve function failed, the end of stdin should end it")
	}
}

// Test if mcp.readLine and mcp.checkLine return with the expected output: a line over the limit is answered and skipped up to its end.
func TestReadLinePositive(state *testing.T) {
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("x", maxLineBytes+1) + "\n" + ` {"jsonrpc":"2.0","method":"a"} ` + "\n"))
	line, isTooLong, err := readLine(reader)
	answer := checkLine(line, isTooLong)

	if (err != nil) || !isTooLong || (line != nil) || !strings.Contains(string(answer), `"code":-32600`) || !strings.Contains(string(answer), "longer than") {
		state.Fatalf("Test of mcp.readLine function failed, a long line should be skipped and answered, error: %v, answer: %s", err, answer)
	}

	line, isTooLong, err = readLine(reader)

	if (err != nil) || isTooLong || (string(line) != `{"jsonrpc":"2.0","method":"a"}`) || (checkLine(line, isTooLong) != nil) {
		state.Fatalf("Test of mcp.readLine function failed, the next line should be read, line: %q, error: %v", line, err)
	}

	_, _, err = readLine(reader)

	if !errors.Is(err, io.EOF) {
		state.Fatalf("Test of mcp.readLine function failed, the end should be %v, error: %v", io.EOF, err)
	}
}

// Test if mcp.serve returns with the expected output: a shutdown during a long tail_events ends the call and the server within a second.
func TestServeShutdownPositive(state *testing.T) {
	streaming := make(chan struct{})
	once := &sync.Once{}
	target := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", eventMediaType)
		writer.WriteHeader(http.StatusOK)

		if flushErr := http.NewResponseController(writer).Flush(); flushErr != nil {
			state.Errorf("Could not flush the fake api answer, error: %s", flushErr.Error())
		}

		once.Do(func() {
			close(streaming)
		})
		<-request.Context().Done()
	})
	ctx, cancel := context.WithCancel(state.Context())
	defer cancel()
	client, errChannel := startRawServe(state, ctx, target)
	client.initialize(state)
	client.send(state, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tail_events","arguments":{"seconds":60}}}`)

	// the answers are read like a client does, a pipe nobody reads blocks the server's write
	go func() {
		for client.answers.Scan() {
		}
	}()

	select {
	case <-streaming:
	case <-time.After(10 * time.Second):
		state.Fatalf("Test of mcp.serve function failed, tail_events should reach the api")
	}

	started := time.Now()
	cancel()

	select {
	case serveErr := <-errChannel:
		if (serveErr != nil) || (time.Since(started) > time.Second) {
			state.Errorf("Test of mcp.serve function failed, a shutdown should end it within a second without an error, took: %s, error: %v", time.Since(started), serveErr)
		}
	case <-time.After(10 * time.Second):
		state.Errorf("Test of mcp.serve function failed, a shutdown should end it while tail_events runs")
	}
}
