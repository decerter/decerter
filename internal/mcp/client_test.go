// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package mcp

import (
	"encoding/json"
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

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/api"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/ui"
)

// a control API on a unix socket that answers every request with handler
// the directory is short: a socket path has at most 107 bytes and the test's own directory can be longer
func startHandlerAPI(state *testing.T, handler http.HandlerFunc) (target ui.Target) {
	directory, err := os.MkdirTemp("", "decerter-mcp-")

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
		state.Fatalf("Could not listen on the fake api socket, error: %s", err.Error())
	}

	server := httptest.NewUnstartedServer(handler)
	closeErr := server.Listener.Close()

	if closeErr != nil {
		state.Fatalf("Could not close the fake api's tcp listener, error: %s", closeErr.Error())
	}

	server.Listener = listener
	server.Start()
	state.Cleanup(server.Close)
	target = ui.Target{Network: ui.UnixNetwork, Address: socket}
	return
}

// the answer status, header and the start of a body, then the connection is closed before the rest of the body
func writeCut(state *testing.T, writer http.ResponseWriter, mediaType string, length int, start string) {
	connection, buffered, err := http.NewResponseController(writer).Hijack()

	if err != nil {
		state.Errorf("Could not hijack the fake api connection, error: %s", err.Error())
		return
	}

	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			state.Errorf("Could not close the fake api connection, error: %s", closeErr.Error())
		}
	}()

	_, err = buffered.WriteString("HTTP/1.1 200 OK\r\nContent-Type: " + mediaType + "\r\nContent-Length: " + strconv.Itoa(length) + "\r\n\r\n" + start)

	if err == nil {
		err = buffered.Flush()
	}

	if err != nil {
		state.Errorf("Could not write the cut answer, error: %s", err.Error())
	}
}

// close the connection without an answer
func closeConnection(state *testing.T, writer http.ResponseWriter) {
	connection, _, err := http.NewResponseController(writer).Hijack()

	if err != nil {
		state.Errorf("Could not hijack the fake api connection, error: %s", err.Error())
		return
	}

	if closeErr := connection.Close(); closeErr != nil {
		state.Errorf("Could not close the fake api connection, error: %s", closeErr.Error())
	}
}

func writeAnswer(state *testing.T, writer http.ResponseWriter, mediaType string, status int, body string) {
	writer.Header().Set("Content-Type", mediaType)
	writer.WriteHeader(status)

	if _, writeErr := io.WriteString(writer, body); writeErr != nil {
		state.Errorf("Could not write the fake api answer, error: %s", writeErr.Error())
	}
}

// Test if mcp.Client.getJSON returns with the expected errors: broken JSON, an answer larger than the limit and a body cut short.
func TestGetJSONNegative(state *testing.T) {
	target := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case v1.BasePath + "/broken":
			writeAnswer(state, writer, jsonMediaType, http.StatusOK, `{"mode": `)
		case v1.BasePath + "/large":
			writer.Header().Set("Content-Type", jsonMediaType)
			writer.WriteHeader(http.StatusOK)

			if _, copyErr := io.CopyN(writer, spaces{}, maxJSONBytes+1); copyErr != nil {
				state.Errorf("Could not write the large answer, error: %s", copyErr.Error())
			}
		default:
			writeCut(state, writer, jsonMediaType, 100, `{"mode": "run"`)
		}
	})
	client := NewClient(target)
	negativeCases := []struct {
		Path     string
		Expected error
		Text     string
	}{
		{Path: "/broken", Expected: ErrAPI, Text: "GET /broken: unexpected end of JSON input"},
		{Path: "/large", Expected: ErrAPI, Text: "the answer is larger than"},
		{Path: "/cut", Expected: io.ErrUnexpectedEOF, Text: ""},
	}

	for _, negative := range negativeCases {
		status := v1.Status{}
		err := client.getJSON(state.Context(), negative.Path, nil, &status)

		if !errors.Is(err, negative.Expected) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of mcp.Client.getJSON function failed, %s, error should be %v with %q, error: %v", negative.Path, negative.Expected, negative.Text, err)
			return
		}
	}
}

// spaces is an endless reader of white space, valid JSON padding
type spaces struct{}

func (reader spaces) Read(data []byte) (read int, err error) {
	for index := range data {
		data[index] = ' '
	}

	read = len(data)
	return
}

// Test if mcp.Client.sendJSON returns with the expected errors: a body that can't be encoded, an invalid method, a connection the api closes, an answer that is not JSON and broken JSON.
func TestSendJSONNegative(state *testing.T) {
	target := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case v1.BasePath + "/close":
			closeConnection(state, writer)
		case v1.BasePath + "/html":
			writeAnswer(state, writer, "text/html", http.StatusOK, "<html>")
		default:
			writeAnswer(state, writer, jsonMediaType, http.StatusOK, "{")
		}
	})
	client := NewClient(target)
	negativeCases := []struct {
		Method   string
		Path     string
		Body     any
		Expected error
		Text     string
	}{
		{Method: http.MethodPost, Path: "/rules", Body: map[string]any{"channel": make(chan int)}, Expected: nil, Text: "json: unsupported type"},
		{Method: "BAD METHOD", Path: "/rules", Body: nil, Expected: nil, Text: "invalid method"},
		{Method: http.MethodPut, Path: "/close", Body: v1.InterceptState{}, Expected: ui.ErrRefused, Text: ""},
		{Method: http.MethodPut, Path: "/html", Body: v1.InterceptState{}, Expected: ErrContentType, Text: `PUT /html: "text/html", expected application/json`},
		{Method: http.MethodPut, Path: "/broken", Body: nil, Expected: ErrAPI, Text: "PUT /broken"},
	}

	for _, negative := range negativeCases {
		result := v1.InterceptState{}
		err := client.sendJSON(state.Context(), negative.Method, negative.Path, negative.Body, &result)

		if (err == nil) || ((negative.Expected != nil) && !errors.Is(err, negative.Expected)) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of mcp.Client.sendJSON function failed, %s %s, error should be %v with %q, error: %v", negative.Method, negative.Path, negative.Expected, negative.Text, err)
			return
		}
	}
}

// Test if mcp.Client.download returns with the expected errors: a body cut short is the api's error and leaves no file.
func TestDownloadNegative(state *testing.T) {
	target := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		writeCut(state, writer, pcapngMediaType, 1000, testPcapng)
	})
	directory := state.TempDir()
	output, err := OpenOutput(directory)

	if err != nil {
		state.Fatalf("Could not open the output directory, error: %s", err.Error())
	}

	defer func() {
		if closeErr := output.Close(); closeErr != nil {
			state.Errorf("Could not close the output directory, error: %s", closeErr.Error())
		}
	}()

	result, _, err := NewClient(target).download(state.Context(), "/flows/pcap", nil, pcapngMediaType, output, "flows", "pcapng", io.Discard)
	entries, readErr := os.ReadDir(directory)

	if !errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, ErrOutputFile) || (result.Path != "") || (readErr != nil) || (len(entries) != 0) {
		state.Errorf("Test of mcp.Client.download function failed, a cut body should be %v and leave no file, result: %+v, error: %v, entries: %v, read: %v", io.ErrUnexpectedEOF, result, err, entries, readErr)
		return
	}
}

// Test if mcp.Client.events returns with the expected output: the events until the api ends the stream, which is a closed stream.
func TestEventsPositive(state *testing.T) {
	target := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		data, _ := json.Marshal(v1.Event{Seq: 1, Type: v1.RuleAddedEventType})
		writeAnswer(state, writer, eventMediaType, http.StatusOK, ": decerter events\n\nid: 1\ndata: "+string(data)+"\n\n")
	})
	seen := []uint64{}
	isClosed, err := NewClient(target).events(state.Context(), func(event v1.Event) (isMore bool) {
		seen = append(seen, event.Seq)
		isMore = true
		return
	})

	if (err != nil) || !isClosed || (len(seen) != 1) {
		state.Errorf("Test of mcp.Client.events function failed, one event and a closed stream expected, events: %v, closed: %v, error: %v", seen, isClosed, err)
		return
	}
}

// Test if mcp.Client.events returns with the expected errors: an event that is not JSON, a stream cut in the middle of a chunk.
func TestEventsNegative(state *testing.T) {
	broken := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		writeAnswer(state, writer, eventMediaType, http.StatusOK, "data: {\"seq\":\n\n")
	})
	cut := startHandlerAPI(state, func(writer http.ResponseWriter, request *http.Request) {
		connection, buffered, err := http.NewResponseController(writer).Hijack()

		if err != nil {
			state.Errorf("Could not hijack the fake api connection, error: %s", err.Error())
			return
		}

		_, err = buffered.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n100\r\n: decerter events")

		if err == nil {
			err = buffered.Flush()
		}

		if err = errors.Join(err, connection.Close()); err != nil {
			state.Errorf("Could not write the cut stream, error: %s", err.Error())
		}
	})
	negativeCases := []struct {
		Name     string
		Target   ui.Target
		Expected error
	}{
		{Name: "an event that is not JSON", Target: broken, Expected: ErrEventStream},
		{Name: "a stream cut in a chunk", Target: cut, Expected: io.ErrUnexpectedEOF},
	}

	for _, negative := range negativeCases {
		isClosed, err := NewClient(negative.Target).events(state.Context(), func(event v1.Event) (isMore bool) {
			isMore = true
			return
		})

		if !errors.Is(err, ErrEventStream) || !errors.Is(err, negative.Expected) || isClosed {
			state.Errorf("Test of mcp.Client.events function failed, %s, error should be %v, closed: %v, error: %v", negative.Name, negative.Expected, isClosed, err)
			return
		}
	}
}

// Test if mcp.Client returns with the expected output for an api over TCP, as adb forward has it: it sends the loopback ip:port as Host, which the api takes
// there, not decerter, which it takes only on its socket.
func TestTCPHostPositive(state *testing.T) {
	backend := api.NewBackend(api.Info{Mode: v1.CaptureMode}, history.DefaultLimits(), nil)
	server := httptest.NewServer(api.Handler(backend, slog.New(slog.DiscardHandler)))
	defer server.Close()
	target, err := ui.ParseTarget(strings.TrimPrefix(server.URL, "http://"))

	if err != nil {
		state.Fatalf("Could not parse the target, error: %s", err.Error())
	}

	status := v1.Status{}
	err = NewClient(target).getJSON(state.Context(), "/status", nil, &status)

	if (err != nil) || (status.Mode != v1.CaptureMode) {
		state.Errorf("Test of mcp.Client failed, the api over TCP should answer, status: %+v, error: %v", status, err)
	}
}
