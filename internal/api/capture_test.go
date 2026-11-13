// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package api

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/capture"
	"github.com/decerter/decerter/internal/history"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers/legacy"
)

const (
	// the block type of the Section Header Block, the first bytes of every pcapng
	sectionHeaderType uint32 = 0x0A0D0D0A
)

// Test if the capture operations answer as api/openapi.yaml says in capture mode: captures are started, listed, stopped and downloaded as pcapng, the limit of running captures holds, the history exports in both formats and the stream starts with a pcapng section.
func TestCaptureHandlerPositive(state *testing.T) {
	document, err := loadSpec(state.Context())

	if err != nil {
		state.Fatalf("Test of the capture handlers failed, cannot load the spec, error: %s", err.Error())
	}

	logger := slog.New(slog.DiscardHandler)
	info := Info{Mode: v1.CaptureMode, Processing: v1.RecordProcessing, Platform: "linux", Scope: "", Started: time.Now(), HoldTimeout: 0, HasTLSSecrets: false, IsInterceptCapable: false}
	backend := NewBackend(info, history.DefaultLimits(), nil)
	// a hub that is never run: the captures get no packets and are valid empty files
	hub, err := capture.NewHub(capturebpf.MaxSnaplen, nil, nil, nil, backend.History, logger)

	if err != nil {
		state.Fatalf("Test of the capture handlers failed, cannot make the hub, error: %s", err.Error())
	}

	backend.Captures, err = capture.NewCaptures(hub, state.TempDir(), logger)

	if err != nil {
		state.Fatalf("Test of the capture handlers failed, cannot make the captures, error: %s", err.Error())
	}

	defer func() {
		if closeErr := backend.Captures.Close(); closeErr != nil {
			state.Errorf("Test of the capture handlers failed, cannot remove the captures, error: %s", closeErr.Error())
		}
	}()

	server := httptest.NewServer(Handler(backend, logger))
	defer server.Close()
	document.Servers = openapi3.Servers{{URL: server.URL + v1.BasePath}}
	router, err := legacy.NewRouter(document)

	if err != nil {
		state.Fatalf("Test of the capture handlers failed, cannot build the router, error: %s", err.Error())
	}

	positiveCases := []apiCase{
		{Method: http.MethodGet, Path: "/status", Status: http.StatusOK},
		{Method: http.MethodPost, Path: "/captures", Status: http.StatusCreated},
		{Method: http.MethodPost, Path: "/captures", Body: `{"filter": "tcp.dstport == 443", "plaintext": true}`, Status: http.StatusCreated},
		{Method: http.MethodPost, Path: "/captures", Body: `{"filter": "tcp.port =="}`, Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/captures", Body: `{"format": "dsb"}`, Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: "/captures", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/captures/1/pcap", Status: http.StatusConflict},
		{Method: http.MethodPost, Path: "/captures/1/stop", Status: http.StatusOK},
		{Method: http.MethodPost, Path: "/captures/1/stop", Status: http.StatusOK},
		{Method: http.MethodPost, Path: "/captures/2/stop", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/captures/2/pcap", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/captures/99/pcap", Status: http.StatusNotFound},
		{Method: http.MethodPost, Path: "/captures/99/stop", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/captures/x/pcap", Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: "/flows/pcap?format=dsb", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows/pcap?format=plaintext&filter=tls", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/captures/stream?plaintext=maybe", Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: "/keylog", Status: http.StatusConflict},
		{Method: http.MethodPost, Path: "/rules", Body: `{"find": {"type": "text", "value": "a"}, "replace": {"type": "text", "value": "b"}}`, Status: http.StatusConflict},
	}

	// the running captures are limited, a stopped one makes room
	for range capture.MaxRunningCaptures {
		positiveCases = append(positiveCases, apiCase{Method: http.MethodPost, Path: "/captures", Body: `{"filter": "udp"}`, Status: http.StatusCreated})
	}

	positiveCases = append(positiveCases, apiCase{Method: http.MethodPost, Path: "/captures", Body: `{}`, Status: http.StatusConflict})

	for id := range capture.MaxRunningCaptures {
		positiveCases = append(positiveCases, apiCase{Method: http.MethodPost, Path: fmt.Sprintf("/captures/%d/stop", id+3), Status: http.StatusOK})
	}

	for _, positive := range positiveCases {
		_, body, caseErr := checkCase(state.Context(), server, router, positive)

		if caseErr != nil {
			state.Fatalf("Test of the capture handlers failed, %s %s, error: %s, body: %s", positive.Method, positive.Path, caseErr.Error(), body)
		}
	}

	// the file of a stopped capture and both exports are pcapng
	for _, path := range []string{"/captures/1/pcap", "/flows/pcap?format=dsb", "/flows/pcap"} {
		status, header, body, sendErr := send(state.Context(), server, http.MethodGet, v1.BasePath+path, "")

		if (sendErr != nil) || (status != http.StatusOK) || (header.Get("Content-Type") != pcapngMediaType) || (len(body) < 4) || (binary.LittleEndian.Uint32(body) != sectionHeaderType) {
			state.Errorf("Test of the capture handlers failed, GET %s should be a pcapng, status: %d, header: %v, body: %x, error: %v", path, status, header, body, sendErr)
			return
		}
	}

	list := v1.CaptureList{}
	_, err = getJSON(server, "/captures", &list)

	if (err != nil) || (len(list.Captures) != 2+capture.MaxRunningCaptures) || (list.Captures[1].Format != v1.PlaintextCaptureFormat) || (list.Captures[1].Filter != "tcp.dstport == 443") || (list.Captures[0].State != v1.StoppedCaptureState) || (list.Captures[0].Size == 0) {
		state.Errorf("Test of the capture handlers failed, the list should have the stopped captures with their filter, format and size, list: %+v, error: %v", list, err)
		return
	}
}

// Test if the capture stream of api.Handler starts with the section and interface blocks at once and ends when the client goes away.
func TestStreamCapturePositive(state *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	info := Info{Mode: v1.CaptureMode, Processing: v1.RecordProcessing, Platform: "linux", Scope: "", Started: time.Now(), HoldTimeout: 0, HasTLSSecrets: false, IsInterceptCapable: false}
	backend := NewBackend(info, history.DefaultLimits(), nil)
	hub, err := capture.NewHub(capturebpf.MaxSnaplen, nil, nil, nil, backend.History, logger)

	if err != nil {
		state.Fatalf("Test of api.streamCapture failed, cannot make the hub, error: %s", err.Error())
	}

	backend.Captures, err = capture.NewCaptures(hub, state.TempDir(), logger)

	if err != nil {
		state.Fatalf("Test of api.streamCapture failed, cannot make the captures, error: %s", err.Error())
	}

	server := httptest.NewServer(Handler(backend, logger))
	defer server.Close()

	for _, path := range []string{"/captures/stream", "/captures/stream?plaintext=true&filter=tcp.dstport+%3D%3D+443"} {
		ctx, cancel := context.WithCancel(state.Context())
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+v1.BasePath+path, nil)

		if requestErr != nil {
			cancel()
			state.Fatalf("Test of api.streamCapture failed, cannot make the request, error: %s", requestErr.Error())
		}

		response, doErr := server.Client().Do(request)

		if doErr != nil {
			cancel()
			state.Fatalf("Test of api.streamCapture failed, cannot connect, error: %s", doErr.Error())
		}

		// the section header block and the interface description block come before any packet
		head := make([]byte, 4)
		_, readErr := io.ReadFull(response.Body, head)
		cancel()
		closeErr := response.Body.Close()

		if (readErr != nil) || (response.StatusCode != http.StatusOK) || (response.Header.Get("Content-Type") != pcapngMediaType) || (binary.LittleEndian.Uint32(head) != sectionHeaderType) || ((closeErr != nil) && !errors.Is(closeErr, context.Canceled)) {
			state.Errorf("Test of api.streamCapture failed, GET %s should start a pcapng stream, status: %d, header: %v, head: %x, error: %v", path, response.StatusCode, response.Header, head, errors.Join(readErr, closeErr))
			return
		}
	}

	// the streams leave the hub when their clients are gone
	deadline := time.Now().Add(5 * time.Second)

	for hub.Consumers() > 0 {
		if time.Now().After(deadline) {
			state.Errorf("Test of api.streamCapture failed, the streams should end when their clients go away, writers: %d", hub.Consumers())
			return
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// GET a JSON answer of the test server
func getJSON(server *httptest.Server, path string, result any) (status int, err error) {
	status, _, body, err := send(context.Background(), server, http.MethodGet, v1.BasePath+path, "")

	if err != nil {
		return
	}

	err = json.Unmarshal(bytes.TrimSpace(body), result)
	return
}
