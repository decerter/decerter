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
	"net/netip"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/capture"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
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
	hub, err := capture.NewHub(capturebpf.MaxSnaplen, nil, nil, nil, backend.History, false, logger)

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
		// a capture decides a flow when it starts, before its HTTP layer read anything
		{Method: http.MethodPost, Path: "/captures", Body: `{"filter": "http.host == \"a\""}`, Status: http.StatusBadRequest},
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

// Test if the capture operations answer as api/openapi.yaml says in run mode with the capture of the proxy's upstream sockets: captures start, format=dsb writes the captured packets and format=plaintext still the history.
func TestCaptureHandlerRunModePositive(state *testing.T) {
	document, err := loadSpec(state.Context())

	if err != nil {
		state.Fatalf("Test of the capture handlers failed, cannot load the spec, error: %s", err.Error())
	}

	logger := slog.New(slog.DiscardHandler)
	info := Info{Mode: v1.RunMode, Processing: v1.InterceptProcessing, Platform: "linux", Scope: "", Started: time.Now(), HoldTimeout: 0, HasTLSSecrets: false, IsInterceptCapable: true}
	backend := NewBackend(info, history.DefaultLimits(), nil)
	hub, err := capture.NewHub(capturebpf.MaxSnaplen, nil, nil, nil, backend.History, true, logger)

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

	// a message of the proxy in the history: the app's side, which only the plaintext export has
	values := filter.Values{PID: 1, UID: 1001, IPProtocol: syscall.IPPROTO_UDP, Source: netip.MustParseAddrPort("[::ffff:127.0.0.1]:5000"), Destination: netip.MustParseAddrPort("127.0.0.1:53"), TLS: filter.AbsentTLSState}
	flowID := backend.History.OpenFlow(1, values, [32]byte{})
	flow := intercept.FlowOf(flowID, 1, redirectFlow(values), values.Source, values)
	backend.History.Record(intercept.Message{Flow: flow, ID: 100, Direction: tlsrecord.ClientDirection, Layer: intercept.UDPLayer, Plain: []byte("query")}, intercept.Result{Plain: []byte("query"), Verdict: intercept.ForwardVerdict, Changed: false}, intercept.RulesOrigin)
	server := httptest.NewServer(Handler(backend, logger))
	defer server.Close()
	document.Servers = openapi3.Servers{{URL: server.URL + v1.BasePath}}
	router, err := legacy.NewRouter(document)

	if err != nil {
		state.Fatalf("Test of the capture handlers failed, cannot build the router, error: %s", err.Error())
	}

	positiveCases := []apiCase{
		{Method: http.MethodPost, Path: "/captures", Body: `{"filter": "tls"}`, Status: http.StatusCreated},
		{Method: http.MethodGet, Path: "/captures/1/pcap", Status: http.StatusConflict},
		{Method: http.MethodPost, Path: "/captures/1/stop", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/captures/1/pcap", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/captures/2/pcap", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/flows/pcap?format=dsb", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows/pcap?format=plaintext", Status: http.StatusOK},
	}

	for _, positive := range positiveCases {
		_, body, caseErr := checkCase(state.Context(), server, router, positive)

		if caseErr != nil {
			state.Fatalf("Test of the capture handlers failed, %s %s, error: %s, body: %s", positive.Method, positive.Path, caseErr.Error(), body)
		}
	}

	status := v1.Status{}
	_, err = getJSON(server, "/status", &status)

	if (err != nil) || !status.Captures.Available || (status.Mode != v1.RunMode) {
		state.Errorf("Test of the capture handlers failed, run mode with the capture should have captures available, status: %+v, error: %v", status, err)
		return
	}

	// the plaintext export is synthesized from the history, the dsb export has the captured packets, none in this test
	for path, hasMessage := range map[string]bool{"/flows/pcap": true, "/flows/pcap?format=dsb": false} {
		_, _, body, sendErr := send(state.Context(), server, http.MethodGet, v1.BasePath+path, "")

		if (sendErr != nil) || (bytes.Contains(body, []byte("query")) != hasMessage) {
			state.Errorf("Test of the capture handlers failed, GET %s should have the message of the history: %v, body: %x, error: %v", path, hasMessage, body, sendErr)
			return
		}
	}
}

// Test if the capture stream of api.Handler starts with the section and interface blocks at once and ends when the client goes away.
func TestStreamCapturePositive(state *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	info := Info{Mode: v1.CaptureMode, Processing: v1.RecordProcessing, Platform: "linux", Scope: "", Started: time.Now(), HoldTimeout: 0, HasTLSSecrets: false, IsInterceptCapable: false}
	backend := NewBackend(info, history.DefaultLimits(), nil)
	hub, err := capture.NewHub(capturebpf.MaxSnaplen, nil, nil, nil, backend.History, false, logger)

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
