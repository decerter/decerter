// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
)

const (
	specPath string = "../../api/openapi.yaml"
)

var (
	testRandom = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	testKeyLog = "CLIENT_RANDOM 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 " + strings.Repeat("ab", 48) + "\n"
)

// one request against the test server: Status is what it must answer, IsInvalid marks a request the spec itself refuses, only its response is checked
type apiCase struct {
	Method    string
	Path      string
	Body      string
	Status    int
	IsInvalid bool
}

// the backend of a run with one closed TLS flow (a request a rule changed, a response, a dropped message), one open udp flow, one rule and two held messages
// stop forwards the held messages and waits for them
type testBackend struct {
	backend  *Backend
	tlsFlow  uint64
	udpFlow  uint64
	request  uint64
	dropped  uint64
	heldID   uint64
	dropID   uint64
	ruleID   uint64
	stop     func()
	pipeline *intercept.Pipeline
}

// Test if the routes of the server are the operations of api/openapi.yaml, with the same method, path and operationId, and the spec is valid.
func TestRoutesPositive(state *testing.T) {
	document, err := loadSpec(state.Context())

	if err != nil {
		state.Fatalf("Test of api routes failed, cannot load the spec, error: %s", err.Error())
	}

	specOperations := []string{}

	for path, item := range document.Paths.Map() {
		for method, operation := range item.Operations() {
			specOperations = append(specOperations, method+" "+v1.BasePath+path+" "+operation.OperationID)
		}
	}

	serverOperations := []string{}

	for _, operation := range routes() {
		serverOperations = append(serverOperations, operation.method+" "+v1.BasePath+operation.path+" "+operation.operationID)
	}

	slices.Sort(specOperations)
	slices.Sort(serverOperations)

	if !slices.Equal(specOperations, serverOperations) {
		state.Errorf("Test of api routes failed, the server should have the operations of the spec %v, server: %v", specOperations, serverOperations)
		return
	}
}

// Test if the fields of the Go types in api/types.go are the properties of their schemas, and the ones without omitzero are required.
func TestTypesPositive(state *testing.T) {
	document, err := loadSpec(state.Context())

	if err != nil {
		state.Fatalf("Test of api types failed, cannot load the spec, error: %s", err.Error())
	}

	types := map[string]any{
		"Error": v1.Error{}, "Value": v1.Value{}, "Status": v1.Status{}, "HistoryStatus": v1.HistoryStatus{}, "HistoryLimits": v1.HistoryLimits{},
		"InterceptState": v1.InterceptState{}, "InterceptRequest": v1.InterceptRequest{}, "Process": v1.Process{}, "TLSInfo": v1.TLSInfo{},
		"Traffic": v1.Traffic{}, "Flow": v1.Flow{}, "FlowList": v1.FlowList{}, "Message": v1.Message{}, "MessageList": v1.MessageList{},
		"Payload": v1.Payload{}, "MessageDetail": v1.MessageDetail{}, "Hold": v1.Hold{}, "HoldList": v1.HoldList{}, "EditRequest": v1.EditRequest{},
		"RuleRequest": v1.RuleRequest{}, "Rule": v1.Rule{}, "RuleList": v1.RuleList{}, "Event": v1.Event{},
	}

	for name, value := range types {
		schemaRef, found := document.Components.Schemas[name]

		if !found {
			state.Errorf("Test of api types failed, the spec has no schema %s", name)
			return
		}

		properties, required := schemaFields(schemaRef.Value)
		fields, fieldsRequired := jsonFields(reflect.TypeOf(value))

		if !slices.Equal(properties, fields) || !slices.Equal(required, fieldsRequired) {
			state.Errorf("Test of api types failed, %s should have properties %v required %v, the Go type has %v required %v", name, properties, required, fields, fieldsRequired)
			return
		}
	}
}

// Test if every operation answers as api/openapi.yaml says, against a backend with a TLS flow, a udp flow, a rule and a held message: every operation is called at least once with success.
func TestHandlerPositive(state *testing.T) {
	document, err := loadSpec(state.Context())

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot load the spec, error: %s", err.Error())
	}

	test, err := newTestBackend(state.Context())

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot fill the backend, error: %s", err.Error())
	}

	defer test.stop()
	server := httptest.NewServer(Handler(test.backend, slog.New(slog.DiscardHandler)))
	defer server.Close()
	document.Servers = openapi3.Servers{{URL: server.URL + v1.BasePath}}
	router, err := legacy.NewRouter(document)

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot build the router, error: %s", err.Error())
	}

	positiveCases := []apiCase{
		{Method: http.MethodGet, Path: "/status", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows?filter=tls.sni+%3D%3D+%22example.com%22&limit=1", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows?limit=1&cursor=" + fmt.Sprint(test.udpFlow), Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows?filter=proc.comm+%3D+%22curl%22", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows?limit=101", Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d", test.tlsFlow), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d", test.udpFlow), Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows/999", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/flows/x", Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/messages?limit=2", test.tlsFlow), Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows/999/messages", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: fmt.Sprintf("/messages/%d?offset=4&length=6", test.request), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/messages/%d", test.dropped), Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/messages/999", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/messages/1?length=70000", Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: "/holds", Status: http.StatusOK},
		{Method: http.MethodPut, Path: fmt.Sprintf("/holds/%d", test.heldID), Body: `{"payload": {"type": "text", "value": "GET /test HTTP/1.1\r\n\r\n"}}`, Status: http.StatusOK},
		{Method: http.MethodPut, Path: fmt.Sprintf("/holds/%d", test.heldID), Body: `{"payload": {"type": "hex", "value": "47 45 54 20 2f 74 65 73 74"}}`, Status: http.StatusOK},
		{Method: http.MethodPut, Path: fmt.Sprintf("/holds/%d", test.heldID), Body: `{"payload": {"type": "hex", "value": "4"}}`, Status: http.StatusBadRequest},
		{Method: http.MethodPut, Path: fmt.Sprintf("/holds/%d", test.heldID), Body: `{"payload": {"type": "text", "value": "x"}, "extra": 1}`, Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodPut, Path: "/holds/999", Body: `{"payload": {"type": "text", "value": "x"}}`, Status: http.StatusNotFound},
		{Method: http.MethodPost, Path: "/holds/999/forward", Status: http.StatusNotFound},
		{Method: http.MethodPost, Path: "/holds/999/drop", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/rules", Status: http.StatusOK},
		{Method: http.MethodPost, Path: "/rules", Body: `{"filter": "tcp.dstport == 443", "direction": "up", "layer": "tls", "find": {"type": "regex", "value": "GET /(\\S*) "}, "replace": {"type": "text", "value": "GET /test/$1 "}}`, Status: http.StatusCreated},
		{Method: http.MethodPost, Path: "/rules", Body: `{"find": {"type": "regex", "value": "a*"}, "replace": {"type": "text", "value": "b"}}`, Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/rules", Body: `{"filter": "tcp.port ==", "find": {"type": "text", "value": "a"}, "replace": {"type": "text", "value": "b"}}`, Status: http.StatusBadRequest},
		{Method: http.MethodDelete, Path: fmt.Sprintf("/rules/%d", test.ruleID), Status: http.StatusNoContent},
		{Method: http.MethodDelete, Path: fmt.Sprintf("/rules/%d", test.ruleID), Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/keylog", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/keylog?filter=udp", Status: http.StatusOK},
		{Method: http.MethodPut, Path: "/intercept", Body: `{"enabled": true, "filter": "tls", "direction": "both"}`, Status: http.StatusOK},
		{Method: http.MethodPut, Path: "/intercept", Body: `{"enabled": true, "direction": "sideways"}`, Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodPost, Path: fmt.Sprintf("/holds/%d/forward", test.heldID), Status: http.StatusNoContent},
		{Method: http.MethodPost, Path: fmt.Sprintf("/holds/%d/drop", test.heldID), Status: http.StatusNotFound},
		{Method: http.MethodPost, Path: fmt.Sprintf("/holds/%d/drop", test.dropID), Status: http.StatusNoContent},
		{Method: http.MethodPost, Path: fmt.Sprintf("/holds/%d/forward", test.dropID), Status: http.StatusNotFound},
	}
	succeeded := map[string]bool{}

	for _, positive := range positiveCases {
		operationID, body, caseErr := checkCase(state.Context(), server, router, positive)

		if caseErr != nil {
			state.Errorf("Test of api.Handler failed, %s %s, error: %s, body: %s", positive.Method, positive.Path, caseErr.Error(), body)
			return
		}

		if (positive.Status < 300) && (operationID != "") {
			succeeded[operationID] = true
		}
	}

	// the event stream is checked by its own test
	succeeded["streamEvents"] = true

	for _, operation := range routes() {
		if !succeeded[operation.operationID] {
			state.Errorf("Test of api.Handler failed, operation %s never answered with success", operation.operationID)
			return
		}
	}
}

// Test if api.Handler returns with the expected errors: holding and rules without --intercept, the key log without secrets, unknown paths and methods.
func TestHandlerNegative(state *testing.T) {
	document, err := loadSpec(state.Context())

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot load the spec, error: %s", err.Error())
	}

	info := Info{Mode: "run", Processing: v1.DecryptProcessing, Platform: "linux", Scope: "", Started: time.Now(), HoldTimeout: time.Minute, HasTLSSecrets: false, IsInterceptCapable: false}
	backend := NewBackend(info, history.DefaultLimits(), nil)
	server := httptest.NewServer(Handler(backend, slog.New(slog.DiscardHandler)))
	defer server.Close()
	document.Servers = openapi3.Servers{{URL: server.URL + v1.BasePath}}
	router, err := legacy.NewRouter(document)

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot build the router, error: %s", err.Error())
	}

	negativeCases := []apiCase{
		{Method: http.MethodPut, Path: "/intercept", Body: `{"enabled": true}`, Status: http.StatusConflict},
		{Method: http.MethodPut, Path: "/holds/1", Body: `{"payload": {"type": "text", "value": "x"}}`, Status: http.StatusConflict},
		{Method: http.MethodPost, Path: "/holds/1/forward", Status: http.StatusConflict},
		{Method: http.MethodPost, Path: "/holds/1/drop", Status: http.StatusConflict},
		{Method: http.MethodPost, Path: "/rules", Body: `{"find": {"type": "text", "value": "a"}, "replace": {"type": "text", "value": "b"}}`, Status: http.StatusConflict},
		{Method: http.MethodDelete, Path: "/rules/1", Status: http.StatusConflict},
		{Method: http.MethodGet, Path: "/keylog", Status: http.StatusConflict},
		// empty lists, not errors
		{Method: http.MethodGet, Path: "/holds", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/rules", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/status", Status: http.StatusOK},
	}

	for _, negative := range negativeCases {
		_, body, caseErr := checkCase(state.Context(), server, router, negative)

		if caseErr != nil {
			state.Errorf("Test of api.Handler failed, %s %s, error: %s, body: %s", negative.Method, negative.Path, caseErr.Error(), body)
			return
		}
	}

	// outside the spec: a JSON 405 for a known path, a JSON 404 for anything else
	for path, status := range map[string]int{v1.BasePath + "/status": http.StatusMethodNotAllowed, v1.BasePath + "/nothing": http.StatusNotFound, "/": http.StatusNotFound} {
		answered, _, body, requestErr := send(state.Context(), server, http.MethodDelete, path, "")

		if requestErr != nil {
			state.Fatalf("Test of api.Handler failed, DELETE %s, error: %s", path, requestErr.Error())
		}

		apiError := v1.Error{}

		if (answered != status) || (json.Unmarshal(body, &apiError) != nil) || (apiError.Error == "") {
			state.Errorf("Test of api.Handler failed, DELETE %s should answer %d with a JSON error, status: %d, body: %s", path, status, answered, body)
			return
		}
	}
}

// Test if the event stream of api.Handler sends the events of the backend as server-sent events that follow the Event schema, and ends a client that is too slow with an overflow event.
func TestStreamEventsPositive(state *testing.T) {
	document, err := loadSpec(state.Context())

	if err != nil {
		state.Fatalf("Test of api.streamEvents failed, cannot load the spec, error: %s", err.Error())
	}

	info := Info{Mode: "run", Processing: v1.InterceptProcessing, Platform: "linux", Scope: "", Started: time.Now(), HoldTimeout: time.Minute, HasTLSSecrets: false, IsInterceptCapable: true}
	backend := NewBackend(info, history.DefaultLimits(), nil)
	server := httptest.NewServer(Handler(backend, slog.New(slog.DiscardHandler)))
	defer server.Close()
	request, err := http.NewRequestWithContext(state.Context(), http.MethodGet, server.URL+v1.BasePath+"/events", nil)

	if err != nil {
		state.Fatalf("Test of api.streamEvents failed, cannot make the request, error: %s", err.Error())
	}

	response, err := server.Client().Do(request)

	if err != nil {
		state.Fatalf("Test of api.streamEvents failed, cannot connect, error: %s", err.Error())
	}

	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			state.Errorf("Test of api.streamEvents failed, cannot close the stream, error: %s", closeErr.Error())
		}
	}()

	reader := bufio.NewReader(response.Body)
	// the comment line comes once the stream is subscribed
	comment, err := reader.ReadString('\n')

	if (err != nil) || (comment != ": decerter events\n") || (response.Header.Get("Content-Type") != "text/event-stream") {
		state.Fatalf("Test of api.streamEvents failed, the stream should start with a comment, line: %q, error: %v", comment, err)
	}

	// a flow, a message, a rule and intercept changes
	values := filter.Values{PID: 1, UID: 1001, IPProtocol: syscall.IPPROTO_UDP, Source: netip.MustParseAddrPort("[::ffff:127.0.0.1]:5000"), Destination: netip.MustParseAddrPort("127.0.0.1:53"), TLS: filter.AbsentTLSState}
	flowID := backend.History.OpenFlow(1, values, [32]byte{})
	flow := intercept.FlowOf(flowID, 1, redirectFlow(values), values.Source, values)
	backend.History.Record(intercept.Message{Flow: flow, ID: 100, Direction: tlsrecord.ClientDirection, Layer: intercept.UDPLayer, Plain: []byte("query")}, intercept.Result{Plain: []byte("query"), Verdict: intercept.ForwardVerdict, Changed: false}, intercept.RulesOrigin)
	backend.History.CloseFlow(flowID, history.Counters{Bytes: 5, Datagrams: 1}, history.Counters{Bytes: 0, Datagrams: 0})
	rule, err := intercept.NewMatchRule(intercept.MatchSpec{Find: "a", Replace: "b"})

	if err != nil {
		state.Fatalf("Test of api.streamEvents failed, cannot make a rule, error: %s", err.Error())
	}

	backend.Rules.Add(rule)
	view := ruleView(rule)
	backend.Bus.Publish(v1.Event{Type: v1.RuleAddedEventType, Rule: &view})
	release := holdOne(state.Context(), backend, intercept.New([]intercept.Rule{backend.Holds}, nil, backend.History.Record), flow)
	release()
	expected := []v1.EventType{v1.FlowOpenedEventType, v1.MessageEventType, v1.FlowClosedEventType, v1.RuleAddedEventType, v1.HeldEventType, v1.HoldReleasedEventType, v1.MessageEventType}
	eventSchema := document.Components.Schemas["Event"].Value

	for index, expectedType := range expected {
		event, readErr := readEvent(reader)

		if readErr != nil {
			state.Fatalf("Test of api.streamEvents failed, event %d, error: %s", index, readErr.Error())
		}

		var data any
		decodeErr := json.Unmarshal(event.data, &data)

		if decodeErr == nil {
			decodeErr = eventSchema.VisitJSON(data)
		}

		if (decodeErr != nil) || (event.name != string(expectedType)) || (event.id != fmt.Sprint(index+1)) || bytes.Contains(event.data, []byte(`"payload"`)) {
			state.Errorf("Test of api.streamEvents failed, event %d should be %s with id %d and no payload, event: %s id %s data %s, error: %v", index, expectedType, index+1, event.name, event.id, event.data, decodeErr)
			return
		}
	}

	// a subscriber that does not read is dropped once its buffer is full, and the stream says so
	current := backend.Bus.subscribe()

	for range eventBuffer + 1 {
		backend.Bus.Publish(v1.Event{Type: v1.MessageEventType})
	}

	select {
	case <-current.overflow:
	default:
		state.Errorf("Test of api.Bus.Publish failed, a subscriber %d events behind should be dropped", eventBuffer+1)
		return
	}

	if lost := backend.Bus.lost(current); lost != uint64(len(expected)+eventBuffer+1) {
		state.Errorf("Test of api.Bus.Publish failed, the first lost event should be %d, lost: %d", len(expected)+eventBuffer+1, lost)
		return
	}
}

// Test if api.isPeerAllowed and api.accessPolicyOf let in who they should: root, adb's shell user on Android, the group decerter on Linux, anyone the kernel let through a socket file.
func TestAccessPolicyPositive(state *testing.T) {
	positiveCases := []struct {
		Socket   string
		Platform platform.Type
		GroupID  int64
		UID      uint32
		GID      uint32
		Allowed  bool
	}{
		{Socket: "@decerter-api", Platform: platform.AndroidType, GroupID: -1, UID: 0, GID: 0, Allowed: true},
		{Socket: "@decerter-api", Platform: platform.AndroidType, GroupID: -1, UID: 2000, GID: 2000, Allowed: true},
		{Socket: "@decerter-api", Platform: platform.AndroidType, GroupID: -1, UID: 10092, GID: 10092, Allowed: false},
		{Socket: "@decerter-api", Platform: platform.LinuxType, GroupID: 990, UID: 1000, GID: 990, Allowed: true},
		{Socket: "@decerter-api", Platform: platform.LinuxType, GroupID: 990, UID: 1000, GID: 1000, Allowed: false},
		{Socket: "@decerter-api", Platform: platform.LinuxType, GroupID: -1, UID: 2000, GID: 2000, Allowed: false},
		{Socket: "@decerter-api", Platform: platform.LinuxType, GroupID: -1, UID: 0, GID: 0, Allowed: true},
		// the mode and group of the file decided already
		{Socket: "/run/decerter/api.sock", Platform: platform.LinuxType, GroupID: -1, UID: 1000, GID: 1000, Allowed: true},
	}

	for _, positive := range positiveCases {
		policy := accessPolicyOf(positive.Socket, positive.Platform, positive.GroupID)
		allowed := isPeerAllowed(positive.UID, positive.GID, policy)

		if allowed != positive.Allowed {
			state.Errorf("Test of api.isPeerAllowed function failed, %s on %s with group %d, uid %d gid %d should be allowed %v, allowed: %v", positive.Socket, positive.Platform, positive.GroupID, positive.UID, positive.GID, positive.Allowed, allowed)
			return
		}
	}
}

// Test if api.Listen and api.Server.Close return with the expected output: a socket file with mode 0600 or 0660, a stale socket replaced, the file removed on close.
func TestListenPositive(state *testing.T) {
	directory := state.TempDir()
	socketPath := filepath.Join(directory, "api.sock")
	logger := slog.New(slog.DiscardHandler)
	currentPlatform := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: filepath.Join(directory, "data"), APISocket: socketPath}

	// a socket nobody answers on, as a killed decerter leaves it
	stale, err := Listen(socketPath, currentPlatform, logger)

	if err != nil {
		state.Fatalf("Test of api.Listen failed, cannot listen, error: %s", err.Error())
	}

	unixListener := stale.listener.(peerListener).Listener.(interface{ Close() error })
	err = unixListener.Close()

	if err != nil {
		state.Fatalf("Test of api.Listen failed, cannot close the first listener, error: %s", err.Error())
	}

	server, err := Listen(socketPath, currentPlatform, logger)

	if err != nil {
		state.Fatalf("Test of api.Listen failed, a stale socket should be replaced, error: %s", err.Error())
	}

	info, err := os.Lstat(socketPath)

	// without root the file can't be given the group, a test run as root may find the group decerter
	if (err != nil) || (info.Mode().Type() != os.ModeSocket) || ((info.Mode().Perm() != 0o600) && (info.Mode().Perm() != 0o660)) {
		state.Errorf("Test of api.Listen failed, the socket should have mode 0600 or 0660, info: %v, error: %v", info, err)
		return
	}

	err = server.Close()

	if err != nil {
		state.Errorf("Test of api.Server.Close failed, error: %s", err.Error())
		return
	}

	if _, statErr := os.Lstat(socketPath); !errors.Is(statErr, os.ErrNotExist) {
		state.Errorf("Test of api.Server.Close failed, the socket should be removed, error: %v", statErr)
		return
	}
}

// Test if api.Listen returns with the expected errors: a path that is no socket, a socket another server answers on.
func TestListenNegative(state *testing.T) {
	directory := state.TempDir()
	logger := slog.New(slog.DiscardHandler)
	filePath := filepath.Join(directory, "file")
	err := os.WriteFile(filePath, nil, 0o600)

	if err != nil {
		state.Fatalf("Test of api.Listen failed, cannot write a file, error: %s", err.Error())
	}

	currentPlatform := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: filepath.Join(directory, "data"), APISocket: filePath}
	_, err = Listen(filePath, currentPlatform, logger)

	if !errors.Is(err, ErrNotSocket) {
		state.Errorf("Test of api.Listen function failed, error should be %v, error: %v", ErrNotSocket, err)
		return
	}

	socketPath := filepath.Join(directory, "api.sock")
	live, err := Listen(socketPath, currentPlatform, logger)

	if err != nil {
		state.Fatalf("Test of api.Listen failed, cannot listen, error: %s", err.Error())
	}

	defer func() {
		if closeErr := live.Close(); closeErr != nil {
			state.Errorf("Test of api.Listen failed, cannot close, error: %s", closeErr.Error())
		}
	}()

	// the listener accepts in the kernel's backlog, the probe connects without a server goroutine
	_, err = Listen(socketPath, currentPlatform, logger)

	if !errors.Is(err, ErrSocketInUse) {
		state.Errorf("Test of api.Listen function failed, error should be %v, error: %v", ErrSocketInUse, err)
		return
	}
}

// Test if api.payloadWindow returns with the expected output: windows of a payload and its escaped text.
func TestPayloadWindowPositive(state *testing.T) {
	positiveCases := []struct {
		Data     []byte
		Offset   int
		Length   int
		Expected v1.Payload
	}{
		{Data: []byte("GET /\r\n\x1b\\\xff"), Offset: 0, Length: 100, Expected: v1.Payload{Offset: 0, Length: 10, Total: 10, Hex: "474554202f0d0a1b5cff", Escaped: `GET /\r\n\x1b\\\xff`}},
		{Data: []byte("abcdef"), Offset: 2, Length: 3, Expected: v1.Payload{Offset: 2, Length: 3, Total: 6, Hex: "636465", Escaped: "cde"}},
		{Data: []byte("abc"), Offset: 10, Length: 3, Expected: v1.Payload{Offset: 3, Length: 0, Total: 3, Hex: "", Escaped: ""}},
		{Data: nil, Offset: 0, Length: 4096, Expected: v1.Payload{Offset: 0, Length: 0, Total: 0, Hex: "", Escaped: ""}},
	}

	for _, positive := range positiveCases {
		payload := payloadWindow(positive.Data, positive.Offset, positive.Length)

		if payload != positive.Expected {
			state.Errorf("Test of api.payloadWindow function failed, payload should be %+v, payload: %+v", positive.Expected, payload)
			return
		}
	}
}

func loadSpec(ctx context.Context) (document *openapi3.T, err error) {
	loader := openapi3.NewLoader()
	loader.Context = ctx
	document, err = loader.LoadFromFile(specPath)

	if err != nil {
		return
	}

	err = document.Validate(ctx)
	return
}

// the property names of an object schema sorted, and the required ones; allOf parts are merged
func schemaFields(schema *openapi3.Schema) (properties []string, required []string) {
	for _, part := range schema.AllOf {
		partProperties, partRequired := schemaFields(part.Value)
		properties = append(properties, partProperties...)
		required = append(required, partRequired...)
	}

	for name := range schema.Properties {
		properties = append(properties, name)
	}

	required = append(required, schema.Required...)
	slices.Sort(properties)
	slices.Sort(required)
	return
}

// the JSON names of a struct sorted, and those without omitzero; an embedded struct adds its fields
func jsonFields(structType reflect.Type) (fields []string, required []string) {
	for field := range structType.Fields() {
		if field.Anonymous {
			embeddedFields, embeddedRequired := jsonFields(field.Type)
			fields = append(fields, embeddedFields...)
			required = append(required, embeddedRequired...)
			continue
		}

		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		fields = append(fields, name)

		if options != "omitzero" {
			required = append(required, name)
		}
	}

	slices.Sort(fields)
	slices.Sort(required)
	return
}

// send the request of a case, check the request against the spec unless it is invalid on purpose, and the response always
func checkCase(ctx context.Context, server *httptest.Server, router routers.Router, current apiCase) (operationID string, body []byte, err error) {
	request, err := http.NewRequestWithContext(ctx, current.Method, server.URL+v1.BasePath+current.Path, strings.NewReader(current.Body))

	if err != nil {
		return
	}

	if current.Body != "" {
		request.Header.Set("Content-Type", "application/json")
	}

	route, pathParameters, err := router.FindRoute(request)

	if err != nil {
		return
	}

	operationID = route.Operation.OperationID
	input := &openapi3filter.RequestValidationInput{Request: request, PathParams: pathParameters, Route: route, Options: &openapi3filter.Options{MultiError: false}}
	requestErr := openapi3filter.ValidateRequest(ctx, input)

	if (requestErr == nil) == current.IsInvalid {
		err = fmt.Errorf("the spec should refuse the request %v, error: %w", current.IsInvalid, requestErr)
		return
	}

	status, header, body, err := send(ctx, server, current.Method, v1.BasePath+current.Path, current.Body)

	if err != nil {
		return
	}

	if status != current.Status {
		err = fmt.Errorf("status should be %d, status: %d", current.Status, status)
		return
	}

	err = openapi3filter.ValidateResponse(ctx, &openapi3filter.ResponseValidationInput{
		RequestValidationInput: input,
		Status:                 status,
		Header:                 header,
		Body:                   io.NopCloser(bytes.NewReader(body)),
		Options:                &openapi3filter.Options{IncludeResponseStatus: true},
	})
	return
}

// the status, headers and body of the answer, the body is read and closed
func send(ctx context.Context, server *httptest.Server, method string, path string, requestBody string) (status int, header http.Header, body []byte, err error) {
	request, err := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(requestBody))

	if err != nil {
		return
	}

	response, err := server.Client().Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	status, header = response.StatusCode, response.Header
	body, err = io.ReadAll(response.Body)
	return
}

// one server-sent event
type sentEvent struct {
	id   string
	name string
	data []byte
}

// the next event of the stream, comment lines are skipped
func readEvent(reader *bufio.Reader) (event sentEvent, err error) {
	for {
		line, readErr := reader.ReadString('\n')

		if err = readErr; err != nil {
			return
		}

		line = strings.TrimSuffix(line, "\n")

		switch {
		case line == "":
			if event.name != "" {
				return
			}
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "id: "):
			event.id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			event.name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			event.data = []byte(strings.TrimPrefix(line, "data: "))
		default:
			err = fmt.Errorf("unexpected line %q", line)
			return
		}
	}
}

func newTestBackend(ctx context.Context) (test testBackend, err error) {
	info := Info{Mode: "run", Processing: v1.InterceptProcessing, Platform: "linux", Scope: "proc.uid == 1001", Started: time.Now(), HoldTimeout: time.Minute, HasTLSSecrets: true, IsInterceptCapable: true}
	keyLog := func(clientRandom [32]byte) (keyLog string, found bool, err error) {
		if clientRandom == testRandom {
			keyLog, found = testKeyLog, true
		}

		return
	}
	test.backend = NewBackend(info, history.DefaultLimits(), keyLog)
	backend := test.backend
	values := filter.Values{PID: 42, UID: 1001, GID: 1001, Comm: "curl", Cmdline: "curl https://example.com/", Exe: "/usr/bin/curl", IPProtocol: syscall.IPPROTO_TCP, Source: netip.MustParseAddrPort("[::ffff:127.0.0.1]:40000"), Destination: netip.MustParseAddrPort("93.184.216.34:443"), TLS: filter.UnknownTLSState}
	values = values.WithClientHello(true, tlsrecord.VersionTLS13, "example.com", []string{"h2", "http/1.1"})
	test.tlsFlow = backend.History.OpenFlow(7, values, testRandom)
	flow := intercept.FlowOf(test.tlsFlow, 7, redirectFlow(values), values.Source, values)
	flow.Session = tlsrecord.Session{ClientRandom: testRandom, ServerName: "example.com", OfferedProtocols: []string{"h2", "http/1.1"}, Protocol: "http/1.1", Version: tlsrecord.VersionTLS13, CipherSuite: 0x1301}
	rule, err := intercept.NewMatchRule(intercept.MatchSpec{Filter: `tls.sni == "example.com"`, Directions: intercept.UpDirections, Layer: intercept.TLSLayer, FindType: intercept.TextValueType, Find: "GET / ", ReplaceType: intercept.TextValueType, Replace: "GET /test "})

	if err != nil {
		return
	}

	backend.Rules.Add(rule)
	test.ruleID = rule.ID
	dropRule, err := intercept.NewMatchRule(intercept.MatchSpec{Directions: intercept.DownDirections, FindType: intercept.HexValueType, Find: "00", ReplaceType: intercept.TextValueType, Replace: ""})

	if err != nil {
		return
	}

	test.pipeline = intercept.New([]intercept.Rule{backend.Rules, dropRule, backend.Holds}, nil, backend.History.Record)
	logger := slog.New(slog.DiscardHandler)
	request := test.pipeline.Message(flow, tlsrecord.ClientDirection, intercept.TLSLayer, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	test.request = request.ID
	result := test.pipeline.Process(ctx, request, logger)

	if !bytes.HasPrefix(result.Plain, []byte("GET /test ")) {
		err = fmt.Errorf("the rule did not change the request: %q", result.Plain)
		return
	}

	test.pipeline.Process(ctx, test.pipeline.Message(flow, tlsrecord.ServerDirection, intercept.TLSLayer, []byte("HTTP/1.1 200 OK\r\n\r\n")), logger)
	// a message the history keeps as dropped, as a rule or a drop of a held message leaves it
	dropped := test.pipeline.Message(flow, tlsrecord.ServerDirection, intercept.TLSLayer, []byte("x"))
	test.dropped = dropped.ID
	backend.History.Record(dropped, intercept.Result{Plain: nil, Verdict: intercept.DropVerdict, Changed: true}, intercept.RulesOrigin)
	backend.History.CloseFlow(test.tlsFlow, history.Counters{Bytes: 100, Datagrams: 0}, history.Counters{Bytes: 200, Datagrams: 0})
	// an open udp flow whose TLS state was never read
	udpValues := filter.Values{PID: 43, UID: 1001, GID: 1001, Comm: "dig", IPProtocol: syscall.IPPROTO_UDP, Source: netip.MustParseAddrPort("[::ffff:127.0.0.1]:5353"), Destination: netip.MustParseAddrPort("127.0.0.1:53"), TLS: filter.UnknownTLSState}
	test.udpFlow = backend.History.OpenFlow(8, udpValues, [32]byte{})
	udpFlow := intercept.FlowOf(test.udpFlow, 8, redirectFlow(udpValues), udpValues.Source, udpValues)
	release := holdOne(ctx, backend, test.pipeline, udpFlow)
	releaseSecond := holdOne(ctx, backend, test.pipeline, udpFlow)
	test.stop = func() {
		release()
		releaseSecond()
	}

	held := backend.Holds.List()

	if len(held) != 2 {
		err = fmt.Errorf("two messages should be held, held: %d", len(held))
		return
	}

	test.heldID = held[0].Message.ID
	test.dropID = held[1].Message.ID
	return
}

// hold one message of the flow in the backend's hold queue, pipeline gives its id and ends in the hold queue; release forwards it, if nobody did, and waits until it is through
func holdOne(ctx context.Context, backend *Backend, pipeline *intercept.Pipeline, flow intercept.Flow) (release func()) {
	current := backend.Bus.subscribe()
	defer backend.Bus.unsubscribe(current)
	backend.Holds.Set(true, nil, intercept.UpDirections)
	message := pipeline.Message(flow, tlsrecord.ClientDirection, intercept.UDPLayer, []byte("query"))
	waitGroup := sync.WaitGroup{}

	// the sender of the flow, blocked in the hold queue
	waitGroup.Go(func() {
		pipeline.Process(ctx, message, slog.New(slog.DiscardHandler))
	})

	for event := range current.events {
		if event.Type == v1.HeldEventType {
			break
		}
	}

	release = func() {
		backend.Holds.Set(false, nil, intercept.UpDirections)
		waitGroup.Wait()
	}
	return
}

// the kernel's flow of the values, for intercept.FlowOf
func redirectFlow(values filter.Values) (flow redirect.Flow) {
	flow = redirect.Flow{
		OriginalDestination: values.Destination,
		IPProtocol:          values.IPProtocol,
		Redirected:          true,
		Tgid:                values.PID,
		UID:                 values.UID,
		GID:                 values.GID,
		CgroupID:            0,
		Comm:                values.Comm,
		Mark:                0,
		Client:              values.Source,
	}
	return
}
