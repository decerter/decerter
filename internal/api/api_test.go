// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/http1"
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
	// a DNS query for example.com A and its answer 93.184.216.34, the name of the answer compressed
	testDNSQuery  = []byte{0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	testDNSAnswer = slices.Concat([]byte{0xbe, 0xef, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, testDNSQuery[12:], []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34})
	// a ClientHello for example.com with one suite and the server_name extension, a ServerHello that selects the suite, a fatal alert
	testClientHello = slices.Concat([]byte{1, 0, 0, 59, 3, 3}, make([]byte, 32), []byte{0, 0, 2, 0x13, 0x01, 1, 0, 0, 16, 0, 0, 0, 12, 0, 10, 0, 0, 7}, []byte("example"))
	testServerHello = slices.Concat([]byte{2, 0, 0, 40, 3, 3}, make([]byte, 32), []byte{0, 0x13, 0x01, 0, 0, 0})
	// a gRPC message whose protobuf has field 1 "hello" and field 2 150
	testGRPCBody = []byte{0, 0, 0, 0, 10, 0x0a, 5, 'h', 'e', 'l', 'l', 'o', 0x10, 0x96, 0x01}
	// a WebSocket text frame "hi" masked with 01 02 03 04, a server text frame "hello" and a close 1000
	testClientFrame  = []byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}
	testServerFrames = []byte{0x81, 5, 'h', 'e', 'l', 'l', 'o', 0x88, 2, 0x03, 0xe8}
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
	exchange uint64
	dnsQuery uint64
	dohPost  uint64
	dohGet   uint64
	grpcCall uint64
	wsFlow   uint64
	wsUp     uint64
	wsDown   uint64
	dnsTCP   uint64
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
		"Header": v1.Header{}, "HTTPHead": v1.HTTPHead{}, "HTTPMessage": v1.HTTPMessage{}, "GRPCMessage": v1.GRPCMessage{}, "Exchange": v1.Exchange{}, "ExchangeList": v1.ExchangeList{}, "ExchangeBody": v1.ExchangeBody{},
		"Decode": v1.Decode{}, "DecodeCandidate": v1.DecodeCandidate{}, "DecodeNode": v1.DecodeNode{},
		"CaptureStatus": v1.CaptureStatus{}, "CaptureLimits": v1.CaptureLimits{}, "CaptureRequest": v1.CaptureRequest{}, "Capture": v1.Capture{}, "CaptureList": v1.CaptureList{},
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
		{Method: http.MethodGet, Path: fmt.Sprintf("/messages/%d/decode", test.dnsQuery), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/messages/%d/decode?as=raw", test.dnsQuery), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/messages/%d/decode?original=true", test.request), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/messages/%d/decode?as=nosuch", test.dnsQuery), Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: fmt.Sprintf("/messages/%d/decode?original=maybe", test.dnsQuery), Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: "/messages/999/decode", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d/decode", test.dohPost), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d/decode", test.grpcCall), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/messages/%d/decode", test.wsUp), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode", test.tlsFlow), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode?part=handshake&direction=down&as=raw", test.tlsFlow), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode?part=stream", test.tlsFlow), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode?part=stream&direction=down&offset=2&length=3&original=true", test.dnsTCP), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode?part=stream", test.udpFlow), Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode?part=stream&offset=-1", test.dnsTCP), Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode?part=stream&original=maybe", test.dnsTCP), Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode?part=other", test.tlsFlow), Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode?direction=sideways", test.tlsFlow), Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode?as=nosuch", test.tlsFlow), Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/decode", test.udpFlow), Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/flows/999/decode", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/flows/x/decode", Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d/decode?side=response&as=dns", test.dohPost), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d/decode", test.dohGet), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d/decode?side=response&original=true", test.exchange), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d/decode?as=nosuch", test.dohPost), Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d/decode?side=trailer", test.dohPost), Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: "/exchanges/999/decode", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/exchanges", test.tlsFlow), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/flows/%d/exchanges?limit=1", test.udpFlow), Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows/999/exchanges", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d", test.exchange), Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/exchanges/999", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d/body?side=response&offset=6", test.exchange), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d/body", test.exchange), Status: http.StatusOK},
		{Method: http.MethodGet, Path: fmt.Sprintf("/exchanges/%d/body?side=trailer", test.exchange), Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: "/flows?filter=http.request.method+%3D%3D+%22GET%22+%26%26+http.response.code+%3D%3D+200", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/messages/1?length=70000", Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: "/holds", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/holds?offset=1&length=2", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/holds?length=70000", Status: http.StatusBadRequest, IsInvalid: true},
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
		{Method: http.MethodPut, Path: "/intercept", Body: `{"enabled": true, "layer": "frames"}`, Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodPost, Path: "/rules", Body: `{"layer": "http", "direction": "down", "filter": "http.host == \"example.com\"", "find": {"type": "text", "value": "world"}, "replace": {"type": "text", "value": "planet"}}`, Status: http.StatusCreated},
		{Method: http.MethodPost, Path: fmt.Sprintf("/holds/%d/forward", test.heldID), Status: http.StatusNoContent},
		{Method: http.MethodPost, Path: fmt.Sprintf("/holds/%d/drop", test.heldID), Status: http.StatusNotFound},
		{Method: http.MethodPost, Path: fmt.Sprintf("/holds/%d/drop", test.dropID), Status: http.StatusNoContent},
		{Method: http.MethodPost, Path: fmt.Sprintf("/holds/%d/forward", test.dropID), Status: http.StatusNotFound},
		// run mode exports its history as synthesized packets; without capture programs, a backend that has no captures, the capture operations answer 409
		{Method: http.MethodGet, Path: "/flows/pcap", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows/pcap?format=plaintext&filter=tls", Status: http.StatusOK},
		{Method: http.MethodGet, Path: "/flows/pcap?format=dsb", Status: http.StatusConflict},
		{Method: http.MethodGet, Path: "/flows/pcap?format=pcap", Status: http.StatusBadRequest, IsInvalid: true},
		{Method: http.MethodGet, Path: "/captures", Status: http.StatusOK},
		{Method: http.MethodPost, Path: "/captures", Body: `{"plaintext": true}`, Status: http.StatusConflict},
		{Method: http.MethodPost, Path: "/captures/1/stop", Status: http.StatusConflict},
		{Method: http.MethodGet, Path: "/captures/1/pcap", Status: http.StatusConflict},
		{Method: http.MethodGet, Path: "/captures/stream", Status: http.StatusConflict},
	}
	succeeded := map[string]bool{}
	// a window of each held payload, "query" from byte 1, and the whole payloads without one
	for path, expected := range map[string]v1.Payload{"/holds?offset=1&length=2": {Offset: 1, Length: 2, Total: 5, Hex: "7565", Escaped: "ue"}, "/holds": {Offset: 0, Length: 5, Total: 5, Hex: "7175657279", Escaped: "query"}} {
		holds := v1.HoldList{}
		_, err = getJSON(server, path, &holds)

		if (err != nil) || (len(holds.Holds) != 2) || (holds.Holds[0].Payload == nil) || (*holds.Holds[0].Payload != expected) || (holds.Holds[1].Payload == nil) || (*holds.Holds[1].Payload != expected) {
			state.Fatalf("Test of api.Handler failed, GET %s should have the payload %+v of each hold, holds: %+v, error: %v", path, expected, holds, err)
		}
	}

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

	// the event stream and the capture operations are checked by their own tests
	for _, operationID := range []string{"streamEvents", "startCapture", "stopCapture", "downloadCapture", "streamCapture"} {
		succeeded[operationID] = true
	}

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

// Test if api.Handler serves the clients that are no browser: curl and decerter mcp on the socket (host decerter or localhost) and on the adb forward (a loopback address with its port), and a JSON body with parameters in its Content-Type.
func TestHandlerClientPositive(state *testing.T) {
	test, err := newTestBackend(state.Context())

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot make the backend, error: %s", err.Error())
	}

	defer test.stop()
	server := httptest.NewServer(Handler(test.backend, slog.New(slog.DiscardHandler)))
	defer server.Close()

	for _, host := range []string{v1.HostName, "DECERTER", "decerter:80", "localhost", "LocalHost:8080", "127.0.0.1", "127.0.0.1:8080", "127.1.2.3:80", "[::1]", "[::1]:8080"} {
		request, requestErr := http.NewRequestWithContext(state.Context(), http.MethodGet, server.URL+v1.BasePath+"/status", http.NoBody)

		if requestErr != nil {
			state.Fatalf("Could not make the request, error: %s", requestErr.Error())
		}

		request.Host = host
		status, body, sendErr := sendRequest(server, request)

		if (sendErr != nil) || (status != http.StatusOK) {
			state.Errorf("Test of api.Handler failed, the host %q should be served, status: %d, body: %s, error: %v", host, status, body, sendErr)
			return
		}
	}

	request, err := http.NewRequestWithContext(state.Context(), http.MethodPut, server.URL+v1.BasePath+"/intercept", strings.NewReader(`{"enabled": false}`))

	if err != nil {
		state.Fatalf("Could not make the request, error: %s", err.Error())
	}

	request.Header.Set("Content-Type", "Application/JSON; charset=utf-8")
	status, body, err := sendRequest(server, request)

	if (err != nil) || (status != http.StatusOK) {
		state.Errorf("Test of api.Handler failed, a JSON body with a charset should be read, status: %d, body: %s, error: %v", status, body, err)
		return
	}
}

// Test if api.Handler refuses a browser with 403 (a request with Origin or Sec-Fetch-Site, a Host that is no loopback name or address, as with DNS rebinding) and a body that is no application/json with 400, as the spec says, and nothing of it changes decerter.
func TestHandlerClientNegative(state *testing.T) {
	document, err := loadSpec(state.Context())

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot load the spec, error: %s", err.Error())
	}

	test, err := newTestBackend(state.Context())

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot make the backend, error: %s", err.Error())
	}

	defer test.stop()
	server := httptest.NewServer(Handler(test.backend, slog.New(slog.DiscardHandler)))
	defer server.Close()
	document.Servers = openapi3.Servers{{URL: server.URL + v1.BasePath}}
	router, err := legacy.NewRouter(document)

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot build the router, error: %s", err.Error())
	}

	off := `{"enabled": false}`
	held := strconv.FormatUint(test.heldID, 10)
	negativeCases := []struct {
		Method  string
		Path    string
		Body    string
		Host    string
		Headers map[string]string
		Status  int
	}{
		// a web page: a simple POST and a fetch carry Origin, a no-cors GET Sec-Fetch-Site
		{Method: http.MethodPut, Path: "/intercept", Body: off, Headers: map[string]string{"Origin": "https://attacker.example", "Content-Type": "application/json"}, Status: http.StatusForbidden},
		{Method: http.MethodPost, Path: "/holds/" + held + "/forward", Headers: map[string]string{"Origin": "null"}, Status: http.StatusForbidden},
		{Method: http.MethodPost, Path: "/captures", Headers: map[string]string{"Origin": "http://127.0.0.1:8080"}, Status: http.StatusForbidden},
		{Method: http.MethodGet, Path: "/keylog", Headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, Status: http.StatusForbidden},
		{Method: http.MethodGet, Path: "/flows", Headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, Status: http.StatusForbidden},
		// DNS rebinding: the page's own name resolves to 127.0.0.1
		{Method: http.MethodGet, Path: "/keylog", Host: "rebind.example:8080", Status: http.StatusForbidden},
		{Method: http.MethodGet, Path: "/flows", Host: "rebind.example", Status: http.StatusForbidden},
		{Method: http.MethodGet, Path: "/status", Host: "localhost.rebind.example", Status: http.StatusForbidden},
		{Method: http.MethodGet, Path: "/status", Host: "127.0.0.1.nip.io", Status: http.StatusForbidden},
		{Method: http.MethodGet, Path: "/status", Host: "192.168.1.2:8080", Status: http.StatusForbidden},
		{Method: http.MethodGet, Path: "/status", Host: "decerter:http", Status: http.StatusForbidden},
		{Method: http.MethodGet, Path: "/status", Host: "[fe80::1%25lo]:8080", Status: http.StatusForbidden},
		{Method: http.MethodGet, Path: "/nothing", Host: "rebind.example", Status: http.StatusForbidden},
		// a body a web page can send without a preflight is no JSON to the api
		{Method: http.MethodPut, Path: "/intercept", Body: off, Headers: map[string]string{"Content-Type": "text/plain"}, Status: http.StatusBadRequest},
		{Method: http.MethodPut, Path: "/intercept", Body: off, Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/rules", Body: `{"find": {"type": "text", "value": "a"}, "replace": {"type": "text", "value": "b"}}`, Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=x"}, Status: http.StatusBadRequest},
		{Method: http.MethodPut, Path: "/holds/" + held, Body: `{"payload": {"type": "text", "value": "x"}}`, Status: http.StatusBadRequest},
	}

	for _, negative := range negativeCases {
		request, requestErr := http.NewRequestWithContext(state.Context(), negative.Method, server.URL+v1.BasePath+negative.Path, strings.NewReader(negative.Body))

		if requestErr != nil {
			state.Fatalf("Could not make the request, error: %s", requestErr.Error())
		}

		if negative.Host != "" {
			request.Host = negative.Host
		}

		for name, value := range negative.Headers {
			request.Header.Set(name, value)
		}

		status, body, sendErr := sendRequest(server, request)

		if sendErr != nil {
			state.Fatalf("Test of api.Handler failed, %s %s, error: %s", negative.Method, negative.Path, sendErr.Error())
		}

		apiError := v1.Error{}

		if (status != negative.Status) || (json.Unmarshal(body, &apiError) != nil) || (apiError.Error == "") {
			state.Errorf("Test of api.Handler failed, %s %s with host %q and headers %v should answer %d with a JSON error, status: %d, body: %s", negative.Method, negative.Path, negative.Host, negative.Headers, negative.Status, status, body)
			return
		}

		// every operation has the answer in the spec
		route, pathParameters, routeErr := router.FindRoute(request)

		if routeErr != nil {
			continue
		}

		input := &openapi3filter.RequestValidationInput{Request: request, PathParams: pathParameters, Route: route, Options: &openapi3filter.Options{MultiError: false}}
		header := http.Header{"Content-Type": []string{jsonMediaType}}
		validateErr := openapi3filter.ValidateResponse(state.Context(), &openapi3filter.ResponseValidationInput{RequestValidationInput: input, Status: status, Header: header, Body: io.NopCloser(bytes.NewReader(body)), Options: &openapi3filter.Options{IncludeResponseStatus: true}})

		if validateErr != nil {
			state.Errorf("Test of api.Handler failed, %s %s answered %d, which the spec should have, error: %s", negative.Method, negative.Path, status, validateErr.Error())
			return
		}
	}

	interceptState := test.backend.Holds.State()

	if !interceptState.IsEnabled || (interceptState.HeldCount != 2) || (len(test.backend.Rules.List()) != 1) {
		state.Errorf("Test of api.Handler failed, a refused request should change nothing, intercept: %+v, rules: %d", interceptState, len(test.backend.Rules.List()))
		return
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
	setSocketGroup(state, "")
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

	// the test has no group decerter, whatever the host has
	if (err != nil) || (info.Mode().Type() != os.ModeSocket) || (info.Mode().Perm() != 0o600) {
		state.Errorf("Test of api.Listen failed, the socket should have mode 0600, info: %v, error: %v", info, err)
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

// Test if api.Listen returns with the expected errors: a path that is no socket, an ip:port, a socket another server answers on.
func TestListenNegative(state *testing.T) {
	setSocketGroup(state, "")
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

	// an ip:port is for the clients, no file of that name is made
	for _, address := range []string{"127.0.0.1:18090", "[::1]:18090", "localhost:8080", ":18090"} {
		_, err = Listen(address, currentPlatform, logger)
		_, statErr := os.Stat(address)

		if !errors.Is(err, ErrTCPSocket) || !errors.Is(statErr, os.ErrNotExist) {
			state.Errorf("Test of api.Listen function failed, address %q, error should be %v, error: %v, file: %v", address, ErrTCPSocket, err, statErr)
			return
		}
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
		{Data: []byte("a\tb"), Offset: 0, Length: 3, Expected: v1.Payload{Offset: 0, Length: 3, Total: 3, Hex: "610962", Escaped: `a\tb`}},
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

// an edit request with payload bytes in hex
func hexEdit(length int) (body string) {
	encoded, _ := json.Marshal(v1.EditRequest{Payload: v1.Value{Type: v1.HexValueType, Value: strings.Repeat("ab", length)}})
	body = string(encoded)
	return
}

// Test if a request body takes the edit of the largest HTTP message a hold can have: the largest body and head, in hex.
func TestReadJSONSizePositive(state *testing.T) {
	request := httptest.NewRequest(http.MethodPut, v1.BasePath+"/holds/1", strings.NewReader(hexEdit(intercept.MaxHTTPBodyBytes+2*http1.MaxHeadBytes)))
	request.Header.Set("Content-Type", jsonMediaType)
	edit := v1.EditRequest{}
	err := readJSON(httptest.NewRecorder(), request, &edit)

	if (err != nil) || (len(edit.Payload.Value) != 2*(intercept.MaxHTTPBodyBytes+2*http1.MaxHeadBytes)) {
		state.Errorf("Test of api.readJSON failed, the edit of the largest HTTP message should be read, length: %d, error: %v", len(edit.Payload.Value), err)
	}
}

// Test if a request body larger than the limit is refused.
func TestReadJSONSizeNegative(state *testing.T) {
	request := httptest.NewRequest(http.MethodPut, v1.BasePath+"/holds/1", strings.NewReader(hexEdit(int(maxRequestBytes))))
	request.Header.Set("Content-Type", jsonMediaType)
	edit := v1.EditRequest{}
	err := readJSON(httptest.NewRecorder(), request, &edit)

	if _, isTooLarge := errors.AsType[*http.MaxBytesError](err); !isTooLarge || !errors.Is(err, ErrBadRequest) {
		state.Errorf("Test of api.readJSON failed, a body over %d bytes should be refused, error: %v", maxRequestBytes, err)
	}
}

// the status, headers and body of the answer, the body is read and closed
func send(ctx context.Context, server *httptest.Server, method string, path string, requestBody string) (status int, header http.Header, body []byte, err error) {
	request, err := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(requestBody))

	if err != nil {
		return
	}

	if requestBody != "" {
		request.Header.Set("Content-Type", jsonMediaType)
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

// the status and body of the answer to request, the body is read and closed
func sendRequest(server *httptest.Server, request *http.Request) (status int, body []byte, err error) {
	response, err := server.Client().Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	status = response.StatusCode
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
	// an exchange of the TLS flow whose chunked response a rule of layer http edited
	head := v1.HTTPMessage{HTTPHead: v1.HTTPHead{Method: "GET", Target: "/", Version: "HTTP/1.1", Headers: []v1.Header{{Name: "Host", Value: "example.com"}, {Name: "User-Agent", Value: "curl/8"}}}, URL: "https://example.com/", Time: time.Now(), Framing: v1.NoneFraming, State: v1.HeadHTTPState}
	test.exchange = backend.History.OpenExchange(test.tlsFlow, "HTTP/1.1", v1.RequestSide, head)
	backend.History.EndMessage(test.exchange, v1.RequestSide, history.HTTPEnd{State: v1.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	response := v1.HTTPMessage{HTTPHead: v1.HTTPHead{Version: "HTTP/1.1", Status: 200, Reason: "OK", Headers: []v1.Header{{Name: "Transfer-Encoding", Value: "chunked"}}}, Time: time.Now(), Framing: v1.ChunkedFraming, State: v1.HeadHTTPState}
	backend.History.AddHead(test.exchange, v1.ResponseSide, response, false)
	backend.History.AppendBody(test.exchange, v1.ResponseSide, []byte("hello world"))
	edit := history.HTTPEdit{Head: response.HTTPHead, URL: "", Body: []byte("hello planet"), Verdict: v1.ForwardVerdict}
	backend.History.EndMessage(test.exchange, v1.ResponseSide, history.HTTPEnd{State: v1.CompleteHTTPState, Trailers: []v1.Header{{Name: "X-Sum", Value: "1"}}, Note: "", Edit: &edit})
	// an HTTP/2 server push on the same flow whose response is a gRPC message cut short
	pushed := backend.History.OpenStream(test.tlsFlow, "HTTP/2", history.Stream{ID: 2, PromisedBy: 1}, v1.RequestSide, v1.HTTPMessage{HTTPHead: v1.HTTPHead{Method: "POST", Target: "/a.B/C", Version: "HTTP/2", Headers: []v1.Header{{Name: ":method", Value: "POST"}, {Name: ":path", Value: "/a.B/C"}}}, URL: "https://example.com/a.B/C", Time: time.Now(), Framing: v1.NoneFraming, State: v1.HeadHTTPState})
	backend.History.EndMessage(pushed, v1.RequestSide, history.HTTPEnd{State: v1.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	backend.History.AddHead(pushed, v1.ResponseSide, v1.HTTPMessage{HTTPHead: v1.HTTPHead{Version: "HTTP/2", Status: 200, Headers: []v1.Header{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "application/grpc"}}}, Time: time.Now(), Framing: v1.FramesFraming, State: v1.HeadHTTPState}, false)
	backend.History.AppendBody(pushed, v1.ResponseSide, []byte{1, 0, 0, 0, 9, 'h', 'i'})
	backend.History.AppendGRPC(pushed, v1.ResponseSide, []v1.GRPCMessage{{Offset: 0, Length: 9, Compressed: true}})
	backend.History.EndMessage(pushed, v1.ResponseSide, history.HTTPEnd{State: v1.IncompleteHTTPState, Trailers: nil, Note: "the server reset the stream: CANCEL; the last gRPC message is cut short", Edit: nil})
	// DoH on the same flow: a POST with the query as its body and the answer, a GET with the query in its dns parameter
	dohRequest := v1.HTTPMessage{HTTPHead: v1.HTTPHead{Method: "POST", Target: "/dns-query", Version: "HTTP/2", Headers: []v1.Header{{Name: ":method", Value: "POST"}, {Name: "content-type", Value: "application/dns-message"}}}, URL: "https://example.com/dns-query", Time: time.Now(), Framing: v1.FramesFraming, State: v1.HeadHTTPState}
	test.dohPost = backend.History.OpenStream(test.tlsFlow, "HTTP/2", history.Stream{ID: 3, PromisedBy: 0}, v1.RequestSide, dohRequest)
	backend.History.AppendBody(test.dohPost, v1.RequestSide, testDNSQuery)
	backend.History.EndMessage(test.dohPost, v1.RequestSide, history.HTTPEnd{State: v1.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	backend.History.AddHead(test.dohPost, v1.ResponseSide, v1.HTTPMessage{HTTPHead: v1.HTTPHead{Version: "HTTP/2", Status: 200, Headers: []v1.Header{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "application/dns-message"}}}, Time: time.Now(), Framing: v1.FramesFraming, State: v1.HeadHTTPState}, false)
	backend.History.AppendBody(test.dohPost, v1.ResponseSide, testDNSAnswer)
	backend.History.EndMessage(test.dohPost, v1.ResponseSide, history.HTTPEnd{State: v1.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	dohRequest.Method, dohRequest.Target, dohRequest.Headers = "GET", "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(testDNSQuery), []v1.Header{{Name: ":method", Value: "GET"}}
	test.dohGet = backend.History.OpenStream(test.tlsFlow, "HTTP/2", history.Stream{ID: 5, PromisedBy: 0}, v1.RequestSide, dohRequest)
	backend.History.EndMessage(test.dohGet, v1.RequestSide, history.HTTPEnd{State: v1.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	// a gRPC call on the same flow
	grpcRequest := v1.HTTPMessage{HTTPHead: v1.HTTPHead{Method: "POST", Target: "/decerter.Echo/Say", Version: "HTTP/2", Headers: []v1.Header{{Name: ":method", Value: "POST"}, {Name: "content-type", Value: "application/grpc"}}}, URL: "https://example.com/decerter.Echo/Say", Time: time.Now(), Framing: v1.FramesFraming, State: v1.HeadHTTPState}
	test.grpcCall = backend.History.OpenStream(test.tlsFlow, "HTTP/2", history.Stream{ID: 7, PromisedBy: 0}, v1.RequestSide, grpcRequest)
	backend.History.AppendBody(test.grpcCall, v1.RequestSide, testGRPCBody)
	backend.History.EndMessage(test.grpcCall, v1.RequestSide, history.HTTPEnd{State: v1.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	// the handshake records of the flow as the record layer gave them
	backend.History.KeepHandshake(test.tlsFlow, tlsrecord.Record{Direction: tlsrecord.ClientDirection, ContentType: tlsrecord.HandshakeContentType, Version: 0x0301, Payload: testClientHello}, false)
	backend.History.KeepHandshake(test.tlsFlow, tlsrecord.Record{Direction: tlsrecord.ServerDirection, ContentType: tlsrecord.HandshakeContentType, Version: 0x0303, Payload: testServerHello}, false)
	backend.History.KeepHandshake(test.tlsFlow, tlsrecord.Record{Direction: tlsrecord.ServerDirection, ContentType: tlsrecord.AlertContentType, Version: 0x0303, Decrypted: true, Payload: []byte{2, 40}}, false)
	backend.History.CloseFlow(test.tlsFlow, history.Counters{Bytes: 100, Datagrams: 0}, history.Counters{Bytes: 200, Datagrams: 0})
	// a plain tcp flow that switches to WebSocket: the upgrade exchange, then a frame each way
	wsValues := filter.Values{PID: 44, UID: 1001, GID: 1001, Comm: "curl", IPProtocol: syscall.IPPROTO_TCP, Source: netip.MustParseAddrPort("[::ffff:127.0.0.1]:40001"), Destination: netip.MustParseAddrPort("127.0.0.1:8080"), TLS: filter.AbsentTLSState}
	test.wsFlow = backend.History.OpenFlow(9, wsValues, [32]byte{})
	wsFlow := intercept.FlowOf(test.wsFlow, 9, redirectFlow(wsValues), wsValues.Source, wsValues)
	upgrade := backend.History.OpenExchange(test.wsFlow, "HTTP/1.1", v1.RequestSide, v1.HTTPMessage{HTTPHead: v1.HTTPHead{Method: "GET", Target: "/chat", Version: "HTTP/1.1", Headers: []v1.Header{{Name: "Upgrade", Value: "websocket"}}}, URL: "http://127.0.0.1:8080/chat", Time: time.Now(), Framing: v1.NoneFraming, State: v1.HeadHTTPState})
	backend.History.EndMessage(upgrade, v1.RequestSide, history.HTTPEnd{State: v1.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	backend.History.AddHead(upgrade, v1.ResponseSide, v1.HTTPMessage{HTTPHead: v1.HTTPHead{Version: "HTTP/1.1", Status: 101, Reason: "Switching Protocols", Headers: []v1.Header{{Name: "Upgrade", Value: "websocket"}, {Name: "Connection", Value: "Upgrade"}}}, Time: time.Now(), Framing: v1.NoneFraming, State: v1.HeadHTTPState}, false)
	backend.History.EndMessage(upgrade, v1.ResponseSide, history.HTTPEnd{State: v1.CompleteHTTPState, Trailers: nil, Note: "", Edit: nil})
	wsUp := test.pipeline.Message(wsFlow, tlsrecord.ClientDirection, intercept.TCPLayer, testClientFrame)
	test.wsUp = wsUp.ID
	backend.History.Record(wsUp, intercept.Result{Plain: testClientFrame, Verdict: intercept.ForwardVerdict, Changed: false}, intercept.RulesOrigin)
	wsDown := test.pipeline.Message(wsFlow, tlsrecord.ServerDirection, intercept.TCPLayer, testServerFrames)
	test.wsDown = wsDown.ID
	backend.History.Record(wsDown, intercept.Result{Plain: testServerFrames, Verdict: intercept.ForwardVerdict, Changed: false}, intercept.RulesOrigin)
	// DNS over tcp: the query in two reads, the answer in three
	dnsValues := filter.Values{PID: 45, UID: 1001, GID: 1001, Comm: "dig", IPProtocol: syscall.IPPROTO_TCP, Source: netip.MustParseAddrPort("[::ffff:127.0.0.1]:40002"), Destination: netip.MustParseAddrPort("127.0.0.1:53"), TLS: filter.AbsentTLSState}
	test.dnsTCP = backend.History.OpenFlow(10, dnsValues, [32]byte{})
	dnsFlow := intercept.FlowOf(test.dnsTCP, 10, redirectFlow(dnsValues), dnsValues.Source, dnsValues)
	tcpQuery := binary.BigEndian.AppendUint16(nil, uint16(len(testDNSQuery)))
	tcpQuery = append(tcpQuery, testDNSQuery...)
	tcpAnswer := binary.BigEndian.AppendUint16(nil, uint16(len(testDNSAnswer)))
	tcpAnswer = append(tcpAnswer, testDNSAnswer...)

	for direction, pieces := range map[tlsrecord.Direction][][]byte{tlsrecord.ClientDirection: {tcpQuery[:1], tcpQuery[1:]}, tlsrecord.ServerDirection: {tcpAnswer[:5], tcpAnswer[5:20], tcpAnswer[20:]}} {
		for _, piece := range pieces {
			message := test.pipeline.Message(dnsFlow, direction, intercept.TCPLayer, piece)
			backend.History.Record(message, intercept.Result{Plain: piece, Verdict: intercept.ForwardVerdict, Changed: false}, intercept.RulesOrigin)
		}
	}

	// an open udp flow whose TLS state was never read
	udpValues := filter.Values{PID: 43, UID: 1001, GID: 1001, Comm: "dig", IPProtocol: syscall.IPPROTO_UDP, Source: netip.MustParseAddrPort("[::ffff:127.0.0.1]:5353"), Destination: netip.MustParseAddrPort("127.0.0.1:53"), TLS: filter.UnknownTLSState}
	test.udpFlow = backend.History.OpenFlow(8, udpValues, [32]byte{})
	udpFlow := intercept.FlowOf(test.udpFlow, 8, redirectFlow(udpValues), udpValues.Source, udpValues)
	// a DNS query to port 53, before the holds
	query := test.pipeline.Message(udpFlow, tlsrecord.ClientDirection, intercept.UDPLayer, testDNSQuery)
	test.dnsQuery = query.ID
	test.pipeline.Process(ctx, query, logger)
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
	backend.Holds.Set(true, nil, intercept.UpDirections, "")
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
		backend.Holds.Set(false, nil, intercept.UpDirections, "")
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
