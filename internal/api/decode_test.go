// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package api

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/decerter/decerter/api"
)

// the first node of that name, depth first
func nodeNamed(nodes []v1.DecodeNode, name string) (found *v1.DecodeNode) {
	for index := range nodes {
		if nodes[index].Name == name {
			found = &nodes[index]
			return
		}

		if found = nodeNamed(nodes[index].Children, name); found != nil {
			return
		}
	}

	return
}

// Test if the decode operations return with the expected output: the DNS query of a udp flow by its port with offsets of its payload, Decode As raw, a DoH POST
// body and its answer by their content type, the query of a DoH GET from its dns parameter with the bytes in data, and a body no decoder takes as raw.
func TestDecodePositive(state *testing.T) {
	test, err := newTestBackend(state.Context())

	if err != nil {
		state.Fatalf("Test of the decode operations failed, cannot fill the backend, error: %s", err.Error())
	}

	defer test.stop()
	server := httptest.NewServer(Handler(test.backend, slog.New(slog.DiscardHandler)))
	defer server.Close()
	result := v1.Decode{}
	status, err := getJSON(server, fmt.Sprintf("/messages/%d/decode", test.dnsQuery), &result)
	name := nodeNamed(result.Tree, "dns.qry.name")

	if (err != nil) || (status != http.StatusOK) || (result.Protocol != "dns") || (result.MessageID != test.dnsQuery) || (result.Source != v1.PayloadDecodeSource) || (result.Summary != "Standard query 0xbeef A example.com") ||
		(result.Candidates[0].Basis != v1.PortDecodeBasis) || (result.Candidates[0].Reason != "udp port 53 is Domain Name System") || (name == nil) || (name.Value != "example.com") || (name.Offset != 12) || (name.Length != 13) || (result.Total != len(testDNSQuery)) {
		state.Errorf("Test of decodeMessage failed, the query should be dns by its port, status: %d, result: %+v, error: %v", status, result, err)
	}

	result = v1.Decode{}
	status, err = getJSON(server, fmt.Sprintf("/messages/%d/decode?as=raw", test.dnsQuery), &result)

	if (err != nil) || (status != http.StatusOK) || (result.Protocol != "raw") || (len(result.Tree) != 1) || (result.Candidates[0].Basis != v1.OverrideDecodeBasis) {
		state.Errorf("Test of decodeMessage failed, as=raw should give the raw tree, status: %d, result: %+v, error: %v", status, result, err)
	}

	// the request a rule changed: original=true decodes what curl sent, both are raw
	result = v1.Decode{}
	status, err = getJSON(server, fmt.Sprintf("/messages/%d/decode?original=true", test.request), &result)

	if (err != nil) || (status != http.StatusOK) || (result.Protocol != "raw") || (result.Total != len("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")) {
		state.Errorf("Test of decodeMessage failed, original=true should decode the original request, status: %d, result: %+v, error: %v", status, result, err)
	}

	for side, expected := range map[v1.Side]string{v1.RequestSide: "Standard query 0xbeef A example.com", v1.ResponseSide: "Standard query response 0xbeef A example.com A 93.184.216.34"} {
		result = v1.Decode{}
		status, err = getJSON(server, fmt.Sprintf("/exchanges/%d/decode?side=%s", test.dohPost, side), &result)

		if (err != nil) || (status != http.StatusOK) || (result.Protocol != "dns") || (result.Summary != expected) || (result.ExchangeID != test.dohPost) || (result.Side != side) || (result.Source != v1.BodyDecodeSource) ||
			(result.Candidates[0].Reason != "content type application/dns-message is DNS over HTTPS") || (result.Data != nil) {
			state.Errorf("Test of decodeExchangeBody failed, the DoH %s should be dns by its content type, status: %d, result: %+v, error: %v", side, status, result, err)
		}
	}

	result = v1.Decode{}
	status, err = getJSON(server, fmt.Sprintf("/exchanges/%d/decode", test.dohGet), &result)

	if (err != nil) || (status != http.StatusOK) || (result.Protocol != "dns") || (result.Source != v1.TargetDecodeSource) || (result.Data == nil) || (result.Data.Hex != hex.EncodeToString(testDNSQuery)) ||
		(result.Candidates[0].Reason != "the dns parameter of the GET is DNS over HTTPS") || (result.Summary != "Standard query 0xbeef A example.com") {
		state.Errorf("Test of decodeExchangeBody failed, the DoH GET should be decoded from its target, status: %d, result: %+v, error: %v", status, result, err)
	}

	// a GET whose target the as names no protocol of: the empty body, raw
	result = v1.Decode{}
	status, err = getJSON(server, fmt.Sprintf("/exchanges/%d/decode?as=raw", test.dohGet), &result)

	if (err != nil) || (status != http.StatusOK) || (result.Protocol != "raw") || (result.Source != v1.BodyDecodeSource) || (result.Total != 0) {
		state.Errorf("Test of decodeExchangeBody failed, as=raw should take the empty body, status: %d, result: %+v, error: %v", status, result, err)
	}

	result = v1.Decode{}
	status, err = getJSON(server, fmt.Sprintf("/exchanges/%d/decode?side=response", test.exchange), &result)

	if (err != nil) || (status != http.StatusOK) || (result.Protocol != "raw") || (result.Total != len("hello planet")) || (result.Candidates[0].Basis != v1.NoneDecodeBasis) {
		state.Errorf("Test of decodeExchangeBody failed, a text body should be raw, status: %d, result: %+v, error: %v", status, result, err)
	}
}

// Test if the decode operations of stage 49 return with the expected output: a flow's handshake records each way with their bytes in data, a gRPC body by
// its content type with the protobuf fields, and the frames of a flow an HTTP Upgrade switched to WebSocket, masked or not.
func TestDecodeFlowPositive(state *testing.T) {
	test, err := newTestBackend(state.Context())

	if err != nil {
		state.Fatalf("Test of the decode operations failed, cannot fill the backend, error: %s", err.Error())
	}

	defer test.stop()
	server := httptest.NewServer(Handler(test.backend, slog.New(slog.DiscardHandler)))
	defer server.Close()
	flow := v1.Flow{}
	status, err := getJSON(server, fmt.Sprintf("/flows/%d", test.tlsFlow), &flow)

	if (err != nil) || (status != http.StatusOK) || (flow.Up.HandshakeBytes != 5+len(testClientHello)) || (flow.Down.HandshakeBytes != 5+len(testServerHello)+7) {
		state.Errorf("Test of getFlow failed, the flow should count its handshake bytes, status: %d, flow: %+v, error: %v", status, flow, err)
	}

	result := v1.Decode{}
	status, err = getJSON(server, fmt.Sprintf("/flows/%d/decode", test.tlsFlow), &result)
	serverName := nodeNamed(result.Tree, "tls.handshake.extensions_server_name")

	if (err != nil) || (status != http.StatusOK) || (result.Protocol != "tls") || (result.FlowID != test.tlsFlow) || (result.Direction != v1.UpDirection) || (result.Source != v1.HandshakeDecodeSource) ||
		(result.Data == nil) || (result.Data.Total != 5+len(testClientHello)) || (serverName == nil) || (serverName.Value != "example") || (result.Summary != "Client Hello SNI example") ||
		(result.Candidates[0].Reason != "the handshake records decerter kept of the TLS flow") || (nodeNamed(result.Tree, "tls.handshake.ja4") == nil) {
		state.Errorf("Test of decodeFlow failed, the ClientHello should decode as tls with its bytes in data, status: %d, result: %+v, error: %v", status, result, err)
	}

	result = v1.Decode{}
	status, err = getJSON(server, fmt.Sprintf("/flows/%d/decode?direction=down", test.tlsFlow), &result)
	alert := nodeNamed(result.Tree, "tls.alert_message.desc")

	if (err != nil) || (status != http.StatusOK) || (result.Direction != v1.DownDirection) || (len(result.Tree) != 2) || (alert == nil) || (alert.Value != "handshake_failure (40)") ||
		(result.Summary != "Server Hello TLS 1.2 TLS_AES_128_GCM_SHA256, Alert fatal handshake_failure") {
		state.Errorf("Test of decodeFlow failed, the ServerHello and the alert should decode, status: %d, result: %+v, error: %v", status, result, err)
	}

	result = v1.Decode{}
	status, err = getJSON(server, fmt.Sprintf("/exchanges/%d/decode", test.grpcCall), &result)
	text := nodeNamed(result.Tree, "protobuf.field.string")

	if (err != nil) || (status != http.StatusOK) || (result.Protocol != "grpc") || (text == nil) || (text.Value != `"hello"`) || (text.Offset != 7) || (result.Summary != "gRPC request /decerter.Echo/Say, 1 message") {
		state.Errorf("Test of decodeExchangeBody failed, the gRPC body should decode with its protobuf fields, status: %d, result: %+v, error: %v", status, result, err)
	}

	for id, expected := range map[uint64]string{test.wsUp: `WebSocket, 1 frame: Text "hi"`, test.wsDown: `WebSocket, 2 frames: Text "hello", Close 1000 Normal Closure`} {
		result = v1.Decode{}
		status, err = getJSON(server, fmt.Sprintf("/messages/%d/decode", id), &result)

		if (err != nil) || (status != http.StatusOK) || (result.Protocol != "websocket") || (result.Summary != expected) || (result.Candidates[0].Reason != "the flow switched to WebSocket with an HTTP Upgrade") {
			state.Errorf("Test of decodeMessage failed, message %d should decode as WebSocket after the upgrade, status: %d, result: %+v, error: %v", id, status, result, err)
		}
	}
}
