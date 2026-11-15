// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/http2"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// the exchanges of the history of flow 1 by stream
func exchangesByStream(exchanges []api.Exchange) (byStream map[uint32]api.Exchange) {
	byStream = map[uint32]api.Exchange{}

	for _, exchange := range exchanges {
		byStream[exchange.StreamID] = exchange
	}

	return
}

// Test if the HTTP/2 layer of the proxy returns with the expected output for kept messages: a dropped request never reaches the server, a CONNECT and a request without
// :authority get their target and URL, a kept gRPC request the client resets and a body over the limit go on as they came with a note, a whole one goes through the rules,
// and a response on a stream no request opened is not shown.
func TestHTTP2FlowPositive(state *testing.T) {
	recorder, flowHTTP := httpRulesLayer([]intercept.Rule{dropRule{word: []byte(":path: /drop")}, replaceRule{old: []byte("/kept"), new: []byte("/kept")}})
	flow := intercept.Flow{ID: 1, Destination: netip.MustParseAddrPort("[::ffff:127.0.0.1]:8443"), Session: tlsrecord.Session{Version: tlsrecord.VersionTLS13, Protocol: "h2"}}
	client, server := newHTTP2Writer(), newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.err = errors.Join(client.err, client.framer.WriteSettings())
	server.err = errors.Join(server.err, server.framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 22}), server.framer.WriteWindowUpdate(0, 1<<22), server.framer.WriteSettingsAck())
	pieces := []http2Piece{{Direction: tlsrecord.ClientDirection, Data: client.take(), IsClose: false}, {Direction: tlsrecord.ServerDirection, Data: server.take(), IsClose: false}}
	client.err = errors.Join(client.err, client.framer.WriteSettingsAck())
	client.headers(1, true, ":method", "GET", ":scheme", "https", ":authority", "h2.test", ":path", "/drop")
	client.headers(3, true, ":method", "CONNECT", ":authority", "proxy.test:443")
	client.headers(5, true, ":method", "GET", ":path", "/h", "host", "hosted.test")
	client.headers(7, false, ":method", "POST", ":scheme", "https", ":authority", "h2.test", ":path", "/kept/reset", "content-type", "application/grpc")
	client.err = errors.Join(client.err, client.framer.WriteData(7, false, []byte("\x00\x00\x00\x00\x02hi")), client.framer.WriteRSTStream(7, http2.ErrCodeCancel))
	client.headers(9, false, ":method", "POST", ":scheme", "https", ":authority", "h2.test", ":path", "/kept/whole", "content-type", "application/grpc")
	client.err = errors.Join(client.err, client.framer.WriteData(9, true, []byte("\x00\x00\x00\x00\x03abc")))
	client.headers(11, false, ":method", "POST", ":scheme", "https", ":authority", "h2.test", ":path", "/kept/big")

	for range (maxHTTPBodyBytes / 16384) + 1 {
		client.err = errors.Join(client.err, client.framer.WriteData(11, false, bytes.Repeat([]byte("b"), 16384)))
	}

	client.err = errors.Join(client.err, client.framer.WriteData(11, true, []byte("end")))
	pieces = append(pieces, http2Piece{Direction: tlsrecord.ClientDirection, Data: client.take(), IsClose: false})
	server.headers(3, true, ":status", "200")
	server.headers(5, true, ":status", "204")
	server.headers(9, true, ":status", "200")
	server.headers(11, true, ":status", "200")
	// a response on a stream of the server that no PUSH_PROMISE opened
	server.headers(4, false, ":status", "200")
	server.err = errors.Join(server.err, server.framer.WriteData(4, true, []byte("orphan")))
	pieces = append(pieces, http2Piece{Direction: tlsrecord.ServerDirection, Data: server.take(), IsClose: false}, http2Piece{Direction: tlsrecord.ClientDirection, Data: nil, IsClose: true}, http2Piece{Direction: tlsrecord.ServerDirection, Data: nil, IsClose: true})
	outputs, _ := relayHTTP2(flowHTTP, flow, pieces)
	requests, bodies, err := readHTTP2(outputs[tlsrecord.ClientDirection])
	exchanges, _, _ := recorder.Exchanges(1, 0, 100)
	byStream := exchangesByStream(exchanges)

	if err = errors.Join(err, client.err, server.err); (err != nil) || (len(requests[1]) != 0) || (len(requests[3]) == 0) || (string(bodies[9]) != "\x00\x00\x00\x00\x03abc") || (len(bodies[11]) != (maxHTTPBodyBytes/16384+1)*16384+3) {
		state.Errorf("Test of the http/2 layer failed, the dropped request should not go on and the others should, requests: %v, bodies: %q %d, error: %v", requests, bodies[9], len(bodies[11]), err)
		return
	}

	dropped, connect, hosted, reset, whole, big := byStream[1], byStream[3], byStream[5], byStream[7], byStream[9], byStream[11]

	if (dropped.Request == nil) || !dropped.Request.Edited || (connect.Request == nil) || (connect.Request.Target != "proxy.test:443") || (hosted.Request == nil) || (hosted.Request.URL != "https://hosted.test/h") {
		state.Errorf("Test of the http/2 layer failed, the dropped, CONNECT and host requests should be in the history, exchanges: %+v %+v %+v", dropped.Request, connect.Request, hosted.Request)
		return
	}

	if (reset.Request == nil) || !strings.Contains(reset.Request.Note, "the stream ended before the message") || (len(reset.Request.GRPCMessages) != 1) ||
		(whole.Request == nil) || (len(whole.Request.GRPCMessages) != 1) || (big.Request == nil) || !strings.Contains(big.Request.Note, "the body is larger than") || (len(exchanges) != 6) {
		state.Errorf("Test of the http/2 layer failed, the kept requests should have their notes and gRPC messages, exchanges: %+v %+v %+v, count: %d", reset.Request, whole.Request, big.Request, len(exchanges))
		return
	}
}

// Test if the HTTP/2 layer of the proxy returns with the expected errors: streams over the limit are not shown, header fields over 64 KiB are cut with a note,
// and an HPACK error stops the layer and its editor, the frames go on as they came.
func TestHTTP2FlowNegative(state *testing.T) {
	flow := intercept.Flow{ID: 1, Destination: netip.MustParseAddrPort("127.0.0.1:443"), Session: tlsrecord.Session{Version: tlsrecord.VersionTLS13, Protocol: "h2"}}

	// one stream more than the layer reads at once
	recorder, flowHTTP := httpRulesLayer(nil)
	logger, logs := bufferLogger()
	client := newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.err = errors.Join(client.err, client.framer.WriteSettings())

	for stream := range uint32(1001) {
		client.headers(2*stream+1, false, ":method", "GET", ":scheme", "https", ":authority", "many.test", ":path", "/")
	}

	data := client.take()
	output := flowHTTP.feed(state.Context(), flow, tlsrecord.ClientDirection, data, true, logger)
	exchanges, _, _ := recorder.Exchanges(1, 0, 2000)

	if (client.err != nil) || !bytes.Equal(output.output, data) || (len(exchanges) != 1000) || !strings.Contains(logs.String(), "Http/2 streams not shown") {
		state.Errorf("Test of the http/2 layer failed, the stream over the limit should not be shown, exchanges: %d, error: %v, logs: %s", len(exchanges), client.err, shorten(logs.String()))
		return
	}

	// a header block over 64 KiB in a HEADERS frame and its CONTINUATION frames
	recorder, flowHTTP = httpRulesLayer(nil)
	client = newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.err = errors.Join(client.err, client.framer.WriteSettings())
	block := client.encode(":method", "GET", ":scheme", "https", ":authority", "cut.test", ":path", "/", "x-large", strings.Repeat("v", 70<<10))
	client.err = errors.Join(client.err, client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:16384], EndStream: true, EndHeaders: false, PadLength: 0, Priority: http2.PriorityParam{}}))

	for start := 16384; start < len(block); start += 16384 {
		client.err = errors.Join(client.err, client.framer.WriteContinuation(1, start+16384 >= len(block), block[start:min(start+16384, len(block))]))
	}

	data = client.take()
	output = flowHTTP.feed(state.Context(), flow, tlsrecord.ClientDirection, data, true, logger)
	exchanges, _, _ = recorder.Exchanges(1, 0, 10)

	if (client.err != nil) || !bytes.Equal(output.output, data) || (len(exchanges) != 1) || !strings.Contains(exchanges[0].Request.Note, "the header fields are larger than 64 KiB") {
		state.Errorf("Test of the http/2 layer failed, the cut head should have a note, exchanges: %+v, error: %v", exchanges, client.err)
		return
	}

	// an HPACK error while the rules may keep messages
	recorder, flowHTTP = httpRulesLayer([]intercept.Rule{replaceRule{old: []byte("nowhere"), new: []byte("x")}})
	client = newHTTP2Writer()
	client.buffer.WriteString(http2.ClientPreface)
	client.err = errors.Join(client.err, client.framer.WriteSettings())
	client.err = errors.Join(client.err, client.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0xff, 0x7f}, EndStream: true, EndHeaders: true, PadLength: 0, Priority: http2.PriorityParam{}}))
	data = client.take()
	outputs, _ := relayHTTP2(flowHTTP, flow, []http2Piece{{Direction: tlsrecord.ClientDirection, Data: data, IsClose: false}, {Direction: tlsrecord.ClientDirection, Data: []byte("more"), IsClose: false}})
	exchanges, _, _ = recorder.Exchanges(1, 0, 10)

	if (client.err != nil) || !bytes.Equal(outputs[tlsrecord.ClientDirection], append(data, "more"...)) || (len(exchanges) != 0) {
		state.Errorf("Test of the http/2 layer failed, the frames should go on as they came after the hpack error, output: %q, exchanges: %+v, error: %v", shorten(string(outputs[tlsrecord.ClientDirection])), exchanges, client.err)
		return
	}
}

// Test if proxy.versionOf returns with the expected output: a server that says too much before the client is HTTP/1.
func TestVersionOfPositive(state *testing.T) {
	positiveCases := []struct {
		Direction tlsrecord.Direction
		Data      []byte
		Version   httpVersion
	}{
		{Direction: tlsrecord.ServerDirection, Data: []byte("220 hello"), Version: undecidedHTTPVersion},
		{Direction: tlsrecord.ServerDirection, Data: make([]byte, maxUndecidedBytes+1), Version: http1HTTPVersion},
		{Direction: tlsrecord.ClientDirection, Data: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), Version: http2HTTPVersion},
		{Direction: tlsrecord.ClientDirection, Data: []byte("PRI * HT"), Version: undecidedHTTPVersion},
	}

	for _, positive := range positiveCases {
		if version := versionOf(positive.Direction, [2][]byte{}, positive.Data, tlsrecord.Session{}, false); version != positive.Version {
			state.Errorf("Test of proxy.versionOf function failed, data %q, version should be %s, version: %s", shorten(string(positive.Data)), positive.Version, version)
			return
		}
	}
}
