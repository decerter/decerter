// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// one piece of a test flow of the HTTP layer: what a direction sent under the ALPN protocol of its TLS session, or the end of its stream
type httpPiece struct {
	Direction tlsrecord.Direction
	Data      string
	IsClose   bool
	Protocol  string
}

// flow 1 of a new history with the HTTP layer of rules, nil rules only read
func httpRulesLayer(rules []intercept.Rule) (recorder *history.History, flowHTTP *httpFlow) {
	recorder = history.New(history.DefaultLimits(), nil)
	recorder.OpenFlow(1, filter.Values{}, [32]byte{})
	layer := HTTPLayer{Pipeline: nil, Timeout: 5 * time.Second}

	if rules != nil {
		layer.Pipeline = intercept.New(nil, nil, nil).Derive(rules)
	}

	flowHTTP = newHTTPFlow(1, recorder, layer)
	return
}

// the flow of a piece: a TLS session when it has a protocol
func httpPieceFlow(piece httpPiece) (flow intercept.Flow) {
	flow = intercept.Flow{ID: 1, Destination: netip.MustParseAddrPort("[::ffff:127.0.0.1]:8080")}

	if piece.Protocol != "" {
		flow.Session = tlsrecord.Session{Version: tlsrecord.VersionTLS13, Protocol: piece.Protocol}
	}

	return
}

// the pieces through the HTTP layer as the intercepting senders do, what went on in each direction
func feedHTTPPieces(flowHTTP *httpFlow, pieces []httpPiece) (outputs [2]string) {
	logger := discardLogger()

	for _, piece := range pieces {
		flow := httpPieceFlow(piece)

		if piece.IsClose {
			outputs[piece.Direction] += string(flowHTTP.close(context.Background(), flow, piece.Direction, logger))
			continue
		}

		outputs[piece.Direction] += string(flowHTTP.feed(context.Background(), flow, piece.Direction, []byte(piece.Data), true, logger).output)
	}

	return
}

// Test if the HTTP/1 layer of the proxy returns with the expected output: a flow whose ALPN changes is left alone, a response before any request opens its exchange,
// a stream that ends or stops being HTTP/1 ends its message incomplete, a dropped request leaves the next response to the next request,
// an edit that is no HTTP/1 goes on as written, a changed method is told to the parser, an absolute target is the URL.
func TestHTTPFlowPositive(state *testing.T) {
	positiveCases := []struct {
		Name      string
		Rules     []intercept.Rule
		Pieces    []httpPiece
		Outputs   [2]string
		Exchanges int
		Check     func(exchanges []api.Exchange) bool
	}{
		{
			Name:  "another ALPN",
			Rules: nil,
			Pieces: []httpPiece{
				{Direction: tlsrecord.ClientDirection, Data: "GET /a HTTP/1.1\r\n\r\n", IsClose: false, Protocol: ""},
				{Direction: tlsrecord.ClientDirection, Data: "GET /b HTTP/1.1\r\n\r\n", IsClose: false, Protocol: "imap"},
				{Direction: tlsrecord.ClientDirection, Data: "", IsClose: true, Protocol: "imap"},
			},
			Outputs:   [2]string{"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n", ""},
			Exchanges: 1,
			Check: func(exchanges []api.Exchange) bool {
				return exchanges[0].Request.URL == "http://127.0.0.1:8080/a"
			},
		},
		{
			Name:  "response first",
			Rules: nil,
			Pieces: []httpPiece{
				{Direction: tlsrecord.ServerDirection, Data: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", IsClose: false, Protocol: ""},
				{Direction: tlsrecord.ServerDirection, Data: "", IsClose: true, Protocol: ""},
			},
			Outputs:   [2]string{"", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"},
			Exchanges: 1,
			Check: func(exchanges []api.Exchange) bool {
				return (exchanges[0].Request == nil) && (exchanges[0].Response != nil) && (exchanges[0].Response.Status == 200)
			},
		},
		{
			Name:  "early bytes of the server",
			Rules: nil,
			Pieces: []httpPiece{
				{Direction: tlsrecord.ServerDirection, Data: "HTTP/1.1 100 Continue\r\n\r\n", IsClose: false, Protocol: ""},
				{Direction: tlsrecord.ClientDirection, Data: "GET /early HTTP/1.1\r\nHost: decerter.test\r\n\r\n", IsClose: false, Protocol: ""},
				{Direction: tlsrecord.ServerDirection, Data: "HTTP/1.1 204 No Content\r\n\r\n", IsClose: false, Protocol: ""},
			},
			Outputs:   [2]string{"GET /early HTTP/1.1\r\nHost: decerter.test\r\n\r\n", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"},
			Exchanges: 1,
			Check: func(exchanges []api.Exchange) bool {
				return (exchanges[0].Response != nil) && (exchanges[0].Response.Status == 204) && (exchanges[0].Request.URL == "http://decerter.test/early")
			},
		},
		{
			Name:  "stream ends before the message",
			Rules: nil,
			Pieces: []httpPiece{
				{Direction: tlsrecord.ClientDirection, Data: "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc", IsClose: false, Protocol: ""},
				{Direction: tlsrecord.ClientDirection, Data: "", IsClose: true, Protocol: ""},
			},
			Outputs:   [2]string{"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc", ""},
			Exchanges: 1,
			Check: func(exchanges []api.Exchange) bool {
				return (exchanges[0].Request.State == api.IncompleteHTTPState) && (exchanges[0].Request.Note == "the stream ended before the message")
			},
		},
		{
			Name:  "no HTTP/1 from here",
			Rules: []intercept.Rule{replaceRule{old: []byte("nowhere"), new: []byte("x")}},
			Pieces: []httpPiece{
				{Direction: tlsrecord.ClientDirection, Data: "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", IsClose: false, Protocol: ""},
				{Direction: tlsrecord.ClientDirection, Data: "zz\r\nrest", IsClose: false, Protocol: ""},
			},
			Outputs:   [2]string{"POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nrest", ""},
			Exchanges: 1,
			Check: func(exchanges []api.Exchange) bool {
				return (exchanges[0].Request.State == api.IncompleteHTTPState) && strings.Contains(exchanges[0].Request.Note, "the stream is no HTTP/1 from here")
			},
		},
		{
			Name:  "dropped request",
			Rules: []intercept.Rule{dropRule{word: []byte("DELETE")}},
			Pieces: []httpPiece{
				{Direction: tlsrecord.ClientDirection, Data: "DELETE /a HTTP/1.1\r\nHost: h\r\nUser-Agent: test\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n", IsClose: false, Protocol: ""},
				{Direction: tlsrecord.ServerDirection, Data: "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb", IsClose: false, Protocol: ""},
			},
			Outputs:   [2]string{"GET /b HTTP/1.1\r\nHost: h\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb"},
			Exchanges: 2,
			Check: func(exchanges []api.Exchange) bool {
				return exchanges[0].Request.Edited && (exchanges[0].Response == nil) && (exchanges[1].Response != nil) && (exchanges[1].Request.Target == "/b")
			},
		},
		{
			Name:  "edit that is no HTTP/1",
			Rules: []intercept.Rule{replaceRule{old: []byte("HTTP/1.1\r\n\r\n"), new: []byte("HTTP/1.1\r\n")}},
			Pieces: []httpPiece{
				{Direction: tlsrecord.ClientDirection, Data: "GET /e HTTP/1.1\r\n\r\n", IsClose: false, Protocol: ""},
			},
			Outputs:   [2]string{"GET /e HTTP/1.1\r\n", ""},
			Exchanges: 1,
			Check: func(exchanges []api.Exchange) bool {
				return strings.Contains(exchanges[0].Request.Note, "the edit is no HTTP/1 message")
			},
		},
		{
			Name:  "changed method",
			Rules: []intercept.Rule{replaceRule{old: []byte("GET /m"), new: []byte("PUT /m")}},
			Pieces: []httpPiece{
				{Direction: tlsrecord.ClientDirection, Data: "GET /m HTTP/1.1\r\nHost: h\r\n\r\n", IsClose: false, Protocol: ""},
				{Direction: tlsrecord.ServerDirection, Data: "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n", IsClose: false, Protocol: ""},
			},
			Outputs:   [2]string{"PUT /m HTTP/1.1\r\nHost: h\r\n\r\n", "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"},
			Exchanges: 1,
			Check: func(exchanges []api.Exchange) bool {
				return exchanges[0].Request.Edited && (exchanges[0].Request.Method == "PUT") && (exchanges[0].Response.Status == 201)
			},
		},
		{
			Name:  "absolute target",
			Rules: nil,
			Pieces: []httpPiece{
				{Direction: tlsrecord.ClientDirection, Data: "GET http://decerter.test/x HTTP/1.1\r\n\r\n", IsClose: false, Protocol: ""},
			},
			Outputs:   [2]string{"GET http://decerter.test/x HTTP/1.1\r\n\r\n", ""},
			Exchanges: 1,
			Check: func(exchanges []api.Exchange) bool {
				return exchanges[0].Request.URL == "http://decerter.test/x"
			},
		},
	}

	for _, positive := range positiveCases {
		recorder, flowHTTP := httpRulesLayer(positive.Rules)
		outputs := feedHTTPPieces(flowHTTP, positive.Pieces)
		exchanges, _, _ := recorder.Exchanges(1, 0, 10)

		if (outputs != positive.Outputs) || (len(exchanges) != positive.Exchanges) || !positive.Check(exchanges) {
			state.Errorf("Test of the http layer failed, case %q, outputs should be %q, outputs: %q, exchanges: %+v", positive.Name, positive.Outputs, outputs, exchanges)
			return
		}
	}
}

// Test if the HTTP/1 layer of the proxy returns with the expected output for a kept message whose wait ends: before its deadline nothing goes on,
// a handshake message in between lets it go at once, after that nothing is kept.
func TestHTTPFlowExpirePositive(state *testing.T) {
	// a rule that matches the request keeps it until it is whole
	recorder, flowHTTP := httpRulesLayer([]intercept.Rule{replaceRule{old: []byte("POST"), new: []byte("POST")}})
	flow := httpPieceFlow(httpPiece{Direction: tlsrecord.ClientDirection, Data: "", IsClose: false, Protocol: ""})
	logger := discardLogger()
	partial := "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab"
	kept := flowHTTP.feed(state.Context(), flow, tlsrecord.ClientDirection, []byte(partial), true, logger)
	isKeeping := flowHTTP.isKeeping(tlsrecord.ClientDirection)
	early := flowHTTP.expire(tlsrecord.ClientDirection, logger)
	released := flowHTTP.expireNow(tlsrecord.ClientDirection, "a TLS handshake message came in between", logger)
	again := flowHTTP.expireNow(tlsrecord.ClientDirection, "again", logger)
	idle := flowHTTP.expire(tlsrecord.ClientDirection, logger)

	if (len(kept.output) != 0) || kept.isWhole || !isKeeping || (early != nil) || (string(released) != partial) || (again != nil) || (idle != nil) || flowHTTP.isKeeping(tlsrecord.ClientDirection) {
		state.Errorf("Test of proxy.httpFlow.expireNow function failed, the kept message should go on once, kept: %q, early: %q, released: %q, again: %q", kept.output, early, released, again)
		return
	}

	flowHTTP.feed(state.Context(), flow, tlsrecord.ClientDirection, []byte("cde"), true, logger)
	exchange, found := recorder.Exchange(1)

	if !found || (exchange.Request == nil) || (exchange.Request.Note != "a TLS handshake message came in between") || (exchange.Request.BodyLength != 5) {
		state.Errorf("Test of proxy.httpFlow.expireNow function failed, the request should have the note and its whole body, exchange: %+v", exchange)
		return
	}

	// HTTP/2 keeps its messages, only its ready frames go on
	_, h2Flow := httpRulesLayer(nil)
	h2 := httpPieceFlow(httpPiece{Direction: tlsrecord.ClientDirection, Data: "", IsClose: false, Protocol: "h2"})
	output := h2Flow.feed(state.Context(), h2, tlsrecord.ClientDirection, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), true, logger)

	if !bytes.Equal(output.output, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) || (h2Flow.expireNow(tlsrecord.ClientDirection, "note", logger) != nil) || h2Flow.isKeeping(tlsrecord.ClientDirection) {
		state.Errorf("Test of proxy.httpFlow.expireNow function failed, http/2 should keep nothing, output: %q", output.output)
		return
	}
}

var (
	// a NewSessionTicket of 6 body bytes and a KeyUpdate (update_requested)
	ticketRecord    = tlsrecord.Record{ContentType: tlsrecord.HandshakeContentType, Payload: []byte{newSessionTicketType, 0, 0, 6, 0, 0, 0, 60, 0, 0}}
	keyUpdateRecord = tlsrecord.Record{ContentType: tlsrecord.HandshakeContentType, Payload: []byte{24, 0, 0, 1, 1}}
)

// Test if proxy.isTicketRecord returns with the expected output: only records of whole NewSessionTicket messages are ticket records.
func TestIsTicketRecordPositive(state *testing.T) {
	positiveCases := []struct {
		Record   tlsrecord.Record
		IsTicket bool
	}{
		{Record: ticketRecord, IsTicket: true},
		{Record: tlsrecord.Record{ContentType: tlsrecord.HandshakeContentType, Payload: slices.Concat(ticketRecord.Payload, ticketRecord.Payload)}, IsTicket: true},
		{Record: tlsrecord.Record{ContentType: tlsrecord.HandshakeContentType, Payload: []byte{newSessionTicketType, 0, 0, 0}}, IsTicket: true},
		{Record: keyUpdateRecord, IsTicket: false},
		{Record: tlsrecord.Record{ContentType: tlsrecord.HandshakeContentType, Payload: slices.Concat(ticketRecord.Payload, keyUpdateRecord.Payload)}, IsTicket: false},
		{Record: tlsrecord.Record{ContentType: tlsrecord.HandshakeContentType, Payload: slices.Concat(keyUpdateRecord.Payload, ticketRecord.Payload)}, IsTicket: false},
		{Record: tlsrecord.Record{ContentType: tlsrecord.HandshakeContentType, Payload: []byte{newSessionTicketType, 0, 0, 5, 0}}, IsTicket: false},
		{Record: tlsrecord.Record{ContentType: tlsrecord.HandshakeContentType, Payload: slices.Concat(ticketRecord.Payload, []byte{newSessionTicketType, 0})}, IsTicket: false},
		{Record: tlsrecord.Record{ContentType: tlsrecord.HandshakeContentType, Payload: nil}, IsTicket: false},
		{Record: tlsrecord.Record{ContentType: tlsrecord.ApplicationDataContentType, Payload: ticketRecord.Payload}, IsTicket: false},
	}

	for _, positive := range positiveCases {
		if isTicketRecord(positive.Record) != positive.IsTicket {
			state.Errorf("Test of proxy.isTicketRecord function failed, record %+v, ticket should be %v", positive.Record, positive.IsTicket)
			return
		}
	}
}

// Test if proxy.interception.canSeal returns with the expected output: bytes the HTTP layer kept go on under the keys of an application data or a ticket
// record only, a KeyUpdate coalesced with a ticket changed the keys.
func TestCanSealPositive(state *testing.T) {
	plain := newTestInterception(nil, intercept.New(nil, nil, nil), nil, discardLogger())
	encrypted := newTestInterception(nil, intercept.New(nil, nil, nil), nil, discardLogger())
	encrypted.wasTLS = true
	positiveCases := []struct {
		Name         string
		Interception *interception
		Carrier      *tlsrecord.Record
		CanSeal      bool
	}{
		{Name: "tcp", Interception: plain, Carrier: nil, CanSeal: true},
		{Name: "tls before a record", Interception: encrypted, Carrier: nil, CanSeal: false},
		{Name: "application data", Interception: encrypted, Carrier: &tlsrecord.Record{ContentType: tlsrecord.ApplicationDataContentType, Payload: []byte("data")}, CanSeal: true},
		{Name: "ticket", Interception: encrypted, Carrier: &ticketRecord, CanSeal: true},
		{Name: "key update", Interception: encrypted, Carrier: &keyUpdateRecord, CanSeal: false},
		{Name: "ticket and key update", Interception: encrypted, Carrier: &tlsrecord.Record{ContentType: tlsrecord.HandshakeContentType, Payload: slices.Concat(ticketRecord.Payload, keyUpdateRecord.Payload)}, CanSeal: false},
		{Name: "alert", Interception: encrypted, Carrier: &tlsrecord.Record{ContentType: tlsrecord.AlertContentType, Payload: []byte{1, 0}}, CanSeal: false},
	}

	for _, positive := range positiveCases {
		if canSeal := positive.Interception.canSeal(positive.Carrier); canSeal != positive.CanSeal {
			state.Errorf("Test of proxy.interception.canSeal function failed, case %q, canSeal should be %v, canSeal: %v", positive.Name, positive.CanSeal, canSeal)
			return
		}
	}
}
