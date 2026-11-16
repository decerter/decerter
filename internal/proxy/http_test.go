// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
)

// a history with flow 1, the rules of layer http and the HTTP layer of the flow; rules nil is the HTTP layer without a pipeline
func httpTestLayer(state *testing.T, specs []intercept.MatchSpec, timeout time.Duration) (recorder *history.History, flowHTTP *httpFlow, pipeline *intercept.Pipeline) {
	recorder = history.New(history.DefaultLimits(), nil)
	recorder.OpenFlow(1, filter.Values{}, [32]byte{})
	pipeline = intercept.New(nil, nil, nil)
	layer := HTTPLayer{Pipeline: nil, Timeout: timeout}

	if specs != nil {
		ruleSet := intercept.NewRuleSet()

		for _, spec := range specs {
			rule, err := intercept.NewMatchRule(spec)

			if err != nil {
				state.Fatalf("Could not build rule %+v, error: %s", spec, err.Error())
			}

			ruleSet.Add(rule)
		}

		layer.Pipeline = pipeline.Derive([]intercept.Rule{ruleSet})
	}

	flowHTTP = newHTTPFlow(1, recorder, layer)
	return
}

// Test if the HTTP layer of proxy.interceptTCP returns with the expected output: pipelined keep-alive requests stay in step when rules of layer http change their lengths,
// a word across two chunks is replaced, a body over the limit goes on as it came with a note, and without a rule nothing changes but the exchanges are read.
func TestInterceptHTTPPositive(state *testing.T) {
	chunked := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nwor\r\n2\r\nld\r\n0\r\n\r\n"
	large := strings.Repeat("x", maxHTTPBodyBytes) + "hello"
	positiveCases := []struct {
		Name      string
		Specs     []intercept.MatchSpec
		Request   string
		Response  string
		Upstream  string
		Client    string
		Exchanges int
		Edited    int
		Note      string
	}{
		{
			Name:      "three keep-alive requests and chunked responses",
			Specs:     []intercept.MatchSpec{{Directions: intercept.UpDirections, Layer: intercept.HTTPLayer, Find: "hello", Replace: "hello, world"}, {Directions: intercept.DownDirections, Layer: intercept.HTTPLayer, Find: "world", Replace: "planet"}},
			Request:   "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: h\r\n\r\nPOST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n",
			Response:  chunked + chunked + chunked,
			Upstream:  "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 12\r\n\r\nhello, worldGET /b HTTP/1.1\r\nHost: h\r\n\r\nPOST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nc\r\nhello, world\r\n0\r\n\r\n",
			Client:    strings.Repeat("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nplanet\r\n0\r\n\r\n", 3),
			Exchanges: 3,
			Edited:    5,
			Note:      "",
		},
		{
			Name:      "a body over the limit",
			Specs:     []intercept.MatchSpec{{Directions: intercept.UpDirections, Layer: intercept.HTTPLayer, Find: "hello", Replace: "bye"}},
			Request:   "POST /big HTTP/1.1\r\nContent-Length: " + strconv.Itoa(len(large)) + "\r\n\r\n" + large,
			Response:  "HTTP/1.1 204 No Content\r\n\r\n",
			Upstream:  "POST /big HTTP/1.1\r\nContent-Length: " + strconv.Itoa(len(large)) + "\r\n\r\n" + large,
			Client:    "HTTP/1.1 204 No Content\r\n\r\n",
			Exchanges: 1,
			Edited:    0,
			Note:      "the body is larger than",
		},
		{
			Name:      "a record rule and no rule of layer http",
			Specs:     []intercept.MatchSpec{{Directions: intercept.UpDirections, Find: "hello", Replace: "bye"}},
			Request:   "GET / HTTP/1.1\r\n\r\n",
			Response:  chunked,
			Upstream:  "GET / HTTP/1.1\r\n\r\n",
			Client:    chunked,
			Exchanges: 1,
			Edited:    0,
			Note:      "",
		},
		{
			Name:      "the view only",
			Specs:     nil,
			Request:   "GET / HTTP/1.1\r\n\r\n",
			Response:  "HTTP/1.0 200 OK\r\n\r\nuntil the end",
			Upstream:  "GET / HTTP/1.1\r\n\r\n",
			Client:    "HTTP/1.0 200 OK\r\n\r\nuntil the end",
			Exchanges: 1,
			Edited:    0,
			Note:      "",
		},
	}

	for _, positive := range positiveCases {
		recorder, flowHTTP, pipeline := httpTestLayer(state, positive.Specs, 5*time.Second)
		upstream, client, err := relayWith(state, []byte(positive.Request), []byte(positive.Response), pipeline, flowHTTP)

		if (err != nil) || (string(upstream) != positive.Upstream) || (string(client) != positive.Client) {
			state.Errorf("Test of the http layer of proxy.interceptTCP failed, %s, upstream should get %q and the client %q, they got %q and %q, error: %v", positive.Name, shorten(positive.Upstream), shorten(positive.Client), shorten(string(upstream)), shorten(string(client)), err)
			return
		}

		exchanges, _, _ := recorder.Exchanges(1, 0, 100)
		edited, notes := 0, ""

		for _, exchange := range exchanges {
			for _, message := range []*api.HTTPMessage{exchange.Request, exchange.Response} {
				if (message == nil) || (message.State != api.CompleteHTTPState) {
					state.Errorf("Test of the http layer of proxy.interceptTCP failed, %s, every message should be complete, exchange: %+v", positive.Name, exchange)
					return
				}

				if message.Edited {
					edited++
				}

				notes += message.Note
			}
		}

		if (len(exchanges) != positive.Exchanges) || (edited != positive.Edited) || !strings.Contains(notes, positive.Note) || ((positive.Note == "") && (notes != "")) {
			state.Errorf("Test of the http layer of proxy.interceptTCP failed, %s, the history should have %d exchanges with %d edited messages and the note %q, exchanges: %d, edited: %d, notes: %q", positive.Name, positive.Exchanges, positive.Edited, positive.Note, len(exchanges), edited, notes)
			return
		}
	}

	// what the history kept of the edited chunked response: the body without its chunks, before and after the rule
	recorder, flowHTTP, pipeline := httpTestLayer(state, positiveCases[0].Specs, 5*time.Second)
	_, _, err := relayWith(state, []byte("GET / HTTP/1.1\r\n\r\n"), []byte(chunked), pipeline, flowHTTP)
	body, original, isEdited, _, found := recorder.ExchangeBody(1, api.ResponseSide)

	if (err != nil) || !found || !isEdited || (string(body) != "planet") || (string(original) != "world") {
		state.Errorf("Test of the http layer of proxy.interceptTCP failed, the response body should be planet and world before, body: %q, original: %q, error: %v", body, original, err)
	}
}

// Test if the HTTP layer of proxy.interceptTCP returns with the expected errors: a message that does not come whole before the timeout goes on as it came, the stream is not stalled.
func TestInterceptHTTPNegative(state *testing.T) {
	recorder, flowHTTP, pipeline := httpTestLayer(state, []intercept.MatchSpec{{Directions: intercept.UpDirections, Layer: intercept.HTTPLayer, Find: "abc", Replace: "xyz"}}, 200*time.Millisecond)
	app, proxyClient, err := tcpPair()

	if err != nil {
		state.Fatalf("Could not connect, error: %s", err.Error())
	}

	proxyUpstream, server, err := tcpPair()

	if err != nil {
		state.Fatalf("Could not connect, error: %s", err.Error())
	}

	defer func() {
		if closeErr := errors.Join(app.Close(), proxyClient.Close(), proxyUpstream.Close(), server.Close()); closeErr != nil {
			state.Errorf("Could not close the sockets, error: %s", closeErr.Error())
		}
	}()

	flow := intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	doneChannel := make(chan struct{})

	// the proxy in the middle
	go func() {
		interceptTCP(state.Context(), proxyClient, proxyUpstream, nil, flow, pipeline, nil, flowHTTP, nil, logger)
		close(doneChannel)
	}()

	partial := "POST /slow HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"
	start := time.Now()
	_, err = app.Write([]byte(partial))
	received := make([]byte, len(partial))
	readErr := server.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, fullErr := io.ReadFull(server, received)

	if err = errors.Join(err, readErr, fullErr); (err != nil) || (string(received) != partial) || (time.Since(start) < 200*time.Millisecond) {
		state.Errorf("Test of the http layer of proxy.interceptTCP failed, the partial message should go on as it came after the timeout, received: %q after %s, error: %v", received, time.Since(start), err)
		return
	}

	// the rest of the message follows at once, the rule never sees it
	_, err = app.Write([]byte("defghijGET / HTTP/1.1\r\n\r\n"))
	rest := make([]byte, len("defghijGET / HTTP/1.1\r\n\r\n"))
	_, fullErr = io.ReadFull(server, rest)

	if err = errors.Join(err, fullErr, app.CloseWrite(), server.CloseWrite()); (err != nil) || (string(rest) != "defghijGET / HTTP/1.1\r\n\r\n") {
		state.Errorf("Test of the http layer of proxy.interceptTCP failed, the rest should follow unchanged, received: %q, error: %v", rest, err)
		return
	}

	<-doneChannel
	exchange, found := recorder.Exchange(1)

	if !found || (exchange.Request == nil) || exchange.Request.Edited || !strings.Contains(exchange.Request.Note, "not whole after 200ms") || (exchange.Request.BodyLength != 10) {
		state.Errorf("Test of the http layer of proxy.interceptTCP failed, the slow request should have a note and its whole body, exchange: %+v", exchange)
	}
}

// the start of a long text in an error
func shorten(text string) (short string) {
	short = text[:min(len(text), 300)]
	return
}
