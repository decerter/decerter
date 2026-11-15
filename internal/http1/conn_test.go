// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package http1_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/http1"
)

// one case of streams: the feeds in their order, the sides that end after them and what the events of a side have to say, nil for a side that is not looked at
type streamCase struct {
	Name     string
	Feeds    []feed
	Closed   []http1.Side
	Expected [2][]string
}

// feed the case, whole pieces or every byte on its own, and close the sides named in closed; the events of each side, in order
func runFeeds(feeds []feed, closed []http1.Side, isSplit bool) (conn *http1.Conn, events [2][]http1.Event) {
	conn = http1.New()

	for _, current := range feeds {
		pieces := []string{current.Data}

		if isSplit {
			pieces = strings.Split(current.Data, "")
		}

		for _, piece := range pieces {
			events[current.Side] = append(events[current.Side], copied(conn.Feed(current.Side, []byte(piece)))...)
		}
	}

	for _, side := range closed {
		events[side] = append(events[side], conn.Close(side)...)
	}

	return
}

// whole and byte by byte the events of the sides that are looked at have to be the expected ones and cover every byte of their stream
func checkStreams(state *testing.T, testCase streamCase) (conn *http1.Conn, isGood bool) {
	total := [2]int64{}

	for _, current := range testCase.Feeds {
		total[current.Side] += int64(len(current.Data))
	}

	for _, isSplit := range []bool{false, true} {
		var events [2][]http1.Event
		conn, events = runFeeds(testCase.Feeds, testCase.Closed, isSplit)

		for side, expected := range testCase.Expected {
			if expected == nil {
				continue
			}

			if lines := summary(events[side]); !slices.Equal(lines, expected) {
				state.Errorf("Test of http1.Conn failed, %s, byte by byte: %v, side %d should read\n%s\nread:\n%s", testCase.Name, isSplit, side, strings.Join(expected, "\n"), strings.Join(lines, "\n"))
				return
			}

			if err := checkCoverage(events[side], total[side]); err != nil {
				state.Errorf("Test of http1.Conn failed, %s, byte by byte: %v, side %d should cover every byte, error: %s", testCase.Name, isSplit, side, err.Error())
				return
			}
		}
	}

	isGood = true
	return
}

// Test if http1.Conn returns with the expected output for the edges of the framing: chunk sizes, trailers, lengths and codings that say the same or differ, interim responses, a refused CONNECT, and a switch of protocol while a request is open.
func TestConnFramingPositive(state *testing.T) {
	positiveCases := []streamCase{
		{
			Name:   "chunk sizes with leading zeros in both cases, white space before the extension, bare line feeds",
			Feeds:  []feed{{http1.RequestSide, "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n00A\n0123456789\n000a \t;x=y\r\nabcdefghij\r\n0\n\n"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 POST /c HTTP/1.1 0 "" [{Transfer-Encoding chunked}] chunked 0 interim=false [0,48)`, `body "0123456789abcdefghij"`, `end 0 complete=true trailers=[] "\n" at 90`},
				nil,
			},
		},
		{
			Name:   "empty lines before the messages, a folded and an empty trailer field",
			Feeds:  []feed{{http1.RequestSide, "\r\n\r\nPOST /t HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nA: 1\r\n\t2\r\nB:\r\n\r\n\r\nGET /n HTTP/1.1\r\n\r\n"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 POST /t HTTP/1.1 0 "" [{Transfer-Encoding chunked}] chunked 0 interim=false [0,52)`, `end 0 complete=true trailers=[{A 1 2} {B }] "A: 1\r\n\t2\r\nB:\r\n\r\n" at 71`, "begin 71", `head 1 GET /n HTTP/1.1 0 "" [] none 0 interim=false [71,92)`, `end 1 complete=true trailers=[] "" at 92`},
				nil,
			},
		},
		{
			Name:   "the same length twice and in a list is one length, chunked with a parameter wins over a length",
			Feeds:  []feed{{http1.RequestSide, "POST /a HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2, 2\r\n\r\nabPOST /b HTTP/1.1\r\nContent-Length: 9\r\nTransfer-Encoding: Chunked ; q\r\n\r\n1\r\nz\r\n0\r\n\r\n"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 POST /a HTTP/1.1 0 "" [{Content-Length 2} {Content-Length 2, 2}] length 2 interim=false [0,61)`, `body "ab"`, `end 0 complete=true trailers=[] "" at 63`, "begin 63", `head 1 POST /b HTTP/1.1 0 "" [{Content-Length 9} {Transfer-Encoding Chunked ; q}] chunked 0 interim=false [63,134)`, `body "z"`, `end 1 complete=true trailers=[] "\r\n" at 145`},
				nil,
			},
		},
		{
			Name:   "a response coding that does not end in chunked is read until the stream ends, whatever its length says",
			Feeds:  []feed{{http1.RequestSide, "GET / HTTP/1.1\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nContent-Length: 3\r\n\r\nall of it"}},
			Closed: []http1.Side{http1.ResponseSide},
			Expected: [2][]string{
				nil,
				{"begin 0", `head 0   HTTP/1.1 200 "OK" [{Transfer-Encoding chunked, gzip} {Content-Length 3}] close 0 interim=false [0,72)`, `body "all of it"`, `end 0 complete=true trailers=[] "" at 81`},
			},
		},
		{
			Name:   "two interim responses keep their request, the final one takes it",
			Feeds:  []feed{{http1.RequestSide, "GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 204 No Content\r\n\r\n"}},
			Closed: nil,
			Expected: [2][]string{
				nil,
				{"begin 0", `head 0   HTTP/1.1 103 "Early Hints" [{Link </s.css>}] none 0 interim=true [0,44)`, `end 0 complete=true trailers=[] "" at 44`, "begin 44", `head 0   HTTP/1.1 102 "Processing" [] none 0 interim=true [44,71)`, `end 0 complete=true trailers=[] "" at 71`, "begin 71", `head 0   HTTP/1.1 200 "OK" [{Content-Length 1}] length 1 interim=false [71,109)`, `body "a"`, `end 0 complete=true trailers=[] "" at 110`, "begin 110", `head 1   HTTP/1.1 204 "No Content" [] none 0 interim=false [110,137)`, `end 1 complete=true trailers=[] "" at 137`},
			},
		},
		{
			Name:   "a connect the proxy refuses is a response with a body, the next response follows it",
			Feeds:  []feed{{http1.RequestSide, "CONNECT a:443 HTTP/1.1\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 4\r\n\r\nnopeHTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"}},
			Closed: nil,
			Expected: [2][]string{
				nil,
				{"begin 0", `head 0   HTTP/1.1 407 "Proxy Authentication Required" [{Content-Length 4}] length 4 interim=false [0,65)`, `body "nope"`, `end 0 complete=true trailers=[] "" at 69`, "begin 69", `head 1   HTTP/1.1 400 "Bad Request" [{Content-Length 0}] length 0 interim=false [69,116)`, `end 1 complete=true trailers=[] "" at 116`},
			},
		},
		{
			Name:   "a switch of protocol while the request sends its body stops the request at the start of its message",
			Feeds:  []feed{{http1.RequestSide, "POST /u HTTP/1.1\r\nUpgrade: x\r\nContent-Length: 10\r\n\r\nabc"}, {http1.ResponseSide, "HTTP/1.1 101 Switching Protocols\r\n\r\n"}, {http1.RequestSide, "defg"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 POST /u HTTP/1.1 0 "" [{Upgrade x} {Content-Length 10}] length 10 interim=false [0,52)`, `body "abc"`, "stop protocol switched by 101 switching protocols at 0"},
				{"begin 0", `head 0   HTTP/1.1 101 "Switching Protocols" [] none 0 interim=false [0,36)`, `end 0 complete=true trailers=[] "" at 36`, "stop protocol switched by 101 switching protocols at 36"},
			},
		},
	}

	for _, positive := range positiveCases {
		if _, isGood := checkStreams(state, positive); !isGood {
			return
		}
	}
}

// Test if http1.Conn returns with the expected errors for start lines, fields, lengths, chunk sizes and trailers that are no HTTP/1: the side stops once, at the start of the message, and reads nothing after it.
func TestConnFramingNegative(state *testing.T) {
	chunked := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	negativeCases := []struct {
		Name     string
		Side     http1.Side
		Data     string
		Expected error
		Start    int64
	}{
		{Name: "a request line without a method", Side: http1.RequestSide, Data: " / HTTP/1.1\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a request line without a version", Side: http1.RequestSide, Data: "GET /\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a request line with two targets", Side: http1.RequestSide, Data: "GET /a /b HTTP/1.1\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a request line with two spaces", Side: http1.RequestSide, Data: "GET  HTTP/1.1\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a target with a control character", Side: http1.RequestSide, Data: "GET /a\x01b HTTP/1.1\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a method that is no token", Side: http1.RequestSide, Data: "G(T / HTTP/1.1\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a version in lower case", Side: http1.RequestSide, Data: "GET / http/1.1\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a second request that is none", Side: http1.RequestSide, Data: "GET /a HTTP/1.1\r\n\r\nGET /b\r\n\r\n", Expected: http1.ErrMalformed, Start: 19},
		{Name: "a status below 100", Side: http1.ResponseSide, Data: "HTTP/1.1 099 Low\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a status of four digits", Side: http1.ResponseSide, Data: "HTTP/1.1 2000 OK\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a status line without a status", Side: http1.ResponseSide, Data: "HTTP/1.1\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a reason with a control character", Side: http1.ResponseSide, Data: "HTTP/1.1 200 O\x01K\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a response of http/2", Side: http1.ResponseSide, Data: "HTTP/2.0 200 OK\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a field without a name", Side: http1.RequestSide, Data: "GET / HTTP/1.1\r\n: a\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a field name with a space", Side: http1.RequestSide, Data: "GET / HTTP/1.1\r\nX Y: a\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a length of 19 digits", Side: http1.RequestSide, Data: "POST / HTTP/1.1\r\nContent-Length: 1000000000000000000\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a length with a sign", Side: http1.RequestSide, Data: "POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a list of two lengths", Side: http1.RequestSide, Data: "POST / HTTP/1.1\r\nContent-Length: 5, 6\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a response with two lengths", Side: http1.ResponseSide, Data: "HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 2\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a chunk size over the largest number", Side: http1.ResponseSide, Data: chunked + "ffffffffffffffff\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a chunk size of 17 digits", Side: http1.ResponseSide, Data: chunked + "00000000000000001\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a chunk-size line without a size", Side: http1.ResponseSide, Data: chunked + "\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a chunk-size line of only an extension", Side: http1.ResponseSide, Data: chunked + ";x=y\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a chunk size with a sign", Side: http1.ResponseSide, Data: chunked + "-1\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a chunk size with white space in front", Side: http1.ResponseSide, Data: chunked + " 1\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a chunk-size line over the limit", Side: http1.ResponseSide, Data: chunked + "1;" + strings.Repeat("x", 5000), Expected: http1.ErrMalformed, Start: 0},
		{Name: "chunk data followed by a carriage return alone", Side: http1.ResponseSide, Data: chunked + "2\r\nab\rX", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a second chunk after a first one that is none", Side: http1.RequestSide, Data: "GET / HTTP/1.1\r\n\r\nPOST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nxyz\r\n", Expected: http1.ErrMalformed, Start: 18},
		{Name: "a trailer field without a colon", Side: http1.ResponseSide, Data: chunked + "0\r\nbroken\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a trailer section that starts with a continuation line", Side: http1.ResponseSide, Data: chunked + "0\r\n x\r\n\r\n", Expected: http1.ErrMalformed, Start: 0},
		{Name: "a trailer section over the limit", Side: http1.ResponseSide, Data: chunked + "0\r\nT: " + strings.Repeat("a", 64<<10), Expected: http1.ErrMalformed, Start: 0},
		{Name: "a head over the limit without its end", Side: http1.RequestSide, Data: "GET / HTTP/1.1\r\nX: " + strings.Repeat("a", http1.MaxHeadBytes), Expected: http1.ErrHeadTooLong, Start: 0},
	}

	for _, negative := range negativeCases {
		// whole, and split before the last byte, so an early stop is seen before the line ends
		for _, split := range []int{0, len(negative.Data) - 1} {
			events := run([]feed{{negative.Side, negative.Data}, {negative.Side, "GET / HTTP/1.1\r\n\r\n"}}, []http1.Side{negative.Side}, split)[negative.Side]
			var stops []http1.Event

			for _, event := range events {
				if event.Type == http1.StopEventType {
					stops = append(stops, event)
				}
			}

			// the stop is the last event: nothing is read after it and the end of the stream adds nothing
			if (len(stops) != 1) || !errors.Is(stops[0].Err, negative.Expected) || (stops[0].Start != negative.Start) || (events[len(events)-1].Type != http1.StopEventType) {
				state.Errorf("Test of http1.Conn failed, %s, split %d, the side should stop once with %v at %d, events: %v", negative.Name, split, negative.Expected, negative.Start, summary(events))
				return
			}
		}
	}
}

// Test if http1.Conn.Close returns with the expected output: an open head stops its side, an open body ends incomplete, a side between messages or stopped says nothing; nothing is read after it.
func TestClosePositive(state *testing.T) {
	chunked := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	positiveCases := []streamCase{
		{Name: "nothing sent", Feeds: nil, Closed: []http1.Side{http1.RequestSide, http1.ResponseSide}, Expected: [2][]string{{}, {}}},
		{Name: "part of a start line", Feeds: []feed{{http1.RequestSide, "GET / HT"}}, Closed: []http1.Side{http1.RequestSide}, Expected: [2][]string{{"begin 0", "stop stream ended at 0"}, nil}},
		{Name: "a head without its empty line", Feeds: []feed{{http1.ResponseSide, "HTTP/1.1 200 OK\r\nServer: s\r\n"}}, Closed: []http1.Side{http1.ResponseSide}, Expected: [2][]string{nil, {"begin 0", "stop stream ended at 0"}}},
		{Name: "between two messages", Feeds: []feed{{http1.RequestSide, "GET / HTTP/1.1\r\n\r\n"}}, Closed: []http1.Side{http1.RequestSide}, Expected: [2][]string{{"begin 0", `head 0 GET / HTTP/1.1 0 "" [] none 0 interim=false [0,18)`, `end 0 complete=true trailers=[] "" at 18`}, nil}},
		{Name: "part of a body with a length", Feeds: []feed{{http1.RequestSide, "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab"}}, Closed: []http1.Side{http1.RequestSide}, Expected: [2][]string{{"begin 0", `head 0 POST / HTTP/1.1 0 "" [{Content-Length 5}] length 5 interim=false [0,38)`, `body "ab"`, `end 0 complete=false trailers=[] "" at 40`}, nil}},
		{Name: "part of a chunk-size line", Feeds: []feed{{http1.ResponseSide, chunked + "5"}}, Closed: []http1.Side{http1.ResponseSide}, Expected: [2][]string{nil, {"begin 0", `head 0   HTTP/1.1 200 "OK" [{Transfer-Encoding chunked}] chunked 0 interim=false [0,47)`, `end 0 complete=false trailers=[] "" at 48`}}},
		{Name: "part of the line end of a chunk", Feeds: []feed{{http1.ResponseSide, chunked + "1\r\na\r"}}, Closed: []http1.Side{http1.ResponseSide}, Expected: [2][]string{nil, {"begin 0", `head 0   HTTP/1.1 200 "OK" [{Transfer-Encoding chunked}] chunked 0 interim=false [0,47)`, `body "a"`, `end 0 complete=false trailers=[] "" at 52`}}},
		{Name: "a trailer section without its empty line", Feeds: []feed{{http1.ResponseSide, chunked + "0\r\nT: 1\r\n"}}, Closed: []http1.Side{http1.ResponseSide}, Expected: [2][]string{nil, {"begin 0", `head 0   HTTP/1.1 200 "OK" [{Transfer-Encoding chunked}] chunked 0 interim=false [0,47)`, `end 0 complete=false trailers=[] "" at 56`}}},
		{Name: "a side that stopped", Feeds: []feed{{http1.RequestSide, "GET\r\n"}}, Closed: []http1.Side{http1.RequestSide}, Expected: [2][]string{{"begin 0", `stop malformed http/1 message: request line "GET" at 0`}, nil}},
	}

	for _, positive := range positiveCases {
		conn, isGood := checkStreams(state, positive)

		if !isGood {
			return
		}

		for _, side := range positive.Closed {
			events := append(conn.Feed(side, []byte("GET / HTTP/1.1\r\n\r\nHTTP/1.1 200 OK\r\n\r\n")), conn.Close(side)...)

			if !conn.IsStopped(side) || (len(events) != 0) {
				state.Errorf("Test of http1.Conn.Close function failed, %s, side %d should read nothing after its end, stopped: %v, events: %v", positive.Name, side, conn.IsStopped(side), summary(events))
				return
			}
		}
	}
}

// Test if http1.Conn.SetMethod returns with the expected output: the response of a request is read by the method the request went on with.
func TestSetMethodPositive(state *testing.T) {
	conn := http1.New()
	conn.Feed(http1.RequestSide, []byte("GET /a HTTP/1.1\r\n\r\nHEAD /b HTTP/1.1\r\n\r\nGET /c HTTP/1.1\r\n\r\n"))
	// the first request went on as HEAD, the second as GET; no request has index 7
	conn.SetMethod(0, "HEAD")
	conn.SetMethod(1, "GET")
	conn.SetMethod(7, "HEAD")
	events := copied(conn.Feed(http1.ResponseSide, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nc")))
	expected := []string{
		"begin 0", `head 0   HTTP/1.1 200 "OK" [{Content-Length 5}] none 0 interim=false [0,38)`, `end 0 complete=true trailers=[] "" at 38`,
		"begin 38", `head 1   HTTP/1.1 200 "OK" [{Content-Length 2}] length 2 interim=false [38,76)`, `body "hi"`, `end 1 complete=true trailers=[] "" at 78`,
		"begin 78", `head 2   HTTP/1.1 200 "OK" [{Content-Length 1}] length 1 interim=false [78,116)`, `body "c"`, `end 2 complete=true trailers=[] "" at 117`,
	}

	if lines := summary(events); !slices.Equal(lines, expected) {
		state.Errorf("Test of http1.Conn.SetMethod function failed, the responses should read\n%s\nread:\n%s", strings.Join(expected, "\n"), strings.Join(lines, "\n"))
		return
	}

	// a request that got its response has no method to set any more, the response of the next exchange is read as any other
	conn.SetMethod(2, "HEAD")
	events = copied(conn.Feed(http1.ResponseSide, []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nd")))
	expected = []string{"begin 117", `head 3   HTTP/1.1 200 "OK" [{Content-Length 1}] length 1 interim=false [117,155)`, `body "d"`, `end 3 complete=true trailers=[] "" at 156`}

	if lines := summary(events); !slices.Equal(lines, expected) {
		state.Errorf("Test of http1.Conn.SetMethod function failed, a response without a request should read\n%s\nread:\n%s", strings.Join(expected, "\n"), strings.Join(lines, "\n"))
		return
	}
}

// Test if http1.Conn.IsStopped returns with the expected output.
func TestIsStoppedPositive(state *testing.T) {
	conn := http1.New()
	steps := []struct {
		Name     string
		Do       func()
		Expected [2]bool
	}{
		{Name: "new conn", Do: func() {}, Expected: [2]bool{false, false}},
		{Name: "a request and part of the next", Do: func() { conn.Feed(http1.RequestSide, []byte("GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\nGET")) }, Expected: [2]bool{false, false}},
		{Name: "an interim response", Do: func() { conn.Feed(http1.ResponseSide, []byte("HTTP/1.1 100 Continue\r\n\r\n")) }, Expected: [2]bool{false, false}},
		// the request side only learns of the switch with its next bytes
		{Name: "a switch of protocol", Do: func() { conn.Feed(http1.ResponseSide, []byte("HTTP/1.1 101 Switching Protocols\r\n\r\n")) }, Expected: [2]bool{false, true}},
		{Name: "no bytes of the client", Do: func() { conn.Feed(http1.RequestSide, nil) }, Expected: [2]bool{true, true}},
		{Name: "bytes after the stop", Do: func() { conn.Feed(http1.RequestSide, []byte(" / HTTP/1.1\r\n\r\n")) }, Expected: [2]bool{true, true}},
	}

	for _, current := range steps {
		current.Do()

		if result := [2]bool{conn.IsStopped(http1.RequestSide), conn.IsStopped(http1.ResponseSide)}; result != current.Expected {
			state.Errorf("Test of http1.Conn.IsStopped function failed, step: %s, result should be %v, result: %v", current.Name, current.Expected, result)
			return
		}
	}

	// a stream that is no HTTP/1 stops only its side, the end of the other stops that one
	conn = http1.New()
	conn.Feed(http1.ResponseSide, []byte("220 mail ESMTP\r\n"))

	if conn.IsStopped(http1.RequestSide) || !conn.IsStopped(http1.ResponseSide) {
		state.Errorf("Test of http1.Conn.IsStopped function failed, only the side of the server should be stopped, result: %v %v", conn.IsStopped(http1.RequestSide), conn.IsStopped(http1.ResponseSide))
		return
	}

	if events := conn.Close(http1.RequestSide); (len(events) != 0) || !conn.IsStopped(http1.RequestSide) {
		state.Errorf("Test of http1.Conn.IsStopped function failed, the side of the client should be stopped by its end, events: %v", summary(events))
		return
	}
}
