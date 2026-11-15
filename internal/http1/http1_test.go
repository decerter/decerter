// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package http1_test

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/http1"
)

// one side's bytes and where they are fed in a case: side then data, in this order
type feed struct {
	Side http1.Side
	Data string
}

// what the events of a side said, with the body of each message merged, so a stream split anywhere reads the same
func summary(events []http1.Event) (lines []string) {
	body := []byte(nil)
	isBody := false

	flush := func() {
		if isBody {
			lines = append(lines, fmt.Sprintf("body %q", body))
			body = nil
			isBody = false
		}
	}

	for _, event := range events {
		switch event.Type {
		case http1.BodyEventType:
			body = append(body, event.Data...)
			isBody = isBody || (len(event.Data) > 0)
			continue
		case http1.BeginEventType:
			flush()
			lines = append(lines, fmt.Sprintf("begin %d", event.Start))
		case http1.HeadEventType:
			flush()
			head := event.Head
			lines = append(lines, fmt.Sprintf("head %d %s %s %s %d %q %v %s %d interim=%t [%d,%d)", event.Index, head.Method, head.Target, head.Version, head.Status, head.Reason, head.Headers, event.Framing, event.Length, event.IsInterim, event.Start, event.End))
		case http1.EndEventType:
			flush()
			lines = append(lines, fmt.Sprintf("end %d complete=%t trailers=%v %q at %d", event.Index, event.IsComplete, event.Trailers, event.TrailerRaw, event.End))
		case http1.StopEventType:
			flush()
			lines = append(lines, fmt.Sprintf("stop %v at %d", event.Err, event.Start))
		}
	}

	flush()
	return
}

// feed the case and close the sides that are named in closed; the events of each side, in order
func run(feeds []feed, closed []http1.Side, split int) (events [2][]http1.Event) {
	conn := http1.New()

	for index, current := range feeds {
		data := []byte(current.Data)

		// one of the feeds is cut in two at split, the bytes are copied so no event may keep them
		if (index == 0) && (split > 0) && (split < len(data)) {
			first := bytes.Clone(data[:split])
			events[current.Side] = append(events[current.Side], copied(conn.Feed(current.Side, first))...)
			clear(first)
			data = data[split:]
		}

		events[current.Side] = append(events[current.Side], copied(conn.Feed(current.Side, bytes.Clone(data)))...)
	}

	for _, side := range closed {
		events[side] = append(events[side], conn.Close(side)...)
	}

	return
}

// the body data of events points into the fed bytes, a test keeps a copy
func copied(events []http1.Event) (result []http1.Event) {
	for _, event := range events {
		event.Data = bytes.Clone(event.Data)
		result = append(result, event)
	}

	return
}

// every byte of the stream is in a begin..end range, between messages or after a stop no byte is left over
func checkCoverage(events []http1.Event, total int64) (err error) {
	position := int64(0)

	for _, event := range events {
		switch event.Type {
		case http1.StopEventType:
			return
		case http1.BeginEventType:
			if event.Start != position {
				err = fmt.Errorf("begin at %d, the stream is at %d", event.Start, position)
				return
			}
		case
			http1.HeadEventType,
			http1.BodyEventType:
			position = event.End
		case http1.EndEventType:
			position = max(position, event.End)
		}
	}

	if position != total {
		err = fmt.Errorf("the events end at %d, the stream at %d", position, total)
	}

	return
}

var (
	parserCases = []struct {
		Name     string
		Feeds    []feed
		Closed   []http1.Side
		Expected [2][]string
	}{
		{
			Name:   "keep-alive request and response with content-length",
			Feeds:  []feed{{http1.RequestSide, "GET / HTTP/1.1\r\nHost: a\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 GET / HTTP/1.1 0 "" [{Host a}] none 0 interim=false [0,27)`, `end 0 complete=true trailers=[] "" at 27`},
				{"begin 0", `head 0   HTTP/1.1 200 "OK" [{Content-Length 5}] length 5 interim=false [0,38)`, `body "hello"`, `end 0 complete=true trailers=[] "" at 43`},
			},
		},
		{
			Name:   "pipelined requests and responses in one piece each, a post with a body between",
			Feeds:  []feed{{http1.RequestSide, "GET /a HTTP/1.1\r\n\r\nPOST /b HTTP/1.1\r\nContent-Length: 3\r\n\r\nxyzGET /c HTTP/1.0\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 GET /a HTTP/1.1 0 "" [] none 0 interim=false [0,19)`, `end 0 complete=true trailers=[] "" at 19`, "begin 19", `head 1 POST /b HTTP/1.1 0 "" [{Content-Length 3}] length 3 interim=false [19,58)`, `body "xyz"`, `end 1 complete=true trailers=[] "" at 61`, "begin 61", `head 2 GET /c HTTP/1.0 0 "" [] none 0 interim=false [61,80)`, `end 2 complete=true trailers=[] "" at 80`},
				{"begin 0", `head 0   HTTP/1.1 200 "OK" [{Content-Length 1}] length 1 interim=false [0,38)`, `body "a"`, `end 0 complete=true trailers=[] "" at 39`, "begin 39", `head 1   HTTP/1.1 201 "Created" [{Content-Length 0}] length 0 interim=false [39,82)`, `end 1 complete=true trailers=[] "" at 82`, "begin 82", `head 2   HTTP/1.1 404 "Not Found" [{Content-Length 2}] length 2 interim=false [82,127)`, `body "no"`, `end 2 complete=true trailers=[] "" at 129`},
			},
		},
		{
			Name:   "chunked response with extensions and trailers",
			Feeds:  []feed{{http1.RequestSide, "GET / HTTP/1.1\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4;name=value\r\nwiki\r\n5 ; x\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0;last\r\nExpires: never\r\nX-Sum: 1\r\n\r\n"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 GET / HTTP/1.1 0 "" [] none 0 interim=false [0,18)`, `end 0 complete=true trailers=[] "" at 18`},
				{"begin 0", `head 0   HTTP/1.1 200 "OK" [{Transfer-Encoding gzip, chunked}] chunked 0 interim=false [0,53)`, `body "wikipedia in\r\n\r\nchunks."`, `end 0 complete=true trailers=[{Expires never} {X-Sum 1}] "Expires: never\r\nX-Sum: 1\r\n\r\n" at 142`},
			},
		},
		{
			Name:   "100-continue: the interim response, then the body and the final response",
			Feeds:  []feed{{http1.RequestSide, "PUT /f HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 100 Continue\r\n\r\n"}, {http1.RequestSide, "ok"}, {http1.ResponseSide, "HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 PUT /f HTTP/1.1 0 "" [{Expect 100-continue} {Content-Length 2}] length 2 interim=false [0,60)`, `body "ok"`, `end 0 complete=true trailers=[] "" at 62`},
				{"begin 0", `head 0   HTTP/1.1 100 "Continue" [] none 0 interim=true [0,25)`, `end 0 complete=true trailers=[] "" at 25`, "begin 25", `head 0   HTTP/1.1 204 "No Content" [{Content-Length 9}] none 0 interim=false [25,71)`, `end 0 complete=true trailers=[] "" at 71`},
			},
		},
		{
			Name:   "head and 304 have no body even with a length, the next response follows",
			Feeds:  []feed{{http1.RequestSide, "HEAD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\nIf-None-Match: x\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 HEAD / HTTP/1.1 0 "" [] none 0 interim=false [0,19)`, `end 0 complete=true trailers=[] "" at 19`, "begin 19", `head 1 GET / HTTP/1.1 0 "" [{If-None-Match x}] none 0 interim=false [19,55)`, `end 1 complete=true trailers=[] "" at 55`},
				{"begin 0", `head 0   HTTP/1.1 200 "OK" [{Content-Length 100}] none 0 interim=false [0,40)`, `end 0 complete=true trailers=[] "" at 40`, "begin 40", `head 1   HTTP/1.1 304 "Not Modified" [{Content-Length 100}] none 0 interim=false [40,90)`, `end 1 complete=true trailers=[] "" at 90`},
			},
		},
		{
			Name:   "a response without a length ends with the stream, bare line feeds, a leading empty line, a folded field",
			Feeds:  []feed{{http1.RequestSide, "\r\nGET /x HTTP/1.0\nA: 1\n  2\n\n"}, {http1.ResponseSide, "HTTP/1.0 200\nServer: s\n\nuntil the end"}},
			Closed: []http1.Side{http1.ResponseSide, http1.RequestSide},
			Expected: [2][]string{
				{"begin 0", `head 0 GET /x HTTP/1.0 0 "" [{A 1 2}] none 0 interim=false [0,28)`, `end 0 complete=true trailers=[] "" at 28`},
				{"begin 0", `head 0   HTTP/1.0 200 "" [{Server s}] close 0 interim=false [0,24)`, `body "until the end"`, `end 0 complete=true trailers=[] "" at 37`},
			},
		},
		{
			Name:   "101 switching protocols stops both sides, the request side at its next bytes",
			Feeds:  []feed{{http1.RequestSide, "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x05hello"}, {http1.RequestSide, "\x81\x85frame"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 GET /ws HTTP/1.1 0 "" [{Upgrade websocket} {Connection Upgrade}] none 0 interim=false [0,61)`, `end 0 complete=true trailers=[] "" at 61`, "stop protocol switched by 101 switching protocols at 61"},
				{"begin 0", `head 0   HTTP/1.1 101 "Switching Protocols" [{Upgrade websocket}] none 0 interim=false [0,56)`, `end 0 complete=true trailers=[] "" at 56`, "stop protocol switched by 101 switching protocols at 56"},
			},
		},
		{
			Name:   "connect stops the response side after a 2xx and the request side at its next bytes after its head",
			Feeds:  []feed{{http1.RequestSide, "CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 200 Connection Established\r\n\r\n\x16\x03\x03"}, {http1.RequestSide, "\x16\x03\x01"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 CONNECT a:443 HTTP/1.1 0 "" [{Host a:443}] none 0 interim=false [0,39)`, `end 0 complete=true trailers=[] "" at 39`, "stop tunnel of a connect request at 39"},
				{"begin 0", `head 0   HTTP/1.1 200 "Connection Established" [] none 0 interim=false [0,39)`, `end 0 complete=true trailers=[] "" at 39`, "stop tunnel of a connect request at 39"},
			},
		},
		{
			Name:   "a refused connect (407) is followed by its retry on the same connection, which is read up to its tunnel",
			Feeds:  []feed{{http1.RequestSide, "CONNECT a:443 HTTP/1.1\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 2\r\n\r\nno"}, {http1.RequestSide, "CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic eA==\r\n\r\n"}, {http1.ResponseSide, "HTTP/1.1 200 OK\r\n\r\n\x16\x03\x03"}, {http1.RequestSide, "\x16\x03\x01"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 CONNECT a:443 HTTP/1.1 0 "" [] none 0 interim=false [0,26)`, `end 0 complete=true trailers=[] "" at 26`, "begin 26", `head 1 CONNECT a:443 HTTP/1.1 0 "" [{Proxy-Authorization Basic eA==}] none 0 interim=false [26,85)`, `end 1 complete=true trailers=[] "" at 85`, "stop tunnel of a connect request at 85"},
				{"begin 0", `head 0   HTTP/1.1 407 "Proxy Authentication Required" [{Content-Length 2}] length 2 interim=false [0,65)`, `body "no"`, `end 0 complete=true trailers=[] "" at 67`, "begin 67", `head 1   HTTP/1.1 200 "OK" [] none 0 interim=false [67,86)`, `end 1 complete=true trailers=[] "" at 86`, "stop tunnel of a connect request at 86"},
			},
		},
		{
			Name:   "bytes sent while a connect waits stop the request side even when it is refused",
			Feeds:  []feed{{http1.RequestSide, "CONNECT a:443 HTTP/1.1\r\n\r\n\x16\x03\x01"}, {http1.ResponseSide, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"}, {http1.RequestSide, "\x16"}},
			Closed: nil,
			Expected: [2][]string{
				{"begin 0", `head 0 CONNECT a:443 HTTP/1.1 0 "" [] none 0 interim=false [0,26)`, `end 0 complete=true trailers=[] "" at 26`, "stop tunnel of a connect request at 26"},
				{"begin 0", `head 0   HTTP/1.1 403 "Forbidden" [{Content-Length 0}] length 0 interim=false [0,45)`, `end 0 complete=true trailers=[] "" at 45`},
			},
		},
		{
			Name:   "a stream that ends inside a body leaves its message incomplete",
			Feeds:  []feed{{http1.RequestSide, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab"}},
			Closed: []http1.Side{http1.RequestSide},
			Expected: [2][]string{
				{"begin 0", `head 0 POST / HTTP/1.1 0 "" [{Transfer-Encoding chunked}] chunked 0 interim=false [0,47)`, `body "ab"`, `end 0 complete=false trailers=[] "" at 52`},
				nil,
			},
		},
	}
	malformedCases = []struct {
		Name     string
		Side     http1.Side
		Data     string
		Expected error
	}{
		{Name: "a tls ClientHello", Side: http1.RequestSide, Data: "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03", Expected: http1.ErrMalformed},
		{Name: "smtp from the client", Side: http1.RequestSide, Data: "HELO example.com\r\n", Expected: http1.ErrMalformed},
		{Name: "smtp banner from the server", Side: http1.ResponseSide, Data: "220 mail ESMTP\r\n", Expected: http1.ErrMalformed},
		{Name: "the http/2 preface", Side: http1.RequestSide, Data: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Expected: http1.ErrHTTP2},
		{Name: "an unknown version", Side: http1.RequestSide, Data: "GET / HTTP/3.0\r\n\r\n", Expected: http1.ErrMalformed},
		{Name: "a status that is no number", Side: http1.ResponseSide, Data: "HTTP/1.1 2x0 OK\r\n\r\n", Expected: http1.ErrMalformed},
		{Name: "two different lengths", Side: http1.RequestSide, Data: "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", Expected: http1.ErrMalformed},
		{Name: "a length that is no number", Side: http1.RequestSide, Data: "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", Expected: http1.ErrMalformed},
		{Name: "a request coding that is not chunked", Side: http1.RequestSide, Data: "POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n", Expected: http1.ErrMalformed},
		{Name: "a field line without a colon", Side: http1.RequestSide, Data: "GET / HTTP/1.1\r\nHost a\r\n\r\n", Expected: http1.ErrMalformed},
		{Name: "white space before the colon", Side: http1.RequestSide, Data: "GET / HTTP/1.1\r\nHost : a\r\n\r\n", Expected: http1.ErrMalformed},
		{Name: "a continuation line first", Side: http1.RequestSide, Data: "GET / HTTP/1.1\r\n a\r\n\r\n", Expected: http1.ErrMalformed},
		{Name: "a chunk size that is no hex", Side: http1.ResponseSide, Data: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", Expected: http1.ErrMalformed},
		{Name: "chunk data without its line end", Side: http1.ResponseSide, Data: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXY", Expected: http1.ErrMalformed},
		{Name: "a head over the limit", Side: http1.RequestSide, Data: "GET / HTTP/1.1\r\nX: " + strings.Repeat("a", http1.MaxHeadBytes) + "\r\n\r\n", Expected: http1.ErrHeadTooLong},
	}
)

// Test if http1.Conn returns with the expected output for whole streams and for every split of the first piece of a stream into two.
func TestConnPositive(state *testing.T) {
	for _, positive := range parserCases {
		total := [2]int64{}

		for _, current := range positive.Feeds {
			total[current.Side] += int64(len(current.Data))
		}

		whole := run(positive.Feeds, positive.Closed, 0)

		for side := range 2 {
			lines := summary(whole[side])

			if !slices.Equal(lines, positive.Expected[side]) {
				state.Errorf("Test of http1.Conn failed, %s, side %d should read\n%s\nread:\n%s", positive.Name, side, strings.Join(positive.Expected[side], "\n"), strings.Join(lines, "\n"))
				return
			}

			if err := checkCoverage(whole[side], total[side]); (len(positive.Expected[side]) > 0) && (err != nil) {
				state.Errorf("Test of http1.Conn failed, %s, side %d should cover every byte, error: %s", positive.Name, side, err.Error())
				return
			}
		}

		// the first piece split at every byte boundary reads the same, apart from the begin offsets that are the same anyway
		for split := 1; split < len(positive.Feeds[0].Data); split++ {
			pieces := run(positive.Feeds, positive.Closed, split)

			for side := range 2 {
				if lines := summary(pieces[side]); !slices.Equal(lines, positive.Expected[side]) {
					state.Errorf("Test of http1.Conn failed, %s, split at %d, side %d should read\n%s\nread:\n%s", positive.Name, split, side, strings.Join(positive.Expected[side], "\n"), strings.Join(lines, "\n"))
					return
				}
			}
		}
	}
}

// Test if http1.Conn returns with the expected output for every split of pipelined messages into single bytes fed one by one.
func TestConnBytesPositive(state *testing.T) {
	stream := "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3;e=1\r\nabc\r\n0\r\nT: 1\r\n\r\nGET /b HTTP/1.1\r\nContent-Length: 2\r\n\r\nxy"
	whole := summary(run([]feed{{http1.RequestSide, stream}}, nil, 0)[http1.RequestSide])
	conn := http1.New()
	events := []http1.Event{}

	for index := range len(stream) {
		events = append(events, copied(conn.Feed(http1.RequestSide, []byte{stream[index]}))...)
	}

	if lines := summary(events); !slices.Equal(lines, whole) {
		state.Errorf("Test of http1.Conn failed, byte by byte should read\n%s\nread:\n%s", strings.Join(whole, "\n"), strings.Join(lines, "\n"))
	}

	if err := checkCoverage(events, int64(len(stream))); err != nil {
		state.Errorf("Test of http1.Conn failed, byte by byte should cover every byte, error: %s", err.Error())
	}
}

// Test if http1.Conn returns with the expected errors: a stream that is no HTTP/1 stops its side at once, and nothing after it is parsed.
func TestConnNegative(state *testing.T) {
	for _, negative := range malformedCases {
		// whole, and split before the last byte, so an early stop is seen before the line ends
		for _, split := range []int{0, len(negative.Data) - 1} {
			events := run([]feed{{negative.Side, negative.Data}, {negative.Side, "GET / HTTP/1.1\r\n\r\n"}}, nil, split)[negative.Side]
			stops := 0
			var stopErr error

			for _, event := range events {
				switch event.Type {
				case http1.StopEventType:
					stops++
					stopErr = event.Err
				case http1.HeadEventType:
					if stops > 0 {
						state.Errorf("Test of http1.Conn failed, %s, nothing should be parsed after the stop, events: %v", negative.Name, summary(events))
						return
					}
				default:
				}
			}

			if (stops != 1) || !errors.Is(stopErr, negative.Expected) {
				state.Errorf("Test of http1.Conn failed, %s, split %d, the side should stop once with %v, events: %v", negative.Name, split, negative.Expected, summary(events))
				return
			}
		}
	}

	// a response the client never sent a request for still gets an exchange of its own, a canceled request gets no response
	conn := http1.New()
	conn.Feed(http1.RequestSide, []byte("GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n"))
	conn.Cancel(0)
	events := conn.Feed(http1.ResponseSide, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	indexes := []int{}

	for _, event := range events {
		if event.Type == http1.HeadEventType {
			indexes = append(indexes, event.Index)
		}
	}

	if !slices.Equal(indexes, []int{1, 2}) {
		state.Errorf("Test of http1.Conn.Cancel function failed, the responses should pair with request 1 and a new exchange 2, indexes: %v", indexes)
	}
}

// a message as the parser assembles it from a stream
func assemble(state *testing.T, side http1.Side, stream string) (message http1.Message) {
	conn := http1.New()

	if side == http1.ResponseSide {
		conn.Feed(http1.RequestSide, []byte("GET / HTTP/1.1\r\n\r\n"))
	}

	events := conn.Feed(side, []byte(stream))

	if side == http1.ResponseSide {
		events = append(events, conn.Close(side)...)
	}

	for _, event := range events {
		switch event.Type {
		case http1.HeadEventType:
			message.Head = event.Head
			message.Framing = event.Framing
		case http1.BodyEventType:
			message.Body = append(message.Body, event.Data...)
		case http1.EndEventType:
			message.TrailerRaw = event.TrailerRaw
		default:
		}
	}

	message.Raw = []byte(stream)

	if message.Head.Raw == nil {
		state.Fatalf("Could not assemble message %q", stream)
	}

	return
}

// Test if http1.Rebuild returns with the expected output: the unchanged form is the original, a changed body gets its length or its chunks, the head stays as written.
func TestRebuildPositive(state *testing.T) {
	positiveCases := []struct {
		Name     string
		Side     http1.Side
		Stream   string
		Form     func(form string) string
		Expected string
	}{
		{Name: "unchanged keeps the chunks", Side: http1.ResponseSide, Stream: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;x\r\nab\r\n1\r\nc\r\n0\r\n\r\n", Form: func(form string) string { return form }, Expected: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;x\r\nab\r\n1\r\nc\r\n0\r\n\r\n"},
		{Name: "a longer body gets its length, the field keeps its case and spacing", Side: http1.RequestSide, Stream: "POST /p HTTP/1.1\r\ncontent-LENGTH:  3\r\nX: y\r\n\r\nabc", Form: func(form string) string { return strings.Replace(form, "abc", "abcdefgh", 1) }, Expected: "POST /p HTTP/1.1\r\ncontent-LENGTH:  8\r\nX: y\r\n\r\nabcdefgh"},
		{Name: "a word across two chunks is replaced and the body is one chunk with the trailers", Side: http1.ResponseSide, Stream: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nwor\r\n2\r\nld\r\n0\r\nT: 1\r\n\r\n", Form: func(form string) string { return strings.Replace(form, "world", "planet", 1) }, Expected: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nplanet\r\n0\r\nT: 1\r\n\r\n"},
		{Name: "an empty chunked body", Side: http1.ResponseSide, Stream: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n", Form: func(form string) string { return strings.TrimSuffix(form, "a") }, Expected: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
		{Name: "a body on a request without one gets a content-length", Side: http1.RequestSide, Stream: "GET / HTTP/1.1\r\nHost: a\r\n\r\n", Form: func(form string) string { return form + "body" }, Expected: "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nbody"},
		{Name: "a changed head only", Side: http1.RequestSide, Stream: "GET / HTTP/1.1\r\nHost: a\r\n\r\n", Form: func(form string) string { return strings.Replace(form, "GET / ", "GET /test ", 1) }, Expected: "GET /test HTTP/1.1\r\nHost: a\r\n\r\n"},
		{Name: "a body delimited by the end of the stream gets no length", Side: http1.ResponseSide, Stream: "HTTP/1.0 200 OK\r\n\r\nold", Form: func(form string) string { return strings.Replace(form, "old", "newer", 1) }, Expected: "HTTP/1.0 200 OK\r\n\r\nnewer"},
		{Name: "chunked written into the head by the edit", Side: http1.RequestSide, Stream: "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nab", Form: func(form string) string { return "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nabc" }, Expected: "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"},
		{Name: "bare line feeds stay", Side: http1.RequestSide, Stream: "POST / HTTP/1.1\nContent-Length: 1\n\na", Form: func(form string) string { return form + "b" }, Expected: "POST / HTTP/1.1\nContent-Length: 2\n\nab"},
	}

	for _, positive := range positiveCases {
		message := assemble(state, positive.Side, positive.Stream)
		form := positive.Form(string(message.Form()))
		rebuilt := http1.Rebuild(message, []byte(form))

		if (rebuilt.Err != nil) || (string(rebuilt.Wire) != positive.Expected) {
			state.Errorf("Test of http1.Rebuild function failed, %s, should give %q, gave: %q, error: %v", positive.Name, positive.Expected, rebuilt.Wire, rebuilt.Err)
			return
		}

		// what goes on reads back as the form that was written
		check := assemble(state, positive.Side, string(rebuilt.Wire))

		if !bytes.Equal(check.Body, rebuilt.Body) || (check.Head.Method != rebuilt.Head.Method) || (check.Head.Status != rebuilt.Head.Status) {
			state.Errorf("Test of http1.Rebuild function failed, %s, the wire should read back as the edit, body: %q, read: %q", positive.Name, rebuilt.Body, check.Body)
			return
		}
	}
}

// Test if http1.Rebuild returns with the expected output for a response without a body by its status or its request: an edited head goes on as
// written, its Content-Length keeps the size of the representation and a chunked one gets no last chunk.
func TestRebuildBodilessPositive(state *testing.T) {
	positiveCases := []struct {
		Name     string
		Request  string
		Response string
	}{
		{Name: "a response to HEAD with its length", Request: "HEAD /file HTTP/1.1\r\nHost: a\r\n\r\n", Response: "HTTP/1.1 200 OK\r\nContent-Length: 104857600\r\nX: old\r\n\r\n"},
		{Name: "a chunked response to HEAD", Request: "HEAD / HTTP/1.1\r\nHost: a\r\n\r\n", Response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX: old\r\n\r\n"},
		{Name: "a 304 with its length", Request: "GET / HTTP/1.1\r\nHost: a\r\n\r\n", Response: "HTTP/1.1 304 Not Modified\r\nContent-Length: 512\r\nX: old\r\n\r\n"},
		{Name: "a 204", Request: "DELETE / HTTP/1.1\r\nHost: a\r\n\r\n", Response: "HTTP/1.1 204 No Content\r\nX: old\r\n\r\n"},
	}

	for _, positive := range positiveCases {
		conn := http1.New()
		conn.Feed(http1.RequestSide, []byte(positive.Request))
		message := http1.Message{Raw: []byte(positive.Response)}

		for _, event := range conn.Feed(http1.ResponseSide, []byte(positive.Response)) {
			if event.Type == http1.HeadEventType {
				message.Head = event.Head
				message.Framing = event.Framing
			}
		}

		expected := strings.Replace(positive.Response, "X: old", "X: new", 1)
		rebuilt := http1.Rebuild(message, []byte(strings.Replace(string(message.Form()), "X: old", "X: new", 1)))

		if (message.Framing != http1.NoneFraming) || (rebuilt.Err != nil) || (string(rebuilt.Wire) != expected) || (len(rebuilt.Body) != 0) {
			state.Errorf("Test of http1.Rebuild function failed, %s, the head should go on as written, framing: %s, wire: %q, error: %v", positive.Name, message.Framing, rebuilt.Wire, rebuilt.Err)
			return
		}
	}
}

// Test if http1.Rebuild returns with the expected errors: a form that is no message goes on as it is written.
func TestRebuildNegative(state *testing.T) {
	message := assemble(state, http1.RequestSide, "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nab")
	negativeCases := []struct {
		Name     string
		Form     string
		Expected error
	}{
		{Name: "no empty line after the head", Form: "POST / HTTP/1.1\r\nContent-Length: 2\r\n", Expected: http1.ErrNoHeadEnd},
		{Name: "a start line that is none", Form: "nonsense\r\n\r\nab", Expected: http1.ErrMalformed},
		{Name: "a field line without a colon", Form: "POST / HTTP/1.1\r\nbroken\r\n\r\nabc", Expected: http1.ErrMalformed},
	}

	for _, negative := range negativeCases {
		rebuilt := http1.Rebuild(message, []byte(negative.Form))

		if !errors.Is(rebuilt.Err, negative.Expected) || (string(rebuilt.Wire) != negative.Form) {
			state.Errorf("Test of http1.Rebuild function failed, %s, should go on as written with %v, wire: %q, error: %v", negative.Name, negative.Expected, rebuilt.Wire, rebuilt.Err)
			return
		}
	}
}
