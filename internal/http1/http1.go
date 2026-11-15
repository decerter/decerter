// SPDX-License-Identifier: AGPL-3.0-only

package http1

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

func New() (conn *Conn) {
	conn = &Conn{
		parsers:   [2]parser{{side: RequestSide, state: idleState}, {side: ResponseSide, state: idleState}},
		pending:   nil,
		nextIndex: 0,
	}
	return
}

// parse the next bytes of a side; once a side stopped its bytes give no events
func (conn *Conn) Feed(side Side, data []byte) (events []Event) {
	parser := &conn.parsers[side]

	if (parser.pendingStop != nil) && (parser.state != stoppedState) {
		events = append(events, parser.stop(parser.openStart(), parser.pendingStop))
	}

	for (len(data) > 0) && (parser.state != stoppedState) {
		consumed := 0
		consumed, events = conn.step(parser, data, events)
		data = data[consumed:]
		parser.offset += int64(consumed)
	}

	parser.offset += int64(len(data))
	return
}

// the stream of a side ended: a body delimited by the end is complete, any other open message is not; nothing is parsed after it
func (conn *Conn) Close(side Side) (events []Event) {
	parser := &conn.parsers[side]

	switch parser.state {
	case
		idleState,
		connectState,
		stoppedState:
	case headState:
		events = append(events, parser.stop(parser.start, ErrClosed))
	case closeBodyState:
		events = append(events, Event{Type: EndEventType, Index: parser.index, Start: parser.offset, End: parser.offset, IsComplete: true})
	default:
		events = append(events, Event{Type: EndEventType, Index: parser.index, Start: parser.offset, End: parser.offset, IsComplete: false})
	}

	parser.state = stoppedState
	return
}

// a request that never went on gets no response, the next response is the one of the request after it
func (conn *Conn) Cancel(index int) {
	conn.pending = slices.DeleteFunc(conn.pending, func(request pendingRequest) bool {
		return request.index == index
	})
}

// a request that was edited to another method before it went on: its response is read by the new one (HEAD has no body)
func (conn *Conn) SetMethod(index int, method string) {
	for position := range conn.pending {
		if conn.pending[position].index == index {
			conn.pending[position].method = method
		}
	}
}

// whether a side still parses
func (conn *Conn) IsStopped(side Side) (isStopped bool) {
	isStopped = conn.parsers[side].state == stoppedState
	return
}

// the stream offset where the open message started, the next byte when none is open
func (parser *parser) openStart() (start int64) {
	start = parser.offset

	if parser.state != idleState {
		start = parser.start
	}

	return
}

func (parser *parser) stop(start int64, reason error) (event Event) {
	event = Event{Type: StopEventType, Index: parser.index, Start: start, End: start, Err: reason}
	parser.state = stoppedState
	parser.head = nil
	parser.line = nil
	parser.trailer = nil
	return
}

// one step of the state machine on the start of data, consumed is how much of it was taken
func (conn *Conn) step(parser *parser, data []byte, events []Event) (consumed int, result []Event) {
	result = events

	switch parser.state {
	case idleState:
		parser.state = headState
		parser.start = parser.offset
		parser.head = nil
		parser.scanned = 0
		parser.lineStart = 0
		parser.hasStartLine = false
		result = append(result, Event{Type: BeginEventType, Index: parser.index, Start: parser.offset, End: parser.offset})
	case headState:
		consumed, result = conn.readHead(parser, data, result)
	case
		lengthBodyState,
		chunkDataState:
		consumed = int(min(parser.remaining, int64(len(data))))
		parser.remaining -= int64(consumed)
		result = append(result, parser.body(data[:consumed], data[:consumed]))

		if parser.remaining > 0 {
			return
		}

		if parser.state == chunkDataState {
			parser.state = chunkEndState
			parser.line = nil
			return
		}

		result = append(result, parser.end(parser.offset+int64(consumed)))
	case chunkSizeState:
		consumed, result = parser.readChunkSize(data, result)
	case chunkEndState:
		consumed, result = parser.readChunkEnd(data, result)
	case trailerState:
		consumed, result = parser.readTrailer(data, result)
	case closeBodyState:
		consumed = len(data)
		result = append(result, parser.body(data, data))
	case connectState:
		consumed = len(data)
		parser.isConnectData = true
	case stoppedState:
		consumed = len(data)
	}

	return
}

// a body event over raw, content is what of it is the body
func (parser *parser) body(raw []byte, content []byte) (event Event) {
	event = Event{Type: BodyEventType, Index: parser.index, Start: parser.offset, End: parser.offset + int64(len(raw)), Data: content}
	return
}

// the message is whole at offset end, the side waits for the next one
func (parser *parser) end(end int64) (event Event) {
	event = Event{Type: EndEventType, Index: parser.index, Start: end, End: end, IsComplete: true}
	parser.state = idleState
	return
}

// collect the head until its empty line; the start line is checked as soon as it is there, and its first bytes before, so a stream that is no HTTP stops at once
func (conn *Conn) readHead(parser *parser, data []byte, events []Event) (consumed int, result []Event) {
	result = events
	before := len(parser.head)
	parser.head = append(parser.head, data...)
	scan := headScan{scanned: parser.scanned, lineStart: parser.lineStart, hasStartLine: parser.hasStartLine}
	end, isFound, startLine := scan.next(parser.head)
	parser.scanned, parser.lineStart = scan.scanned, scan.lineStart

	if !parser.hasStartLine && scan.hasStartLine {
		parser.hasStartLine = true
		_, err := parseStartLine(string(startLine), parser.side)

		if err != nil {
			result = append(result, parser.stop(parser.start, err))
			consumed = len(data)
			return
		}
	}

	if !parser.hasStartLine && !isStartLinePrefix(parser.head[parser.lineStart:], parser.side) {
		result = append(result, parser.stop(parser.start, fmt.Errorf("%w: start line %q", ErrMalformed, truncate(parser.head[parser.lineStart:]))))
		consumed = len(data)
		return
	}

	if !isFound {
		consumed = len(data)

		if len(parser.head) > MaxHeadBytes {
			result = append(result, parser.stop(parser.start, ErrHeadTooLong))
		}

		return
	}

	consumed = end - before

	if end > MaxHeadBytes {
		result = append(result, parser.stop(parser.start, ErrHeadTooLong))
		return
	}

	parser.head = parser.head[:end:end]
	head, err := parseHead(parser.head, parser.side)

	if err != nil {
		result = append(result, parser.stop(parser.start, err))
		return
	}

	headEnd := parser.offset + int64(consumed)
	parser.head = nil
	result = conn.finishHead(parser, head, headEnd, result)
	return
}

// the head is whole: pair it, decide how its body is framed and what comes after it
func (conn *Conn) finishHead(parser *parser, head Head, headEnd int64, events []Event) (result []Event) {
	result = events
	headEvent := Event{Type: HeadEventType, Start: parser.start, End: headEnd, Head: head}
	isTunnel := false
	var err error

	if parser.side == RequestSide {
		parser.index = conn.nextIndex
		conn.nextIndex++
		conn.pending = append(conn.pending, pendingRequest{index: parser.index, method: head.Method})
		headEvent.Framing, headEvent.Length, err = requestFraming(head)
	} else {
		method := ""
		isInterim := (head.Status >= 100) && (head.Status < 200)

		if len(conn.pending) > 0 {
			parser.index = conn.pending[0].index
			method = conn.pending[0].method
		} else {
			parser.index = conn.nextIndex
			conn.nextIndex++
		}

		if !isInterim || (head.Status == 101) {
			conn.Cancel(parser.index)
		}

		// a 101 is the last response of its request, the protocol after it is another
		headEvent.IsInterim = isInterim && (head.Status != 101)
		isTunnel = (method == "CONNECT") && (head.Status >= 200) && (head.Status < 300)
		headEvent.Framing, headEvent.Length, err = responseFraming(head, method)

		if (method == "CONNECT") && !isInterim {
			conn.answerConnect(isTunnel)
		}
	}

	if err != nil {
		result = append(result, parser.stop(parser.start, err))
		return
	}

	headEvent.Index = parser.index
	result = append(result, headEvent)

	switch headEvent.Framing {
	case NoneFraming:
		result = append(result, parser.end(headEnd))
	case LengthFraming:
		parser.state = lengthBodyState
		parser.remaining = headEvent.Length

		if headEvent.Length == 0 {
			result = append(result, parser.end(headEnd))
		}
	case ChunkedFraming:
		parser.state = chunkSizeState
		parser.line = nil
	case CloseFraming:
		parser.state = closeBodyState
	}

	// what follows a switch of protocol or a tunnel is no HTTP/1; a CONNECT waits for its response, a refused one (407) is followed by more requests
	switch {
	case (parser.side == RequestSide) && (head.Method == "CONNECT") && (headEvent.Framing == NoneFraming):
		parser.state = connectState
		parser.start = headEnd
		parser.isConnectData = false
	case (parser.side == RequestSide) && (head.Method == "CONNECT"):
		result = append(result, parser.stop(headEnd, ErrConnect))
	case (parser.side == ResponseSide) && (head.Status == 101):
		result = append(result, parser.stop(headEnd, ErrUpgrade))
		conn.parsers[RequestSide].pendingStop = ErrUpgrade
	case isTunnel:
		result = append(result, parser.stop(headEnd, ErrConnect))
	default:
	}

	return
}

// the final response to a CONNECT came: a 2xx starts the tunnel, the request side stops at its next bytes; a refusal lets it parse the next request,
// unless bytes came while it waited: those were sent into the tunnel or are the middle of a request, the request side stops then too
func (conn *Conn) answerConnect(isTunnel bool) {
	request := &conn.parsers[RequestSide]

	switch {
	case request.state != connectState:
	case isTunnel || request.isConnectData:
		request.pendingStop = ErrConnect
	default:
		request.state = idleState
	}
}

// a request has a body only with Transfer-Encoding, which must end in chunked, or Content-Length (RFC 9112 section 6.3)
func requestFraming(head Head) (framing Framing, length int64, err error) {
	framing = NoneFraming
	codings := head.Values("Transfer-Encoding")

	if len(codings) > 0 {
		if !isChunked(codings) {
			err = fmt.Errorf("%w: transfer-encoding %q of a request does not end in chunked", ErrMalformed, strings.Join(codings, ", "))
			return
		}

		framing = ChunkedFraming
		return
	}

	length, isSet, err := contentLength(head)

	if isSet {
		framing = LengthFraming
	}

	return
}

// a response to HEAD, 1xx, 204 and 304 have no body, a 2xx to CONNECT starts a tunnel; else chunked, Content-Length or until the stream ends (RFC 9112 section 6.3)
func responseFraming(head Head, method string) (framing Framing, length int64, err error) {
	framing = NoneFraming

	switch {
	case
		method == "HEAD",
		head.Status < 200,
		head.Status == 204,
		head.Status == 304,
		(method == "CONNECT") && (head.Status < 300):
		return
	default:
	}

	codings := head.Values("Transfer-Encoding")

	if len(codings) > 0 {
		framing = CloseFraming

		if isChunked(codings) {
			framing = ChunkedFraming
		}

		return
	}

	length, isSet, err := contentLength(head)
	framing = CloseFraming

	if isSet {
		framing = LengthFraming
	}

	return
}

// the last transfer coding is chunked, its parameters aside
func isChunked(codings []string) (isChunked bool) {
	last, _, _ := strings.Cut(codings[len(codings)-1], ";")
	isChunked = strings.EqualFold(strings.TrimSpace(last), "chunked")
	return
}

// Content-Length, the same value in several fields or a list is one value; differing or non-digit values are malformed
func contentLength(head Head) (length int64, isSet bool, err error) {
	values := head.Values("Content-Length")

	for _, value := range values {
		parsed, parseErr := parseDecimal(value)

		if (parseErr != nil) || (isSet && (parsed != length)) {
			err = fmt.Errorf("%w: content-length %q", ErrMalformed, strings.Join(values, ", "))
			isSet = false
			return
		}

		length = parsed
		isSet = true
	}

	return
}

func parseDecimal(text string) (number int64, err error) {
	if (text == "") || (len(text) > maxSizeDigits) || (strings.Trim(text, "0123456789") != "") {
		err = ErrMalformed
		return
	}

	number, err = strconv.ParseInt(text, 10, 64)
	return
}

// a chunk-size line: hex digits, optional extensions after a semicolon, a line end
func (parser *parser) readChunkSize(data []byte, events []Event) (consumed int, result []Event) {
	result = events
	newline := bytes.IndexByte(data, '\n')

	if newline < 0 {
		consumed = len(data)
		parser.line = append(parser.line, data...)
		result = append(result, parser.body(data, nil))

		if len(parser.line) > maxChunkLineBytes {
			result = append(result, parser.stop(parser.start, fmt.Errorf("%w: chunk-size line is too long", ErrMalformed)))
		}

		return
	}

	consumed = newline + 1
	parser.line = append(parser.line, data[:consumed]...)
	result = append(result, parser.body(data[:consumed], nil))
	line := strings.TrimSuffix(strings.TrimSuffix(string(parser.line), "\n"), "\r")
	parser.line = nil
	sizeText, _, _ := strings.Cut(line, ";")
	sizeText = strings.TrimRight(sizeText, " \t")

	if (sizeText == "") || (len(sizeText) > maxSizeDigits-2) || (strings.Trim(strings.ToLower(sizeText), "0123456789abcdef") != "") {
		result = append(result, parser.stop(parser.start, fmt.Errorf("%w: chunk-size line %q", ErrMalformed, truncate([]byte(line)))))
		return
	}

	size, err := strconv.ParseInt(sizeText, 16, 64)

	if err != nil {
		result = append(result, parser.stop(parser.start, fmt.Errorf("%w: chunk size %q", ErrMalformed, sizeText)))
		return
	}

	if size == 0 {
		parser.state = trailerState
		parser.trailer = nil
		parser.trailerStart = parser.offset + int64(consumed)
		parser.scanned = 0
		parser.lineStart = 0
		return
	}

	parser.state = chunkDataState
	parser.remaining = size
	return
}

// the line end after the data of a chunk, CRLF or a bare LF
func (parser *parser) readChunkEnd(data []byte, events []Event) (consumed int, result []Event) {
	result = events
	newline := bytes.IndexByte(data, '\n')
	consumed = len(data)

	if newline >= 0 {
		consumed = newline + 1
	}

	parser.line = append(parser.line, data[:consumed]...)
	result = append(result, parser.body(data[:consumed], nil))
	line := string(parser.line)

	switch {
	case (line == "\r\n") || (line == "\n"):
		parser.state = chunkSizeState
		parser.line = nil
	case (newline < 0) && (line == "\r"):
	default:
		result = append(result, parser.stop(parser.start, fmt.Errorf("%w: chunk data is not followed by a line end", ErrMalformed)))
	}

	return
}

// the trailer section after the last chunk: header fields until an empty line, often only the empty line
func (parser *parser) readTrailer(data []byte, events []Event) (consumed int, result []Event) {
	result = events
	before := len(parser.trailer)
	parser.trailer = append(parser.trailer, data...)
	end, isFound := 0, false

	for index := parser.scanned; index < len(parser.trailer); index++ {
		if parser.trailer[index] != '\n' {
			continue
		}

		line := bytes.TrimSuffix(parser.trailer[parser.lineStart:index], []byte("\r"))
		parser.lineStart = index + 1

		if len(line) == 0 {
			end, isFound = index+1, true
			break
		}
	}

	parser.scanned = len(parser.trailer)

	if !isFound {
		consumed = len(data)

		if len(parser.trailer) > maxTrailerBytes {
			result = append(result, parser.stop(parser.start, fmt.Errorf("%w: trailer section is too long", ErrMalformed)))
		}

		return
	}

	consumed = end - before
	trailer := parser.trailer[:end:end]
	parser.trailer = nil
	fields, err := parseFields(splitLines(trailer))

	if err != nil {
		result = append(result, parser.stop(parser.start, err))
		return
	}

	event := parser.end(parser.offset + int64(consumed))
	event.Start = parser.trailerStart
	event.Trailers = fields
	event.TrailerRaw = trailer
	result = append(result, event)
	return
}

// where a head ends: empty lines before the start line belong to it, the first empty line after it ends it
// scanned is how far data was searched, lineStart the start of the line being searched
type headScan struct {
	scanned      int
	lineStart    int
	hasStartLine bool
}

// search the bytes not searched yet; end is the length of the head once the empty line is found, startLine the start line once it is whole, without its line end
func (scan *headScan) next(data []byte) (end int, isFound bool, startLine []byte) {
	for index := scan.scanned; index < len(data); index++ {
		if data[index] != '\n' {
			continue
		}

		line := bytes.TrimSuffix(data[scan.lineStart:index], []byte("\r"))
		scan.lineStart = index + 1

		switch {
		case !scan.hasStartLine && (len(line) > 0):
			scan.hasStartLine = true
			startLine = line
		case scan.hasStartLine && (len(line) == 0):
			scan.scanned = index + 1
			end, isFound = index+1, true
			return
		default:
		}
	}

	scan.scanned = len(data)
	return
}

// where the head of data ends, found is false without its empty line
func HeadEnd(data []byte) (end int, isFound bool) {
	scan := headScan{scanned: 0, lineStart: 0, hasStartLine: false}
	end, isFound, _ = scan.next(data)
	return
}

// the lines of data without their line ends, a last line without one too
func splitLines(data []byte) (lines []string) {
	for line := range strings.Lines(string(data)) {
		lines = append(lines, strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
	}

	return
}

// read a whole head: the empty lines before the start line are skipped, the fields end at the empty line
func parseHead(raw []byte, side Side) (head Head, err error) {
	lines := splitLines(raw)
	index := 0

	for (index < len(lines)) && (lines[index] == "") {
		index++
	}

	if index == len(lines) {
		err = fmt.Errorf("%w: no start line", ErrMalformed)
		return
	}

	head, err = parseStartLine(lines[index], side)

	if err != nil {
		return
	}

	fieldLines := lines[index+1:]

	if end := slices.Index(fieldLines, ""); end >= 0 {
		fieldLines = fieldLines[:end]
	}

	head.Headers, err = parseFields(fieldLines)
	head.Raw = raw
	return
}

// request-line (method SP request-target SP HTTP-version) or status-line (HTTP-version SP status-code SP [reason-phrase])
func parseStartLine(line string, side Side) (head Head, err error) {
	head.Side = side

	if side == RequestSide {
		method, rest, isCut := strings.Cut(line, " ")
		target, version, isVersion := strings.Cut(rest, " ")

		if !isCut || !isVersion || !isToken(method) || (target == "") || strings.ContainsAny(target, " \t") || hasControl(target) {
			err = fmt.Errorf("%w: request line %q", ErrMalformed, truncate([]byte(line)))
			return
		}

		if version == "HTTP/2.0" {
			err = ErrHTTP2
			return
		}

		if !isVersion1(version) {
			err = fmt.Errorf("%w: version %q", ErrMalformed, truncate([]byte(version)))
			return
		}

		head.Method, head.Target, head.Version = method, target, version
		return
	}

	version, rest, _ := strings.Cut(line, " ")
	statusText, reason, _ := strings.Cut(rest, " ")
	status, statusErr := strconv.Atoi(statusText)

	if !isVersion1(version) || (len(statusText) != 3) || (statusErr != nil) || (status < 100) || hasControl(reason) {
		err = fmt.Errorf("%w: status line %q", ErrMalformed, truncate([]byte(line)))
		return
	}

	head.Version, head.Status, head.Reason = version, status, reason
	return
}

// field lines: name, colon, value; a line that starts with white space continues the value before it (obs-fold)
func parseFields(lines []string) (headers []Header, err error) {
	for _, line := range lines {
		if line == "" {
			continue
		}

		if (line[0] == ' ') || (line[0] == '\t') {
			if len(headers) == 0 {
				err = fmt.Errorf("%w: continuation line without a field", ErrMalformed)
				return
			}

			last := &headers[len(headers)-1]
			last.Value = strings.TrimSpace(last.Value + " " + strings.Trim(line, " \t"))
			continue
		}

		name, value, isCut := strings.Cut(line, ":")

		if !isCut || !isToken(name) {
			err = fmt.Errorf("%w: field line %q", ErrMalformed, truncate([]byte(line)))
			return
		}

		headers = append(headers, Header{Name: name, Value: strings.Trim(value, " \t")})
	}

	return
}

// a token of RFC 9110 section 5.6.2, as in methods and field names
func isToken(text string) (isToken bool) {
	if text == "" {
		return
	}

	for index := range len(text) {
		if !isTokenByte(text[index]) {
			return
		}
	}

	isToken = true
	return
}

func isTokenByte(value byte) (isToken bool) {
	switch {
	case
		(value >= 'a') && (value <= 'z'),
		(value >= 'A') && (value <= 'Z'),
		(value >= '0') && (value <= '9'):
		isToken = true
	default:
		isToken = strings.IndexByte("!#$%&'*+-.^_`|~", value) >= 0
	}

	return
}

func hasControl(text string) (hasControl bool) {
	hasControl = strings.ContainsFunc(text, func(character rune) bool {
		return ((character < ' ') && (character != '\t')) || (character == 0x7f)
	})
	return
}

func isVersion1(version string) (isVersion1 bool) {
	isVersion1 = (version == "HTTP/1.1") || (version == "HTTP/1.0")
	return
}

// the bytes of a start line so far, before its line end, can still be one: a method token then a space for a request, HTTP/ for a response
// empty lines before it are skipped by the scan, a lone CR waits for its LF
func isStartLinePrefix(partial []byte, side Side) (isPrefix bool) {
	partial = bytes.TrimSuffix(partial, []byte("\r"))

	if side == ResponseSide {
		length := min(len(partial), len("HTTP/"))
		isPrefix = bytes.Equal(partial[:length], []byte("HTTP/")[:length])
		return
	}

	for index, value := range partial {
		if value == ' ' {
			isPrefix = index > 0
			return
		}

		if !isTokenByte(value) {
			return
		}
	}

	isPrefix = true
	return
}

// a quoted piece of the stream in an error stays short
func truncate(data []byte) (short string) {
	short = string(data[:min(len(data), 64)])
	return
}
