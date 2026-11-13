// SPDX-License-Identifier: AGPL-3.0-only

package http1

import (
	"strings"
)

const (
	// a head longer than this stops its side, nothing after it is parsed
	MaxHeadBytes int = 64 << 10
	// a chunk-size line with its extensions and the trailer section of a chunked body
	maxChunkLineBytes int = 4 << 10
	maxTrailerBytes   int = 64 << 10
	// the longest Content-Length and chunk size the parser takes, more digits are malformed
	maxSizeDigits int = 18
)

// the side of a conn a message comes from, the numbers are the ones of tlsrecord.Direction
type Side uint8

const (
	// what the client sends: requests
	RequestSide Side = 0
	// what the server sends: responses
	ResponseSide Side = 1
)

// one header field as it came: the name with its case, the value without the white space around it
type Header struct {
	Name  string
	Value string
}

// the start line and the header fields of a message; Raw is every byte of it as it came, empty lines before the start line and the empty line after the fields included
// a request has Method, Target and Version, a response Version, Status and Reason
type Head struct {
	Side    Side
	Method  string
	Target  string
	Version string
	Status  int
	Reason  string
	Headers []Header
	Raw     []byte
}

// how the body of a message is delimited
type Framing string

const (
	// no body: a request without Content-Length or Transfer-Encoding, a response to HEAD, 1xx, 204, 304
	NoneFraming Framing = "none"
	// Content-Length bytes
	LengthFraming Framing = "length"
	// Transfer-Encoding chunked
	ChunkedFraming Framing = "chunked"
	// a response without a length: the body ends with the stream
	CloseFraming Framing = "close"
)

// what the parser found in the bytes of a side
type EventType string

const (
	// the first byte of a message at Start
	BeginEventType EventType = "begin"
	// the head of the message is whole, Head, Framing and Length tell what comes; IsInterim marks a 1xx response, its end follows at once
	HeadEventType EventType = "head"
	// body bytes: Data is the content without the chunk framing, empty for a chunk-size line or the line end after a chunk
	BodyEventType EventType = "body"
	// the message is over: IsComplete is false when the stream ended or the side stopped before; TrailerRaw is the trailer section of a chunked body with its empty line
	EndEventType EventType = "end"
	// Err tells why the side stopped parsing; the bytes from Start on are not read, the message that was open has no end event
	StopEventType EventType = "stop"
)

// one event of a side; Start and End are the offsets in the stream of the side of the bytes it covers, every byte of the stream is in exactly one begin..end or stop range
// Index names the exchange the message belongs to: a request and the responses to it share it; Data is part of the bytes given to Feed and only valid until the next call
type Event struct {
	Type       EventType
	Index      int
	Start      int64
	End        int64
	Head       Head
	Framing    Framing
	Length     int64
	IsInterim  bool
	Data       []byte
	Trailers   []Header
	TrailerRaw []byte
	IsComplete bool
	Err        error
}

// where the parser of a side is in its stream
type parseState uint8

const (
	// between messages, the next byte begins one
	idleState parseState = iota
	headState
	lengthBodyState
	chunkSizeState
	chunkDataState
	chunkEndState
	trailerState
	closeBodyState
	stoppedState
)

// one side of a conn; offset is the stream offset of the next byte, start the one of the open message
// head collects the head, scanned is how far it was searched for its end, lineStart where the line being searched starts, hasStartLine whether a non-empty line came
// line collects a chunk-size line or the line end after a chunk, trailer the trailer section; remaining are the body or chunk bytes still to come
// pendingStop stops the side at its next Feed, the other side switched the protocol
type parser struct {
	side         Side
	state        parseState
	offset       int64
	start        int64
	index        int
	head         []byte
	scanned      int
	lineStart    int
	hasStartLine bool
	line         []byte
	trailer      []byte
	trailerStart int64
	remaining    int64
	pendingStop  error
}

// a request whose final response has not come yet
type pendingRequest struct {
	index  int
	method string
}

// the HTTP/1 parser of one tcp stream: the requests the client sends and the responses the server sends, paired in their order
// a response needs the method of its request (HEAD, CONNECT), so both sides are one conn; it is not safe for concurrent use, the caller locks it
type Conn struct {
	parsers   [2]parser
	pending   []pendingRequest
	nextIndex int
}

// a whole message as it came, assembled from the events of its side: Body is the content without the chunk framing, TrailerRaw the trailer section of a chunked body, Raw every byte of the message
type Message struct {
	Head       Head
	Framing    Framing
	Body       []byte
	TrailerRaw []byte
	Raw        []byte
}

// what goes on for an edited form: Wire is the message on the wire, Head and Body what it says; Err is set when the form is no message and went on as it was written
type Rebuilt struct {
	Wire []byte
	Head Head
	Body []byte
	Err  error
}

// the first value of a header field, names are compared without case
func (head Head) Get(name string) (value string, found bool) {
	for _, header := range head.Headers {
		if strings.EqualFold(header.Name, name) {
			value = header.Value
			found = true
			return
		}
	}

	return
}

// every value of a header field in their order, a list value (a, b) counts as its elements
func (head Head) Values(name string) (values []string) {
	for _, header := range head.Headers {
		if !strings.EqualFold(header.Name, name) {
			continue
		}

		for element := range strings.SplitSeq(header.Value, ",") {
			element = strings.TrimSpace(element)

			if element != "" {
				values = append(values, element)
			}
		}
	}

	return
}

// the editable form: the head as it came and the body without its chunk framing
func (message Message) Form() (form []byte) {
	form = make([]byte, 0, len(message.Head.Raw)+len(message.Body))
	form = append(form, message.Head.Raw...)
	form = append(form, message.Body...)
	return
}
