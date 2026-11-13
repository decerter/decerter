// SPDX-License-Identifier: AGPL-3.0-only

package http2

import (
	"io"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// the client connection preface (RFC 9113 section 3.4), the first bytes of every HTTP/2 connection
	Preface string = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	// the fixed header of every frame
	frameHeaderLength int = 9
	// what SETTINGS_HEADER_TABLE_SIZE and SETTINGS_MAX_FRAME_SIZE are until a peer says otherwise
	defaultHeaderTableSize uint32 = 4096
	defaultMaxFrameSize    uint32 = 16384
	// the header fields of one head kept, later ones are still decoded to keep the dynamic table in step but not shown
	MaxHeadBytes int = 64 << 10
	// a header field name or value longer than this stops the conn, the decoder would have to buffer it whole
	maxStringBytes int = 1 << 20
	// the open streams of a conn followed at once, a stream over it is not shown
	DefaultMaxStreams int = 1000
	// the gRPC message boundaries listed per message, the rest are not
	MaxGRPCMessages int = 1000
	// the media type of gRPC, application/grpc+proto and the other subtypes start with it
	grpcContentType string = "application/grpc"
)

// the peer that sent a stream of frames, the numbers are the ones of tlsrecord.Direction
type Peer uint8

const (
	ClientPeer Peer = 0
	ServerPeer Peer = 1
)

// the side of an exchange a message belongs to: the request (a server push's comes from the server in its PUSH_PROMISE) or the response
type Side uint8

const (
	RequestSide  Side = 0
	ResponseSide Side = 1
)

// one header field as it was decoded, pseudo-header fields (:method, :path, :status…) included
type Field struct {
	Name  string
	Value string
}

// the fields of one header block: the pseudo-header fields of a request (Method, Scheme, Authority, Path, Protocol) or of a response (Status, 0 when it is missing or no number)
// Fields are all of them in the order they came; IsCut is true when they were over MaxHeadBytes and the later ones are not in Fields
type Head struct {
	Method    string
	Scheme    string
	Authority string
	Path      string
	Protocol  string
	Status    int
	Fields    []Field
	IsCut     bool
}

// one length-prefixed message of a gRPC body: Offset is the body offset of its 5-byte prefix, Length the message bytes after it as the prefix says
type GRPCMessage struct {
	Offset       int64
	Length       uint32
	IsCompressed bool
}

// what the conn found in the frames of a peer
type EventType string

const (
	// a whole head of a message: a request, a response, a 1xx response before it (IsInterim) or the request of a server push (PromisedBy is the stream of its PUSH_PROMISE)
	HeadEventType EventType = "head"
	// body bytes of a message from one DATA frame without its padding, GRPC the gRPC messages whose prefix is in them
	BodyEventType EventType = "body"
	// the message is over: IsComplete is false when the stream or the connection ended first, Trailers are the fields of a header block after the body, Note says what happened
	EndEventType EventType = "end"
	// the stream is done, no more events name it; HasResponse is false when no final response head came, Note then says why
	CloseEventType EventType = "close"
	// a stream over the max streams of the conn is not followed, told once per conn
	SkipEventType EventType = "skip"
	// Err tells why the conn stopped parsing; every open message got its end and every stream its close event before
	StopEventType EventType = "stop"
)

// one event; Start and End are the offsets in the stream of the peer of the frames it comes from, Data is a copy
// EndsMessage is true for a head whose frame had END_STREAM (or a promised request): its end event follows at once, there is no body
type Event struct {
	Type        EventType
	StreamID    uint32
	PromisedBy  uint32
	Side        Side
	Start       int64
	End         int64
	Head        Head
	IsInterim   bool
	EndsMessage bool
	Data        []byte
	GRPC        []GRPCMessage
	Trailers    []Field
	IsComplete  bool
	HasResponse bool
	Note        string
	Err         error
}

// the settings of a peer as {id: value}, only the ones it sent
type Settings map[http2.SettingID]uint32

// where a message of a stream is
type messageState uint8

const (
	// no final head yet
	waitingState messageState = iota
	// the head came, body or trailers may follow
	bodyState
	endedState
)

// one message of a stream: bodyLength the body bytes so far, splitter the gRPC framing of its body when isGRPC
type message struct {
	state      messageState
	isGRPC     bool
	splitter   grpcSplitter
	bodyLength int64
}

// one stream of the conn, promisedBy the stream of the PUSH_PROMISE of a server push; hasResponse is true once a final response head came
type stream struct {
	id          uint32
	promisedBy  uint32
	messages    [2]message
	hasResponse bool
}

// the header block being read: from a HEADERS frame (isPush false) or a PUSH_PROMISE (promised is its new stream), with its CONTINUATION frames
// size counts the decoded fields kept, start is the stream offset of its first frame
type headerBlock struct {
	streamID  uint32
	isPush    bool
	promised  uint32
	endStream bool
	fields    []Field
	size      int
	isCut     bool
	start     int64
}

// the frames one peer sends: buffer holds what came of the next frames, offset is the stream offset of buffer[0]
// acknowledged are the other peer's settings this peer acknowledged, pending the ones it did not yet; its frames and header blocks keep to the largest of them
type reader struct {
	peer          Peer
	buffer        []byte
	offset        int64
	isPrefaceRead bool
	source        *frameSource
	framer        *http2.Framer
	decoder       *hpack.Decoder
	block         *headerBlock
	acknowledged  Settings
	pending       []Settings
}

// hands the framer exactly the bytes of one whole frame, so its reads never wait
type frameSource struct {
	data []byte
}

// the gRPC framing of a body: header collects a 5-byte prefix (have bytes of it, headerStart its body offset), remaining are the message bytes still to come
// count is the messages listed, isCut is true once more came than MaxGRPCMessages
type grpcSplitter struct {
	header      [5]byte
	have        int
	headerStart int64
	remaining   int64
	count       int
	isCut       bool
}

// the HTTP/2 reader of one tcp stream: the frames of both peers, the streams they open and the messages on them
// it only reads, nothing it does changes the bytes; it is not safe for concurrent use, the caller locks it
// lastStream is the highest stream each peer opened, a stream at or below it that is not in streams is closed (or skipped)
type Conn struct {
	readers    [2]*reader
	streams    map[uint32]*stream
	lastStream [2]uint32
	maxStreams int
	isSkipped  bool
	err        error
}

func (source *frameSource) Read(buffer []byte) (count int, err error) {
	if len(source.data) == 0 {
		err = io.EOF
		return
	}

	count = copy(buffer, source.data)
	source.data = source.data[count:]
	return
}

// the first value of a header field, names are compared without case
func (head Head) Get(name string) (value string, found bool) {
	for _, field := range head.Fields {
		if strings.EqualFold(field.Name, name) {
			value = field.Value
			found = true
			return
		}
	}

	return
}
