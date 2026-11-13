// SPDX-License-Identifier: AGPL-3.0-only

package http2

import (
	"bytes"
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
	// the header fields of one block a frame event carries, the editor encodes them again
	maxEditHeadBytes int = 1 << 20
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
	// one whole frame of the peer, only with EmitFrames; it comes before the events the frame makes, Frame tells what it is
	FrameEventType EventType = "frame"
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
	Frame       *Frame
}

// one whole frame as it came: its header, Length the payload with the padding (what flow control counts)
// Data is a DATA frame's payload without the padding, Increment a WINDOW_UPDATE's, Priority what a HEADERS frame says when HasPriority, PromiseID a PUSH_PROMISE's stream
// Settings: on a SETTINGS ACK the settings of the other peer that are in effect for this peer's frames from now on
// Block: on the frame that ends a header block (END_HEADERS) the whole block
type Frame struct {
	Type        http2.FrameType
	Flags       http2.Flags
	StreamID    uint32
	Length      uint32
	Data        []byte
	Increment   uint32
	ErrCode     http2.ErrCode
	Priority    http2.PriorityParam
	HasPriority bool
	PromiseID   uint32
	Settings    Settings
	Block       *Block
}

// a whole header block of HEADERS or PUSH_PROMISE and its CONTINUATION frames: every field decoded, IsCut when they were over maxEditHeadBytes and not all are in Fields
type Block struct {
	StreamID    uint32
	IsPush      bool
	PromiseID   uint32
	EndStream   bool
	Priority    http2.PriorityParam
	HasPriority bool
	Fields      []Field
	IsCut       bool
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
// all are every field for the frame events, allSize their size
type headerBlock struct {
	streamID    uint32
	isPush      bool
	promised    uint32
	endStream   bool
	priority    http2.PriorityParam
	hasPriority bool
	fields      []Field
	size        int
	isCut       bool
	start       int64
	all         []Field
	allSize     int
	isAllCut    bool
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
	isFraming     bool
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
// isFraming is true once EmitFrames asked for frame events
type Conn struct {
	isFraming  bool
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

// what a unit of the editor is
type unitKind uint8

const (
	// a DATA frame, or body bytes decerter sends as DATA frames
	dataUnit unitKind = iota
	// a whole header block of HEADERS or PUSH_PROMISE with its CONTINUATION frames
	blockUnit
	// any other frame, sent as it is
	frameUnit
)

// one piece of a side's frames on its way: raw is how it came (nil when decerter builds it), payload the body bytes of DATA without padding
// need is what DATA takes of the windows, seq the number of a header block in its side; isPart is true for the frames of a message (DATA, header blocks)
type unit struct {
	kind      unitKind
	streamID  uint32
	raw       []byte
	payload   []byte
	need      int64
	endStream bool
	block     *Block
	seq       int
	isPart    bool
}

// a message kept back for the rules: its frames, isComplete once END_STREAM came
type keptMessage struct {
	units      []unit
	isComplete bool
}

// one side of a stream in the editor, the frames its peer sends on it
// isOpened is true once the receiver knows the stream (it opened it, or decerter sent its first HEADERS or its PUSH_PROMISE), isEnded once the sender ended or a peer reset it
// window is what the receiver granted decerter on the stream, excess what the sender sent and the receiver did not get counted against it (below 0: got more)
// message is kept back for the rules, held are the later frames behind it or behind the opening of an earlier stream, queue what waits for the window
type streamSide struct {
	isOpened bool
	isEnded  bool
	window   int64
	excess   int64
	message  *keptMessage
	held     []unit
	queue    []unit
}

type editStream struct {
	id    uint32
	sides [2]*streamSide
}

// the frames one peer sends through the editor
// buffer holds the bytes from bufferStart taken but not yet in a whole frame, cursor is where the last frame ended, passedEnd where the bytes that went on already end
// isPassingBlock is true while a header block that started in passed bytes goes on, blockRaw collects the frames of an open block, undecided is a whole block waiting for Keep
// output goes on next, later waits until output is at a frame boundary again; blocks counts the header blocks, sentBlocks the ones that went on as they came in their order
// encoder (table size 0) writes every block once one did not go on in its order; maxFrameSize and initialWindow are the receiver's settings for this side
// window and excess are the connection's, as on a stream; openings are the streams this peer opened that the receiver does not know yet, in order
type editSide struct {
	peer           Peer
	buffer         []byte
	bufferStart    int64
	cursor         int64
	passedEnd      int64
	isPassingBlock bool
	blockRaw       []byte
	undecided      *unit
	output         []byte
	later          []byte
	blocks         int
	sentBlocks     int
	encoder        *hpack.Encoder
	encoded        *bytes.Buffer
	maxFrameSize   uint32
	initialWindow  int64
	window         int64
	excess         int64
	openings       []uint32
}

// the frames of both peers of a conn on their way through decerter, so whole HTTP/2 messages can be kept back, edited or dropped
// it reads no frames itself: the caller gives it the bytes (Take or Pass) and the frame events of a Conn with EmitFrames, then decides on the heads (Keep) and messages (Release, Replace, Drop)
// isTouched is true once a message was kept, the frames of the conn go on whole from then on; it is not safe for concurrent use
type Editor struct {
	sides      [2]*editSide
	streams    map[uint32]*editStream
	lastStream [2]uint32
	maxStreams int
	isTouched  bool
	isStopped  bool
	framed     *bytes.Buffer
	framer     *http2.Framer
	err        error
}

// a message as the rules left it: Fields the head, Body the content; the head or body that did not change go on in the frames they came in
type Edit struct {
	Fields        []Field
	Body          []byte
	IsHeadChanged bool
	IsBodyChanged bool
}
