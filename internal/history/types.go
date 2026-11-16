// SPDX-License-Identifier: AGPL-3.0-only

package history

import (
	"sync"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// the bounds of the history, the oldest flow goes first when one is reached
	DefaultFlows        int   = 10000
	DefaultMessages     int   = 200000
	DefaultPayloadBytes int64 = 64 << 20
	// what one flow may keep, its later messages and bytes are not kept and the flow is marked truncated
	DefaultFlowMessages     int   = 20000
	DefaultFlowPayloadBytes int64 = 1 << 20
	// the HTTP exchanges and the header and body bytes they keep, apart from the payload of the messages; a flow's later exchanges are not kept, its later bodies are cut
	DefaultExchanges         int   = 100000
	DefaultFlowExchanges     int   = 10000
	DefaultExchangeBytes     int64 = 32 << 20
	DefaultFlowExchangeBytes int64 = 1 << 20
	// the distinct values of each http field a flow keeps for the filter
	maxFlowHTTPValues int = 256
	// the bytes a gRPC message boundary counts in the history
	grpcMessageBytes int64 = 16
	// the interim (1xx) heads one exchange keeps, a server that sends them without end does not grow the history
	maxInterimHeads int = 16
	// a head the exchange limits have no room for keeps its start line only, with at most this much of its target
	maxCutTarget int = 256
	// the bytes of the handshake records one direction of a TLS or DTLS flow keeps, counted in the payload limits
	MaxHandshakeBytes int = 16 << 10
)

// how much the history keeps: flows, messages and payload bytes in total and per flow, exchanges and their bytes in total and per flow
type Limits struct {
	Flows             int
	Messages          int
	FlowMessages      int
	PayloadBytes      int64
	FlowPayloadBytes  int64
	Exchanges         int
	FlowExchanges     int
	ExchangeBytes     int64
	FlowExchangeBytes int64
}

// what one direction of a flow sent on, given when it closes
type Counters struct {
	Bytes     int64
	Datagrams int64
}

// values is what the scope filter knew of the flow when it was decided, clientRandom the one of its ClientHello, zero without one
// handshake is by tlsrecord.Direction: its handshake, alert and change cipher spec records in their kept form (tlsrecord.AppendKept), isHandshakeCut
// when a record did not fit
// session comes from the messages once the record layer has it; traffic is by tlsrecord.Direction
// upstreamCookie is the proxy's upstream socket of a flow of run mode, zero in capture mode
type flowRecord struct {
	id             uint64
	cookie         uint64
	upstreamCookie uint64
	values         filter.Values
	clientRandom   [32]byte
	session        tlsrecord.Session
	layer          intercept.Layer
	opened         time.Time
	closed         time.Time
	isOpen         bool
	traffic        [2]api.Traffic
	messageIDs     []uint64
	payloadBytes   int64
	isTruncated    bool
	exchangeIDs    []uint64
	exchangeBytes  int64
	http           *filter.HTTPValues
	handshake      [2][]byte
	isHandshakeCut [2]bool
}

// one exchange of a flow: its request and final response by api.Side, the 1xx responses before it; bytes is what it keeps of heads and bodies
// stream is its HTTP/2 stream, zero for HTTP/1
type exchangeRecord struct {
	id       uint64
	flowID   uint64
	protocol string
	stream   Stream
	messages map[api.Side]*httpRecord
	interim  []api.HTTPMessage
	bytes    int64
}

// the HTTP/2 stream of an exchange: ID, and PromisedBy the stream whose PUSH_PROMISE opened a server push, 0 for any other
type Stream struct {
	ID         uint32
	PromisedBy uint32
}

// one HTTP message: view without StoredLength, body what went on and original what the peer sent when it was edited, both cut by the limits
type httpRecord struct {
	view     api.HTTPMessage
	body     []byte
	original []byte
}

// payload is what went on and original what the peer sent, kept only when they differ; both can be cut short by the limits
type messageRecord struct {
	id             uint64
	flowID         uint64
	direction      tlsrecord.Direction
	layer          intercept.Layer
	time           time.Time
	origin         intercept.Origin
	verdict        intercept.Verdict
	isEdited       bool
	length         int
	originalLength int
	payload        []byte
	original       []byte
}

// the flows in scope of a run and their messages, in memory; order has the flow ids oldest first, which is also ascending
// nextMessageID numbers the observed messages of --decrypt, intercepted ones come with the id of the pipeline
// notify gets an event for every flow, message and change of an exchange, it must not block; it is called without the mutex
type History struct {
	mutex          *sync.RWMutex
	limits         Limits
	flows          map[uint64]*flowRecord
	order          []uint64
	messages       map[uint64]*messageRecord
	exchanges      map[uint64]*exchangeRecord
	nextFlowID     uint64
	nextMessageID  uint64
	nextExchangeID uint64
	payloadBytes   int64
	exchangeBytes  int64
	openFlows      int
	evictedFlows   uint64
	notify         func(event api.Event)
}

// what the HTTP layer knows of a message when it ends: Trailers of a chunked body, Note why it was not taken as a whole
// Edit is set when a rule or an edit of layer http changed it or dropped it: the body appended so far is then its original
type HTTPEnd struct {
	State    api.HTTPState
	Trailers []api.Header
	Note     string
	Edit     *HTTPEdit
}

// what went on instead: Head and URL as the edit wrote them, Body without chunk framing, Verdict drop when nothing went on
type HTTPEdit struct {
	Head    api.HTTPHead
	URL     string
	Body    []byte
	Verdict api.Verdict
}

func DefaultLimits() (limits Limits) {
	limits = Limits{
		Flows:             DefaultFlows,
		Messages:          DefaultMessages,
		FlowMessages:      DefaultFlowMessages,
		PayloadBytes:      DefaultPayloadBytes,
		FlowPayloadBytes:  DefaultFlowPayloadBytes,
		Exchanges:         DefaultExchanges,
		FlowExchanges:     DefaultFlowExchanges,
		ExchangeBytes:     DefaultExchangeBytes,
		FlowExchangeBytes: DefaultFlowExchangeBytes,
	}
	return
}

// a flow of the history for the pcap export: Values are its fields with the session the record layer read, ClientRandom the one of its session, zero without one
// SocketCookie is the socket whose packets the capture keeps for the flow: the proxy's upstream socket of the flow in run mode, the flow's own in capture
// mode; the UDP sessions of one unconnected socket share the flow's cookie, each has an upstream socket of its own
type ExportFlow struct {
	Flow         api.Flow
	Values       filter.Values
	ClientRandom [32]byte
	SocketCookie uint64
	Messages     []ExportMessage
}

// a message and what the history kept of the payload that went on, shared with the history and never changed
type ExportMessage struct {
	Message api.Message
	Payload []byte
}

// a message of a flow's direction: Payload is what went on, Original what the peer sent when it was changed (nil otherwise), both as the history kept them
type StreamMessage struct {
	Message  api.Message
	Payload  []byte
	Original []byte
}
