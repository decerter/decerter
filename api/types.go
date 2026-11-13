// SPDX-License-Identifier: MIT

package api

import (
	"time"
)

// the request and response bodies of the control API, as api/openapi.yaml describes them; this file and the spec are MIT, so any client can use them
// JSON names are snake_case, times are RFC 3339 with nanoseconds, payloads are lowercase hex plus an escaped text form

const (
	// every path of this version of the API starts with it, a breaking change goes to /api/v2
	BasePath string = "/api/v1"
	// the host name clients put in the URL, the server does not look at it: curl --unix-socket /run/decerter/api.sock http://decerter/api/v1/status
	HostName string = "decerter"
)

// what the proxy does with the flows in scope
type Processing string

const (
	// relayed unchanged, the history has the flows but no payloads
	RelayProcessing Processing = "relay"
	// relayed unchanged, the decrypted TLS and DTLS application data is in the history (decerter run --decrypt)
	DecryptProcessing Processing = "decrypt"
	// every message goes through the rules and can be held (decerter run --intercept)
	InterceptProcessing Processing = "intercept"
	// nothing is redirected, the packets of the flows in scope are recorded (decerter capture)
	RecordProcessing Processing = "record"
)

// what decerter does: run redirects the flows through the proxy, capture records their packets
type Mode string

const (
	RunMode     Mode = "run"
	CaptureMode Mode = "capture"
)

// how the packets of a capture or a pcap export are written
type CaptureFormat string

const (
	// the packets as they were captured, each TLS and DTLS session behind a Decryption Secrets Block with its key log lines
	DSBCaptureFormat CaptureFormat = "dsb"
	// synthesized packets with the decrypted payload, no secrets
	PlaintextCaptureFormat CaptureFormat = "plaintext"
)

type CaptureState string

const (
	RunningCaptureState CaptureState = "running"
	StoppedCaptureState CaptureState = "stopped"
)

// the direction of a message, or the directions a rule or the hold queue takes (both only there)
type Direction string

const (
	// client to server
	UpDirection Direction = "up"
	// server to client
	DownDirection Direction = "down"
	BothDirection Direction = "both"
)

// what one message of a flow is
type Layer string

const (
	// one read of a plain tcp stream
	TCPLayer Layer = "tcp"
	// the application data of one TLS record
	TLSLayer Layer = "tls"
	// one udp datagram
	UDPLayer Layer = "udp"
	// the application data of one DTLS record
	DTLSLayer Layer = "dtls"
	// one whole HTTP/1 request or response of an exchange: the head as it came and the body without its chunk framing; only rules and holds name it, the messages of a flow are records
	HTTPLayer Layer = "http"
)

// which message of an exchange
type Side string

const (
	RequestSide  Side = "request"
	ResponseSide Side = "response"
)

// how the body of an HTTP message is delimited
type Framing string

const (
	NoneFraming    Framing = "none"
	LengthFraming  Framing = "length"
	ChunkedFraming Framing = "chunked"
	// the response body ends with the stream
	CloseFraming Framing = "close"
	// HTTP/2: the body comes in DATA frames, END_STREAM ends it
	FramesFraming Framing = "frames"
)

// how far an HTTP message came
type HTTPState string

const (
	// the head is there, the body is still coming
	HeadHTTPState HTTPState = "head"
	// the whole message went on
	CompleteHTTPState HTTPState = "complete"
	// the stream ended, was reset or stopped being HTTP before the message did
	IncompleteHTTPState HTTPState = "incomplete"
)

type FlowState string

const (
	OpenFlowState   FlowState = "open"
	ClosedFlowState FlowState = "closed"
)

// how a message got into the history
type Origin string

const (
	// it went through the rules (and the hold queue)
	RulesOrigin Origin = "rules"
	// it went on before the rules could see it, the TLS secrets came too late
	PassedOrigin Origin = "passed"
	// a decrypted copy of what was relayed unchanged (--decrypt)
	ObservedOrigin Origin = "observed"
)

type Verdict string

const (
	ForwardVerdict Verdict = "forward"
	DropVerdict    Verdict = "drop"
)

// how a value of a request is written
type ValueType string

const (
	// the UTF-8 bytes of the string as they are
	TextValueType ValueType = "text"
	// two hex digits per byte, white space is ignored
	HexValueType ValueType = "hex"
	// only the find value of a rule: an RE2 expression over the bytes, the replace value is its template ($1, ${name}, $$)
	RegexValueType ValueType = "regex"
)

type EventType string

const (
	FlowOpenedEventType       EventType = "flow_opened"
	FlowClosedEventType       EventType = "flow_closed"
	MessageEventType          EventType = "message"
	HeldEventType             EventType = "held"
	HoldEditedEventType       EventType = "hold_edited"
	HoldReleasedEventType     EventType = "hold_released"
	RuleAddedEventType        EventType = "rule_added"
	RuleDeletedEventType      EventType = "rule_deleted"
	InterceptChangedEventType EventType = "intercept_changed"
	// an exchange started, got its response, or one of its messages ended or was edited
	ExchangeEventType EventType = "exchange"
	// the last event of a stream whose client read too slowly, the server ends the stream after it
	OverflowEventType EventType = "overflow"
)

// GET /api/v1/status
type Status struct {
	Mode       Mode           `json:"mode"`
	Processing Processing     `json:"processing"`
	Version    string         `json:"version"`
	Platform   string         `json:"platform"`
	Scope      string         `json:"scope"`
	TLSSecrets bool           `json:"tls_secrets"`
	Started    time.Time      `json:"started"`
	Intercept  InterceptState `json:"intercept"`
	Rules      int            `json:"rules"`
	History    HistoryStatus  `json:"history"`
	Captures   CaptureStatus  `json:"captures"`
}

// the captures of the API: Available is true when decerter captures packets (decerter capture, and decerter run with the API: the proxy's upstream sockets), Stored counts the kept files, running ones included, and Size their bytes
type CaptureStatus struct {
	Available bool          `json:"available"`
	Running   int           `json:"running"`
	Stored    int           `json:"stored"`
	Size      int64         `json:"size"`
	Limits    CaptureLimits `json:"limits"`
}

// how many captures are kept and may run at once, and the bytes all their files may hold; the oldest stopped capture is removed to make room
type CaptureLimits struct {
	Captures int   `json:"captures"`
	Running  int   `json:"running"`
	Size     int64 `json:"size"`
}

// what the flow history holds now and its bounds; the oldest flows go first when a bound is reached
// ExchangeBytes are the header and body bytes the exchanges keep, counted apart from the payload of the messages
type HistoryStatus struct {
	Flows         int           `json:"flows"`
	OpenFlows     int           `json:"open_flows"`
	Messages      int           `json:"messages"`
	PayloadBytes  int64         `json:"payload_bytes"`
	Exchanges     int           `json:"exchanges"`
	ExchangeBytes int64         `json:"exchange_bytes"`
	EvictedFlows  uint64        `json:"evicted_flows"`
	Limits        HistoryLimits `json:"limits"`
}

type HistoryLimits struct {
	Flows             int   `json:"flows"`
	Messages          int   `json:"messages"`
	FlowMessages      int   `json:"flow_messages"`
	PayloadBytes      int64 `json:"payload_bytes"`
	FlowPayloadBytes  int64 `json:"flow_payload_bytes"`
	Exchanges         int   `json:"exchanges"`
	FlowExchanges     int   `json:"flow_exchanges"`
	ExchangeBytes     int64 `json:"exchange_bytes"`
	FlowExchangeBytes int64 `json:"flow_exchange_bytes"`
}

// GET /api/v1/status and PUT /api/v1/intercept; Available is false unless decerter runs with --intercept, holding and rules need the intercept pipeline
// Layer empty holds the messages of every record layer (tcp, tls, udp, dtls), http whole HTTP/1 messages instead
type InterceptState struct {
	Available          bool      `json:"available"`
	Enabled            bool      `json:"enabled"`
	Filter             string    `json:"filter"`
	Direction          Direction `json:"direction"`
	Layer              Layer     `json:"layer,omitzero"`
	HoldTimeoutSeconds float64   `json:"hold_timeout_seconds"`
	Held               int       `json:"held"`
}

// PUT /api/v1/intercept: Filter empty holds every message of the direction, Direction empty is up, Layer empty every record layer
type InterceptRequest struct {
	Enabled   bool      `json:"enabled"`
	Filter    string    `json:"filter,omitzero"`
	Direction Direction `json:"direction,omitzero"`
	Layer     Layer     `json:"layer,omitzero"`
}

type Process struct {
	PID     uint32 `json:"pid"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Comm    string `json:"comm"`
	Cmdline string `json:"cmdline"`
	Exe     string `json:"exe"`
}

// the ClientHello the client sent and, once the record layer has seen the ServerHello, the session; ClientRandom names the session in a key log
type TLSInfo struct {
	OfferedVersion string   `json:"offered_version"`
	ServerName     string   `json:"server_name"`
	OfferedALPN    []string `json:"offered_alpn"`
	ClientRandom   string   `json:"client_random,omitzero"`
	Version        string   `json:"version,omitzero"`
	CipherSuite    string   `json:"cipher_suite,omitzero"`
	ALPN           string   `json:"alpn,omitzero"`
}

// one direction of a flow: Bytes and Datagrams (udp) are what the proxy sent on, known when the flow is closed; Messages counts its messages in the history
type Traffic struct {
	Bytes     int64 `json:"bytes"`
	Datagrams int64 `json:"datagrams"`
	Messages  int   `json:"messages"`
}

// one flow of the history: a redirected tcp connection or udp session in scope
// Layer is the layer of its messages, empty until it has one; Truncated is true when messages or payload bytes of it were not kept
type Flow struct {
	ID           uint64    `json:"id"`
	Protocol     string    `json:"protocol"`
	State        FlowState `json:"state"`
	Opened       time.Time `json:"opened"`
	Closed       time.Time `json:"closed,omitzero"`
	Client       string    `json:"client"`
	Destination  string    `json:"destination"`
	Cookie       uint64    `json:"cookie"`
	Process      Process   `json:"process"`
	TLS          *TLSInfo  `json:"tls,omitzero"`
	Layer        Layer     `json:"layer,omitzero"`
	Up           Traffic   `json:"up"`
	Down         Traffic   `json:"down"`
	PayloadBytes int64     `json:"payload_bytes"`
	Truncated    bool      `json:"truncated"`
}

// GET /api/v1/flows, newest first; NextCursor is empty on the last page
type FlowList struct {
	Flows      []Flow `json:"flows"`
	NextCursor string `json:"next_cursor,omitzero"`
}

// one message of a flow without its payload
// Length is what went on (0 for a drop), OriginalLength what the peer sent; StoredLength is how much of the payload the history kept
type Message struct {
	ID             uint64    `json:"id"`
	FlowID         uint64    `json:"flow_id"`
	Direction      Direction `json:"direction"`
	Layer          Layer     `json:"layer"`
	Time           time.Time `json:"time"`
	Origin         Origin    `json:"origin"`
	Verdict        Verdict   `json:"verdict"`
	Edited         bool      `json:"edited"`
	Length         int       `json:"length"`
	OriginalLength int       `json:"original_length"`
	StoredLength   int       `json:"stored_length"`
}

// GET /api/v1/flows/{id}/messages, oldest first
type MessageList struct {
	Messages   []Message `json:"messages"`
	NextCursor string    `json:"next_cursor,omitzero"`
}

// a window of a payload: Offset and Length are the bytes in it, Total what there is; Escaped keeps printable ASCII and writes \n, \r, \t, \\ and \xNN for the rest
type Payload struct {
	Offset  int    `json:"offset"`
	Length  int    `json:"length"`
	Total   int    `json:"total"`
	Hex     string `json:"hex"`
	Escaped string `json:"escaped"`
}

// GET /api/v1/messages/{id}: Payload is what went on, Original what the peer sent when a rule or an edit changed it, the same window of both
type MessageDetail struct {
	Message
	Payload  Payload  `json:"payload"`
	Original *Payload `json:"original,omitzero"`
}

// a held message waiting for forward, drop or the timeout; its id is the message id
// Payload is the whole payload that goes on when it is forwarded, left out in events; a hold of layer http is a whole HTTP message of the exchange ExchangeID
type Hold struct {
	ID             uint64    `json:"id"`
	FlowID         uint64    `json:"flow_id"`
	ExchangeID     uint64    `json:"exchange_id,omitzero"`
	Direction      Direction `json:"direction"`
	Layer          Layer     `json:"layer"`
	HeldAt         time.Time `json:"held_at"`
	Deadline       time.Time `json:"deadline"`
	Edited         bool      `json:"edited"`
	Length         int       `json:"length"`
	OriginalLength int       `json:"original_length"`
	Payload        *Payload  `json:"payload,omitzero"`
}

// GET /api/v1/holds, oldest first
type HoldList struct {
	Holds []Hold `json:"holds"`
}

// a value of a request: text, hex, or for the find value of a rule a regex
type Value struct {
	Type  ValueType `json:"type"`
	Value string    `json:"value"`
}

// PUT /api/v1/holds/{id}: the new payload, text or hex
type EditRequest struct {
	Payload Value `json:"payload"`
}

// POST /api/v1/rules: every occurrence of Find in a message of the direction, layer and filter becomes Replace
// Direction empty is both, Layer empty is every record layer (http has to be named), Filter empty every flow
type RuleRequest struct {
	Filter    string    `json:"filter,omitzero"`
	Direction Direction `json:"direction,omitzero"`
	Layer     Layer     `json:"layer,omitzero"`
	Find      Value     `json:"find"`
	Replace   Value     `json:"replace"`
}

// a rule of the API, Hits counts the messages it changed
type Rule struct {
	ID        uint64    `json:"id"`
	Created   time.Time `json:"created"`
	Filter    string    `json:"filter"`
	Direction Direction `json:"direction"`
	Layer     Layer     `json:"layer,omitzero"`
	Find      Value     `json:"find"`
	Replace   Value     `json:"replace"`
	Hits      uint64    `json:"hits"`
}

// GET /api/v1/rules, in the order they run
type RuleList struct {
	Rules []Rule `json:"rules"`
}

// one event of GET /api/v1/events, the data of a server-sent event whose event name is Type; Seq counts the events of the server
// the field of the type is set: Flow for flow_*, Message for message (no payload), Hold for held and hold_* (no payload, Reason for hold_released), Rule for rule_*, Intercept for intercept_changed,
// Exchange for exchange (no bodies); Reason for overflow
type Event struct {
	Seq       uint64          `json:"seq"`
	Type      EventType       `json:"type"`
	Time      time.Time       `json:"time"`
	Flow      *Flow           `json:"flow,omitzero"`
	Message   *Message        `json:"message,omitzero"`
	Exchange  *Exchange       `json:"exchange,omitzero"`
	Hold      *Hold           `json:"hold,omitzero"`
	Rule      *Rule           `json:"rule,omitzero"`
	Intercept *InterceptState `json:"intercept,omitzero"`
	Reason    string          `json:"reason,omitzero"`
}

// one header field as it came: the name with its case, the value without the white space around it; fields keep their order
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// the start line and the fields of an HTTP message: a request has method, target and version, a response version, status and reason
type HTTPHead struct {
	Method  string   `json:"method,omitzero"`
	Target  string   `json:"target,omitzero"`
	Version string   `json:"version"`
	Status  int      `json:"status,omitzero"`
	Reason  string   `json:"reason,omitzero"`
	Headers []Header `json:"headers"`
}

// one HTTP message of an exchange as it went on, without its body (read it with GET /api/v1/exchanges/{id}/body)
// URL is the scheme of the flow, the Host field and the target of a request; BodyLength is the body that went on without its chunk framing, StoredLength what the history kept of it
// Edited is true when a rule or an edit of layer http changed the message, Original is then its head as it came and OriginalBodyLength its body; Verdict drop is a message that did not go on
// Note says why the HTTP layer did not take the message as a whole: too large, too slow, or the stream stopped being HTTP/1; for HTTP/2 also a reset, a GOAWAY or that rules skip it
// GRPCMessages are the length-prefixed messages of a gRPC body (HTTP/2 with content-type application/grpc…), at most 1000
type HTTPMessage struct {
	HTTPHead
	URL                string        `json:"url,omitzero"`
	Time               time.Time     `json:"time"`
	Framing            Framing       `json:"framing"`
	State              HTTPState     `json:"state"`
	Trailers           []Header      `json:"trailers,omitzero"`
	BodyLength         int           `json:"body_length"`
	OriginalBodyLength int           `json:"original_body_length"`
	StoredLength       int           `json:"stored_length"`
	Edited             bool          `json:"edited"`
	Verdict            Verdict       `json:"verdict,omitzero"`
	Original           *HTTPHead     `json:"original,omitzero"`
	Note               string        `json:"note,omitzero"`
	GRPCMessages       []GRPCMessage `json:"grpc_messages,omitzero"`
}

// one length-prefixed message of a gRPC body: Offset is the body offset of its 5-byte prefix, Length the message bytes after the prefix as the prefix says
// (a message whose Offset+5+Length is past the body length was cut short), Compressed the flag of the prefix; the message is not decoded
type GRPCMessage struct {
	Offset     int64  `json:"offset"`
	Length     uint32 `json:"length"`
	Compressed bool   `json:"compressed,omitzero"`
}

// one HTTP request and its response on a flow, in the order the requests came; Interim are the 1xx responses before the final one
// a response without a request (the server spoke first) is an exchange of its own
// HTTP/2: StreamID is the stream of the exchange, PromiseStreamID the stream whose PUSH_PROMISE made it a server push (its request is the one the server promised)
type Exchange struct {
	ID              uint64        `json:"id"`
	FlowID          uint64        `json:"flow_id"`
	Protocol        string        `json:"protocol"`
	StreamID        uint32        `json:"stream_id,omitzero"`
	PromiseStreamID uint32        `json:"promise_stream_id,omitzero"`
	Request         *HTTPMessage  `json:"request,omitzero"`
	Interim         []HTTPMessage `json:"interim,omitzero"`
	Response        *HTTPMessage  `json:"response,omitzero"`
}

// GET /api/v1/flows/{id}/exchanges, oldest first
type ExchangeList struct {
	Exchanges  []Exchange `json:"exchanges"`
	NextCursor string     `json:"next_cursor,omitzero"`
}

// GET /api/v1/exchanges/{id}/body: a window of the body of one side without its chunk framing, Payload what went on, Original what the peer sent when it was edited
type ExchangeBody struct {
	ExchangeID uint64   `json:"exchange_id"`
	Side       Side     `json:"side"`
	Payload    Payload  `json:"payload"`
	Original   *Payload `json:"original,omitzero"`
}

// POST /api/v1/captures: Filter empty captures every flow in scope, Plaintext writes synthesized decrypted packets instead of the packets and their secrets
type CaptureRequest struct {
	Filter    string `json:"filter,omitzero"`
	Plaintext bool   `json:"plaintext,omitzero"`
}

// a capture of the API; Size is the bytes of its file so far, DroppedPackets the packets it lost because it fell behind
// Reason says why a capture stopped that nobody stopped: the size limit, an error, decerter stopping
type Capture struct {
	ID             uint64        `json:"id"`
	Filter         string        `json:"filter"`
	Format         CaptureFormat `json:"format"`
	State          CaptureState  `json:"state"`
	Started        time.Time     `json:"started"`
	Stopped        time.Time     `json:"stopped,omitzero"`
	Size           int64         `json:"size"`
	DroppedPackets uint64        `json:"dropped_packets"`
	Reason         string        `json:"reason,omitzero"`
}

// GET /api/v1/captures, oldest first
type CaptureList struct {
	Captures []Capture `json:"captures"`
}

// the body of every error response
type Error struct {
	Error string `json:"error"`
}
