// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	v1 "github.com/decerter/decerter/api"
)

const (
	// what a decode reads of a payload, the rest is left out and the result is truncated
	MaxInputBytes int = 1 << 20
	// the nodes of one tree, how deep they nest and the bytes of their strings; a tree that reaches one stops growing and is truncated
	MaxNodes       int = 10000
	MaxDepth       int = 32
	MaxOutputBytes int = 4 << 20
	// the bytes one value shows of a field it writes as hex or base64 (a signature, unknown rdata), the node still spans the whole field
	maxValueBytes int = 256
	// the bytes a node costs in the output besides its strings: offsets, the JSON names, the brackets
	nodeOverheadBytes int = 64
	// sniffing alone takes a protocol from this score on; a hint of the context or a port needs only more than 0
	sniffThreshold int = 50
	// the protocol of a payload no decoder took, as= takes it too
	RawProtocol string = "raw"
	// \xNN of a byte the last pass finds outside printable ASCII
	hexDigits string = "0123456789abcdef"
	// the bytes one value shows of a text field (a protobuf string, a WebSocket text frame), the node still spans the whole field
	maxTextBytes int = 1024
	// the bytes a decoder inflates of one compressed payload (gRPC gzip, WebSocket permessage-deflate)
	maxInflatedBytes int = 1 << 20
)

// how a payload came, which decides its framing
type Transport string

const (
	// one udp datagram or the application data of one DTLS record: one PDU
	DatagramTransport Transport = "datagram"
	// one read of a tcp stream or the application data of one TLS record: PDUs with their own framing, maybe several or only a part of one
	StreamTransport Transport = "stream"
	// an HTTP body without its chunk framing: one PDU
	BodyTransport Transport = "body"
)

// what is known about a payload besides its bytes: the layer and port of its flow, the TLS ALPN, and for an HTTP body the fields of its message
// ContentType, Method, Target and Encoding are only set for a body; Target is the request target of the exchange, Encoding its grpc-encoding
// Upgrade is the protocol an HTTP/1 Upgrade (101) switched the flow to, for a message after it, or the :protocol of an HTTP/2 extended CONNECT for its body;
// Extensions is the Sec-WebSocket-Extensions the server answered it with; Handshake is set for the handshake records the history kept of a TLS or DTLS flow
type Context struct {
	Transport   Transport
	Layer       v1.Layer
	Direction   v1.Direction
	ServerPort  uint16
	ALPN        string
	ContentType string
	Upgrade     string
	Method      string
	Target      string
	Encoding    string
	Extensions  string
	Handshake   bool
}

// a port a protocol is known by, on a record layer (tcp, tls, udp, dtls)
type Port struct {
	Layer  v1.Layer
	Number uint16
}

// one protocol of the registry: Protocol is its name in as= and the first part of its field names, Title its long name
// hint gives a reason when the context names the protocol (a content type, an ALPN, an Upgrade), empty otherwise
// sniff scores the bytes from 0 (not this protocol) to 100; decode adds the nodes and the summary to the tree
// fromTarget finds the PDU in a request target when the body is empty (DoH GET ?dns=), nil when the protocol has none there
// a protocol that needs bytes of more than one message (TCP reassembly) will get a frame function here that tells the length of a PDU from its first bytes
type decoder struct {
	Protocol   string
	Title      string
	Ports      []Port
	hint       func(context Context) (reason string)
	sniff      func(data []byte, context Context) (score int)
	decode     func(tree *Tree, data []byte, context Context)
	fromTarget func(target string) (data []byte, found bool)
}

// a protocol that might be the payload's and why
type candidate struct {
	Protocol string
	Basis    v1.DecodeBasis
	Reason   string
	Score    int
}

// the tree of one decode while it grows: count, size and isFull keep it within the limits, sink takes the nodes past them and keeps none
// errors counts the nodes with an error, sniffing scores a payload by it
type Tree struct {
	roots   []*node
	count   int
	size    int
	isFull  bool
	errors  int
	summary []string
	sink    *node
}

// one field: offset and length are bytes of the payload, mask the bits of a field smaller than its bytes
type node struct {
	name     string
	label    string
	value    string
	err      string
	offset   int
	length   int
	mask     uint32
	depth    int
	children []*node
}

// a DNS message being read: data is the message alone, base its offset in the payload, isMulticast for mDNS (the top bit of a class is a flag there)
// rcode is the reply code of its header, EDNS extends it
type dnsMessage struct {
	data        []byte
	base        int
	isMulticast bool
	rcode       uint8
}

// the names of the values of a field, unknown formats a value it has no name for
type nameTable struct {
	names   map[uint16]string
	unknown string
}

// one resource record as far as it was read
type dnsResource struct {
	name     string
	rrType   uint16
	class    uint16
	ttl      uint32
	rdata    int
	rdLength int
	end      int
}

// the fields of one rdata read in order under parent: offset is the next byte of the message, end the end of the rdata
// isShort is set by the first field that does not fit, the fields after it are left out
type rdataReader struct {
	tree    *Tree
	parent  *node
	message dnsMessage
	offset  int
	end     int
	isShort bool
}

// one run of bytes a decoder reads that lies elsewhere in the source: bytes from..from+length are source bytes at..at+length
type segment struct {
	from   int
	at     int
	length int
}

// where the nodes of the bytes a decoder reads go in the source: at base on, through segments when the bytes were put together from pieces
// (a TLS handshake message over records), or every node spans the fixed bytes when the bytes are not in the source (inflated)
type placement struct {
	base        int
	segments    []segment
	isFixed     bool
	fixedOffset int
	fixedLength int
}

// fields read in order from data: offset is the next byte, end the end of the fields; place puts them into the source
// isShort is set by the first field that does not fit, the fields after it are left out
type cursor struct {
	tree    *Tree
	parent  *node
	data    []byte
	offset  int
	end     int
	place   placement
	isShort bool
}

// what the extensions of a hello may hold
type helloKind uint8

const (
	clientHelloKind         helloKind = 1
	serverHelloKind         helloKind = 2
	helloRetryKind          helloKind = 3
	encryptedExtensionsKind helloKind = 4
	certificateKind         helloKind = 5
	newSessionTicketKind    helloKind = 6
	certificateRequestKind  helloKind = 7
)

// one decode of TLS or DTLS records: isKept for the handshake decerter kept (decrypted records are plaintext there), version and cipherSuite as a ServerHello
// of the decode selected them; isEncrypted once the records on the wire are protected; pending is the start of a handshake message that goes on in the next
// record with its total length (0 while its header is cut) and its pieces; summary lists the messages
type tlsState struct {
	isDTLS       bool
	isKept       bool
	version      uint16
	cipherSuite  uint16
	isEncrypted  bool
	pending      []byte
	pendingTotal int
	segments     []segment
	summary      []string
}

// what a hello says for its summary and its fingerprints: the values in the order they came, GREASE values included
// selectedVersion is the supported_versions of a ServerHello, selected the version it agrees on
type helloInfo struct {
	version         uint16
	ciphers         []uint16
	extensions      []uint16
	groups          []uint16
	pointFormats    []uint16
	signatures      []uint16
	alpn            []string
	firstALPN       []byte
	versions        []uint16
	serverName      string
	hasServerName   bool
	selectedVersion uint16
	selected        uint16
}

// the header of one WebSocket frame: start is its first byte, payloadStart the first byte of its payload, key the masking key when isMasked
type websocketFrame struct {
	start        int
	isFin        bool
	rsv          byte
	opcode       byte
	isMasked     bool
	length       uint64
	lengthBytes  int
	key          [4]byte
	payloadStart int
}

// one decode of WebSocket frames: the message that goes on over frames (its opcode, 0 for none, isCompressed, the payload of its frames in joined and
// where they are in parts, firstStart its first frame), the frames so far and the summary of each
type websocketState struct {
	isDeflate    bool
	opcode       byte
	isCompressed bool
	parts        []segment
	joined       []byte
	firstStart   int
	frames       int
	summary      []string
	context      Context
}
