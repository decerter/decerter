// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
	"golang.org/x/net/http2/hpack"
)

const (
	http2FrameHeaderLength int = 9
	// the smallest SETTINGS_MAX_FRAME_SIZE a peer can announce, a rewritten header block is cut into frames of at most this
	http2MaxFrameLength int   = 16384
	http2HeadersFrame   uint8 = 0x1
	http2SettingsFrame  uint8 = 0x4
	http2ContinueFrame  uint8 = 0x9
	http2EndStreamFlag  uint8 = 0x1
	http2EndHeadersFlag uint8 = 0x4
	http2PaddedFlag     uint8 = 0x8
	http2PriorityFlag   uint8 = 0x20
	http2PriorityLength int   = 5
	// the header field of the split rule and its length, more than the 16 KiB of a record; the client's is of u, the server's of d
	grownHeaderName string = "X-Decerter-Grown"
	grownLength     int    = 20000
	clientGrownByte byte   = 'u'
	serverGrownByte byte   = 'd'
	// the server's answer /test after the split rule
	matrixAnswer string = "/TEST"
	// the SETTINGS_HEADER_TABLE_SIZE every HTTP/2 peer starts with, Go's server does not announce another one
	hpackTableSize uint32 = 4096
)

var (
	errMalformedFrame = errors.New("malformed http/2 frame")
)

var (
	http1OldGet   = []byte("GET / ")
	http1NewGet   = []byte("GET /test ")
	http2Preface  = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	http2OldPath  = "/"
	http2NewPath  = "/test"
	http2PathName = ":path"
	// the head lines the split rule adds its header field to, after the request line and after the status line of a 200
	http1Host   = []byte("\r\nHost: ")
	http1Status = []byte("HTTP/1.1 200 OK\r\n")
)

// eproxy's HTTP/1.1 rewrite from socket.InspectPacket: every GET / the client sends becomes GET /test
type getRule struct{}

func (rule getRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = (message.Direction == tlsrecord.ClientDirection) && ((message.Layer == intercept.TLSLayer) || (message.Layer == intercept.TCPLayer))
	return
}

func (rule getRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	plain = bytes.ReplaceAll(message.Plain, http1OldGet, http1NewGet)
	verdict = intercept.ForwardVerdict
	return
}

// the rewrites of the cipher-suite matrix in the record layer, both directions: an HTTP/1.1 head of either side gets the X-Decerter-Grown header
// field, more than one record holds, so the record goes on as two and every later record of its direction has another sequence number;
// the server's answer /test becomes /TEST, in an HTTP/1.1 body and in an HTTP/2 DATA frame alike, the length stays
type splitRule struct{}

func (rule splitRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = (message.Layer == intercept.TLSLayer)
	return
}

func (rule splitRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	verdict = intercept.ForwardVerdict

	if message.Direction == tlsrecord.ClientDirection {
		plain = bytes.Replace(message.Plain, http1Host, slices.Concat([]byte("\r\n"), grownField(clientGrownByte), http1Host[2:]), 1)
		return
	}

	plain = bytes.Replace(message.Plain, http1Status, slices.Concat(http1Status, grownField(serverGrownByte)), 1)
	plain = bytes.ReplaceAll(plain, []byte(http2NewPath), []byte(matrixAnswer))
	return
}

// the header field X-Decerter-Grown: <grownLength times filler>\r\n
func grownField(filler byte) (field []byte) {
	field = fmt.Appendf(nil, "%s: %s\r\n", grownHeaderName, bytes.Repeat([]byte{filler}, grownLength))
	return
}

// changes the lines openssl s_client and s_server send over DTLS: each key of replacements becomes its value
type dtlsRule struct {
	replacements map[string]string
}

func (rule dtlsRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = (message.Layer == intercept.DTLSLayer)
	return
}

func (rule dtlsRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	plain = message.Plain

	for original, edited := range rule.replacements {
		plain = bytes.ReplaceAll(plain, []byte(original), []byte(edited))
	}

	verdict = intercept.ForwardVerdict
	return
}

// eproxy's HTTP/2 rewrite swapped the bytes of one curl HEADERS frame: the indexed :path / (0x84) became the literal :path /test without indexing (04 83 60 68 93) and the frame length grew from 31 to 35
// that only fits one curl version and one authority; this rule decodes every header block of the client with the client's HPACK state, sets :path / of a GET to /test,
// and encodes the block again without the dynamic table, so the server's decoder never depends on what the client had indexed
// frames are taken from the stream, not from a message: a frame that goes on in the next TLS record waits for it, and a message without a whole frame is dropped
type headersRule struct {
	mutex *sync.Mutex
	flows map[uint64]*headersFlow
	// header blocks with :path changed, and frames that were not whole in one message
	rewritten int
	spanned   int
}

// the HTTP/2 client side of one flow, only the sending goroutine of the client direction uses it
type headersFlow struct {
	isDecided bool
	isHTTP2   bool
	buffer    []byte
	// a HEADERS frame without END_HEADERS: its flags, stream, priority fields and the block so far
	isBlockOpen   bool
	blockFlags    uint8
	blockStream   uint32
	blockPriority []byte
	block         []byte
	decoder       *hpack.Decoder
	encoder       *hpack.Encoder
	encoded       *bytes.Buffer
}

func newHeadersRule() (rule *headersRule) {
	rule = &headersRule{
		mutex:     &sync.Mutex{},
		flows:     map[uint64]*headersFlow{},
		rewritten: 0,
		spanned:   0,
	}
	return
}

func (rule *headersRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = (message.Direction == tlsrecord.ClientDirection) && ((message.Layer == intercept.TLSLayer) || (message.Layer == intercept.TCPLayer))
	return
}

func (rule *headersRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	flow := rule.flow(message.Flow.Cookie)
	verdict = intercept.ForwardVerdict
	data := append(flow.buffer, message.Plain...)
	flow.buffer = nil

	// HTTP/2 starts with the client preface, which can be cut across messages too; a flow that doesn't start with it is left alone
	if !flow.isDecided {
		length := min(len(data), len(http2Preface))

		switch {
		case !bytes.Equal(data[:length], http2Preface[:length]):
			flow.isDecided = true
			plain = data
			return
		case length < len(http2Preface):
			flow.buffer = data
			verdict = intercept.DropVerdict
			rule.count(false, true)
			return
		}

		flow.isDecided = true
		flow.isHTTP2 = true
		plain = append(plain, http2Preface...)
		data = data[len(http2Preface):]
	}

	if !flow.isHTTP2 {
		plain = message.Plain
		return
	}

	for len(data) >= http2FrameHeaderLength {
		length := int(data[0])<<16 | int(data[1])<<8 | int(data[2])

		if len(data) < (http2FrameHeaderLength + length) {
			break
		}

		frame := data[:http2FrameHeaderLength+length]
		data = data[http2FrameHeaderLength+length:]
		plain, err = rule.frame(flow, frame, plain)

		if err != nil {
			return
		}
	}

	if len(data) > 0 {
		rule.count(false, true)
	}

	flow.buffer = bytes.Clone(data)

	if len(plain) == 0 {
		verdict = intercept.DropVerdict
	}

	return
}

// the rewritten header blocks and the frames that spanned messages so far
func (rule *headersRule) stats() (rewritten int, spanned int) {
	rule.mutex.Lock()
	defer rule.mutex.Unlock()
	rewritten = rule.rewritten
	spanned = rule.spanned
	return
}

func (rule *headersRule) count(isRewritten bool, isSpanned bool) {
	rule.mutex.Lock()
	defer rule.mutex.Unlock()

	if isRewritten {
		rule.rewritten++
	}

	if isSpanned {
		rule.spanned++
	}
}

// the state of a flow, created with its first message; flows are never removed, the rule lives for one test
func (rule *headersRule) flow(cookie uint64) (flow *headersFlow) {
	rule.mutex.Lock()
	defer rule.mutex.Unlock()
	flow, found := rule.flows[cookie]

	if found {
		return
	}

	encoded := &bytes.Buffer{}
	encoder := hpack.NewEncoder(encoded)
	// the first block starts with a table size update to 0, every field after it is static or literal without indexing
	encoder.SetMaxDynamicTableSize(0)
	flow = &headersFlow{
		isDecided:     false,
		isHTTP2:       false,
		buffer:        nil,
		isBlockOpen:   false,
		blockFlags:    0,
		blockStream:   0,
		blockPriority: nil,
		block:         nil,
		decoder:       hpack.NewDecoder(hpackTableSize, nil),
		encoder:       encoder,
		encoded:       encoded,
	}
	rule.flows[cookie] = flow
	return
}

// a whole frame: HEADERS and CONTINUATION collect a header block, every other frame goes on as it came
func (rule *headersRule) frame(flow *headersFlow, frame []byte, plain []byte) (output []byte, err error) {
	output = plain
	frameType := frame[3]
	flags := frame[4]
	stream := binary.BigEndian.Uint32(frame[5:9]) & 0x7fffffff
	payload := frame[http2FrameHeaderLength:]

	switch frameType {
	case http2HeadersFrame:
		if flags&http2PaddedFlag != 0 {
			if (len(payload) < 1) || (int(payload[0]) >= len(payload)) {
				err = errMalformedFrame
				return
			}

			payload = payload[1 : len(payload)-int(payload[0])]
		}

		flow.blockPriority = nil

		if flags&http2PriorityFlag != 0 {
			if len(payload) < http2PriorityLength {
				err = errMalformedFrame
				return
			}

			flow.blockPriority = bytes.Clone(payload[:http2PriorityLength])
			payload = payload[http2PriorityLength:]
		}

		flow.isBlockOpen = true
		flow.blockFlags = flags
		flow.blockStream = stream
		flow.block = append(flow.block[:0], payload...)
	case http2ContinueFrame:
		if !flow.isBlockOpen {
			output = append(output, frame...)
			return
		}

		flow.block = append(flow.block, payload...)
	default:
		output = append(output, frame...)
		return
	}

	if flags&http2EndHeadersFlag == 0 {
		return
	}

	flow.isBlockOpen = false
	output, err = rule.block(flow, output)
	return
}

// decode a whole header block, change :path of a GET for /, and write it again as HEADERS and CONTINUATION frames
func (rule *headersRule) block(flow *headersFlow, plain []byte) (output []byte, err error) {
	output = plain
	fields, decodeErr := flow.decoder.DecodeFull(flow.block)

	if err = decodeErr; err != nil {
		return
	}

	isGet := false

	for _, field := range fields {
		if (field.Name == ":method") && (field.Value == "GET") {
			isGet = true
		}
	}

	isRewritten := false

	for index, field := range fields {
		if isGet && (field.Name == http2PathName) && (field.Value == http2OldPath) {
			fields[index].Value = http2NewPath
			isRewritten = true
		}
	}

	flow.encoded.Reset()
	_, err = flow.encoded.Write(flow.blockPriority)

	if err != nil {
		return
	}

	for _, field := range fields {
		err = flow.encoder.WriteField(field)

		if err != nil {
			return
		}
	}

	if isRewritten {
		rule.count(true, false)
	}

	block := flow.encoded.Bytes()
	frameType := http2HeadersFrame
	flags := flow.blockFlags & (http2EndStreamFlag | http2PriorityFlag)

	for {
		chunk := block[:min(len(block), http2MaxFrameLength)]
		block = block[len(chunk):]

		if len(block) == 0 {
			flags |= http2EndHeadersFlag
		}

		output = appendFrame(output, frameType, flags, flow.blockStream, chunk)

		if len(block) == 0 {
			return
		}

		frameType = http2ContinueFrame
		flags = 0
	}
}

// Test if the HTTP/2 HEADERS rewrite keeps the HPACK state when frames and header blocks are cut across messages.
func TestHeadersRulePositive(state *testing.T) {
	stream, err := clientStream()

	if err != nil {
		state.Fatalf("Test of the HTTP/2 HEADERS rewrite failed, cannot build the client stream, error: %s", err.Error())
	}

	for _, size := range []int{1, 7, 64, len(stream)} {
		err = testHeadersRuleChunks(state.Context(), stream, size)

		if err != nil {
			state.Errorf("Test of the HTTP/2 HEADERS rewrite failed, message size: %d, error: %s", size, err.Error())
		}
	}
}

// the client side of a connection: the preface, an empty SETTINGS frame, a GET / block, and a second one cut into HEADERS and CONTINUATION
// the client's encoder indexes, so the second block refers to the dynamic table entries the first one added
func clientStream() (stream []byte, err error) {
	encoded := &bytes.Buffer{}
	encoder := hpack.NewEncoder(encoded)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "GET", Sensitive: false},
		{Name: ":scheme", Value: "https", Sensitive: false},
		{Name: ":authority", Value: "127.0.0.1:8443", Sensitive: false},
		{Name: ":path", Value: "/", Sensitive: false},
		{Name: "user-agent", Value: "curl/8.20.0", Sensitive: false},
	}
	var blocks [][]byte

	for range 2 {
		encoded.Reset()

		for _, field := range fields {
			err = encoder.WriteField(field)

			if err != nil {
				return
			}
		}

		blocks = append(blocks, bytes.Clone(encoded.Bytes()))
	}

	stream = append(stream, http2Preface...)
	stream = appendFrame(stream, http2SettingsFrame, 0, 0, nil)
	stream = appendFrame(stream, http2HeadersFrame, http2EndStreamFlag|http2EndHeadersFlag, 1, blocks[0])
	stream = appendFrame(stream, http2HeadersFrame, http2EndStreamFlag, 3, blocks[1][:2])
	stream = appendFrame(stream, http2ContinueFrame, http2EndHeadersFlag, 3, blocks[1][2:])
	return
}

// feed the stream to a new rule in messages of size bytes, and read what it forwarded with the HPACK state of a server
func testHeadersRuleChunks(ctx context.Context, stream []byte, size int) (err error) {
	rule := newHeadersRule()
	var output []byte

	for start := 0; start < len(stream); start += size {
		message := intercept.Message{
			Flow:      intercept.Flow{Cookie: 1},
			ID:        uint64(start),
			Direction: tlsrecord.ClientDirection,
			Layer:     intercept.TLSLayer,
			Plain:     stream[start:min(start+size, len(stream))],
		}
		plain, verdict, applyErr := rule.Apply(ctx, message)

		if err = applyErr; err != nil {
			return
		}

		if verdict == intercept.ForwardVerdict {
			output = append(output, plain...)
		}
	}

	if !bytes.HasPrefix(output, http2Preface) {
		err = fmt.Errorf("output does not start with the preface: %q", output)
		return
	}

	data := output[len(http2Preface):]
	decoder := hpack.NewDecoder(hpackTableSize, nil)
	var paths []string

	for len(data) > 0 {
		if len(data) < http2FrameHeaderLength {
			err = fmt.Errorf("output ends in a frame header: %x", data)
			return
		}

		length := int(data[0])<<16 | int(data[1])<<8 | int(data[2])

		if len(data) < (http2FrameHeaderLength + length) {
			err = fmt.Errorf("output ends in a frame: %x", data)
			return
		}

		if data[3] == http2HeadersFrame {
			fields, decodeErr := decoder.DecodeFull(data[http2FrameHeaderLength : http2FrameHeaderLength+length])

			if err = decodeErr; err != nil {
				return
			}

			for _, field := range fields {
				if field.Name == http2PathName {
					paths = append(paths, field.Value)
				}

				if (field.Name == ":authority") && (field.Value != "127.0.0.1:8443") {
					err = fmt.Errorf(":authority return value was not %v instead: %v", "127.0.0.1:8443", field.Value)
					return
				}
			}
		}

		data = data[http2FrameHeaderLength+length:]
	}

	if !slices.Equal(paths, []string{http2NewPath, http2NewPath}) {
		err = fmt.Errorf(":path return value was not %v instead: %v", []string{http2NewPath, http2NewPath}, paths)
		return
	}

	rewritten, spanned := rule.stats()

	if (rewritten != 2) || ((size < len(stream)) != (spanned > 0)) {
		err = fmt.Errorf("rule stats return value was not rewritten 2 and spanned %v instead: rewritten %d spanned %d", size < len(stream), rewritten, spanned)
		return
	}

	return
}

func appendFrame(stream []byte, frameType uint8, flags uint8, streamID uint32, payload []byte) (output []byte) {
	output = append(stream, byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)), frameType, flags)
	output = binary.BigEndian.AppendUint32(output, streamID)
	output = append(output, payload...)
	return
}
