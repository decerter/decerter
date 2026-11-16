// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"strconv"
	"strings"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/output"
)

// gRPC over HTTP/2 (github.com/grpc/grpc, doc/PROTOCOL-HTTP2.md): a body is length-prefixed messages, each a compressed flag byte, a 4-byte big-endian
// length and the message; gRPC-Web (doc/PROTOCOL-WEB.md) frames its trailers the same way with the top bit of the flag set, as HTTP/1 header lines
// the messages are Protocol Buffers unless the content type says +json; a compressed message is inflated when grpc-encoding is gzip
const (
	grpcProtocol      string = "grpc"
	grpcTitle         string = "gRPC"
	grpcPrefixBytes   int    = 5
	grpcCompressedBit byte   = 0x01
	grpcTrailersBit   byte   = 0x80
	grpcMediaType     string = "application/grpc"
	grpcWebMediaType  string = "application/grpc-web"
	grpcSniffScore    int    = 60
)

func init() {
	register(decoder{
		Protocol:   grpcProtocol,
		Title:      grpcTitle,
		Ports:      nil,
		hint:       grpcHint,
		sniff:      grpcSniff,
		decode:     grpcDecode,
		fromTarget: nil,
	})
}

// application/grpc, application/grpc+proto, application/grpc-web and application/grpc-web+proto; grpc-web-text is base64 and not taken
func grpcHint(context Context) (reason string) {
	mediaType := grpcMediaTypeOf(context)

	if (mediaType == grpcMediaType) || (mediaType == grpcWebMediaType) {
		reason = "content type " + strings.ToLower(context.ContentType) + " is " + map[bool]string{false: "gRPC", true: "gRPC-Web"}[mediaType == grpcWebMediaType]
	}

	return
}

// the media type of a body's content type without its +codec, empty for anything else
func grpcMediaTypeOf(context Context) (mediaType string) {
	if context.Transport != BodyTransport {
		return
	}

	parsed, _, parseErr := mime.ParseMediaType(context.ContentType)

	if parseErr != nil {
		return
	}

	base, _, _ := strings.Cut(parsed, "+")

	if (base == grpcMediaType) || (base == grpcWebMediaType) {
		mediaType = base
	}

	return
}

// the codec of the content type: proto unless it names another one after +
func grpcCodec(context Context) (codec string) {
	codec = "proto"
	parsed, _, parseErr := mime.ParseMediaType(context.ContentType)

	if parseErr != nil {
		return
	}

	if _, after, found := strings.Cut(parsed, "+"); found && (after != "") {
		codec = after
	}

	return
}

// a body that is prefixed messages to its end; one that ends inside a prefix or a message or has reserved flag bits gets a little, so the content type still takes it
func grpcSniff(data []byte, context Context) (score int) {
	if (context.Transport != BodyTransport) || (len(data) < grpcPrefixBytes) {
		return
	}

	offset := 0

	for offset < len(data) {
		if (len(data)-offset < grpcPrefixBytes) || (data[offset]&^(grpcCompressedBit|grpcTrailersBit) != 0) {
			score = protobufPartialScore
			return
		}

		length := int(binary.BigEndian.Uint32(data[offset+1:]))

		if length > len(data)-offset-grpcPrefixBytes {
			score = protobufPartialScore
			return
		}

		offset += grpcPrefixBytes + length
		score = grpcSniffScore
	}

	return
}

func grpcDecode(tree *Tree, data []byte, context Context) {
	isWeb := grpcMediaTypeOf(context) == grpcWebMediaType
	title := grpcTitle

	if isWeb {
		title = "gRPC-Web"
	}

	codec := grpcCodec(context)
	messages, trailers := 0, 0
	offset := 0

	for (offset < len(data)) && !tree.isFull {
		start := offset
		message := tree.add(nil, grpcProtocol, title+" message", "", start, len(data)-start)

		if len(data)-start < grpcPrefixBytes {
			tree.fail(message, fmt.Sprintf("the 5-byte prefix of a message is cut short, %d bytes are here", len(data)-start))
			tree.addSummary(title + ": the prefix of a message is cut short")
			return
		}

		flags := data[start]
		length := binary.BigEndian.Uint32(data[start+1:])
		tree.addBits(message, "grpc.compressed", "Compressed flag", yesNo(flags&grpcCompressedBit != 0), start, 1, uint32(grpcCompressedBit))

		if isWeb {
			tree.addBits(message, "grpc.trailers", "Trailers flag", yesNo(flags&grpcTrailersBit != 0), start, 1, uint32(grpcTrailersBit))
		}

		if flags&^(grpcCompressedBit|grpcTrailersBit) != 0 {
			tree.fail(message, fmt.Sprintf("reserved flag bits 0x%02x are set", flags))
		}

		tree.add(message, "grpc.length", "Message length", strconv.FormatUint(uint64(length), 10), start+1, 4)
		payloadStart := start + grpcPrefixBytes
		available := min(int(length), len(data)-payloadStart)
		message.length = grpcPrefixBytes + available
		offset = payloadStart + available

		if available < int(length) {
			tree.fail(message, fmt.Sprintf("the message runs past the end of the body: %d of its %d bytes are here", available, length))
			tree.add(message, "grpc.message_data", "Message data (cut short)", fmt.Sprintf("%d bytes", available), payloadStart, available)
			messages++
			break
		}

		payload := data[payloadStart:offset]

		if isWeb && (flags&grpcTrailersBit != 0) {
			tree.setLabel(message, "gRPC-Web trailers")
			grpcTrailers(tree, message, payload, payloadStart)
			trailers++
			continue
		}

		messages++

		if flags&grpcCompressedBit != 0 {
			grpcCompressed(tree, message, payload, payloadStart, codec, context)
			continue
		}

		grpcPayload(tree, message, payload, at(payloadStart), codec)
	}

	summary := fmt.Sprintf("%s %s", title, map[v1.Direction]string{v1.UpDirection: "request", v1.DownDirection: "response"}[context.Direction])

	if (context.Direction == v1.UpDirection) && (context.Target != "") {
		summary += " " + output.Escape([]byte(context.Target))
	}

	summary += fmt.Sprintf(", %d message%s", messages, map[bool]string{false: "s", true: ""}[messages == 1])

	if trailers > 0 {
		summary += " and trailers"
	}

	tree.addSummary(summary)
}

// one message as its codec has it: Protocol Buffers fields, JSON or other text, bytes for the rest
func grpcPayload(tree *Tree, message *node, payload []byte, place placement, codec string) {
	switch {
	case codec == "proto":
		root := tree.addAt(message, place, protobufProtocol, protobufTitle, "", 0, len(payload))
		count := protobufMessage(tree, root, payload, place, 0)
		tree.setValue(root, fieldCount(count))
	case isText(payload):
		tree.addAt(message, place, "grpc.message_data", "Message ("+output.Escape([]byte(codec))+")", textValue(payload), 0, len(payload))
	default:
		tree.addAt(message, place, "grpc.message_data", "Message ("+output.Escape([]byte(codec))+")", hexValue(payload), 0, len(payload))
	}
}

// a compressed message: gzip is inflated within the tree's limits, and its fields all span the compressed bytes; another encoding stays bytes
func grpcCompressed(tree *Tree, message *node, payload []byte, start int, codec string, context Context) {
	encoding := strings.ToLower(strings.TrimSpace(context.Encoding))

	if encoding != "gzip" {
		data := tree.add(message, "grpc.message_data", "Compressed message", hexValue(payload), start, len(payload))
		tree.fail(data, fmt.Sprintf("compressed with grpc-encoding %q, decerter inflates gzip only", output.Escape([]byte(encoding))))
		return
	}

	// the node comes first: an inflate that spends the decode's budget fills the tree, the node still says so
	data := tree.add(message, "grpc.message_data", "Compressed message (gzip)", "", start, len(payload))
	inflated, err := gunzip(tree, payload)
	tree.setValue(data, fmt.Sprintf("%d bytes, %d inflated", len(payload), len(inflated)))

	if err != nil {
		tree.fail(data, "could not inflate it: "+err.Error())
		return
	}

	grpcPayload(tree, data, inflated, fixed(start, len(payload)), codec)
}

// a gzip stream as far as the tree inflates it
func gunzip(tree *Tree, data []byte) (inflated []byte, err error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))

	if err != nil {
		return
	}

	inflated, err = tree.inflate(reader)
	err = errors.Join(err, reader.Close())
	return
}

// the trailers of gRPC-Web: header lines name: value, each ended by CRLF
func grpcTrailers(tree *Tree, message *node, payload []byte, start int) {
	offset := 0

	for offset < len(payload) {
		end := bytes.Index(payload[offset:], []byte("\r\n"))
		lineLength := end

		if end < 0 {
			lineLength, end = len(payload)-offset, len(payload)-offset
		} else {
			end += 2
		}

		line := payload[offset : offset+lineLength]

		if len(line) > 0 {
			name, value, _ := bytes.Cut(line, []byte(":"))
			tree.add(message, "grpc.trailer", output.Escape(bytes.TrimSpace(name)), output.Escape(bytes.TrimSpace(value)), start+offset, end)
		}

		offset += end
	}
}
