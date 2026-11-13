// SPDX-License-Identifier: AGPL-3.0-only

package http1

import (
	"bytes"
	"strconv"
	"strings"
)

// what goes on for the edited form of a message: the form unchanged is the message as it came, chunking and all
// a changed form keeps its head as it is written, with two fixes so the receiver reads the body that was written:
// Transfer-Encoding chunked re-chunks the body as one chunk with the trailer section of the original, Content-Length gets the length of the body;
// a body without either gets a Content-Length field at the end of the head, unless the original body was delimited by the end of the stream
// a form without the empty line after its head or with a head that can't be read goes on as it is written, Err says why
func Rebuild(message Message, form []byte) (rebuilt Rebuilt) {
	if bytes.Equal(form, message.Form()) {
		rebuilt = Rebuilt{Wire: message.Raw, Head: message.Head, Body: message.Body, Err: nil}
		return
	}

	rebuilt.Wire = bytes.Clone(form)
	end, isFound := HeadEnd(form)

	if !isFound {
		rebuilt.Err = ErrNoHeadEnd
		return
	}

	head, err := parseHead(form[:end], message.Head.Side)

	if err != nil {
		rebuilt.Err = err
		return
	}

	rawHead := bytes.Clone(form[:end])
	body := bytes.Clone(form[end:])
	codings := head.Values("Transfer-Encoding")
	_, hasLength := head.Get("Content-Length")
	var framed []byte

	switch {
	case (len(codings) > 0) && isChunked(codings):
		trailer := []byte("\r\n")

		if (message.Framing == ChunkedFraming) && (len(message.TrailerRaw) > 0) {
			trailer = message.TrailerRaw
		}

		framed = Chunk(body, trailer)
	case len(codings) > 0:
		framed = body
	case hasLength:
		rawHead = setContentLength(rawHead, len(body))
		framed = body
	case (len(body) > 0) && (message.Framing != CloseFraming):
		rawHead = addContentLength(rawHead, len(body))
		framed = body
	default:
		framed = body
	}

	head, err = parseHead(rawHead, message.Head.Side)

	if err != nil {
		rebuilt.Err = err
		return
	}

	rebuilt = Rebuilt{Wire: append(rawHead, framed...), Head: head, Body: body, Err: nil}
	return
}

// a body as one chunk and the last chunk, trailer is the trailer section with its empty line
func Chunk(body []byte, trailer []byte) (chunked []byte) {
	if len(body) > 0 {
		chunked = append(chunked, strconv.FormatInt(int64(len(body)), 16)...)
		chunked = append(chunked, "\r\n"...)
		chunked = append(chunked, body...)
		chunked = append(chunked, "\r\n"...)
	}

	chunked = append(chunked, "0\r\n"...)
	chunked = append(chunked, trailer...)
	return
}

// every Content-Length field gets the value length, its name, the white space after the colon and the line end stay
func setContentLength(rawHead []byte, length int) (result []byte) {
	isStartLine := true

	for line := range strings.Lines(string(rawHead)) {
		content := strings.TrimRight(line, "\r\n")

		if isStartLine || (content == "") {
			isStartLine = isStartLine && (content == "")
			result = append(result, line...)
			continue
		}

		name, value, isCut := strings.Cut(content, ":")

		if !isCut || !strings.EqualFold(name, "Content-Length") {
			result = append(result, line...)
			continue
		}

		space := value[:len(value)-len(strings.TrimLeft(value, " \t"))]
		result = append(result, name+":"+space+strconv.Itoa(length)+line[len(content):]...)
	}

	return
}

// a Content-Length field before the empty line that ends the head, with the line end of that empty line
func addContentLength(rawHead []byte, length int) (result []byte) {
	lineEnd := "\r\n"

	if !bytes.HasSuffix(rawHead, []byte("\r\n")) {
		lineEnd = "\n"
	}

	result = append(result, rawHead[:len(rawHead)-len(lineEnd)]...)
	result = append(result, "Content-Length: "+strconv.Itoa(length)+lineEnd+lineEnd...)
	return
}
