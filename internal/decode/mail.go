// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/output"
)

// the mail protocols, all lines of text: SMTP from RFC 5321 (commands, replies of several lines, DATA up to its lone dot, BDAT chunks of RFC 3030),
// IMAP from RFC 9051 (tagged commands, untagged and tagged responses, continuations, literals {n} and {n+} inside a line), POP3 from RFC 1939
// (commands, +OK and -ERR, responses of several lines up to a lone dot); STARTTLS of RFC 3207, RFC 9051 and STLS of RFC 2595 switch the rest of
// the stream to TLS, which decodeFramed shows as TLS records
const (
	smtpProtocol string = "smtp"
	smtpTitle    string = "Simple Mail Transfer Protocol"
	imapProtocol string = "imap"
	imapTitle    string = "Internet Message Access Protocol"
	popProtocol  string = "pop"
	popTitle     string = "Post Office Protocol"
	// streamState.mode of the mail protocols: the rest may be TLS, SMTP mail data until the lone dot, an SMTP BDAT chunk of streamState.waiting bytes
	starttlsMode string = "starttls"
	dataMode     string = "data"
	bdatMode     string = "bdat"
	// the end of SMTP mail data and of a POP3 response of several lines
	dotLine string = "\r\n.\r\n"
	// the header fields of a mail the DATA node shows, and the lines of an IMAP or SMTP PDU it shows one by one
	maxMailHeaders int = 32
	maxLines       int = 256
	// the score of a line of text a line protocol has no word for: above 0 so its port takes it, far below sniffThreshold
	textLineScore int = 10
)

func init() {
	register(decoder{
		Protocol:   smtpProtocol,
		Title:      smtpTitle,
		Ports:      []Port{{Layer: v1.TCPLayer, Number: 25}, {Layer: v1.TCPLayer, Number: 587}, {Layer: v1.TLSLayer, Number: 465}, {Layer: v1.TLSLayer, Number: 587}},
		hint:       noHint,
		sniff:      smtpSniff,
		decode:     framedDecode(smtpProtocol),
		fromTarget: nil,
		frame:      smtpFrame,
		pdu:        smtpPDU,
		unit:       "line",
	})
	register(decoder{
		Protocol:   imapProtocol,
		Title:      imapTitle,
		Ports:      []Port{{Layer: v1.TCPLayer, Number: 143}, {Layer: v1.TLSLayer, Number: 993}},
		hint:       imapHint,
		sniff:      imapSniff,
		decode:     framedDecode(imapProtocol),
		fromTarget: nil,
		frame:      imapFrame,
		pdu:        imapPDU,
		unit:       "line",
	})
	register(decoder{
		Protocol:   popProtocol,
		Title:      popTitle,
		Ports:      []Port{{Layer: v1.TCPLayer, Number: 110}, {Layer: v1.TLSLayer, Number: 995}},
		hint:       popHint,
		sniff:      popSniff,
		decode:     framedDecode(popProtocol),
		fromTarget: nil,
		frame:      popFrame,
		pdu:        popPDU,
		unit:       "line",
	})
}

func imapHint(context Context) (reason string) {
	if (context.Layer == v1.TLSLayer) && (context.ALPN == "imap") {
		reason = "TLS ALPN imap is IMAP"
	}

	return
}

func popHint(context Context) (reason string) {
	if (context.Layer == v1.TLSLayer) && (context.ALPN == "pop3") {
		reason = "TLS ALPN pop3 is POP3"
	}

	return
}

// the first line of data without its line end, at most 512 bytes of it; isLine is false without a line end there
func firstLine(data []byte) (line string, isLine bool) {
	length := lineLength(data[:min(len(data), 4096)])

	if length == 0 {
		return
	}

	line, isLine = string(trimLine(data[:min(length, 512)])), true
	return
}

// a server greeting 220 that names SMTP, or a client's EHLO or HELO, is certain; a reply line only possible; any other line of text a little, so the
// port takes a command or mail data of a read alone
func smtpSniff(data []byte, context Context) (score int) {
	line, isLine := firstLine(data)

	if (context.Transport != StreamTransport) || !isLine {
		return
	}

	upper := asciiUpper(line)

	switch {
	case strings.HasPrefix(upper, "220") && strings.Contains(upper, "SMTP"):
		score = 90
	case strings.HasPrefix(upper, "EHLO ") || strings.HasPrefix(upper, "HELO "):
		score = 90
	case isReplyLine(line):
		score = 20
	case isText([]byte(line)):
		score = textLineScore
	}

	return
}

// three digits and a space, a dash or the end
func isReplyLine(line string) (isReply bool) {
	if (len(line) < 3) || (line[0] < '2') || (line[0] > '5') || (line[1] < '0') || (line[1] > '9') || (line[2] < '0') || (line[2] > '9') {
		return
	}

	isReply = (len(line) == 3) || (line[3] == ' ') || (line[3] == '-')
	return
}

// a reply is its lines up to the one without a dash after the code; mail data is up to the lone dot; a BDAT chunk is its count of bytes
func smtpFrame(data []byte, state *streamState) (length int) {
	switch state.mode {
	case dataMode:
		if bytes.HasPrefix(data, []byte(".\r\n")) {
			length = 3
			return
		}

		if index := bytes.Index(data, []byte(dotLine)); index >= 0 {
			length = index + len(dotLine)
		}

		return
	case bdatMode:
		length = state.waiting
		return
	}

	for offset := 0; offset < len(data); {
		line := lineLength(data[offset:])

		if line == 0 {
			length = 0
			return
		}

		text := string(trimLine(data[offset : offset+line]))
		offset += line

		if !isReplyLine(text) || (len(text) == 3) || (text[3] != '-') {
			length = offset
			return
		}
	}

	return
}

func smtpPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	pdu := data[start:]

	switch state.mode {
	case dataMode:
		root = tree.add(nil, smtpProtocol, smtpTitle+" (mail data)", strconv.Itoa(len(pdu))+" bytes", start, len(pdu))
		mailData(tree, root, data, start, len(data))
		state.mode = ""
		tree.addSummary(fmt.Sprintf("SMTP mail data, %d bytes", len(pdu)))
		return
	case bdatMode:
		root = tree.add(nil, smtpProtocol, smtpTitle+" (BDAT chunk)", strconv.Itoa(len(pdu))+" bytes", start, len(pdu))
		tree.add(root, "smtp.data.fragment", "Chunk", textValue(pdu), start, len(pdu))
		state.mode, state.waiting = "", 0
		tree.addSummary(fmt.Sprintf("SMTP BDAT chunk, %d bytes", len(pdu)))
		return
	}

	first, _ := firstLine(pdu)

	if isReplyLine(first) {
		root = tree.add(nil, smtpProtocol, smtpTitle+" (reply)", "", start, len(pdu))
		code := first[:3]
		lines := textLines(tree, root, data, start, func(line []byte, lineStart int, lineNode *node) {
			text := string(trimLine(line))
			tree.add(lineNode, "smtp.response.code", "Response code", text[:min(3, len(text))], lineStart, min(3, len(text)))

			if len(text) > 4 {
				tree.add(lineNode, "smtp.rsp.parameter", "Response parameter", textValue([]byte(text[4:])), lineStart+4, len(text)-4)
			}
		})
		tree.setValue(root, code)
		state.mode = starttlsMode
		tree.addSummary(fmt.Sprintf("SMTP reply %s %s", code, textValue([]byte(strings.TrimSpace(first[min(len(first), 4):])))) + moreLines(lines))
		return
	}

	root = tree.add(nil, smtpProtocol, smtpTitle+" (command)", "", start, len(pdu))
	command, parameter := commandOf(first)
	textLines(tree, root, data, start, func(line []byte, lineStart int, lineNode *node) {
		text := string(trimLine(line))
		word, rest, _ := strings.Cut(text, " ")
		tree.add(lineNode, "smtp.req.command", "Command", textValue([]byte(word)), lineStart, len(word))

		if rest != "" {
			tree.add(lineNode, "smtp.req.parameter", "Request parameter", textValue([]byte(rest)), lineStart+len(word)+1, len(rest))
		}
	})
	tree.setValue(root, textValue([]byte(command)))

	switch command {
	case "DATA":
		state.mode = dataMode
	case "BDAT":
		count, _, _ := strings.Cut(parameter, " ")

		if size, err := strconv.Atoi(count); (err == nil) && (size > 0) {
			state.mode, state.waiting = bdatMode, size
		}
	case "STARTTLS":
		state.mode = starttlsMode
	}

	tree.addSummary("SMTP " + output.Escape([]byte(command)) + map[bool]string{false: "", true: " " + textValue([]byte(parameter))}[parameter != ""])
	return
}

// the first word of a line in upper case and the rest
func commandOf(line string) (command string, parameter string) {
	command, parameter, _ = strings.Cut(line, " ")
	command = asciiUpper(command)
	return
}

// upper case of ASCII letters only: the text keeps its length, where strings.ToUpper makes U+FFFD of a byte that is no UTF-8
func asciiUpper(text string) (upper string) {
	letters := []byte(text)

	for index, letter := range letters {
		if (letter >= 'a') && (letter <= 'z') {
			letters[index] = letter - 'a' + 'A'
		}
	}

	upper = string(letters)
	return
}

func moreLines(lines int) (text string) {
	if lines > 1 {
		text = fmt.Sprintf(" (%d lines)", lines)
	}

	return
}

// a node per line of the PDU data[start:], each filled in by fields; lines past maxLines are counted in one node
func textLines(tree *Tree, root *node, data []byte, start int, fields func(line []byte, lineStart int, lineNode *node)) (count int) {
	for offset := start; (offset < len(data)) && !tree.isFull; count++ {
		length := lineLength(data[offset:])

		if length == 0 {
			length = len(data) - offset
		}

		if count >= maxLines {
			tree.add(root, "text.more", "More lines", strconv.Itoa(len(data)-offset)+" bytes", offset, len(data)-offset)
			return
		}

		line := data[offset : offset+length]
		lineNode := tree.add(root, "text.line", textValue(trimLine(line)), "", offset, length)
		fields(line, offset, lineNode)
		offset += length
	}

	return
}

// mail data (RFC 5322): its header fields, the body and the lone dot; a dot that starts a line of the body is doubled on the wire (RFC 5321 4.5.2)
func mailData(tree *Tree, root *node, data []byte, start int, end int) {
	offset, headers := start, 0

	for (offset < end) && !tree.isFull {
		length := lineLength(data[offset:end])

		if length == 0 {
			break
		}

		line := trimLine(data[offset : offset+length])

		if len(line) == 0 {
			offset += length
			break
		}

		if headers < maxMailHeaders {
			name, value, _ := bytes.Cut(line, []byte(":"))
			tree.add(root, "imf.header", textValue(name), textValue(bytes.TrimSpace(value)), offset, length)
		}

		headers++
		offset += length
	}

	if headers > maxMailHeaders {
		tree.add(root, "imf.header.more", "More header fields", strconv.Itoa(headers-maxMailHeaders), start, offset-start)
	}

	body := data[offset:end]

	if bytes.HasSuffix(body, []byte(dotLine)) {
		body = body[:len(body)-3]
	}

	if len(body) > 0 {
		tree.add(root, "imf.body", "Body", textValue(body), offset, len(body))
	}
}

// an untagged OK greeting that names IMAP is certain; a tagged command possible; any other line of text (a tagged response, a continuation, another
// command) a little, so the port takes it
func imapSniff(data []byte, context Context) (score int) {
	line, isLine := firstLine(data)

	if (context.Transport != StreamTransport) || !isLine {
		return
	}

	upper := asciiUpper(line)
	fields := strings.Fields(upper)

	switch {
	case strings.HasPrefix(upper, "* OK") && strings.Contains(upper, "IMAP"):
		score = 90
	case (len(fields) >= 2) && (fields[0] != "*") && slices.Contains([]string{"CAPABILITY", "LOGIN", "AUTHENTICATE", "SELECT", "EXAMINE", "LIST", "FETCH", "UID", "LOGOUT", "STARTTLS", "IDLE", "NOOP"}, fields[1]):
		score = 40
	case strings.HasPrefix(upper, "* "):
		score = 20
	case isText([]byte(line)):
		score = textLineScore
	}

	return
}

// a line and the literals it announces with {n} or {n+} at its end, each followed by the rest of the line
func imapFrame(data []byte, state *streamState) (length int) {
	offset := 0

	for offset < len(data) {
		line := lineLength(data[offset:])

		if line == 0 {
			return
		}

		size, isLiteral := literalOf(trimLine(data[offset : offset+line]))
		offset += line

		if !isLiteral {
			length = offset
			return
		}

		// a size from the traffic is checked against the bytes left before it is added to an offset
		if size > len(data)-offset {
			return
		}

		offset += size
	}

	return
}

// the size of the literal {n} or {n+} (or ~{n} of a binary literal) a line ends with
func literalOf(line []byte) (size int, isLiteral bool) {
	if !bytes.HasSuffix(line, []byte("}")) {
		return
	}

	open := bytes.LastIndexByte(line, '{')

	if open < 0 {
		return
	}

	number := strings.TrimSuffix(string(line[open+1:len(line)-1]), "+")
	value, err := strconv.Atoi(number)

	if (err != nil) || (value < 0) {
		return
	}

	size, isLiteral = value, true
	return
}

func imapPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	pdu := data[start:]
	first, _ := firstLine(pdu)
	fields := strings.SplitN(first, " ", 3)
	tag := fields[0]
	kind := "request"

	if (state.context.Direction == v1.DownDirection) || (tag == "*") || (tag == "+") {
		kind = "response"
	}

	root = tree.add(nil, imapProtocol, imapTitle+" ("+kind+")", "", start, len(pdu))
	tagName := "imap.request.tag"
	words := "imap.request.command"

	if kind == "response" {
		tagName, words = "imap.response.tag", "imap.response.status"
	}

	tree.add(root, tagName, "Tag", textValue([]byte(tag)), start, len(tag))
	summary := "IMAP " + kind + " " + textValue([]byte(tag))

	if len(fields) > 1 {
		tree.add(root, words, map[bool]string{false: "Command", true: "Status"}[kind == "response"], textValue([]byte(fields[1])), start+len(tag)+1, len(fields[1]))
		summary += " " + textValue([]byte(fields[1]))
	}

	// the lines and literals as they come
	offset := start

	for count := 0; (offset < len(data)) && !tree.isFull && (count < maxLines); count++ {
		line := lineLength(data[offset:])

		if line == 0 {
			line = len(data) - offset
		}

		tree.add(root, "imap.line", "Line", textValue(trimLine(data[offset:offset+line])), offset, line)
		size, isLiteral := literalOf(trimLine(data[offset : offset+line]))
		offset += line

		if isLiteral {
			literal := data[offset : offset+min(size, len(data)-offset)]
			tree.add(root, "imap.literal", fmt.Sprintf("Literal of %d bytes", size), textValue(literal), offset, len(literal))
			offset += len(literal)
		}
	}

	if ((len(fields) > 1) && (asciiUpper(fields[1]) == "STARTTLS")) || (kind == "response") {
		state.mode = starttlsMode
	}

	tree.addSummary(summary)
	return
}

// +OK or -ERR of a server, or a command of the client
func popSniff(data []byte, context Context) (score int) {
	line, isLine := firstLine(data)

	if (context.Transport != StreamTransport) || !isLine {
		return
	}

	upper := asciiUpper(line)
	command, _ := commandOf(line)

	switch {
	case strings.HasPrefix(upper, "+OK ") && (strings.Contains(upper, "POP") || strings.Contains(upper, "READY")):
		score = 90
	case (upper == "+OK") || strings.HasPrefix(upper, "+OK ") || strings.HasPrefix(upper, "-ERR"):
		score = 40
	case slices.Contains([]string{"USER", "PASS", "STAT", "LIST", "RETR", "DELE", "UIDL", "TOP", "CAPA", "STLS", "APOP", "QUIT", "NOOP", "RSET"}, command):
		score = 30
	}

	return
}

// a client's line; a server's +OK line, with the lines after it up to a lone dot when they come before the next +OK or -ERR (a response of several lines)
func popFrame(data []byte, state *streamState) (length int) {
	first := lineLength(data)

	if first == 0 {
		return
	}

	if (state.context.Direction != v1.DownDirection) || !bytes.HasPrefix(data, []byte("+OK")) {
		length = first
		return
	}

	for offset := first; offset < len(data); {
		line := lineLength(data[offset:])

		if line == 0 {
			break
		}

		text := data[offset : offset+line]

		switch {
		case bytes.Equal(trimLine(text), []byte(".")):
			length = offset + line
			return
		case bytes.HasPrefix(text, []byte("+OK")) || bytes.HasPrefix(text, []byte("-ERR")):
			length = first
			return
		}

		offset += line
	}

	// the stream ends after the line, or the read ends with it (a greeting, the answer to USER, PASS, DELE or QUIT): it is a line alone; lines after it
	// without their dot go on in the next read
	if state.context.Joined || (first == len(data)) {
		length = first
	}

	return
}

func popPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	pdu := data[start:]
	first, _ := firstLine(pdu)
	indicator, description := commandOf(first)

	if (indicator == "+OK") || (indicator == "-ERR") || (state.context.Direction == v1.DownDirection) {
		root = tree.add(nil, popProtocol, popTitle+" (response)", "", start, len(pdu))
		tree.add(root, "pop.response.indicator", "Response indicator", textValue([]byte(indicator)), start, len(indicator))

		if description != "" {
			tree.add(root, "pop.response.description", "Response description", textValue([]byte(description)), start+len(indicator)+1, len(description))
		}

		lineEnd := lineLength(pdu)

		if (lineEnd > 0) && (lineEnd < len(pdu)) {
			tree.add(root, "pop.data", "Data", textValue(pdu[lineEnd:]), start+lineEnd, len(pdu)-lineEnd)
		}

		state.mode = starttlsMode
		tree.addSummary("POP " + output.Escape([]byte(indicator)) + map[bool]string{false: "", true: " " + textValue([]byte(description))}[description != ""])
		return
	}

	root = tree.add(nil, popProtocol, popTitle+" (request)", "", start, len(pdu))
	tree.add(root, "pop.request.command", "Request command", textValue([]byte(indicator)), start, len(indicator))

	if description != "" {
		tree.add(root, "pop.request.parameter", "Request parameter", textValue([]byte(description)), start+len(indicator)+1, len(description))
	}

	if indicator == "STLS" {
		state.mode = starttlsMode
	}

	tree.addSummary("POP " + output.Escape([]byte(indicator)))
	return
}
