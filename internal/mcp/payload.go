// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/output"
)

// the start of a marker inside escaped data, opening or closing, any case, with spaces or escaped bytes before the name: <untrusted-traffic, < /UNTRUSTED-TRAFFIC, <\t/untrusted-traffic, <\x00/untrusted-traffic
var markerPattern = regexp.MustCompile(`(?i)<((?:\s|\\[nrt]|\\x[0-9a-f]{2})*/?(?:\s|\\[nrt]|\\x[0-9a-f]{2})*` + markerName + `)`)

// the escaped form of data from the traffic, output.Escape's: printable ASCII as it is, \\ \n \r \t, \xNN for every other byte (control characters, ANSI escapes,
// NUL, DEL, every byte of UTF-8 or invalid UTF-8); a < that starts the marker becomes \x3c, so data can neither close nor open one; the result is ASCII with no control characters
func Escape(data []byte) (escaped string) {
	escaped = markerPattern.ReplaceAllString(output.Escape(data), `\x3c$1`)
	return
}

// the bytes of the escaped form, the inverse of Escape: \\ \n \r \t and \xNN (either case) are bytes, every other character is its UTF-8 bytes, a real line break too
// any other backslash is an error that names its byte offset
func Unescape(escaped string) (data []byte, err error) {
	data = make([]byte, 0, len(escaped))

	for index := 0; index < len(escaped); index++ {
		if escaped[index] != '\\' {
			data = append(data, escaped[index])
			continue
		}

		next := byte(0)

		if index+1 < len(escaped) {
			next = escaped[index+1]
		}

		switch next {
		case '\\':
			data = append(data, '\\')
		case 'n':
			data = append(data, '\n')
		case 'r':
			data = append(data, '\r')
		case 't':
			data = append(data, '\t')
		case 'x':
			value, decodeErr := hex.DecodeString(escaped[index+2 : min(index+4, len(escaped))])

			if (decodeErr != nil) || (len(value) != 1) {
				err = fmt.Errorf("%w at byte %d: \\x needs two hex digits", ErrEscape, index)
				return
			}

			data = append(data, value[0])
			index += 2
		default:
			err = fmt.Errorf("%w at byte %d: use \\\\ \\n \\r \\t or \\xNN, a backslash is \\\\", ErrEscape, index)
			return
		}

		index++
	}

	return
}

// hex digits of a payload, white space between them is ignored
func unhex(text string) (data []byte, err error) {
	data, err = hex.DecodeString(strings.Join(strings.Fields(text), ""))

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrPayloadHex, err)
	}

	return
}

// Escape for a string field of the traffic's metadata
func escapeText(text string) (escaped string) {
	escaped = Escape([]byte(text))
	return
}

// a string of a decode tree, which decerter escaped already: a byte outside printable ASCII becomes \xNN (a backslash stays, it starts an escape), and a < that
// starts the marker \x3c, so a tree that came through the api unescaped still can't reach the client raw
func escapeDecoded(text string) (escaped string) {
	builder := strings.Builder{}
	builder.Grow(len(text))

	for index := range len(text) {
		character := text[index]

		if (character >= 0x20) && (character < 0x7f) {
			builder.WriteByte(character)
			continue
		}

		builder.WriteString(`\x`)
		builder.WriteByte(hexDigits[character>>4])
		builder.WriteByte(hexDigits[character&0x0f])
	}

	escaped = markerPattern.ReplaceAllString(builder.String(), `\x3c$1`)
	return
}

// one payload in the marker; id is made by decerter, never taken from the data
func Wrap(id string, escaped string) (wrapped string) {
	wrapped = `<` + markerName + ` id="` + id + `">` + "\n" + escaped + "\n" + `</` + markerName + `>`
	return
}

// the window [offset, offset+length) of data, cut to its end; an offset past the end gives an empty window at the end
func window(data []byte, offset int, length int) (payload PayloadWindow) {
	start := min(offset, len(data))
	end := min(start+length, len(data))
	payload = newWindow(data[start:end], start, len(data))
	return
}

// a window of total bytes that starts at offset
func newWindow(data []byte, offset int, total int) (payload PayloadWindow) {
	payload = PayloadWindow{
		Offset:         offset,
		Length:         len(data),
		Total:          total,
		NextOffset:     0,
		PayloadHex:     hex.EncodeToString(data),
		PayloadEscaped: Escape(data),
	}

	if offset+len(data) < total {
		payload.NextOffset = offset + len(data)
	}

	return
}

// a window the api sent: its hex is decoded and escaped here again, the escaped form of the api is not used
func apiWindow(payload v1.Payload) (window PayloadWindow, err error) {
	data, decodeErr := hex.DecodeString(payload.Hex)

	if err = decodeErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrHex, err)
		return
	}

	window = newWindow(data, payload.Offset, payload.Total)
	return
}

// the window for the metadata in the text of a result: the escaped data goes into the marker, the hex only withHex
func (payload PayloadWindow) metadata(withHex bool) (stripped PayloadWindow) {
	stripped = payload
	stripped.PayloadEscaped = ""

	if !withHex {
		stripped.PayloadHex = ""
	}

	return
}

// the string fields of a flow that come from the traffic's processes and peers, escaped like a payload
func escapeFlow(flow v1.Flow) (escaped v1.Flow) {
	escaped = flow
	escaped.Process.Comm = escapeText(flow.Process.Comm)
	escaped.Process.Cmdline = escapeText(flow.Process.Cmdline)
	escaped.Process.Exe = escapeText(flow.Process.Exe)

	if flow.TLS != nil {
		tlsInfo := *flow.TLS
		tlsInfo.OfferedVersion = escapeText(tlsInfo.OfferedVersion)
		tlsInfo.ServerName = escapeText(tlsInfo.ServerName)
		tlsInfo.ClientRandom = escapeText(tlsInfo.ClientRandom)
		tlsInfo.Version = escapeText(tlsInfo.Version)
		tlsInfo.CipherSuite = escapeText(tlsInfo.CipherSuite)
		tlsInfo.ALPN = escapeText(tlsInfo.ALPN)
		tlsInfo.OfferedALPN = nil

		for _, protocol := range flow.TLS.OfferedALPN {
			tlsInfo.OfferedALPN = append(tlsInfo.OfferedALPN, escapeText(protocol))
		}

		escaped.TLS = &tlsInfo
	}

	return
}

// the short form of an event: ids, the flow's destination and comm, an exchange's method, URL and status
func summarizeEvent(event v1.Event) (summary EventSummary) {
	summary = EventSummary{Type: event.Type, Time: event.Time, Reason: escapeText(event.Reason)}

	if flow := event.Flow; flow != nil {
		summary.FlowID, summary.Protocol, summary.Destination, summary.Comm = flow.ID, flow.Protocol, flow.Destination, escapeText(flow.Process.Comm)

		if flow.TLS != nil {
			summary.ServerName = escapeText(flow.TLS.ServerName)
		}
	}

	if message := event.Message; message != nil {
		summary.MessageID, summary.FlowID, summary.Direction, summary.Layer, summary.Length, summary.Verdict = message.ID, message.FlowID, message.Direction, message.Layer, message.Length, message.Verdict
	}

	if hold := event.Hold; hold != nil {
		summary.HoldID, summary.FlowID, summary.ExchangeID, summary.Direction, summary.Layer, summary.Length = hold.ID, hold.FlowID, hold.ExchangeID, hold.Direction, hold.Layer, hold.Length
	}

	if event.Exchange != nil {
		exchange := summarize(escapeExchange(*event.Exchange))
		summary.ExchangeID, summary.FlowID, summary.Method, summary.URL, summary.Status = exchange.ID, exchange.FlowID, exchange.Method, exchange.URL, exchange.Status
		summary.RequestState, summary.ResponseState = exchange.RequestState, exchange.ResponseState
	}

	if event.Rule != nil {
		summary.RuleID = event.Rule.ID
	}

	if event.Intercept != nil {
		summary.Enabled = new(event.Intercept.Enabled)
	}

	return
}

// an event without payload, its flow escaped; events carry no payload, a hold's is dropped if one came
func escapeEvent(event v1.Event) (escaped v1.Event) {
	escaped = event

	if event.Flow != nil {
		flow := escapeFlow(*event.Flow)
		escaped.Flow = &flow
	}

	if event.Hold != nil {
		hold := *event.Hold
		hold.Payload = nil
		escaped.Hold = &hold
	}

	if event.Exchange != nil {
		exchange := escapeExchange(*event.Exchange)
		escaped.Exchange = &exchange
	}

	return
}

// the string fields of an exchange come from its peers, escaped like a payload
func escapeExchange(exchange v1.Exchange) (escaped v1.Exchange) {
	escaped = exchange
	escaped.Protocol = escapeText(exchange.Protocol)
	escaped.Interim = nil

	if exchange.Request != nil {
		escaped.Request = new(escapeHTTPMessage(*exchange.Request))
	}

	if exchange.Response != nil {
		escaped.Response = new(escapeHTTPMessage(*exchange.Response))
	}

	for _, interim := range exchange.Interim {
		escaped.Interim = append(escaped.Interim, escapeHTTPMessage(interim))
	}

	return
}

func escapeHTTPMessage(message v1.HTTPMessage) (escaped v1.HTTPMessage) {
	escaped = message
	escaped.HTTPHead = escapeHead(message.HTTPHead)
	escaped.URL = escapeText(message.URL)
	escaped.Note = escapeText(message.Note)
	escaped.Trailers = escapeHeaders(message.Trailers)

	if message.Original != nil {
		escaped.Original = new(escapeHead(*message.Original))
	}

	return
}

func escapeHead(head v1.HTTPHead) (escaped v1.HTTPHead) {
	escaped = head
	escaped.Method = escapeText(head.Method)
	escaped.Target = escapeText(head.Target)
	escaped.Version = escapeText(head.Version)
	escaped.Reason = escapeText(head.Reason)
	escaped.Headers = escapeHeaders(head.Headers)

	if escaped.Headers == nil {
		escaped.Headers = []v1.Header{}
	}

	return
}

func escapeHeaders(headers []v1.Header) (escaped []v1.Header) {
	for _, header := range headers {
		escaped = append(escaped, v1.Header{Name: escapeText(header.Name), Value: escapeText(header.Value)})
	}

	return
}

// the text of a result with data from the traffic: the fixed note when it has any (isTraffic), the metadata as JSON, then each payload in its marker
func untrustedText(metadata any, payloads []string, isTraffic bool) (text string, err error) {
	builder := &strings.Builder{}

	if isTraffic || (len(payloads) > 0) {
		builder.WriteString(untrustedNote + "\n\n")
	}

	metadataText, err := jsonText(metadata)

	if err != nil {
		return
	}

	builder.WriteString(metadataText + "\n")

	for _, payload := range payloads {
		builder.WriteString("\n" + payload + "\n")
	}

	text = builder.String()
	return
}

// value as compact JSON without HTML escaping: a filter's && and a regex's (?P<name>) stay as they are
func jsonText(value any) (text string, err error) {
	builder := &strings.Builder{}
	encoder := json.NewEncoder(builder)
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(value)

	if err != nil {
		return
	}

	text = strings.TrimSuffix(builder.String(), "\n")
	return
}
