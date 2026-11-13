// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	v1 "github.com/decerter/decerter/api"
)

// the start of a marker inside escaped data, opening or closing, any case, with spaces or escaped bytes before the name: <untrusted-traffic, < /UNTRUSTED-TRAFFIC, <\t/untrusted-traffic, <\x00/untrusted-traffic
var markerPattern = regexp.MustCompile(`(?i)<((?:\s|\\[nrt]|\\x[0-9a-f]{2})*/?(?:\s|\\[nrt]|\\x[0-9a-f]{2})*` + markerName + `)`)

// the escaped form of data from the traffic: printable ASCII as it is, \\ \n \r \t, \xNN for every other byte (control characters, ANSI escapes, NUL, DEL, every byte of UTF-8 or invalid UTF-8)
// a < that starts the marker becomes \x3c, so data can neither close nor open one; the result is ASCII with no control characters
func Escape(data []byte) (escaped string) {
	builder := strings.Builder{}
	builder.Grow(len(data))

	for _, character := range data {
		switch {
		case character == '\\':
			builder.WriteString(`\\`)
		case character == '\n':
			builder.WriteString(`\n`)
		case character == '\r':
			builder.WriteString(`\r`)
		case character == '\t':
			builder.WriteString(`\t`)
		case (character >= 0x20) && (character < 0x7f):
			builder.WriteByte(character)
		default:
			builder.WriteString(`\x`)
			builder.WriteByte(hexDigits[character>>4])
			builder.WriteByte(hexDigits[character&0x0f])
		}
	}

	escaped = markerPattern.ReplaceAllString(builder.String(), `\x3c$1`)
	return
}

// Escape for a string field of the traffic's metadata
func escapeText(text string) (escaped string) {
	escaped = Escape([]byte(text))
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

// the same window without the data, for the metadata in the text of a result
func (payload PayloadWindow) withoutData() (stripped PayloadWindow) {
	stripped = payload
	stripped.PayloadHex = ""
	stripped.PayloadEscaped = ""
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

	return
}

// the text of a result with data from the traffic: the fixed note, the metadata as JSON, then each payload in its marker
func untrustedText(metadata any, payloads []string) (text string, err error) {
	builder := &strings.Builder{}
	builder.WriteString(untrustedNote + "\n\n")
	encoder := json.NewEncoder(builder)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(metadata)

	if err != nil {
		return
	}

	for _, payload := range payloads {
		builder.WriteString("\n" + payload + "\n")
	}

	text = builder.String()
	return
}
