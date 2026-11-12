// SPDX-License-Identifier: AGPL-3.0-only

package intercept

import (
	"fmt"
	"io"
	"strings"

	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// the payload shown of one message, the header line has the whole length
	MaxPrintBytes int    = 2048
	payloadIndent string = "    "
	hexDigits     string = "0123456789abcdef"
	hexLineBytes  int    = 16
)

// one header line per message, below it the payload that goes on as escaped text and as hex dump, in one write so the messages of other flows don't get in between
// a dropped message shows what was dropped; original is the length the peer sent when a rule changed it, passed marks a message that went on before the rules could see it
func Print(output io.Writer, message Message, result Result, isPassed bool) {
	payload := result.Plain

	if result.Verdict == DropVerdict {
		payload = message.Plain
	}

	shown := min(len(payload), MaxPrintBytes)
	builder := strings.Builder{}
	builder.Grow(256 + 5*shown)
	builder.WriteString(LinePrefix(message.Flow, message.Layer))
	fmt.Fprintf(&builder, " direction=%s id=%d length=%d shown=%d", DirectionName(message.Direction), message.ID, len(payload), shown)

	switch {
	case isPassed:
		builder.WriteString(" passed")
	case result.Verdict == DropVerdict:
		builder.WriteString(" verdict=drop")
	case result.Changed:
		fmt.Fprintf(&builder, " original=%d", len(message.Plain))
	default:
	}

	builder.WriteByte('\n')
	builder.WriteString(Escape(payload[:shown]))
	builder.WriteString(HexDump(payload[:shown]))
	// stdout is the output of the tool, a failed write has nowhere to go
	_, _ = io.WriteString(output, builder.String())
}

// the start of every line of a flow: process, destination, client and for TLS the session
func LinePrefix(flow Flow, layer Layer) (prefix string) {
	prefix = fmt.Sprintf("%s pid=%d uid=%d comm=%s %s client=%s", layer, flow.Tgid, flow.UID, flow.Comm, flow.Destination, flow.Client)

	if layer == TLSLayer {
		prefix += fmt.Sprintf(" version=%s suite=%s", tlsrecord.VersionName(flow.Session.Version), tlsrecord.CipherSuiteName(flow.Session.CipherSuite))
	}

	return
}

// plaintext for a terminal: printable ASCII stays, everything else is escaped, so no control sequence of a peer gets through
// a line feed is shown as \n and also ends the line; every line is indented, so no payload can look like a header or a flow line
func Escape(payload []byte) (text string) {
	if len(payload) == 0 {
		return
	}

	builder := strings.Builder{}
	builder.Grow(len(payloadIndent) + len(payload) + len(payload)/8)
	builder.WriteString(payloadIndent)

	for index, value := range payload {
		switch {
		case value == '\n':
			builder.WriteString(`\n`)

			if index != len(payload)-1 {
				builder.WriteString("\n" + payloadIndent)
			}
		case value == '\r':
			builder.WriteString(`\r`)
		case value == '\t':
			builder.WriteString(`\t`)
		case value == '\\':
			builder.WriteString(`\\`)
		case (value >= ' ') && (value <= '~'):
			builder.WriteByte(value)
		default:
			builder.WriteString(`\x`)
			builder.WriteByte(hexDigits[value>>4])
			builder.WriteByte(hexDigits[value&0x0f])
		}
	}

	builder.WriteByte('\n')
	text = builder.String()
	return
}

// 16 bytes per line: offset, the bytes in hex and the printable ASCII among them, every other byte as a dot; indented like the escaped text
func HexDump(payload []byte) (text string) {
	builder := strings.Builder{}
	builder.Grow((len(payload)/hexLineBytes + 1) * 80)

	for start := 0; start < len(payload); start += hexLineBytes {
		line := payload[start:min(start+hexLineBytes, len(payload))]
		builder.WriteString(payloadIndent)

		for shift := 28; shift >= 0; shift -= 4 {
			builder.WriteByte(hexDigits[(start>>shift)&0x0f])
		}

		builder.WriteByte(' ')

		for index := range hexLineBytes {
			// a gap in the middle of the line, as hexdump -C
			if index == hexLineBytes/2 {
				builder.WriteByte(' ')
			}

			if index >= len(line) {
				builder.WriteString("   ")
				continue
			}

			builder.WriteByte(' ')
			builder.WriteByte(hexDigits[line[index]>>4])
			builder.WriteByte(hexDigits[line[index]&0x0f])
		}

		builder.WriteString("  |")

		for _, value := range line {
			if (value >= ' ') && (value <= '~') {
				builder.WriteByte(value)
			} else {
				builder.WriteByte('.')
			}
		}

		builder.WriteString("|\n")
	}

	text = builder.String()
	return
}
