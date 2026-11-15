// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// count the lines of data, the last one without a line break waits for the next write or add
func (counter *keylogCounter) Write(data []byte) (written int, err error) {
	written = len(data)

	for len(data) > 0 {
		line, rest, isFound := bytes.Cut(data, []byte{'\n'})

		if len(counter.line)+len(line) <= maxKeylogLineBytes {
			counter.line = append(counter.line, line...)
		}

		data = rest

		if !isFound {
			break
		}

		counter.add()
	}

	return
}

// count the collected line: label, client random and secret, comments are no line
func (counter *keylogCounter) add() {
	fields := strings.Fields(string(counter.line))
	counter.line = counter.line[:0]

	if (len(fields) == 3) && !strings.HasPrefix(fields[0], "#") {
		counter.lines++
		counter.sessions[fields[1]] = true
	}
}

// walk the blocks of data: collect a block's start, count it, skip its rest
func (counter *pcapngCounter) Write(data []byte) (written int, err error) {
	written = len(data)

	for len(data) > 0 {
		if counter.skip > 0 {
			step := min(counter.skip, len(data))
			counter.skip -= step
			data = data[step:]
			continue
		}

		step := min(pcapngHeaderBytes-len(counter.header), len(data))
		counter.header = append(counter.header, data[:step]...)
		data = data[step:]

		if len(counter.header) == pcapngHeaderBytes {
			counter.count()
		}
	}

	return
}

// one block: a section header sets the byte order, the type is counted and the rest of the block skipped
func (counter *pcapngCounter) count() {
	header := counter.header
	counter.header = nil

	// the section header's type reads the same in both byte orders, its magic tells them apart
	if binary.LittleEndian.Uint32(header) == sectionHeaderBlockType {
		counter.order = binary.LittleEndian

		if binary.BigEndian.Uint32(header[8:]) == byteOrderMagic {
			counter.order = binary.BigEndian
		}
	}

	if counter.order == nil {
		counter.order = binary.LittleEndian
	}

	switch counter.order.Uint32(header) {
	case
		simplePacketBlockType,
		enhancedPacketType:
		counter.packets++
	case decryptionSecretsType:
		counter.secrets++
	default:
	}

	counter.skip = max(int(counter.order.Uint32(header[4:]))-pcapngHeaderBytes, 0)
}
