// SPDX-License-Identifier: AGPL-3.0-only

package http2

import (
	"encoding/binary"
	"fmt"
)

// the gRPC messages whose 5-byte prefix ends in data, offset is the body offset of data[0]; a prefix or a message may be cut over any number of frames
func (splitter *grpcSplitter) split(offset int64, data []byte) (messages []GRPCMessage) {
	for index := 0; index < len(data); {
		if splitter.remaining > 0 {
			taken := min(splitter.remaining, int64(len(data)-index))
			splitter.remaining -= taken
			index += int(taken)
			continue
		}

		if splitter.have == 0 {
			splitter.headerStart = offset + int64(index)
		}

		copied := copy(splitter.header[splitter.have:], data[index:])
		splitter.have += copied
		index += copied

		if splitter.have < len(splitter.header) {
			continue
		}

		splitter.have = 0
		length := binary.BigEndian.Uint32(splitter.header[1:])
		splitter.remaining = int64(length)

		if splitter.count == MaxGRPCMessages {
			splitter.isCut = true
			continue
		}

		splitter.count++
		messages = append(messages, GRPCMessage{Offset: splitter.headerStart, Length: length, IsCompressed: splitter.header[0]&1 == 1})
	}

	return
}

// what the end of a gRPC body says about its framing: a message cut short, more messages than are listed
func (splitter *grpcSplitter) note(isGRPC bool) (note string) {
	if !isGRPC {
		return
	}

	if (splitter.have > 0) || (splitter.remaining > 0) {
		note = "the last gRPC message is cut short"
	}

	if splitter.isCut {
		note = joinNotes(note, fmt.Sprintf("more than %d gRPC messages, only the first %d are listed", MaxGRPCMessages, MaxGRPCMessages))
	}

	return
}
