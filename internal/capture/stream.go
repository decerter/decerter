// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"bytes"
	"slices"
	"sort"
)

const (
	// what a range that waits costs on top of its bytes, so a flood of tiny segments is bounded too
	segmentOverhead int = 64
	// a segment this far from the next byte is not part of the stream, a receive window is never larger (RFC 7323 section 2.3)
	maxSequenceDistance int64 = 1 << 30
)

// a piece of one direction of a TCP connection, exactly one of the three:
// Data: bytes in the order of the stream, only valid until the next call of the stream
// Missing: bytes of the stream that were never captured
// IsFIN: the direction is closed, nothing follows
type Part struct {
	Data    []byte
	Missing uint32
	IsFIN   bool
}

// a range of the stream that came before its turn: captured bytes, or with data nil bytes the snaplen cut off, they will never come
type segment struct {
	sequence uint32
	length   uint32
	data     []byte
}

// one direction of a TCP connection put back in order from its packets as they were captured: a GSO or GRO packet is one long segment
// next is the sequence number of the next byte of the stream, segments are the ranges behind a hole in the order of the stream, they never overlap
// held is what segments cost, over limit the oldest hole is given up
type Stream struct {
	limit       int
	isStarted   bool
	isFinished  bool
	next        uint32
	segments    []segment
	held        int
	hasFIN      bool
	finSequence uint32
}

// limit is the most bytes that may wait behind a hole
func NewStream(limit int) (stream Stream) {
	stream = Stream{
		limit:       limit,
		isStarted:   false,
		isFinished:  false,
		next:        0,
		segments:    nil,
		held:        0,
		hasFIN:      false,
		finSequence: 0,
	}
	return
}

// the stream starts at this sequence number: the one behind the SYN, or the first one seen of a connection that was already open; a started stream stays as it is
func (stream *Stream) Start(sequence uint32) {
	if stream.isStarted {
		return
	}

	stream.isStarted = true
	stream.next = sequence
}

func (stream *Stream) IsStarted() (isStarted bool) {
	isStarted = stream.isStarted
	return
}

// what waits behind a hole, with the overhead of every range
func (stream *Stream) Held() (held int) {
	held = stream.held
	return
}

// add a segment: data is the captured payload at sequence, length the payload the packet had, the bytes the snaplen cut off are a hole that is known at once
// the parts that are in order now are appended to parts; a retransmit and an overlap are trimmed, the copy that came first stays
func (stream *Stream) Add(sequence uint32, data []byte, length uint32, isFIN bool, parts []Part) (result []Part) {
	result = parts
	stream.Start(sequence)

	if stream.isFinished {
		return
	}

	if isFIN && !stream.hasFIN {
		stream.hasFIN = true
		stream.finSequence = sequence + length
	}

	captured := uint32(min(uint64(len(data)), uint64(length)))
	data = data[:captured]
	ahead := stream.distance(sequence)

	// the usual case is the next segment of a stream without a hole, its bytes are passed on without a copy
	if (len(stream.segments) == 0) && (ahead <= 0) && (ahead+int64(captured) > 0) {
		result = append(result, Part{Data: data[-ahead:], Missing: 0, IsFIN: false})
		stream.next = sequence + captured
	} else if ahead+int64(captured) > 0 {
		// the packet of the reader is used again, so what waits is a copy
		stream.insert(sequence, captured, bytes.Clone(data))
	}

	if captured < length {
		stream.insert(sequence+captured, length-captured, nil)
	}

	result = stream.drain(result)

	for stream.held > stream.limit {
		result = stream.skip(result)
	}

	return
}

// the other side acknowledged everything before sequence, so it has those bytes: what is not here by now was lost by the capture and is a hole that will not be filled
// the programs see a segment before the socket that acknowledges it, so an acknowledgment is never read before its segment
func (stream *Stream) Acknowledge(sequence uint32, parts []Part) (result []Part) {
	result = parts

	if !stream.isStarted {
		stream.Start(sequence)
		return
	}

	for !stream.isFinished {
		target := sequence

		// the FIN is acknowledged like a byte
		if stream.hasFIN && (int32(target-stream.finSequence) > 0) {
			target = stream.finSequence
		}

		ahead := stream.distance(target)

		if (ahead <= 0) || (ahead > maxSequenceDistance) {
			return
		}

		if (len(stream.segments) > 0) && (stream.distance(stream.segments[0].sequence) < ahead) {
			result = stream.skip(result)
			continue
		}

		result = appendMissing(result, uint32(ahead))
		stream.next = target
		result = stream.drain(result)
	}

	return
}

// give every hole up, nothing waits after it: the connection is over or the memory is needed
func (stream *Stream) Flush(parts []Part) (result []Part) {
	result = parts

	for len(stream.segments) > 0 {
		result = stream.skip(result)
	}

	return
}

// how far sequence is behind the next byte of the stream, negative for bytes that were already passed on; sequence numbers wrap around
func (stream *Stream) distance(sequence uint32) (ahead int64) {
	ahead = int64(int32(sequence - stream.next))
	return
}

// put a range that is not in order into segments, only the parts of it that are not there yet; data is nil for bytes that are lost and is kept otherwise
func (stream *Stream) insert(sequence uint32, length uint32, data []byte) {
	start := stream.distance(sequence)
	end := start + int64(length)

	if (end <= 0) || (start > maxSequenceDistance) {
		return
	}

	// the front was already passed on
	if start < 0 {
		if data != nil {
			data = data[-start:]
		}

		start = 0
	}

	// the first range that ends behind the start of the new one
	index := sort.Search(len(stream.segments), func(index int) bool {
		return stream.distance(stream.segments[index].sequence)+int64(stream.segments[index].length) > start
	})

	for start < end {
		pieceEnd := end

		if index < len(stream.segments) {
			existingStart := stream.distance(stream.segments[index].sequence)
			existingEnd := existingStart + int64(stream.segments[index].length)

			// these bytes are here, the copy that came first stays
			if existingStart <= start {
				if existingEnd >= end {
					return
				}

				if data != nil {
					data = data[existingEnd-start:]
				}

				start = existingEnd
				index++
				continue
			}

			pieceEnd = min(end, existingStart)
		}

		piece := segment{
			sequence: stream.next + uint32(start),
			length:   uint32(pieceEnd - start),
			data:     nil,
		}

		if data != nil {
			piece.data = data[:pieceEnd-start]
			data = data[pieceEnd-start:]
		}

		stream.segments = slices.Insert(stream.segments, index, piece)
		stream.held += len(piece.data) + segmentOverhead
		start = pieceEnd
		index++
	}
}

// pass on the ranges that follow the stream without a hole, and the FIN when the stream reached it
func (stream *Stream) drain(parts []Part) (result []Part) {
	result = parts
	count := 0

	for (count < len(stream.segments)) && (stream.segments[count].sequence == stream.next) {
		ready := stream.segments[count]

		if ready.data == nil {
			result = appendMissing(result, ready.length)
		} else {
			result = append(result, Part{Data: ready.data, Missing: 0, IsFIN: false})
		}

		stream.held -= len(ready.data) + segmentOverhead
		stream.next += ready.length
		count++
	}

	stream.segments = slices.Delete(stream.segments, 0, count)

	if stream.hasFIN && (stream.next == stream.finSequence) {
		result = append(result, Part{Data: nil, Missing: 0, IsFIN: true})
		stream.isFinished = true
		stream.next++
		stream.segments = nil
		stream.held = 0
	}

	return
}

// give the hole in front of the first range up
func (stream *Stream) skip(parts []Part) (result []Part) {
	result = parts

	if len(stream.segments) == 0 {
		return
	}

	result = appendMissing(result, uint32(stream.distance(stream.segments[0].sequence)))
	stream.next = stream.segments[0].sequence
	result = stream.drain(result)
	return
}

// holes that follow each other are one hole
func appendMissing(parts []Part, missing uint32) (result []Part) {
	result = parts

	if (len(result) > 0) && (result[len(result)-1].Missing > 0) {
		result[len(result)-1].Missing += missing
		return
	}

	result = append(result, Part{Data: nil, Missing: missing, IsFIN: false})
	return
}
