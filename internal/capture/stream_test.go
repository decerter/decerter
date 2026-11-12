// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture_test

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/decerter/decerter/internal/capture"
)

const (
	streamLimit int = 1 << 20
)

var (
	// close to the end of the sequence space, so the streams of the cases wrap around
	firstSequence uint32 = 0xFFFFFFF0
)

// one segment as a packet carries it: Offset is where its payload starts in the stream, Length the payload on the wire, Captured how much of it the snaplen left, -1 for all
type segmentCase struct {
	Offset   uint32
	Length   uint32
	Captured int
	IsFIN    bool
}

// Expected is the stream as it has to come out: the bytes, with a "[n]" where n bytes are missing and a "." for the FIN
type streamCase struct {
	Name     string
	Segments []segmentCase
	Expected string
}

// the bytes of the stream every case sends parts of
func streamBytes() (data []byte) {
	for index := range 64 {
		data = append(data, byte('a'+index%26))
	}

	return
}

// the parts in one line, as streamCase.Expected has them
func render(parts []capture.Part) (text string) {
	for _, part := range parts {
		switch {
		case part.Missing > 0:
			text += fmt.Sprintf("[%d]", part.Missing)
		case part.IsFIN:
			text += "."
		default:
			text += string(part.Data)
		}
	}

	return
}

func addSegments(stream *capture.Stream, segments []segmentCase) (text string) {
	data := streamBytes()

	for _, segment := range segments {
		captured := segment.Length

		if segment.Captured >= 0 {
			captured = uint32(segment.Captured)
		}

		// the parts are only valid until the next call
		text += render(stream.Add(firstSequence+segment.Offset, data[segment.Offset:segment.Offset+captured], segment.Length, segment.IsFIN, nil))
	}

	return
}

func testAddOrder() (err error) {
	positiveCases := []streamCase{
		{Name: "in order", Segments: []segmentCase{{0, 10, -1, false}, {10, 10, -1, false}, {20, 6, -1, true}}, Expected: "abcdefghijklmnopqrstuvwxyz."},
		{Name: "reordered", Segments: []segmentCase{{0, 5, -1, false}, {15, 5, -1, false}, {10, 5, -1, false}, {5, 5, -1, false}, {20, 6, -1, false}}, Expected: "abcdefghijklmnopqrstuvwxyz"},
		{Name: "duplicated", Segments: []segmentCase{{0, 10, -1, false}, {0, 10, -1, false}, {20, 6, -1, false}, {20, 6, -1, false}, {10, 10, -1, false}, {10, 10, -1, false}}, Expected: "abcdefghijklmnopqrstuvwxyz"},
		{Name: "overlapping", Segments: []segmentCase{{0, 10, -1, false}, {5, 10, -1, false}, {20, 3, -1, false}, {24, 2, -1, false}, {18, 8, -1, false}, {12, 10, -1, false}}, Expected: "abcdefghijklmnopqrstuvwxyz"},
		{Name: "retransmit over a hole", Segments: []segmentCase{{4, 4, -1, false}, {12, 4, -1, false}, {0, 26, -1, false}}, Expected: "abcdefghijklmnopqrstuvwxyz"},
		{Name: "fin before its data", Segments: []segmentCase{{0, 10, -1, false}, {26, 0, -1, true}, {20, 6, -1, false}, {10, 10, -1, false}, {26, 0, -1, true}, {20, 6, -1, false}}, Expected: "abcdefghijklmnopqrstuvwxyz."},
		{Name: "cut by the snaplen", Segments: []segmentCase{{0, 10, -1, false}, {10, 10, 4, false}, {20, 6, -1, false}}, Expected: "abcdefghijklmn[6]uvwxyz"},
		{Name: "cut behind a hole", Segments: []segmentCase{{10, 10, 4, false}, {20, 6, 0, false}, {0, 10, -1, false}, {10, 16, -1, false}}, Expected: "abcdefghijklmn[12]"},
	}

	for _, positive := range positiveCases {
		stream := capture.NewStream(streamLimit)
		stream.Start(firstSequence)
		text := addSegments(&stream, positive.Segments)

		if text != positive.Expected {
			err = fmt.Errorf("Add return value of case %q was not %q instead: %q", positive.Name, positive.Expected, text)
			return
		}

		if stream.Held() != 0 {
			err = fmt.Errorf("Held return value of case %q was not %d instead: %d", positive.Name, 0, stream.Held())
			return
		}
	}

	return
}

// a stream of random segments with retransmits and overlaps, each sent a few places away from its turn, has to come out as it was sent
func testAddShuffled() (err error) {
	random := rand.New(rand.NewPCG(12, 2026))
	data := make([]byte, 1<<18)

	for index := range data {
		data[index] = byte(random.Uint32())
	}

	type piece struct {
		offset int
		length int
	}

	pieces := []piece{}

	for offset := 0; offset < len(data); {
		length := min(1+random.IntN(3000), len(data)-offset)
		pieces = append(pieces, piece{offset: offset, length: length})

		// a retransmit that starts earlier and ends later than its segment
		if random.IntN(4) == 0 {
			start := max(0, offset-random.IntN(2000))
			pieces = append(pieces, piece{offset: start, length: min(length+random.IntN(4000), len(data)-start)})
		}

		offset += length
	}

	for index := range pieces {
		other := min(len(pieces)-1, index+random.IntN(8))
		pieces[index], pieces[other] = pieces[other], pieces[index]
	}

	stream := capture.NewStream(streamLimit)
	stream.Start(firstSequence)
	output := []byte{}

	for _, piece := range pieces {
		for _, part := range stream.Add(firstSequence+uint32(piece.offset), data[piece.offset:piece.offset+piece.length], uint32(piece.length), false, nil) {
			if (part.Missing > 0) || part.IsFIN {
				err = fmt.Errorf("Add return value had a part that is not data: %+v", part)
				return
			}

			output = append(output, part.Data...)
		}
	}

	if !bytes.Equal(output, data) {
		err = fmt.Errorf("Add return value was not the %d bytes of the stream, it had %d bytes", len(data), len(output))
		return
	}

	return
}

// over its limit the stream gives its oldest hole up
func testAddLimit() (err error) {
	stream := capture.NewStream(200)
	stream.Start(firstSequence)
	text := addSegments(&stream, []segmentCase{{0, 4, -1, false}, {8, 4, -1, false}, {16, 4, -1, false}, {24, 2, -1, false}, {30, 4, -1, false}})
	// the third and the fifth segment that waits are one too many, each time the hole in front of the first one is given up
	expected := "abcd[4]ijkl[4]qrst"

	if text != expected {
		err = fmt.Errorf("Add return value was not %q instead: %q", expected, text)
		return
	}

	return
}

func testAcknowledge() (err error) {
	stream := capture.NewStream(streamLimit)
	stream.Start(firstSequence)
	text := addSegments(&stream, []segmentCase{{0, 4, -1, false}, {8, 4, -1, false}, {20, 6, -1, true}})
	// nothing new, two bytes of the hole, then the rest of it, the hole behind the segment that waited and everything up to the FIN
	text += "|" + render(stream.Acknowledge(firstSequence+4, nil))
	text += "|" + render(stream.Acknowledge(firstSequence+6, nil))
	text += "|" + render(stream.Acknowledge(firstSequence+27, nil))
	text += "|" + render(stream.Acknowledge(firstSequence+27, nil))
	expected := "abcd||[2]|[2]ijkl[8]uvwxyz.|"

	if text != expected {
		err = fmt.Errorf("Acknowledge return value was not %q instead: %q", expected, text)
		return
	}

	// a stream nothing was seen of starts where the other side acknowledges
	stream = capture.NewStream(streamLimit)
	text = render(stream.Acknowledge(firstSequence+10, nil))
	text += addSegments(&stream, []segmentCase{{4, 10, -1, false}})
	expected = "klmn"

	if text != expected {
		err = fmt.Errorf("Acknowledge return value was not %q instead: %q", expected, text)
		return
	}

	return
}

func testFlush() (err error) {
	stream := capture.NewStream(streamLimit)
	stream.Start(firstSequence)
	text := addSegments(&stream, []segmentCase{{0, 4, -1, false}, {8, 4, -1, false}, {20, 6, -1, false}})
	text += "|" + render(stream.Flush(nil))
	text += "|" + render(stream.Flush(nil))
	expected := "abcd|[4]ijkl[8]uvwxyz|"

	if text != expected {
		err = fmt.Errorf("Flush return value was not %q instead: %q", expected, text)
		return
	}

	if stream.Held() != 0 {
		err = fmt.Errorf("Held return value was not %d instead: %d", 0, stream.Held())
		return
	}

	return
}

// Test if capture.Stream.Add returns with the expected output.
func TestAddPositive(state *testing.T) {
	err := testAddOrder()

	if err != nil {
		state.Errorf("Test of capture.Stream.Add failed, error: %s", err.Error())
		return
	}

	err = testAddShuffled()

	if err != nil {
		state.Errorf("Test of capture.Stream.Add failed, error: %s", err.Error())
		return
	}

	err = testAddLimit()

	if err != nil {
		state.Errorf("Test of capture.Stream.Add failed, error: %s", err.Error())
		return
	}
}

// Test if capture.Stream.Acknowledge returns with the expected output.
func TestAcknowledgePositive(state *testing.T) {
	err := testAcknowledge()

	if err != nil {
		state.Errorf("Test of capture.Stream.Acknowledge failed, error: %s", err.Error())
		return
	}
}

// Test if capture.Stream.Flush returns with the expected output.
func TestFlushPositive(state *testing.T) {
	err := testFlush()

	if err != nil {
		state.Errorf("Test of capture.Stream.Flush failed, error: %s", err.Error())
		return
	}
}
