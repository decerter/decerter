// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package pcapng_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/pcapng"
)

const (
	snaplen            uint32 = 64
	sectionHeaderType  uint32 = 0x0A0D0D0A
	interfaceType      uint32 = 0x00000001
	enhancedPacketType uint32 = 0x00000006
	secretsType        uint32 = 0x0000000A
	byteOrderMagic     uint32 = 0x1A2B3C4D
	linkTypeRaw        uint16 = 101
	tlsKeyLogType      uint32 = 0x544C534B
	timestamp          uint64 = 1794456844702912486
	keyLog             string = "CLIENT_RANDOM 00 11\n"
	comment            string = "decerter: note"
)

type block struct {
	Type uint32
	Body []byte
}

type packetCase struct {
	Packet pcapng.Packet
	Flags  uint32
}

// a writer that takes nothing
type fullWriter struct{}

func (fullWriter fullWriter) Write(data []byte) (count int, err error) {
	err = io.ErrShortWrite
	return
}

// walk the blocks of a section: every block is a multiple of 32 bits long and has its total length at both ends
func readBlocks(data []byte) (blocks []block, err error) {
	for len(data) > 0 {
		if len(data) < 12 {
			err = fmt.Errorf("%d bytes left are too short for a block", len(data))
			return
		}

		totalLength := binary.LittleEndian.Uint32(data[4:8])

		if (totalLength%4 != 0) || (totalLength < 12) || (int(totalLength) > len(data)) {
			err = fmt.Errorf("block total length was %d with %d bytes left", totalLength, len(data))
			return
		}

		if trailingLength := binary.LittleEndian.Uint32(data[totalLength-4 : totalLength]); trailingLength != totalLength {
			err = fmt.Errorf("trailing block total length was not %d instead: %d", totalLength, trailingLength)
			return
		}

		blocks = append(blocks, block{
			Type: binary.LittleEndian.Uint32(data[0:4]),
			Body: data[8 : totalLength-4],
		})
		data = data[totalLength:]
	}

	return
}

func write(packets []pcapng.Packet, keyLogs []string) (blocks []block, err error) {
	output := bytes.Buffer{}
	writer, newErr := pcapng.New(&output, snaplen)

	if err = newErr; err != nil {
		return
	}

	for _, secrets := range keyLogs {
		err = writer.WriteSecrets([]byte(secrets))

		if err != nil {
			return
		}
	}

	for _, packet := range packets {
		err = writer.WritePacket(packet)

		if err != nil {
			return
		}
	}

	err = writer.Flush()

	if err != nil {
		return
	}

	blocks, err = readBlocks(output.Bytes())
	return
}

func testNewHeader() (err error) {
	blocks, writeErr := write(nil, nil)

	if err = writeErr; err != nil {
		return
	}

	if len(blocks) != 2 {
		err = fmt.Errorf("block count was not %d instead: %d", 2, len(blocks))
		return
	}

	section := blocks[0]

	if (section.Type != sectionHeaderType) || (binary.LittleEndian.Uint32(section.Body[0:4]) != byteOrderMagic) || (binary.LittleEndian.Uint16(section.Body[4:6]) != 1) || (binary.LittleEndian.Uint16(section.Body[6:8]) != 0) || (binary.LittleEndian.Uint64(section.Body[8:16]) != 0xFFFFFFFFFFFFFFFF) {
		err = fmt.Errorf("section header block was not as expected: type 0x%08x body %x", section.Type, section.Body)
		return
	}

	// the options of a block end with opt_endofopt, 4 zero bytes
	if !bytes.HasSuffix(section.Body, []byte{0, 0, 0, 0}) {
		err = fmt.Errorf("section header options do not end with opt_endofopt: %x", section.Body)
		return
	}

	description := blocks[1]

	if (description.Type != interfaceType) || (binary.LittleEndian.Uint16(description.Body[0:2]) != linkTypeRaw) || (binary.LittleEndian.Uint32(description.Body[4:8]) != snaplen) {
		err = fmt.Errorf("interface description block was not as expected: type 0x%08x body %x", description.Type, description.Body)
		return
	}

	// if_tsresol (code 9, length 1) with value 9: nanoseconds, padded to 32 bits
	if !bytes.Contains(description.Body[8:], []byte{9, 0, 1, 0, 9, 0, 0, 0}) {
		err = fmt.Errorf("interface description has no nanosecond if_tsresol option: %x", description.Body)
		return
	}

	return
}

func testWritePacket() (err error) {
	positiveCases := []packetCase{
		{Packet: pcapng.Packet{Timestamp: timestamp, Direction: pcapng.OutboundDirection, OriginalLength: 5, Data: []byte{0x45, 1, 2, 3, 4}}, Flags: 2},
		{Packet: pcapng.Packet{Timestamp: timestamp + 1, Direction: pcapng.InboundDirection, OriginalLength: 4000, Data: bytes.Repeat([]byte{0x60}, int(snaplen))}, Flags: 1},
		{Packet: pcapng.Packet{Timestamp: timestamp + 2, Direction: pcapng.InboundDirection, OriginalLength: 0, Data: nil}, Flags: 1},
		{Packet: pcapng.Packet{Timestamp: timestamp + 3, Direction: pcapng.OutboundDirection, OriginalLength: 5, Data: []byte{0x45, 1, 2, 3, 4}, Comment: comment}, Flags: 2},
	}
	packets := []pcapng.Packet{}

	for _, positive := range positiveCases {
		packets = append(packets, positive.Packet)
	}

	blocks, writeErr := write(packets, nil)

	if err = writeErr; err != nil {
		return
	}

	if len(blocks) != 2+len(positiveCases) {
		err = fmt.Errorf("block count was not %d instead: %d", 2+len(positiveCases), len(blocks))
		return
	}

	for index, positive := range positiveCases {
		packetBlock := blocks[2+index]
		capturedLength := len(positive.Packet.Data)
		paddedLength := (capturedLength + 3) / 4 * 4

		if packetBlock.Type != enhancedPacketType {
			err = fmt.Errorf("block type was not 0x%08x instead: 0x%08x", enhancedPacketType, packetBlock.Type)
			return
		}

		expectedOptions := []byte{}

		// opt_comment (code 1) with the text padded to 32 bits, only when the packet has a comment
		if positive.Packet.Comment != "" {
			expectedOptions = append(expectedOptions, 1, 0, byte(len(positive.Packet.Comment)), 0)
			expectedOptions = append(expectedOptions, positive.Packet.Comment...)
			expectedOptions = append(expectedOptions, make([]byte, (4-len(positive.Packet.Comment)%4)%4)...)
		}

		expectedOptions = binary.LittleEndian.AppendUint32(append(expectedOptions, 2, 0, 4, 0), positive.Flags)
		expectedOptions = append(expectedOptions, 0, 0, 0, 0)

		// interface id, timestamp high and low, captured length, original length, data, the options: opt_comment, epb_flags, opt_endofopt
		if len(packetBlock.Body) != 20+paddedLength+len(expectedOptions) {
			err = fmt.Errorf("enhanced packet block body length was not %d instead: %d", 20+paddedLength+len(expectedOptions), len(packetBlock.Body))
			return
		}

		gotTimestamp := uint64(binary.LittleEndian.Uint32(packetBlock.Body[4:8]))<<32 | uint64(binary.LittleEndian.Uint32(packetBlock.Body[8:12]))

		if (binary.LittleEndian.Uint32(packetBlock.Body[0:4]) != 0) || (gotTimestamp != positive.Packet.Timestamp) || (binary.LittleEndian.Uint32(packetBlock.Body[12:16]) != uint32(capturedLength)) || (binary.LittleEndian.Uint32(packetBlock.Body[16:20]) != positive.Packet.OriginalLength) {
			err = fmt.Errorf("enhanced packet block header was not as expected: %x", packetBlock.Body[:20])
			return
		}

		if !bytes.Equal(packetBlock.Body[20:20+capturedLength], positive.Packet.Data) {
			err = fmt.Errorf("packet data was not %x instead: %x", positive.Packet.Data, packetBlock.Body[20:20+capturedLength])
			return
		}

		if !bytes.Equal(packetBlock.Body[20+paddedLength:], expectedOptions) {
			err = fmt.Errorf("packet options were not %x instead: %x", expectedOptions, packetBlock.Body[20+paddedLength:])
			return
		}
	}

	return
}

func testWriteSecrets() (err error) {
	blocks, writeErr := write(nil, []string{keyLog})

	if err = writeErr; err != nil {
		return
	}

	if len(blocks) != 3 {
		err = fmt.Errorf("block count was not %d instead: %d", 3, len(blocks))
		return
	}

	secrets := blocks[2]
	paddedLength := (len(keyLog) + 3) / 4 * 4

	if (secrets.Type != secretsType) || (binary.LittleEndian.Uint32(secrets.Body[0:4]) != tlsKeyLogType) || (binary.LittleEndian.Uint32(secrets.Body[4:8]) != uint32(len(keyLog))) || (len(secrets.Body) != 8+paddedLength) {
		err = fmt.Errorf("decryption secrets block was not as expected: type 0x%08x body %x", secrets.Type, secrets.Body)
		return
	}

	if string(secrets.Body[8:8+len(keyLog)]) != keyLog {
		err = fmt.Errorf("key log was not %q instead: %q", keyLog, secrets.Body[8:8+len(keyLog)])
		return
	}

	return
}

// Test if pcapng.New returns with the expected output.
func TestNewPositive(state *testing.T) {
	err := testNewHeader()

	if err != nil {
		state.Errorf("Test of pcapng.New failed, error: %s", err.Error())
		return
	}
}

// Test if pcapng.New returns with the expected errors.
func TestNewNegative(state *testing.T) {
	_, err := pcapng.New(&bytes.Buffer{}, 0)

	if !errors.Is(err, pcapng.ErrSnaplen) {
		state.Errorf("Test of pcapng.New function failed, error should be %v, error: %v", pcapng.ErrSnaplen, err)
		return
	}
}

// Test if pcapng.Writer.WritePacket returns with the expected output.
func TestWritePacketPositive(state *testing.T) {
	err := testWritePacket()

	if err != nil {
		state.Errorf("Test of pcapng.Writer.WritePacket failed, error: %s", err.Error())
		return
	}
}

// Test if pcapng.Writer.WritePacket returns with the expected errors.
func TestWritePacketNegative(state *testing.T) {
	negativeCases := []pcapng.Packet{
		{Timestamp: timestamp, Direction: pcapng.OutboundDirection, OriginalLength: 2, Data: []byte{1, 2, 3}},
		{Timestamp: timestamp, Direction: pcapng.OutboundDirection, OriginalLength: 4000, Data: bytes.Repeat([]byte{1}, int(snaplen)+1)},
	}

	for _, negative := range negativeCases {
		_, err := write([]pcapng.Packet{negative}, nil)

		if !errors.Is(err, pcapng.ErrPacketSize) {
			state.Errorf("Test of pcapng.Writer.WritePacket function failed, error should be %v, error: %v", pcapng.ErrPacketSize, err)
			return
		}
	}

	// the length of an option is 16 bits
	_, err := write([]pcapng.Packet{{Timestamp: timestamp, Direction: pcapng.OutboundDirection, OriginalLength: 1, Data: []byte{1}, Comment: strings.Repeat("c", 65536)}}, nil)

	if !errors.Is(err, pcapng.ErrCommentSize) {
		state.Errorf("Test of pcapng.Writer.WritePacket function failed, error should be %v, error: %v", pcapng.ErrCommentSize, err)
		return
	}
}

// Test if pcapng.Writer.WriteSecrets returns with the expected output.
func TestWriteSecretsPositive(state *testing.T) {
	err := testWriteSecrets()

	if err != nil {
		state.Errorf("Test of pcapng.Writer.WriteSecrets failed, error: %s", err.Error())
		return
	}
}

// Test if pcapng.Writer.Flush returns with the expected errors.
func TestFlushNegative(state *testing.T) {
	writer, err := pcapng.New(fullWriter{}, snaplen)

	if err != nil {
		state.Errorf("Test of pcapng.Writer.Flush failed, cannot create writer, error: %s", err.Error())
		return
	}

	err = writer.Flush()

	if !errors.Is(err, pcapng.ErrWrite) {
		state.Errorf("Test of pcapng.Writer.Flush function failed, error should be %v, error: %v", pcapng.ErrWrite, err)
		return
	}
}
