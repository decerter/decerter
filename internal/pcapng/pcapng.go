// SPDX-License-Identifier: AGPL-3.0-only

package pcapng

import (
	"bufio"
	"fmt"
	"io"
)

const (
	// blocks are collected up to this size before they go to the output, a longer block is written through
	bufferLength int = 1 << 16
	// the longest value of an option (section 3.5)
	maxOptionLength int = 65535
)

// writes one pcapng section with one LINKTYPE_RAW interface: packets with nanosecond timestamps and TLS key logs
// block is the block being built, its memory is used again for the next one
type Writer struct {
	output  *bufio.Writer
	snaplen uint32
	block   []byte
}

// start the section: the Section Header Block and the Interface Description Block, no packet has more than snaplen bytes
func New(output io.Writer, snaplen uint32) (writer Writer, err error) {
	if snaplen == 0 {
		err = ErrSnaplen
		return
	}

	writer = Writer{
		output:  bufio.NewWriterSize(output, bufferLength),
		snaplen: snaplen,
		block:   nil,
	}
	writer.block = sectionHeaderBlock(writer.block)
	err = writer.writeBlock()

	if err != nil {
		return
	}

	writer.block = interfaceDescriptionBlock(writer.block, snaplen)
	err = writer.writeBlock()
	return
}

func (writer *Writer) WritePacket(packet Packet) (err error) {
	if (uint32(len(packet.Data)) > packet.OriginalLength) || (uint32(len(packet.Data)) > writer.snaplen) {
		err = fmt.Errorf("%w: %d bytes of %d, snaplen %d", ErrPacketSize, len(packet.Data), packet.OriginalLength, writer.snaplen)
		return
	}

	// the length of an option is 16 bits
	if len(packet.Comment) > maxOptionLength {
		err = fmt.Errorf("%w: %d bytes", ErrCommentSize, len(packet.Comment))
		return
	}

	writer.block = enhancedPacketBlock(writer.block, packet)
	err = writer.writeBlock()
	return
}

// keyLog is one or more lines of the NSS key log format, each ends with a newline
// Wireshark decrypts a session only when its lines are in the file before the packets that need them
func (writer *Writer) WriteSecrets(keyLog []byte) (err error) {
	writer.block = decryptionSecretsBlock(writer.block, keyLog)
	err = writer.writeBlock()
	return
}

// every block goes through here to the buffer, the place to flush each block for a live stream
func (writer *Writer) writeBlock() (err error) {
	_, err = writer.output.Write(writer.block)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrWrite, err)
		return
	}

	return
}

// hand the buffered blocks to the output, the file is a complete pcapng after every Flush
func (writer *Writer) Flush() (err error) {
	err = writer.output.Flush()

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrWrite, err)
		return
	}

	return
}
