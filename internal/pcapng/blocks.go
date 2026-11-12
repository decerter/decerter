// SPDX-License-Identifier: AGPL-3.0-only

package pcapng

import (
	"encoding/binary"
)

// block types (draft-ietf-opsawg-pcapng section 11.1)
const (
	sectionHeaderBlockType        uint32 = 0x0A0D0D0A
	interfaceDescriptionBlockType uint32 = 0x00000001
	enhancedPacketBlockType       uint32 = 0x00000006
	decryptionSecretsBlockType    uint32 = 0x0000000A
)

// Section Header Block (section 4.1): the magic tells the reader the byte order of the section, the section length is not known while writing
const (
	byteOrderMagic       uint32 = 0x1A2B3C4D
	versionMajor         uint16 = 1
	versionMinor         uint16 = 0
	sectionLengthUnknown uint64 = 0xFFFFFFFFFFFFFFFF
)

// Interface Description Block (section 4.2): LINKTYPE_RAW packets start at the IPv4 or IPv6 header, the version nibble tells which
// the timestamps of the one interface are nanoseconds (if_tsresol 9)
const (
	linkTypeRaw            uint16 = 101
	nanosecondResolution   uint8  = 9
	captureInterfaceID     uint32 = 0
	captureInterfaceName   string = "decerter"
	sectionUserApplication string = "decerter"
)

// Decryption Secrets Block (section 4.7): secrets type "TLSK", a TLS key log
const (
	tlsKeyLogSecretsType uint32 = 0x544C534B
)

const (
	blockAlignment int = 4
)

// option codes (sections 3.5, 4.1, 4.2 and 4.3), a list of options ends with opt_endofopt
const (
	endOfOptionsCode             uint16 = 0
	sectionUserApplicationCode   uint16 = 4
	interfaceNameCode            uint16 = 2
	interfaceTimestampResolution uint16 = 9
	commentCode                  uint16 = 1
	packetFlagsCode              uint16 = 2
)

// epb_flags (section 4.3.1), bits 0 and 1 are the direction of the packet
const (
	inboundPacketFlag  uint32 = 1
	outboundPacketFlag uint32 = 2
)

type Direction uint8

const (
	OutboundDirection Direction = 0 // sent by the captured socket
	InboundDirection  Direction = 1 // received by the captured socket
)

// one captured packet, Data starts at the IP header and can be shorter than OriginalLength when the snaplen cut it
// Timestamp is nanoseconds since the Unix epoch
// Comment is shown with the packet by Wireshark and tshark (opt_comment), empty for none
type Packet struct {
	Timestamp      uint64
	Direction      Direction
	OriginalLength uint32
	Data           []byte
	Comment        string
}

// every block is written in little endian byte order, the reader takes the order from the magic of the section header
func appendUint16(block []byte, value uint16) (result []byte) {
	result = binary.LittleEndian.AppendUint16(block, value)
	return
}

func appendUint32(block []byte, value uint32) (result []byte) {
	result = binary.LittleEndian.AppendUint32(block, value)
	return
}

func appendUint64(block []byte, value uint64) (result []byte) {
	result = binary.LittleEndian.AppendUint64(block, value)
	return
}

// block bodies, option values and packet data are padded to 32 bits, the padding is not part of their length fields
func appendPadded(block []byte, data []byte) (result []byte) {
	result = append(block, data...)

	for range (blockAlignment - len(data)%blockAlignment) % blockAlignment {
		result = append(result, 0)
	}

	return
}

func appendOption(block []byte, code uint16, value []byte) (result []byte) {
	result = appendUint16(block, code)
	result = appendUint16(result, uint16(len(value)))
	result = appendPadded(result, value)
	return
}

func appendEndOfOptions(block []byte) (result []byte) {
	result = appendOption(block, endOfOptionsCode, nil)
	return
}

// start a block: its type and room for the total length, which finishBlock fills in
func startBlock(block []byte, blockType uint32) (result []byte) {
	result = appendUint32(block[:0], blockType)
	result = appendUint32(result, 0)
	return
}

// the total length of a block is at its start and again at its end, so a reader can walk the file backwards
func finishBlock(block []byte) (result []byte) {
	totalLength := uint32(len(block) + blockAlignment)
	result = appendUint32(block, totalLength)
	binary.LittleEndian.PutUint32(result[4:8], totalLength)
	return
}

func sectionHeaderBlock(block []byte) (result []byte) {
	result = startBlock(block, sectionHeaderBlockType)
	result = appendUint32(result, byteOrderMagic)
	result = appendUint16(result, versionMajor)
	result = appendUint16(result, versionMinor)
	result = appendUint64(result, sectionLengthUnknown)
	result = appendOption(result, sectionUserApplicationCode, []byte(sectionUserApplication))
	result = appendEndOfOptions(result)
	result = finishBlock(result)
	return
}

func interfaceDescriptionBlock(block []byte, snaplen uint32) (result []byte) {
	result = startBlock(block, interfaceDescriptionBlockType)
	result = appendUint16(result, linkTypeRaw)
	result = appendUint16(result, 0)
	result = appendUint32(result, snaplen)
	result = appendOption(result, interfaceNameCode, []byte(captureInterfaceName))
	result = appendOption(result, interfaceTimestampResolution, []byte{nanosecondResolution})
	result = appendEndOfOptions(result)
	result = finishBlock(result)
	return
}

func enhancedPacketBlock(block []byte, packet Packet) (result []byte) {
	flags := outboundPacketFlag

	if packet.Direction == InboundDirection {
		flags = inboundPacketFlag
	}

	result = startBlock(block, enhancedPacketBlockType)
	result = appendUint32(result, captureInterfaceID)
	result = appendUint32(result, uint32(packet.Timestamp>>32))
	result = appendUint32(result, uint32(packet.Timestamp))
	result = appendUint32(result, uint32(len(packet.Data)))
	result = appendUint32(result, packet.OriginalLength)
	result = appendPadded(result, packet.Data)

	if packet.Comment != "" {
		result = appendOption(result, commentCode, []byte(packet.Comment))
	}

	result = appendOption(result, packetFlagsCode, binary.LittleEndian.AppendUint32(nil, flags))
	result = appendEndOfOptions(result)
	result = finishBlock(result)
	return
}

// Decryption Secrets Block (section 4.7) with a TLS key log: the lines of the NSS key log format, the reader uses them for the packets that follow in the file
func decryptionSecretsBlock(block []byte, keyLog []byte) (result []byte) {
	result = startBlock(block, decryptionSecretsBlockType)
	result = appendUint32(result, tlsKeyLogSecretsType)
	result = appendUint32(result, uint32(len(keyLog)))
	result = appendPadded(result, keyLog)
	result = finishBlock(result)
	return
}
