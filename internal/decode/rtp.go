// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// RTP and RTCP from RFC 3550 (header, CSRCs, padding; SR, RR, SDES, BYE, APP), RFC 8285 (one- and two-byte header extensions), RFC 4585 (RTPFB,
// PSFB), RFC 3611 (XR) by name only, RFC 5761 (RTP and RTCP on one port: an RTCP packet type is 200-223) and RFC 7983 (the first byte 128-191)
// RTP has no port and no magic number: it is taken by as=rtp, or by sniffing when its header extension is one of RFC 8285's
const (
	rtpProtocol     string = "rtp"
	rtpTitle        string = "Real-time Transport Protocol"
	rtcpProtocol    string = "rtcp"
	rtcpTitle       string = "RTP Control Protocol"
	rtpHeaderBytes  int    = 12
	rtcpHeaderBytes int    = 4
	rtpVersion      byte   = 2
	// the extension profiles of RFC 8285: one-byte elements, and two-byte ones with 4 bits of appbits
	rtpOneByteProfile uint16 = 0xbede
	rtpTwoByteProfile uint16 = 0x1000
	// what sniffing gives: an RTP header that adds up, one with an RFC 8285 extension, an RTCP compound packet that adds up to its end
	rtpSniffHeader    int = 40
	rtpSniffExtension int = 60
	rtcpSniffCompound int = 90
)

var (
	rtcpTypes = nameTable{names: map[uint16]string{
		192: "FIR", 193: "NACK", 195: "IJ", 200: "Sender Report", 201: "Receiver Report", 202: "Source description", 203: "Goodbye", 204: "Application specific",
		205: "Generic RTP Feedback", 206: "Payload-specific Feedback", 207: "Extended report", 208: "AVB", 209: "Receiver Summary Information", 210: "Port Mapping",
		211: "IDMS", 212: "Reporting Group Reporting Sources", 213: "Splicing Notification",
	}, unknown: "Type %d"}
	rtcpShortTypes = nameTable{names: map[uint16]string{200: "SR", 201: "RR", 202: "SDES", 203: "BYE", 204: "APP", 205: "RTPFB", 206: "PSFB", 207: "XR"}, unknown: "PT%d"}
	sdesItems      = nameTable{names: map[uint16]string{0: "END", 1: "CNAME", 2: "NAME", 3: "EMAIL", 4: "PHONE", 5: "LOC", 6: "TOOL", 7: "NOTE", 8: "PRIV", 9: "H323-CADDR", 10: "APSI", 11: "RGRP", 12: "RtpStreamId", 13: "RepairedRtpStreamId", 15: "MID"}, unknown: "Item %d"}
	// the static payload types of RFC 3551
	rtpPayloadTypes = nameTable{names: map[uint16]string{
		0: "PCMU", 3: "GSM", 4: "G723", 5: "DVI4 8000", 6: "DVI4 16000", 7: "LPC", 8: "PCMA", 9: "G722", 10: "L16 stereo", 11: "L16 mono", 12: "QCELP", 13: "CN",
		14: "MPA", 15: "G728", 16: "DVI4 11025", 17: "DVI4 22050", 18: "G729", 25: "CelB", 26: "JPEG", 28: "nv", 31: "H261", 32: "MPV", 33: "MP2T", 34: "H263",
	}, unknown: "dynamic %d"}
)

func init() {
	register(decoder{
		Protocol:   rtpProtocol,
		Title:      rtpTitle,
		Ports:      nil,
		hint:       noHint,
		sniff:      rtpSniff,
		decode:     rtpDecode,
		fromTarget: nil,
	})
	register(decoder{
		Protocol:   rtcpProtocol,
		Title:      rtcpTitle,
		Ports:      nil,
		hint:       noHint,
		sniff:      rtcpSniff,
		decode:     rtcpDecode,
		fromTarget: nil,
	})
}

// an RTCP packet type (200-223) in the second byte makes it RTCP, not RTP (RFC 5761 4)
func isRTCPType(value byte) (isRTCP bool) {
	isRTCP = (value >= 192) && (value <= 223)
	return
}

// version 2, no RTCP type, the CSRCs, the extension and the padding inside the datagram
func rtpSniff(data []byte, context Context) (score int) {
	if (context.Transport != DatagramTransport) || (len(data) < rtpHeaderBytes) || (data[0]>>6 != rtpVersion) || isRTCPType(data[1]) {
		return
	}

	end, profile, ok := rtpHeaderEnd(data)

	if !ok {
		return
	}

	if data[0]&0x20 != 0 {
		padding := int(data[len(data)-1])

		if (padding == 0) || (end+padding > len(data)) {
			return
		}
	}

	score = rtpSniffHeader

	if (data[0]&0x10 != 0) && ((profile == rtpOneByteProfile) || (profile&0xfff0 == rtpTwoByteProfile)) {
		score = rtpSniffExtension
	}

	return
}

// where the header ends (after the CSRCs and the extension) and the extension's profile, ok is false when they don't fit
func rtpHeaderEnd(data []byte) (end int, profile uint16, ok bool) {
	end = rtpHeaderBytes + 4*int(data[0]&0x0f)

	if end > len(data) {
		return
	}

	if data[0]&0x10 != 0 {
		if end+4 > len(data) {
			return
		}

		profile = binary.BigEndian.Uint16(data[end:])
		end += 4 + 4*int(binary.BigEndian.Uint16(data[end+2:]))

		if end > len(data) {
			return
		}
	}

	ok = true
	return
}

// one RTP packet: header, CSRCs, extension, payload and padding
func rtpDecode(tree *Tree, data []byte, context Context) {
	root := tree.add(nil, rtpProtocol, rtpTitle, "", 0, len(data))
	reader := fieldsOf(tree, root, data, 0, len(data))

	if len(data) < rtpHeaderBytes {
		tree.fail(root, fmt.Sprintf("an RTP header has %d bytes, the packet %d", rtpHeaderBytes, len(data)))
		tree.addSummary("Malformed RTP packet")
		return
	}

	first, second := data[0], data[1]
	flags := tree.add(root, "rtp.flags", "Flags", fmt.Sprintf("0x%02x", first), 0, 1)
	tree.addBits(flags, "rtp.version", "Version", strconv.Itoa(int(first>>6)), 0, 1, 0xc0)
	tree.addBits(flags, "rtp.padding", "Padding", yesNo(first&0x20 != 0), 0, 1, 0x20)
	tree.addBits(flags, "rtp.ext", "Extension", yesNo(first&0x10 != 0), 0, 1, 0x10)
	tree.addBits(flags, "rtp.cc", "Contributing source count", strconv.Itoa(int(first&0x0f)), 0, 1, 0x0f)
	marker := tree.add(root, "rtp.marker_pt", "Marker and payload type", fmt.Sprintf("0x%02x", second), 1, 1)
	tree.addBits(marker, "rtp.marker", "Marker", yesNo(second&0x80 != 0), 1, 1, 0x80)
	tree.addBits(marker, "rtp.p_type", "Payload type", nameOf(rtpPayloadTypes, uint16(second&0x7f)), 1, 1, 0x7f)
	reader.offset = 2

	if first>>6 != rtpVersion {
		tree.fail(flags, fmt.Sprintf("RTP is version %d", rtpVersion))
	}

	sequence, _ := reader.number("rtp.seq", "Sequence number", 2, nil)
	timestamp, _ := reader.number("rtp.timestamp", "Timestamp", 4, nil)
	ssrc, _ := reader.number("rtp.ssrc", "Synchronization source", 4, hexWord)

	if count := int(first & 0x0f); count > 0 {
		list := tree.add(root, "rtp.csrc.items", "Contributing sources", strconv.Itoa(count), reader.offset, min(4*count, reader.left()))
		csrcs := reader.vector(list, "Contributing sources", 4*count)

		for csrcs.left() >= 4 {
			csrcs.number("rtp.csrc.item", "Contributing source", 4, hexWord)
		}

		reader.offset = csrcs.offset

		if reader.isShort || csrcs.isShort {
			tree.addSummary("RTP header cut short")
			return
		}
	}

	if first&0x10 != 0 {
		rtpExtension(tree, root, data, reader)
	}

	end := len(data)

	if first&0x20 != 0 {
		padding := int(data[len(data)-1])

		if (padding == 0) || (len(data)-padding < reader.offset) {
			tree.fail(root, fmt.Sprintf("a padding of %d bytes does not fit the packet", padding))
		} else {
			end = len(data) - padding
			tree.add(root, "rtp.padding.count", "Padding", strconv.Itoa(padding)+" bytes", end, padding)
		}
	}

	if (reader.offset < end) && !reader.isShort {
		tree.add(root, "rtp.payload", "Payload", strconv.Itoa(end-reader.offset)+" bytes", reader.offset, end-reader.offset)
	}

	tree.addSummary(fmt.Sprintf("RTP PT=%s, SSRC=0x%08x, Seq=%d, Time=%d%s", shortName(rtpPayloadTypes, uint16(second&0x7f)), ssrc, sequence, timestamp, map[bool]string{false: "", true: ", Mark"}[second&0x80 != 0]))
}

// the header extension: profile, length and the elements of RFC 8285, or the bytes of another profile
func rtpExtension(tree *Tree, root *node, data []byte, reader *cursor) {
	start := reader.offset

	if reader.left() < 4 {
		tree.fail(root, "the header extension is cut short")
		reader.offset = reader.end
		return
	}

	profile := binary.BigEndian.Uint16(data[start:])
	words := int(binary.BigEndian.Uint16(data[start+2:]))
	extension := tree.add(root, "rtp.ext", "Header extension", fmt.Sprintf("profile 0x%04x, %d words", profile, words), start, min(4+4*words, reader.left()))
	inner := reader.vector(extension, "Header extension", 4+4*words)
	inner.number("rtp.ext.profile", "Defined by profile", 2, hexWord)
	inner.number("rtp.ext.len", "Length", 2, func(value uint32) (text string) { text = fmt.Sprintf("%d words", value); return })

	switch {
	case profile == rtpOneByteProfile:
		for (inner.left() > 0) && !tree.isFull {
			elementStart := inner.offset
			header := data[elementStart]

			if header == 0 {
				inner.offset++
				continue
			}

			id, length := int(header>>4), int(header&0x0f)+1

			if id == 15 {
				inner.offset = inner.end
				break
			}

			element := inner.add("rtp.ext.element", fmt.Sprintf("Element %d", id), fmt.Sprintf("%d bytes", length), elementStart, min(1+length, inner.end-elementStart))
			inner.offset++

			if value, valueStart, ok := inner.take("Element", length); ok {
				tree.add(element, "rtp.ext.element.data", "Data", hexValue(value), valueStart, length)
			}
		}
	case profile&0xfff0 == rtpTwoByteProfile:
		for (inner.left() > 0) && !tree.isFull {
			elementStart := inner.offset

			if data[elementStart] == 0 {
				inner.offset++
				continue
			}

			header, _, ok := inner.take("Element header", 2)

			if !ok {
				break
			}

			id, length := int(header[0]), int(header[1])
			element := inner.add("rtp.ext.element", fmt.Sprintf("Element %d", id), fmt.Sprintf("%d bytes", length), elementStart, min(2+length, inner.end-elementStart))

			if value, valueStart, ok := inner.take("Element", length); ok && (length > 0) {
				tree.add(element, "rtp.ext.element.data", "Data", hexValue(value), valueStart, length)
			}
		}
	default:
		inner.bytesField("rtp.ext.data", "Data", inner.left())
	}

	reader.offset = inner.end

	if inner.end < start+4+4*words {
		reader.isShort = true
	}
}

func hexWord(value uint32) (text string) {
	text = fmt.Sprintf("0x%08x", value)
	return
}

// a compound packet: version 2, an RTCP type and lengths that add up to the end of the datagram
func rtcpSniff(data []byte, context Context) (score int) {
	if (context.Transport != DatagramTransport) || (len(data) < rtcpHeaderBytes) {
		return
	}

	offset := 0

	for offset < len(data) {
		if (len(data)-offset < rtcpHeaderBytes) || (data[offset]>>6 != rtpVersion) || (data[offset+1] < 192) || (data[offset+1] > 223) {
			return
		}

		offset += 4 * (int(binary.BigEndian.Uint16(data[offset+2:])) + 1)
	}

	if offset == len(data) {
		score = rtcpSniffCompound
	}

	return
}

// the packets of a compound packet, each a root
func rtcpDecode(tree *Tree, data []byte, context Context) {
	offset := 0
	names := []string{}

	for (offset < len(data)) && !tree.isFull {
		if len(data)-offset < rtcpHeaderBytes {
			root := tree.add(nil, rtcpProtocol, rtcpTitle, "", offset, len(data)-offset)
			tree.fail(root, fmt.Sprintf("an RTCP header has %d bytes, %d are left", rtcpHeaderBytes, len(data)-offset))
			break
		}

		length := 4 * (int(binary.BigEndian.Uint16(data[offset+2:])) + 1)
		end := min(len(data), offset+length)
		packetType := data[offset+1]
		root := tree.add(nil, rtcpProtocol, rtcpTitle+" ("+shortName(rtcpTypes, uint16(packetType))+")", "", offset, end-offset)
		names = append(names, shortName(rtcpShortTypes, uint16(packetType)))
		rtcpPacket(tree, root, data, offset, end)

		if offset+length > len(data) {
			tree.fail(root, fmt.Sprintf("the packet runs past the datagram: %d of its %d bytes are there", len(data)-offset, length))
		}

		offset += length
	}

	tree.addSummary("RTCP " + strings.Join(names, ", "))
}

// one packet of a compound packet from its header
func rtcpPacket(tree *Tree, root *node, data []byte, start int, end int) {
	first, packetType := data[start], data[start+1]
	count := int(first & 0x1f)
	flags := tree.add(root, "rtcp.flags", "Flags", fmt.Sprintf("0x%02x", first), start, 1)
	tree.addBits(flags, "rtcp.version", "Version", strconv.Itoa(int(first>>6)), start, 1, 0xc0)
	tree.addBits(flags, "rtcp.padding", "Padding", yesNo(first&0x20 != 0), start, 1, 0x20)
	tree.addBits(flags, "rtcp.rc", "Count", strconv.Itoa(count), start, 1, 0x1f)
	reader := fieldsOf(tree, root, data, start+1, end)
	reader.number("rtcp.pt", "Packet type", 1, named(rtcpTypes))
	reader.number("rtcp.length", "Length", 2, func(value uint32) (text string) {
		text = fmt.Sprintf("%d words (%d bytes)", value, 4*(value+1))
		return
	})

	if first>>6 != rtpVersion {
		tree.fail(flags, fmt.Sprintf("RTCP is version %d", rtpVersion))
	}

	if first&0x20 != 0 {
		padding := int(data[end-1])

		if (padding == 0) || (end-padding < reader.offset) {
			tree.fail(root, fmt.Sprintf("a padding of %d bytes does not fit the packet", padding))
		} else {
			reader.end = end - padding
			tree.add(root, "rtcp.padding.count", "Padding", strconv.Itoa(padding)+" bytes", end-padding, padding)
		}
	}

	switch packetType {
	case 200:
		reader.number("rtcp.senderssrc", "Sender SSRC", 4, hexWord)
		reader.number64("rtcp.timestamp.ntp", "NTP timestamp", ntpTimeText)
		reader.number("rtcp.timestamp.rtp", "RTP timestamp", 4, nil)
		reader.number("rtcp.sender.packetcount", "Sender's packet count", 4, nil)
		reader.number("rtcp.sender.octetcount", "Sender's octet count", 4, nil)
		rtcpReports(tree, root, reader, count)
	case 201:
		reader.number("rtcp.senderssrc", "Sender SSRC", 4, hexWord)
		rtcpReports(tree, root, reader, count)
	case 202:
		rtcpSourceDescription(tree, root, data, reader, count)
	case 203:
		for index := 0; (index < count) && (reader.left() >= 4); index++ {
			reader.number("rtcp.ssrc.identifier", "SSRC", 4, hexWord)
		}

		if reader.left() > 0 {
			length, _ := reader.number("rtcp.bye.reason_length", "Reason length", 1, nil)
			reader.textField("rtcp.bye.reason", "Reason", int(length))
			reader.offset = reader.end
		}
	case 204:
		reader.number("rtcp.senderssrc", "SSRC", 4, hexWord)
		reader.textField("rtcp.app.name", "Name", 4)
		reader.bytesField("rtcp.app.data", "Data", reader.left())
	case 205, 206:
		reader.number("rtcp.senderssrc", "Sender SSRC", 4, hexWord)
		reader.number("rtcp.mediassrc", "Media source SSRC", 4, hexWord)
		reader.bytesField("rtcp.fci", "Feedback control information", reader.left())
	default:
		reader.bytesField("rtcp.data", "Data", reader.left())
	}

	reader.finish()
}

// count report blocks of 24 bytes, then a profile's extension
func rtcpReports(tree *Tree, root *node, reader *cursor, count int) {
	for index := 0; (index < count) && !reader.isShort && !tree.isFull; index++ {
		block := tree.add(root, "rtcp.report", fmt.Sprintf("Report block %d", index+1), "", reader.offset, min(24, reader.left()))
		inner := reader.vector(block, "Report block", 24)
		ssrc, _ := inner.number("rtcp.ssrc.identifier", "Identifier", 4, hexWord)
		block.value = hexWord(ssrc)
		inner.number("rtcp.ssrc.fraction", "Fraction lost", 1, func(value uint32) (text string) { text = fmt.Sprintf("%d / 256", value); return })
		inner.number("rtcp.ssrc.cum_nr", "Cumulative number of packets lost", 3, nil)
		inner.number("rtcp.ssrc.ext_high", "Extended highest sequence number received", 4, nil)
		inner.number("rtcp.ssrc.jitter", "Interarrival jitter", 4, nil)
		inner.number("rtcp.ssrc.lsr", "Last SR timestamp", 4, hexWord)
		inner.number("rtcp.ssrc.dlsr", "Delay since last SR", 4, func(value uint32) (text string) {
			text = fmt.Sprintf("%d (%.3f s)", value, float64(value)/65536)
			return
		})
	}

	if reader.left() > 0 {
		reader.bytesField("rtcp.profile_extension", "Profile-specific extension", reader.left())
	}
}

// count chunks: an SSRC and its items up to an END item, then padding to 4 bytes
func rtcpSourceDescription(tree *Tree, root *node, data []byte, reader *cursor, count int) {
	for index := 0; (index < count) && (reader.left() >= 4) && !tree.isFull; index++ {
		chunkStart := reader.offset
		chunk := tree.add(root, "rtcp.sdes.chunk", fmt.Sprintf("Chunk %d", index+1), "", chunkStart, 0)
		inner := fieldsOf(tree, chunk, data, chunkStart, reader.end)
		ssrc, _ := inner.number("rtcp.sdes.ssrc_csrc", "SSRC / CSRC", 4, hexWord)
		chunk.value = hexWord(ssrc)

		for (inner.left() > 0) && !inner.isShort && !tree.isFull {
			itemType := data[inner.offset]

			if itemType == 0 {
				inner.offset++
				break
			}

			itemStart := inner.offset

			if inner.left() < 2 {
				tree.fail(chunk, "an item header is cut short")
				inner.offset = inner.end
				break
			}

			length := int(data[itemStart+1])
			item := tree.add(chunk, "rtcp.sdes.item", shortName(sdesItems, uint16(itemType)), "", itemStart, min(2+length, inner.end-itemStart))
			itemReader := fieldsOf(tree, item, data, itemStart, inner.end)
			itemReader.number("rtcp.sdes.type", "Type", 1, named(sdesItems))
			itemReader.number("rtcp.sdes.length", "Length", 1, nil)
			text, ok := itemReader.textField("rtcp.sdes.text", "Text", length)

			if ok {
				item.value = textValue(text)
			}

			inner.offset = min(inner.end, itemStart+2+length)
		}

		// a chunk ends at the next 32-bit boundary
		inner.offset = min(inner.end, chunkStart+((inner.offset-chunkStart+3)&^3))
		chunk.length = inner.offset - chunkStart
		reader.offset = inner.offset
	}
}
