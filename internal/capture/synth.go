// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"encoding/binary"
	"net/netip"
	"syscall"
)

// header fields of the packets the writer reads and builds (RFC 791, RFC 8200, RFC 9293, RFC 768)
const (
	ipv4Version           uint8  = 4
	ipv6Version           uint8  = 6
	ipv4MinHeaderLength   int    = 20
	ipv4FragmentOffset    int    = 6
	ipv4FragmentMask      uint8  = 0x1F
	ipv4ProtocolOffset    int    = 9
	ipv4ChecksumOffset    int    = 10
	ipv4SourceOffset      int    = 12
	ipv4DestinationOffset int    = 16
	ipv4AddressLength     int    = 4
	ipv4DontFragment      uint8  = 0x40
	ipv6HeaderLength      int    = 40
	ipv6NextHeaderOffset  int    = 6
	ipv6SourceOffset      int    = 8
	ipv6DestinationOffset int    = 24
	ipv6AddressLength     int    = 16
	ipv6ExtensionUnit     int    = 8
	ipv6HopByHop          uint8  = 0
	ipv6Routing           uint8  = 43
	ipv6DestinationOption uint8  = 60
	ipv6MaxExtensions     int    = 8
	tcpMinHeaderLength    int    = 20
	tcpSequenceOffset     int    = 4
	tcpAcknowledgeOffset  int    = 8
	tcpDataOffsetOffset   int    = 12
	tcpFlagsOffset        int    = 13
	tcpChecksumOffset     int    = 16
	tcpOptionMSS          uint8  = 2
	tcpOptionMSSLength    uint8  = 4
	udpHeaderLength       int    = 8
	udpChecksumOffset     int    = 6
	synthesizedHopLimit   uint8  = 64
	synthesizedWindow     uint16 = 65535
)

// TCP flags
const (
	FINFlag uint8 = 0x01
	SYNFlag uint8 = 0x02
	RSTFlag uint8 = 0x04
	PSHFlag uint8 = 0x08
	ACKFlag uint8 = 0x10
)

const (
	// the payload of a synthesized TCP packet: the MSS of Ethernet, so a synthesized packet is never longer than SynthesizedLength
	ipv4SegmentLength int = 1460
	ipv6SegmentLength int = 1440
	// the longest synthesized TCP packet
	SynthesizedLength uint32 = 1500
)

// one end of a recorded flow
type Endpoint struct {
	Address netip.Addr
	Port    uint16
}

// what the writer reads of a captured packet that starts at its IP header
// the ports are there for TCP and UDP, sequence, acknowledgment and flags for TCP, payloadOffset is where the payload starts, it can be behind the captured bytes
type packetHeader struct {
	protocol       uint8
	source         Endpoint
	destination    Endpoint
	sequence       uint32
	acknowledgment uint32
	flags          uint8
	payloadOffset  int
}

// read the IP header and the TCP or UDP header behind it, ok is false for everything else: another protocol, a later fragment, headers the snaplen cut
func parsePacket(data []byte) (header packetHeader, ok bool) {
	if len(data) == 0 {
		return
	}

	transportOffset := 0

	switch data[0] >> 4 {
	case ipv4Version:
		headerLength := int(data[0]&0x0F) * 4

		if (headerLength < ipv4MinHeaderLength) || (len(data) < headerLength) {
			return
		}

		// only the first fragment has the transport header
		if (data[ipv4FragmentOffset]&ipv4FragmentMask != 0) || (data[ipv4FragmentOffset+1] != 0) {
			return
		}

		header.protocol = data[ipv4ProtocolOffset]
		header.source.Address = netip.AddrFrom4([ipv4AddressLength]byte(data[ipv4SourceOffset:]))
		header.destination.Address = netip.AddrFrom4([ipv4AddressLength]byte(data[ipv4DestinationOffset:]))
		transportOffset = headerLength
	case ipv6Version:
		if len(data) < ipv6HeaderLength {
			return
		}

		header.protocol = data[ipv6NextHeaderOffset]
		header.source.Address = netip.AddrFrom16([ipv6AddressLength]byte(data[ipv6SourceOffset:]))
		header.destination.Address = netip.AddrFrom16([ipv6AddressLength]byte(data[ipv6DestinationOffset:]))
		transportOffset = ipv6HeaderLength

		// the options a socket can set come before the transport header: next header, then the length in units of 8 bytes without the first unit
		for range ipv6MaxExtensions {
			if (header.protocol != ipv6HopByHop) && (header.protocol != ipv6Routing) && (header.protocol != ipv6DestinationOption) {
				break
			}

			if len(data) < transportOffset+ipv6ExtensionUnit {
				return
			}

			header.protocol = data[transportOffset]
			transportOffset += (int(data[transportOffset+1]) + 1) * ipv6ExtensionUnit
		}
	default:
		return
	}

	switch header.protocol {
	case syscall.IPPROTO_TCP:
		if len(data) < transportOffset+tcpMinHeaderLength {
			return
		}

		header.sequence = binary.BigEndian.Uint32(data[transportOffset+tcpSequenceOffset:])
		header.acknowledgment = binary.BigEndian.Uint32(data[transportOffset+tcpAcknowledgeOffset:])
		header.flags = data[transportOffset+tcpFlagsOffset]
		header.payloadOffset = transportOffset + int(data[transportOffset+tcpDataOffsetOffset]>>4)*4

		if header.payloadOffset < transportOffset+tcpMinHeaderLength {
			return
		}
	case syscall.IPPROTO_UDP:
		if len(data) < transportOffset+udpHeaderLength {
			return
		}

		header.payloadOffset = transportOffset + udpHeaderLength
	default:
		return
	}

	header.source.Port = binary.BigEndian.Uint16(data[transportOffset:])
	header.destination.Port = binary.BigEndian.Uint16(data[transportOffset+2:])
	ok = true
	return
}

// the TCP or UDP payload of a packet that starts at its IP header, isDatagram for UDP, nil for everything else
func transportPayload(data []byte) (payload []byte, isDatagram bool) {
	header, ok := parsePacket(data)

	if !ok || (len(data) <= header.payloadOffset) {
		return
	}

	switch header.protocol {
	case syscall.IPPROTO_TCP:
		payload = data[header.payloadOffset:]
	case syscall.IPPROTO_UDP:
		payload = data[header.payloadOffset:]
		isDatagram = true
	default:
	}

	return
}

// the most payload of one synthesized TCP packet between two addresses of this family
func segmentLength(address netip.Addr) (length int) {
	length = ipv6SegmentLength

	if address.Is4() {
		length = ipv4SegmentLength
	}

	return
}

// append a TCP packet with its IP header to buffer: no IP options, a SYN carries the MSS the synthesized packets keep to, the checksums are valid
// source and destination have to be of one family, the payload of an IPv4 packet has to fit its 16 bit total length
func TCPPacket(buffer []byte, source Endpoint, destination Endpoint, sequence uint32, acknowledgment uint32, flags uint8, payload []byte) (packet []byte) {
	headerLength := tcpMinHeaderLength

	if flags&SYNFlag != 0 {
		headerLength += int(tcpOptionMSSLength)
	}

	packet, transportOffset := appendIPHeader(buffer, source.Address, destination.Address, syscall.IPPROTO_TCP, headerLength+len(payload))
	packet = binary.BigEndian.AppendUint16(packet, source.Port)
	packet = binary.BigEndian.AppendUint16(packet, destination.Port)
	packet = binary.BigEndian.AppendUint32(packet, sequence)
	packet = binary.BigEndian.AppendUint32(packet, acknowledgment)
	packet = append(packet, uint8(headerLength/4)<<4, flags)
	packet = binary.BigEndian.AppendUint16(packet, synthesizedWindow)
	// checksum, filled in below, and the urgent pointer
	packet = append(packet, 0, 0, 0, 0)

	if flags&SYNFlag != 0 {
		packet = append(packet, tcpOptionMSS, tcpOptionMSSLength)
		packet = binary.BigEndian.AppendUint16(packet, uint16(segmentLength(source.Address)))
	}

	packet = append(packet, payload...)
	binary.BigEndian.PutUint16(packet[transportOffset+tcpChecksumOffset:], transportChecksum(packet[len(buffer):], transportOffset-len(buffer), syscall.IPPROTO_TCP))
	return
}

// append a UDP datagram with its IP header to buffer, the checksums are valid
// source and destination have to be of one family, the payload has to fit the 16 bit length of a datagram
func UDPPacket(buffer []byte, source Endpoint, destination Endpoint, payload []byte) (packet []byte) {
	packet, transportOffset := appendIPHeader(buffer, source.Address, destination.Address, syscall.IPPROTO_UDP, udpHeaderLength+len(payload))
	packet = binary.BigEndian.AppendUint16(packet, source.Port)
	packet = binary.BigEndian.AppendUint16(packet, destination.Port)
	packet = binary.BigEndian.AppendUint16(packet, uint16(udpHeaderLength+len(payload)))
	packet = append(packet, 0, 0)
	packet = append(packet, payload...)
	sum := transportChecksum(packet[len(buffer):], transportOffset-len(buffer), syscall.IPPROTO_UDP)

	// zero in the header means no checksum, a sum of zero is sent as all ones (RFC 768)
	if sum == 0 {
		sum = 0xFFFF
	}

	binary.BigEndian.PutUint16(packet[transportOffset+udpChecksumOffset:], sum)
	return
}

// append the IPv4 or IPv6 header of a packet with transportLength bytes behind it, transportOffset is where they start in packet
func appendIPHeader(buffer []byte, source netip.Addr, destination netip.Addr, protocol uint8, transportLength int) (packet []byte, transportOffset int) {
	if source.Is4() {
		sourceAddress := source.As4()
		destinationAddress := destination.As4()
		// version and header length, type of service
		packet = append(buffer, ipv4Version<<4|uint8(ipv4MinHeaderLength/4), 0)
		packet = binary.BigEndian.AppendUint16(packet, uint16(ipv4MinHeaderLength+transportLength))
		// identification, never fragmented, checksum filled in below
		packet = append(packet, 0, 0, ipv4DontFragment, 0, synthesizedHopLimit, protocol, 0, 0)
		packet = append(packet, sourceAddress[:]...)
		packet = append(packet, destinationAddress[:]...)
		transportOffset = len(packet)
		binary.BigEndian.PutUint16(packet[len(buffer)+ipv4ChecksumOffset:], foldChecksum(sumBytes(0, packet[len(buffer):])))
		return
	}

	sourceAddress := source.As16()
	destinationAddress := destination.As16()
	// version, traffic class and flow label
	packet = append(buffer, ipv6Version<<4, 0, 0, 0)
	packet = binary.BigEndian.AppendUint16(packet, uint16(transportLength))
	packet = append(packet, protocol, synthesizedHopLimit)
	packet = append(packet, sourceAddress[:]...)
	packet = append(packet, destinationAddress[:]...)
	transportOffset = len(packet)
	return
}

// the checksum of the TCP segment or UDP datagram at transportOffset of a packet built by appendIPHeader, its checksum field has to be zero
// the pseudo header is the two addresses, the protocol and the length of the segment (RFC 9293 section 3.1, RFC 8200 section 8.1)
func transportChecksum(packet []byte, transportOffset int, protocol uint8) (checksum uint16) {
	addresses := packet[ipv4SourceOffset:transportOffset]

	if packet[0]>>4 == ipv6Version {
		addresses = packet[ipv6SourceOffset:transportOffset]
	}

	sum := sumBytes(0, addresses)
	sum += uint64(protocol) + uint64(len(packet)-transportOffset)
	checksum = foldChecksum(sumBytes(sum, packet[transportOffset:]))
	return
}

// add data to a sum of 16 bit words in network byte order, a last odd byte counts as the high byte of a word
func sumBytes(sum uint64, data []byte) (result uint64) {
	result = sum

	for len(data) >= 2 {
		result += uint64(data[0])<<8 | uint64(data[1])
		data = data[2:]
	}

	if len(data) == 1 {
		result += uint64(data[0]) << 8
	}

	return
}

// the internet checksum of a sum: the carries are added back in, then the one's complement (RFC 1071)
func foldChecksum(sum uint64) (checksum uint16) {
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}

	checksum = ^uint16(sum)
	return
}
