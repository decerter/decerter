// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/decerter/decerter/internal/capture"
)

const (
	protocolTCP    uint8  = 6
	protocolUDP    uint8  = 17
	sequence       uint32 = 0xFFFFFFFE
	acknowledgment uint32 = 0x01020304
	mssOption      uint16 = 0x0204
)

type packetCase struct {
	Source      capture.Endpoint
	Destination capture.Endpoint
	Flags       uint8
	Payload     []byte
}

// the sum of 16 bit words with the carries added back in, a packet with a valid checksum sums up to 0xFFFF with it
func onesSum(sum uint32, data []byte) (result uint32) {
	result = sum

	for index := 0; index+1 < len(data); index += 2 {
		result += uint32(binary.BigEndian.Uint16(data[index:]))
	}

	if len(data)%2 == 1 {
		result += uint32(data[len(data)-1]) << 8
	}

	for result>>16 != 0 {
		result = result&0xFFFF + result>>16
	}

	return
}

// check the IP header of a synthesized packet and the checksum of what it carries, transport is the TCP segment or UDP datagram
func checkPacket(packet []byte, positive packetCase, protocol uint8) (transport []byte, err error) {
	var addresses []byte

	if positive.Source.Address.Is4() {
		if (len(packet) < 20) || (packet[0] != 0x45) || (int(binary.BigEndian.Uint16(packet[2:])) != len(packet)) || (packet[9] != protocol) {
			err = fmt.Errorf("IPv4 header was not as expected: %x", packet[:min(len(packet), 20)])
			return
		}

		if sum := onesSum(0, packet[:20]); sum != 0xFFFF {
			err = fmt.Errorf("IPv4 header checksum sum was not 0x%04x instead: 0x%04x", 0xFFFF, sum)
			return
		}

		addresses = packet[12:20]
		transport = packet[20:]
	} else {
		if (len(packet) < 40) || (packet[0] != 0x60) || (int(binary.BigEndian.Uint16(packet[4:])) != len(packet)-40) || (packet[6] != protocol) {
			err = fmt.Errorf("IPv6 header was not as expected: %x", packet[:min(len(packet), 40)])
			return
		}

		addresses = packet[8:40]
		transport = packet[40:]
	}

	if !bytes.Equal(addresses, append(positive.Source.Address.AsSlice(), positive.Destination.Address.AsSlice()...)) {
		err = fmt.Errorf("addresses were not %s and %s instead: %x", positive.Source.Address, positive.Destination.Address, addresses)
		return
	}

	if (binary.BigEndian.Uint16(transport[0:]) != positive.Source.Port) || (binary.BigEndian.Uint16(transport[2:]) != positive.Destination.Port) {
		err = fmt.Errorf("ports were not %d and %d instead: %d and %d", positive.Source.Port, positive.Destination.Port, binary.BigEndian.Uint16(transport[0:]), binary.BigEndian.Uint16(transport[2:]))
		return
	}

	// the pseudo header: both addresses, the protocol and the length of the segment
	sum := onesSum(0, addresses)
	sum = onesSum(sum, []byte{0, protocol, byte(len(transport) >> 8), byte(len(transport))})

	if sum = onesSum(sum, transport); sum != 0xFFFF {
		err = fmt.Errorf("checksum sum with the pseudo header was not 0x%04x instead: 0x%04x", 0xFFFF, sum)
		return
	}

	return
}

func packetCases() (cases []packetCase) {
	ipv4Client := capture.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 40000}
	ipv4Server := capture.Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 443}
	ipv6Client := capture.Endpoint{Address: netip.MustParseAddr("2001:db8::10"), Port: 40000}
	ipv6Server := capture.Endpoint{Address: netip.MustParseAddr("2001:db8:ffff::20"), Port: 443}
	// an odd and an even length, and bytes that make carries
	cases = []packetCase{
		{Source: ipv4Client, Destination: ipv4Server, Flags: capture.SYNFlag, Payload: nil},
		{Source: ipv4Server, Destination: ipv4Client, Flags: capture.SYNFlag | capture.ACKFlag, Payload: nil},
		{Source: ipv4Client, Destination: ipv4Server, Flags: capture.ACKFlag | capture.PSHFlag, Payload: []byte("GET / HTTP/1.1\r\n\r\n")},
		{Source: ipv4Server, Destination: ipv4Client, Flags: capture.ACKFlag, Payload: bytes.Repeat([]byte{0xFF, 0xFE, 0xFD}, 487)},
		{Source: ipv4Client, Destination: ipv4Server, Flags: capture.FINFlag | capture.ACKFlag, Payload: nil},
		{Source: ipv6Client, Destination: ipv6Server, Flags: capture.SYNFlag, Payload: nil},
		{Source: ipv6Client, Destination: ipv6Server, Flags: capture.ACKFlag | capture.PSHFlag, Payload: []byte("GET / HTTP/1.1\r\n\r\n!")},
		{Source: ipv6Server, Destination: ipv6Client, Flags: capture.ACKFlag, Payload: bytes.Repeat([]byte{0xFF}, 1440)},
		{Source: ipv6Server, Destination: ipv6Client, Flags: capture.RSTFlag, Payload: nil},
	}
	return
}

func testTCPPacket() (err error) {
	// the packet is appended to what the buffer holds
	prefix := []byte{1, 2, 3}

	for _, positive := range packetCases() {
		buffer := capture.TCPPacket(bytes.Clone(prefix), positive.Source, positive.Destination, sequence, acknowledgment, positive.Flags, positive.Payload)

		if !bytes.HasPrefix(buffer, prefix) {
			err = fmt.Errorf("TCPPacket return value did not start with the buffer %x: %x", prefix, buffer[:len(prefix)])
			return
		}

		segment, checkErr := checkPacket(buffer[len(prefix):], positive, protocolTCP)

		if err = checkErr; err != nil {
			return
		}

		headerLength := 20

		// a SYN has the MSS option: the payload a synthesized packet of this family has at most
		if positive.Flags&capture.SYNFlag != 0 {
			headerLength = 24
			expectedMSS := uint16(1440)

			if positive.Source.Address.Is4() {
				expectedMSS = 1460
			}

			if (binary.BigEndian.Uint16(segment[20:]) != mssOption) || (binary.BigEndian.Uint16(segment[22:]) != expectedMSS) {
				err = fmt.Errorf("MSS option was not %d instead: %x", expectedMSS, segment[20:24])
				return
			}
		}

		if (binary.BigEndian.Uint32(segment[4:]) != sequence) || (binary.BigEndian.Uint32(segment[8:]) != acknowledgment) || (int(segment[12]>>4)*4 != headerLength) || (segment[13] != positive.Flags) {
			err = fmt.Errorf("TCP header was not as expected: %x", segment[:headerLength])
			return
		}

		if !bytes.Equal(segment[headerLength:], positive.Payload) {
			err = fmt.Errorf("TCP payload was not %x instead: %x", positive.Payload, segment[headerLength:])
			return
		}
	}

	return
}

func testUDPPacket() (err error) {
	for _, positive := range packetCases() {
		datagram, checkErr := checkPacket(capture.UDPPacket(nil, positive.Source, positive.Destination, positive.Payload), positive, protocolUDP)

		if err = checkErr; err != nil {
			return
		}

		if int(binary.BigEndian.Uint16(datagram[4:])) != 8+len(positive.Payload) {
			err = fmt.Errorf("UDP length was not %d instead: %d", 8+len(positive.Payload), binary.BigEndian.Uint16(datagram[4:]))
			return
		}

		if !bytes.Equal(datagram[8:], positive.Payload) {
			err = fmt.Errorf("UDP payload was not %x instead: %x", positive.Payload, datagram[8:])
			return
		}
	}

	return
}

// Test if capture.TCPPacket returns with the expected output.
func TestTCPPacketPositive(state *testing.T) {
	err := testTCPPacket()

	if err != nil {
		state.Errorf("Test of capture.TCPPacket failed, error: %s", err.Error())
		return
	}
}

// Test if capture.UDPPacket returns with the expected output.
func TestUDPPacketPositive(state *testing.T) {
	err := testUDPPacket()

	if err != nil {
		state.Errorf("Test of capture.UDPPacket failed, error: %s", err.Error())
		return
	}
}
