// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"time"

	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/pcapng"
)

var (
	ipv4Client = Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 40000}
	ipv4Server = Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 443}
	ipv6Client = Endpoint{Address: netip.MustParseAddr("2001:db8::10"), Port: 40000}
	ipv6Server = Endpoint{Address: netip.MustParseAddr("2001:db8:ffff::20"), Port: 53}
)

// Test if capture.parsePacket and capture.transportPayload return with the expected output.
func TestParsePacketPositive(state *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	tcpPacket := TCPPacket(nil, ipv4Client, ipv4Server, 1000, 2000, ACKFlag|PSHFlag, payload)
	positiveCases := []struct {
		Name     string
		Data     []byte
		Expected packetHeader
		Payload  []byte
	}{
		{Name: "ipv4 tcp", Data: tcpPacket, Expected: packetHeader{protocol: syscall.IPPROTO_TCP, source: ipv4Client, destination: ipv4Server, sequence: 1000, acknowledgment: 2000, flags: ACKFlag | PSHFlag, payloadOffset: 40}, Payload: payload},
		{Name: "ipv4 options", Data: withIPv4Options(tcpPacket), Expected: packetHeader{protocol: syscall.IPPROTO_TCP, source: ipv4Client, destination: ipv4Server, sequence: 1000, acknowledgment: 2000, flags: ACKFlag | PSHFlag, payloadOffset: 44}, Payload: payload},
		// the first fragment has the transport header
		{Name: "first fragment", Data: withFlags(tcpPacket, 0x20, 0), Expected: packetHeader{protocol: syscall.IPPROTO_TCP, source: ipv4Client, destination: ipv4Server, sequence: 1000, acknowledgment: 2000, flags: ACKFlag | PSHFlag, payloadOffset: 40}, Payload: payload},
		// a SYN with the MSS option
		{Name: "tcp options", Data: TCPPacket(nil, ipv4Client, ipv4Server, 7, 0, SYNFlag, nil), Expected: packetHeader{protocol: syscall.IPPROTO_TCP, source: ipv4Client, destination: ipv4Server, sequence: 7, acknowledgment: 0, flags: SYNFlag, payloadOffset: 44}, Payload: nil},
		// the snaplen cut the payload off, the headers are there
		{Name: "cut payload", Data: tcpPacket[:40], Expected: packetHeader{protocol: syscall.IPPROTO_TCP, source: ipv4Client, destination: ipv4Server, sequence: 1000, acknowledgment: 2000, flags: ACKFlag | PSHFlag, payloadOffset: 40}, Payload: nil},
		{Name: "ipv6 udp", Data: UDPPacket(nil, ipv6Client, ipv6Server, payload), Expected: packetHeader{protocol: syscall.IPPROTO_UDP, source: ipv6Client, destination: ipv6Server, payloadOffset: 48}, Payload: payload},
		{Name: "ipv6 extensions", Data: withIPv6Extensions(UDPPacket(nil, ipv6Client, ipv6Server, payload), []uint8{ipv6HopByHop, ipv6DestinationOption, ipv6Routing}), Expected: packetHeader{protocol: syscall.IPPROTO_UDP, source: ipv6Client, destination: ipv6Server, payloadOffset: 40 + 3*16 + 8}, Payload: payload},
	}

	for _, positive := range positiveCases {
		header, ok := parsePacket(positive.Data)

		if !ok || (header != positive.Expected) {
			state.Errorf("Test of capture.parsePacket function failed, case %q, header should be %+v, header: %+v, ok: %v", positive.Name, positive.Expected, header, ok)
			return
		}

		// a packet without payload is no datagram to decrypt either
		transport, isDatagram := transportPayload(positive.Data)
		expectedDatagram := (positive.Expected.protocol == syscall.IPPROTO_UDP) && (positive.Payload != nil)

		if !bytes.Equal(transport, positive.Payload) || (isDatagram != expectedDatagram) {
			state.Errorf("Test of capture.transportPayload function failed, case %q, payload should be %q, payload: %q, datagram: %v", positive.Name, positive.Payload, transport, isDatagram)
			return
		}
	}
}

// Test if capture.parsePacket returns with the expected errors: everything that is not a whole TCP or UDP header behind an IP header.
func TestParsePacketNegative(state *testing.T) {
	tcpPacket := TCPPacket(nil, ipv4Client, ipv4Server, 1000, 2000, ACKFlag, []byte("data"))
	udpPacket := UDPPacket(nil, ipv6Client, ipv6Server, []byte("data"))
	icmpPacket := slices.Clone(tcpPacket)
	icmpPacket[ipv4ProtocolOffset] = syscall.IPPROTO_ICMP
	shortHeader := slices.Clone(tcpPacket)
	shortHeader[0] = 0x44
	longHeader := slices.Clone(tcpPacket)
	longHeader[0] = 0x4F
	badDataOffset := slices.Clone(tcpPacket)
	badDataOffset[20+tcpDataOffsetOffset] = 4 << 4
	// one extension more than the parser follows
	extensions := slices.Repeat([]uint8{ipv6DestinationOption}, ipv6MaxExtensions+1)
	negativeCases := []struct {
		Name string
		Data []byte
	}{
		{Name: "empty", Data: nil},
		{Name: "ip version 5", Data: append([]byte{0x50}, tcpPacket[1:]...)},
		{Name: "ipv4 header length under 20", Data: shortHeader},
		{Name: "ipv4 header longer than the packet", Data: longHeader},
		{Name: "later fragment", Data: withFlags(tcpPacket, 0x00, 0xB9)},
		{Name: "later fragment, high offset bits", Data: withFlags(tcpPacket, 0x01, 0x00)},
		{Name: "icmp", Data: icmpPacket},
		{Name: "tcp header cut", Data: tcpPacket[:39]},
		{Name: "tcp data offset under 5", Data: badDataOffset},
		{Name: "ipv6 header cut", Data: udpPacket[:39]},
		{Name: "udp header cut", Data: udpPacket[:47]},
		{Name: "ipv6 extension cut", Data: withIPv6Extensions(udpPacket, []uint8{ipv6HopByHop})[:44]},
		{Name: "too many ipv6 extensions", Data: withIPv6Extensions(udpPacket, extensions)},
	}

	for _, negative := range negativeCases {
		header, ok := parsePacket(negative.Data)

		if ok {
			state.Errorf("Test of capture.parsePacket function failed, case %q, ok should be false, header: %+v", negative.Name, header)
			return
		}

		if transport, isDatagram := transportPayload(negative.Data); (transport != nil) || isDatagram {
			state.Errorf("Test of capture.transportPayload function failed, case %q, payload should be nil, payload: %q", negative.Name, transport)
			return
		}
	}
}

// the packet with 4 bytes of IPv4 options (NOPs) behind its header
func withIPv4Options(packet []byte) (result []byte) {
	result = slices.Concat(packet[:ipv4MinHeaderLength], []byte{1, 1, 1, 1}, packet[ipv4MinHeaderLength:])
	result[0] = 0x46
	return
}

// the packet with its flags and fragment offset bytes set
func withFlags(packet []byte, high byte, low byte) (result []byte) {
	result = slices.Clone(packet)
	result[ipv4FragmentOffset] = high
	result[ipv4FragmentOffset+1] = low
	return
}

// the packet with IPv6 extension headers of 16 bytes each between its header and the transport header
func withIPv6Extensions(packet []byte, types []uint8) (result []byte) {
	result = slices.Clone(packet[:ipv6HeaderLength])
	next := result[ipv6NextHeaderOffset]
	result[ipv6NextHeaderOffset] = types[0]

	for index := range types {
		following := next

		if index+1 < len(types) {
			following = types[index+1]
		}

		// next header, length in units of 8 bytes without the first, padding options
		result = append(result, following, 1, 1, 4, 0, 0, 0, 0, 1, 6, 0, 0, 0, 0, 0, 0)
	}

	result = append(result, packet[ipv6HeaderLength:]...)
	return
}

// one synthesized packet as the test reads it back from the pcapng output
type writtenPacket struct {
	Header  packetHeader
	Payload []byte
	Comment string
}

// Test if the plaintext recorder returns with the expected output for a plain TCP connection whose segments came reordered, duplicated, overlapping and with a hole:
// the synthesized packets carry both streams in order with valid checksums, the hole is a jump in the sequence numbers with a comment
func TestSynthesizeTCPPositive(state *testing.T) {
	request := bytes.Repeat([]byte("GET /plain HTTP/1.1\r\n"), 150)
	response := make([]byte, 6000)

	for index := range response {
		response[index] = byte(index % 251)
	}

	client := Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 40000}
	server := Endpoint{Address: netip.MustParseAddr("198.51.100.20"), Port: 80}
	clientISN, serverISN := uint32(0xFFFFFF00), uint32(9000)
	capturedPacket := func(isIngress bool, sequence uint32, acknowledgment uint32, flags uint8, payload []byte) (packet capturebpf.Packet) {
		data := TCPPacket(nil, client, server, sequence, acknowledgment, flags, payload)

		if isIngress {
			data = TCPPacket(nil, server, client, sequence, acknowledgment, flags, payload)
		}

		packet = capturebpf.Packet{Cookie: 1, TimestampNs: 0, Length: uint32(len(data)), IsIngress: isIngress, Data: data}
		return
	}
	clientData := clientISN + 1
	serverData := serverISN + 1
	packets := []capturebpf.Packet{
		capturedPacket(false, clientISN, 0, SYNFlag, nil),
		capturedPacket(true, serverISN, clientData, SYNFlag|ACKFlag, nil),
		capturedPacket(false, clientData, serverData, ACKFlag, nil),
		// the request: reordered, overlapping and duplicated
		capturedPacket(false, clientData+1000, serverData, ACKFlag, request[1000:2000]),
		capturedPacket(false, clientData, serverData, ACKFlag, request[:1000]),
		capturedPacket(false, clientData+500, serverData, ACKFlag, request[500:1500]),
		capturedPacket(false, clientData+2000, serverData, ACKFlag|PSHFlag, request[2000:]),
		capturedPacket(false, clientData+2000, serverData, ACKFlag|PSHFlag, request[2000:]),
		capturedPacket(true, serverData, clientData+uint32(len(request)), ACKFlag, nil),
		// the response: bytes 2000 to 3000 were never captured, the client acknowledges them
		capturedPacket(true, serverData, clientData+uint32(len(request)), ACKFlag, response[:2000]),
		capturedPacket(true, serverData+3000, clientData+uint32(len(request)), ACKFlag|PSHFlag, response[3000:]),
		capturedPacket(false, clientData+uint32(len(request)), serverData+6000, ACKFlag, nil),
		capturedPacket(false, clientData+uint32(len(request)), serverData+6000, FINFlag|ACKFlag, nil),
		capturedPacket(true, serverData+6000, clientData+uint32(len(request))+1, FINFlag|ACKFlag, nil),
		capturedPacket(false, clientData+uint32(len(request))+1, serverData+6001, ACKFlag, nil),
	}
	output := bytes.Buffer{}
	writer, err := pcapng.New(&output, 1<<18, false)

	if err != nil {
		state.Fatalf("Test of capture plaintext synthesis failed, cannot create writer, error: %s", err.Error())
	}

	// no secrets maps and no filter: every flow is in scope and nothing waits for secrets
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	recorder := newRecorder(&writer, true, 0, nil, nil, nil, time.Now(), logger)

	for index, packet := range packets {
		packet.TimestampNs = uint64(index+1) * 1000
		err = recorder.handle(packet, time.Now())

		if err != nil {
			state.Fatalf("Test of capture plaintext synthesis failed, packet %d, error: %s", index, err.Error())
		}
	}

	err = writer.Flush()

	if err != nil {
		state.Fatalf("Test of capture plaintext synthesis failed, cannot flush, error: %s", err.Error())
	}

	written, err := readPackets(output.Bytes())

	if err != nil {
		state.Fatalf("Test of capture plaintext synthesis failed, cannot read output, error: %s", err.Error())
	}

	err = checkSynthesized(written, request, response, clientISN, serverISN)

	if err != nil {
		state.Errorf("Test of capture plaintext synthesis failed, error: %s", err.Error())
		return
	}
}

// Test if the plaintext recorder returns with the expected output for a connection that was open before the capture and ends with a RST:
// a synthesized handshake in front of its first packet, the data of both sides and the RST, no FIN is made up
func TestSynthesizeTCPResetPositive(state *testing.T) {
	client := Endpoint{Address: netip.MustParseAddr("2001:db8::10"), Port: 40000}
	server := Endpoint{Address: netip.MustParseAddr("2001:db8::20"), Port: 6379}
	packets := []capturebpf.Packet{
		{Cookie: 2, TimestampNs: 1000, IsIngress: false, Data: TCPPacket(nil, client, server, 5000, 7000, ACKFlag|PSHFlag, []byte("PING\r\n"))},
		{Cookie: 2, TimestampNs: 2000, IsIngress: true, Data: TCPPacket(nil, server, client, 7000, 5006, ACKFlag|PSHFlag, []byte("+PONG\r\n"))},
		{Cookie: 2, TimestampNs: 3000, IsIngress: true, Data: TCPPacket(nil, server, client, 7007, 0, RSTFlag, nil)},
		// nothing of a closed connection is written
		{Cookie: 2, TimestampNs: 4000, IsIngress: false, Data: TCPPacket(nil, client, server, 5006, 7007, ACKFlag, []byte("late"))},
	}
	output := bytes.Buffer{}
	writer, err := pcapng.New(&output, 1<<18, false)

	if err != nil {
		state.Fatalf("Test of capture plaintext synthesis failed, cannot create writer, error: %s", err.Error())
	}

	recorder := newRecorder(&writer, true, 0, nil, nil, nil, time.Now(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	for index, packet := range packets {
		packet.Length = uint32(len(packet.Data))
		err = recorder.handle(packet, time.Now())

		if err != nil {
			state.Fatalf("Test of capture plaintext synthesis failed, packet %d, error: %s", index, err.Error())
		}
	}

	err = writer.Flush()

	if err != nil {
		state.Fatalf("Test of capture plaintext synthesis failed, cannot flush, error: %s", err.Error())
	}

	written, err := readPackets(output.Bytes())

	if err != nil {
		state.Fatalf("Test of capture plaintext synthesis failed, cannot read output, error: %s", err.Error())
	}

	expected := []struct {
		Sequence uint32
		Flags    uint8
		Payload  string
	}{
		{Sequence: 4999, Flags: SYNFlag, Payload: ""},
		{Sequence: 6999, Flags: SYNFlag | ACKFlag, Payload: ""},
		{Sequence: 5000, Flags: ACKFlag, Payload: ""},
		{Sequence: 5000, Flags: ACKFlag | PSHFlag, Payload: "PING\r\n"},
		{Sequence: 7000, Flags: ACKFlag | PSHFlag, Payload: "+PONG\r\n"},
		{Sequence: 7007, Flags: RSTFlag, Payload: ""},
	}

	if len(written) != len(expected) {
		state.Fatalf("Test of capture plaintext synthesis function failed, packet count should be %d, count: %d", len(expected), len(written))
	}

	for index, packet := range written {
		if (packet.Header.sequence != expected[index].Sequence) || (packet.Header.flags != expected[index].Flags) || (string(packet.Payload) != expected[index].Payload) {
			state.Errorf("Test of capture plaintext synthesis function failed, packet %d should be %+v, packet: %d 0x%02x %q", index, expected[index], packet.Header.sequence, packet.Header.flags, packet.Payload)
			return
		}
	}
}

// both streams in order with their sequence numbers, the hole in the response as a jump with a comment, every checksum valid, a FIN from both ends
func checkSynthesized(written []writtenPacket, request []byte, response []byte, clientISN uint32, serverISN uint32) (err error) {
	streams := [2][]byte{}
	next := [2]uint32{clientISN, serverISN}
	finCount := 0
	comments := []string{}

	for index, packet := range written {
		direction := 0

		if packet.Header.source.Port == 80 {
			direction = 1
		}

		if (packet.Header.sequence != next[direction]) && (direction == 1) && (packet.Header.sequence == next[direction]+1000) {
			next[direction] += 1000
		}

		if packet.Header.sequence != next[direction] {
			err = fmt.Errorf("packet %d sequence number was not %d instead: %d", index, next[direction], packet.Header.sequence)
			return
		}

		streams[direction] = append(streams[direction], packet.Payload...)
		next[direction] += uint32(len(packet.Payload))

		if packet.Header.flags&(SYNFlag|FINFlag) != 0 {
			next[direction]++
		}

		if packet.Header.flags&FINFlag != 0 {
			finCount++
		}

		if packet.Comment != "" {
			comments = append(comments, packet.Comment)
		}
	}

	expectedResponse := slices.Concat(response[:2000], response[3000:])

	if !bytes.Equal(streams[0], request) || !bytes.Equal(streams[1], expectedResponse) {
		err = fmt.Errorf("streams were not the %d and %d bytes sent instead: %d and %d", len(request), len(expectedResponse), len(streams[0]), len(streams[1]))
		return
	}

	if (finCount != 2) || !slices.Equal(comments, []string{notePrefix + fmt.Sprintf(missingFormat, 1000, directionName(1))}) {
		err = fmt.Errorf("FIN count was not 2 with one comment on the hole instead: %d %q", finCount, comments)
		return
	}

	return
}

// the enhanced packet blocks of a pcapng section: each packet must be a TCP packet whose IPv4 and TCP checksums are valid
func readPackets(data []byte) (written []writtenPacket, err error) {
	for len(data) >= 12 {
		blockType := binary.LittleEndian.Uint32(data[0:])
		totalLength := int(binary.LittleEndian.Uint32(data[4:]))

		if (totalLength < 12) || (totalLength > len(data)) {
			err = fmt.Errorf("block length %d with %d bytes left", totalLength, len(data))
			return
		}

		body := data[8 : totalLength-4]
		data = data[totalLength:]

		if blockType != 6 {
			continue
		}

		capturedLength := int(binary.LittleEndian.Uint32(body[12:]))
		packet := body[20 : 20+capturedLength]
		options := body[20+(capturedLength+3)/4*4:]
		header, ok := parsePacket(packet)

		if !ok || (header.protocol != syscall.IPPROTO_TCP) {
			err = fmt.Errorf("packet %d is not a TCP packet: %x", len(written), packet)
			return
		}

		// a valid checksum sums up to all ones with it: the IPv4 header, and the TCP segment with its pseudo header of both addresses, the protocol and its length
		addresses, transport, ipChecksum := packet[12:20], packet[20:], foldChecksum(sumBytes(0, packet[:20]))

		if header.source.Address.Is6() {
			addresses, transport, ipChecksum = packet[8:40], packet[40:], 0
		}

		pseudo := slices.Concat(addresses, []byte{0, syscall.IPPROTO_TCP, byte(len(transport) >> 8), byte(len(transport))})

		if (ipChecksum != 0) || (foldChecksum(sumBytes(sumBytes(0, pseudo), transport)) != 0) {
			err = fmt.Errorf("packet %d has a wrong checksum: %x", len(written), packet)
			return
		}

		comment := ""

		// opt_comment is code 1
		if binary.LittleEndian.Uint16(options[0:]) == 1 {
			comment = string(options[4 : 4+binary.LittleEndian.Uint16(options[2:])])
		}

		written = append(written, writtenPacket{Header: header, Payload: bytes.Clone(packet[header.payloadOffset:]), Comment: comment})
	}

	return
}
