// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"

	v1 "github.com/decerter/decerter/api"
)

// the contexts of the udp tests: a datagram to a port no decoder has, to the STUN, NTP and DHCP ports, and a tcp read to the STUN port
var (
	plainUDP    = Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 40000, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	stunUDP     = Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 3478, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	stunTCP     = Context{Transport: StreamTransport, Layer: v1.TCPLayer, Direction: v1.UpDirection, ServerPort: 3478, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: true}
	ntpUDP      = Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 123, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	dhcpUDP     = Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 67, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	dhcpv6UDP   = Context{Transport: DatagramTransport, Layer: v1.UDPLayer, Direction: v1.UpDirection, ServerPort: 547, ALPN: "", ContentType: "", Upgrade: "", Method: "", Target: "", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	udpContexts = []Context{plainUDP, stunUDP, ntpUDP, dhcpUDP, dhcpv6UDP, stunTCP}
)

// the test vectors of RFC 5769: a request with SOFTWARE, PRIORITY, ICE-CONTROLLED, USERNAME, MESSAGE-INTEGRITY and FINGERPRINT, and a response with an
// IPv4 and one with an IPv6 XOR-MAPPED-ADDRESS
const (
	stunRequestHex  string = "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e20746573742063" + "6c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a6836765920202000080014" + "9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf"
	stunIPv4Hex     string = "0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643" + "000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96"
	stunIPv6Hex     string = "010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f722000200014" + "0002a1470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf11784c97c8292c275bfe3ed4180280004c8fb0b4c"
	stunRequestName string = "Binding Request"
)

func mustHex(state testing.TB, text string) (data []byte) {
	data, err := hex.DecodeString(text)

	if err != nil {
		state.Fatalf("Could not read the hex %q, error: %s", text, err.Error())
	}

	return
}

// Test if decode.Decode returns with the expected output for STUN: the RFC 5769 vectors with their attributes, the XOR addresses and the fingerprints
// checked, by port and by sniffing; a TURN ChannelData message with DTLS inside; two messages over tcp in one stream.
func TestSTUNPositive(state *testing.T) {
	request := mustHex(state, stunRequestHex)
	result := mustDecode(state, request, plainUDP, "")

	if (result.Protocol != stunProtocol) || (result.Candidates[0].Basis != v1.SniffDecodeBasis) || (result.Summary != "STUN Binding Request") || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of STUN failed, the RFC 5769 request should sniff as STUN without errors, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the STUN request", result, map[string]string{
		"stun.type.method": "Binding (0x0001)", "stun.type.class": "Request (0)", "stun.attribute.text#0": `"STUN test client"`, "stun.priority": "1845494271",
		"stun.tie_breaker": "0x932ff9b151263b36", "stun.attribute.text#1": `"evtj:h6vY"`, "stun.fingerprint": "0xe57a3bcf", "stun.cookie": "0x2112a442",
	})

	if fingerprint := findAll(result.Tree, "stun.attribute"); (len(fingerprint) != 6) || (fingerprint[5].Value != "0xe57a3bcf correct") || (fingerprint[2].Label != "ICE-CONTROLLED") {
		state.Errorf("Test of STUN failed, the request should have 6 attributes with a correct fingerprint, attributes: %+v", fingerprint)
	}

	for text, expected := range map[string]string{stunIPv4Hex: "192.0.2.1:32853", stunIPv6Hex: "[2001:db8:1234:5678:11:2233:4455:6677]:32853"} {
		result = mustDecode(state, mustHex(state, text), stunUDP, "")

		if (result.Protocol != stunProtocol) || (result.Summary != "STUN Binding Success Response "+expected) || (len(errorsOf(result.Tree)) != 0) || (result.Candidates[0].Basis != v1.PortDecodeBasis) {
			state.Errorf("Test of STUN failed, the response should map to %s, result: %+v, errors: %v", expected, result, errorsOf(result.Tree))
		}
	}

	// a fingerprint that does not match
	broken := bytes.Clone(request)
	broken[len(broken)-1] ^= 1
	result = mustDecode(state, broken, stunUDP, "")

	if errors := errorsOf(result.Tree); (len(errors) != 1) || !strings.Contains(errors[0], "the CRC-32 of the message is 0xe57a3bcf") {
		state.Errorf("Test of STUN failed, a wrong fingerprint should be an error, errors: %v", errors)
	}

	// TURN: an Allocate request with REQUESTED-TRANSPORT and LIFETIME, then a ChannelData message carrying a DTLS ClientHello record
	allocate := join(be16(0x0003), be16(16), be32(stunCookie), bytes.Repeat([]byte{9}, 12), be16(0x0019), be16(4), []byte{17, 0, 0, 0}, be16(0x000d), be16(4), be32(600))
	result = mustDecode(state, allocate, stunUDP, "")
	checkValues(state, "the TURN Allocate", result, map[string]string{"stun.transport": "UDP (17)", "stun.lifetime": "600 (10m)", "stun.type.method": "Allocate (0x0003)"})
	hello := dtlsClientHello([]byte{0xc0, 0x2b})
	channel := join(be16(0x4001), be16(uint16(len(hello))), hello)
	result = mustDecode(state, channel, stunUDP, "")

	if (result.Protocol != stunProtocol) || !strings.HasPrefix(result.Summary, "TURN ChannelData 0x4001") || !strings.HasSuffix(result.Summary, "(dtls)") || (findNode(result.Tree, "tls.handshake.type") == nil) {
		state.Errorf("Test of TURN failed, the channel data should carry DTLS, result: %+v", result)
	}

	// over tcp: the channel data is padded to 4 bytes, then a request follows
	padded := join(be16(0x4002), be16(3), []byte{1, 2, 3, 0}, request)
	result = mustDecode(state, padded, stunTCP, "")

	if (len(result.Tree) != 2) || (result.Tree[1].Offset != 8) || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of STUN over tcp failed, the stream should be two messages, tree: %+v, errors: %v", result.Tree, errorsOf(result.Tree))
	}
}

// Test if decode.Decode returns with the expected errors for STUN: a message cut short, a classic message without the cookie as= takes, an attribute past
// the message and a message length that is no multiple of 4.
func TestSTUNNegative(state *testing.T) {
	request := mustHex(state, stunRequestHex)
	negativeCases := map[string]struct {
		data     []byte
		as       string
		expected string
	}{
		"cut":       {data: request[:50], as: "", expected: "the message continues in the next read"},
		"classic":   {data: join(be16(1), be16(0), bytes.Repeat([]byte{7}, 16)), as: stunProtocol, expected: "so this is a classic RFC 3489 message"},
		"attribute": {data: join(be16(1), be16(4), be32(stunCookie), make([]byte, 12), be16(0x8022), be16(40)), as: "", expected: "the value runs past the message"},
		"odd":       {data: join(be16(1), be16(2), be32(stunCookie), make([]byte, 12), []byte{0, 0}), as: stunProtocol, expected: "is no multiple of 4"},
	}

	for name, negative := range negativeCases {
		result := mustDecode(state, negative.data, stunUDP, negative.as)

		if !strings.Contains(strings.Join(errorsOf(result.Tree), "; "), negative.expected) {
			state.Errorf("Test of STUN failed, %s should have the error %q, errors: %v", name, negative.expected, errorsOf(result.Tree))
		}
	}
}

// Test if decode.Decode returns with the expected output for RTP and RTCP: a packet with CSRCs, a one-byte header extension and padding as= rtp (and by
// sniffing for its RFC 8285 extension), compared with pion/rtp; an SR, an SDES and a BYE in one compound packet by sniffing, compared with pion/rtcp.
func TestRTPPositive(state *testing.T) {
	packet := rtp.Packet{
		Header:      rtp.Header{Version: 2, Padding: true, Marker: true, PayloadType: 111, SequenceNumber: 4242, Timestamp: 160000, SSRC: 0x11223344, CSRC: []uint32{0xaabbccdd, 0x01020304}},
		Payload:     []byte("opus frame"),
		PaddingSize: 3,
	}

	if err := packet.SetExtension(1, []byte{0x10}); err != nil {
		state.Fatalf("Could not set the RTP extension, error: %s", err.Error())
	}

	if err := packet.SetExtension(3, []byte{1, 2, 3}); err != nil {
		state.Fatalf("Could not set the RTP extension, error: %s", err.Error())
	}

	data, err := packet.Marshal()

	if err != nil {
		state.Fatalf("Could not marshal the RTP packet, error: %s", err.Error())
	}

	result := mustDecode(state, data, plainUDP, "")
	oracle := rtp.Packet{}

	if err = oracle.Unmarshal(data); err != nil {
		state.Fatalf("Could not unmarshal the RTP packet, error: %s", err.Error())
	}

	payload := findNode(result.Tree, "rtp.payload")

	if (result.Protocol != rtpProtocol) || (result.Summary != "RTP PT=dynamic 111, SSRC=0x11223344, Seq=4242, Time=160000, Mark") || (len(errorsOf(result.Tree)) != 0) ||
		(len(findAll(result.Tree, "rtp.csrc.item")) != len(oracle.CSRC)) || (len(findAll(result.Tree, "rtp.ext.element")) != len(oracle.Extensions)) ||
		(payload == nil) || (payload.Length != len(oracle.Payload)) || !bytes.Equal(data[payload.Offset:payload.Offset+payload.Length], oracle.Payload) {
		state.Errorf("Test of RTP failed, the packet should agree with pion/rtp, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the RTP packet", result, map[string]string{"rtp.csrc.item#1": "0x01020304", "rtp.ext.element.data#1": "010203", "rtp.padding.count": "3 bytes", "rtp.p_type": "dynamic 111 (111)"})

	// a compound packet: SR with one report block, SDES with a CNAME, BYE with a reason
	compound := []rtcp.Packet{
		&rtcp.SenderReport{SSRC: 0x01020304, NTPTime: 0xe0000000_80000000, RTPTime: 1000, PacketCount: 10, OctetCount: 1600, Reports: []rtcp.ReceptionReport{{SSRC: 0x0a0b0c0d, FractionLost: 64, TotalLost: 3, LastSequenceNumber: 99, Jitter: 5, LastSenderReport: 7, Delay: 65536}}},
		&rtcp.SourceDescription{Chunks: []rtcp.SourceDescriptionChunk{{Source: 0x01020304, Items: []rtcp.SourceDescriptionItem{{Type: rtcp.SDESCNAME, Text: "user@example.com"}}}}},
		&rtcp.Goodbye{Sources: []uint32{0x01020304}, Reason: "done"},
	}
	data, err = rtcp.Marshal(compound)

	if err != nil {
		state.Fatalf("Could not marshal the RTCP packet, error: %s", err.Error())
	}

	unmarshaled, err := rtcp.Unmarshal(data)

	if err != nil {
		state.Fatalf("Could not unmarshal the RTCP packet, error: %s", err.Error())
	}

	result = mustDecode(state, data, plainUDP, "")

	if (result.Protocol != rtcpProtocol) || (len(result.Tree) != len(unmarshaled)) || (result.Summary != "RTCP SR, SDES, BYE") || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of RTCP failed, the compound packet should agree with pion/rtcp, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the RTCP packet", result, map[string]string{
		"rtcp.timestamp.ntp": "2019-02-02T11:39:44.5Z", "rtcp.ssrc.fraction": "64 / 256", "rtcp.ssrc.cum_nr": "3", "rtcp.ssrc.dlsr": "65536 (1.000 s)",
		"rtcp.sdes.text": `"user@example.com"`, "rtcp.bye.reason": `"done"`, "rtcp.sender.octetcount": "1600",
	})
}

// Test if decode.Decode returns with the expected errors for RTP and RTCP: a short header, CSRCs past the packet, padding larger than the packet, an RTCP
// packet past its datagram.
func TestRTPNegative(state *testing.T) {
	negativeCases := map[string]struct {
		data     []byte
		as       string
		expected string
	}{
		"short":   {data: []byte{0x80, 0x60, 1}, as: rtpProtocol, expected: "an RTP header has 12 bytes"},
		"csrcs":   {data: join([]byte{0x83, 0x60}, make([]byte, 14)), as: rtpProtocol, expected: "Contributing sources: the field runs past the end"},
		"padding": {data: join([]byte{0xa0, 0x60}, make([]byte, 10), []byte{1, 40}), as: rtpProtocol, expected: "a padding of 40 bytes does not fit"},
		"rtcp":    {data: join([]byte{0x80, 201}, be16(6), be32(1)), as: rtcpProtocol, expected: "the packet runs past the datagram"},
		"version": {data: join([]byte{0x40, 0x60}, make([]byte, 10)), as: rtpProtocol, expected: "RTP is version 2"},
	}

	for name, negative := range negativeCases {
		result := mustDecode(state, negative.data, plainUDP, negative.as)

		if !strings.Contains(strings.Join(errorsOf(result.Tree), "; "), negative.expected) {
			state.Errorf("Test of RTP failed, %s should have the error %q, errors: %v", name, negative.expected, errorsOf(result.Tree))
		}
	}

	// an RTP header that adds up but has no RFC 8285 extension is not taken by sniffing alone
	if result := mustDecode(state, join([]byte{0x80, 0x60}, make([]byte, 30)), plainUDP, ""); result.Protocol == rtpProtocol {
		state.Errorf("Test of RTP failed, a plain RTP header should not be taken by sniffing, result: %+v", result)
	}
}

// an NTP client request of version 4 with its transmit timestamp
func ntpRequest(transmit uint64) (data []byte) {
	data = join([]byte{0x23, 0, 6, 0xec}, make([]byte, 36), be32(uint32(transmit>>32)), be32(uint32(transmit)))
	return
}

// Test if decode.Decode returns with the expected output for NTP: a client request by its port, a server answer by sniffing with its reference id and
// timestamps, an answer with a MAC, and the era of a timestamp after 2036.
func TestNTPPositive(state *testing.T) {
	result := mustDecode(state, ntpRequest(0xe0000000_80000000), ntpUDP, "")

	if (result.Protocol != ntpProtocol) || (result.Summary != "NTP version 4, client, stratum 0, transmit 2019-02-02T11:39:44.5Z") || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of NTP failed, the request should decode by its port, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the NTP request", result, map[string]string{"ntp.flags.mode": "client (3)", "ntp.flags.vn": "4", "ntp.ppoll": "6 (64 s)", "ntp.precision": "-20 (9.5367431640625e-07 s)", "ntp.reftime": "0 (not set)"})
	answer := join([]byte{0x24, 2, 6, 0xe9}, be32(0x00010000), be32(0x00008000), []byte{192, 0, 2, 1}, bytes.Repeat(be32(0xe0000000), 8))
	result = mustDecode(state, answer, plainUDP, "")
	checkValues(state, "the NTP answer", result, map[string]string{"ntp.stratum": "2 (secondary reference)", "ntp.refid": "192.0.2.1", "ntp.rootdelay": "1.000000 s", "ntp.rootdispersion": "0.500000 s"})

	if result.Protocol != ntpProtocol {
		state.Errorf("Test of NTP failed, the answer should sniff as NTP, result: %+v", result)
	}

	// stratum 1 with a clock source, a MAC of a key id and an MD5 digest
	primary := join([]byte{0x24, 1, 6, 0xe9}, make([]byte, 8), []byte("GPS\x00"), make([]byte, 32), be32(7), bytes.Repeat([]byte{0xab}, 16))
	result = mustDecode(state, primary, ntpUDP, "")
	checkValues(state, "the NTP MAC", result, map[string]string{"ntp.refid": `"GPS"`, "ntp.keyid": "0x00000007", "ntp.mac.digest": strings.Repeat("ab", 16)})

	// a timestamp with the top bit clear is in era 1
	if text := ntpTimeText(uint64(0x00000001) << 32); text != "2036-02-07T06:28:17Z" {
		state.Errorf("Test of NTP failed, a timestamp of era 1 should be after 2036, text: %s", text)
	}
}

// Test if decode.Decode returns with the expected errors for NTP: a short packet, an extension field shorter than 16 bytes.
func TestNTPNegative(state *testing.T) {
	result := mustDecode(state, []byte{0x23, 0}, ntpUDP, "")

	if (result.Protocol != RawProtocol) || (len(result.Candidates) != 1) {
		state.Errorf("Test of NTP failed, a short packet should not be taken by its port, result: %+v", result)
	}

	result = mustDecode(state, []byte{0x23, 0}, ntpUDP, ntpProtocol)

	if errors := errorsOf(result.Tree); (len(errors) == 0) || !strings.Contains(errors[0], "an NTP header has 48 bytes") {
		state.Errorf("Test of NTP failed, a short packet should be an error, errors: %v", errors)
	}

	extension := join(ntpRequest(1), be16(0x0104), be16(8), make([]byte, 4), be32(1), make([]byte, 20))
	result = mustDecode(state, extension, ntpUDP, ntpProtocol)

	if errors := errorsOf(result.Tree); !strings.Contains(strings.Join(errors, "; "), "at least 16") {
		state.Errorf("Test of NTP failed, a short extension field should be an error, errors: %v", errors)
	}
}

// a DHCPv4 message: the fixed fields of a request from 52:54:00:12:34:56, the magic cookie and the options
func dhcpPacket(operation byte, yours [4]byte, options []byte) (data []byte) {
	hardware := append([]byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}, make([]byte, 10)...)
	data = join([]byte{operation, 1, 6, 0}, be32(0x3903f326), be16(0), be16(0x8000), make([]byte, 4), yours[:], make([]byte, 8), hardware, make([]byte, 192), be32(dhcpCookie), options)
	return
}

// Test if decode.Decode returns with the expected output for DHCPv4 and DHCPv6: a Discover with its options by port, an Offer with addresses, lease times
// and a classless route by sniffing, a Solicit with its DUID, IA_NA, option request and elapsed time, and a relayed Reply.
func TestDHCPPositive(state *testing.T) {
	discover := dhcpPacket(1, [4]byte{}, join([]byte{53, 1, 1}, []byte{61, 7, 1, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56}, []byte{55, 4, 1, 3, 6, 15}, []byte{12, 4}, []byte("host"), []byte{255, 0, 0}))
	result := mustDecode(state, discover, dhcpUDP, "")

	if (result.Protocol != dhcpProtocol) || (result.Summary != "DHCP Discover - Transaction ID 0x3903f326") || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of DHCP failed, the Discover should decode by its port, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the DHCP Discover", result, map[string]string{
		"dhcp.hw.mac_addr": "52:54:00:12:34:56", "dhcp.client_id": "52:54:00:12:34:56", "dhcp.option.text": `"host"`, "dhcp.flags.bc": "yes",
		"dhcp.option.request_list_item#3": "Domain Name (15)", "dhcp.option.padding": "2 bytes", "dhcp.option.dhcp": "Discover (1)",
	})
	offer := dhcpPacket(2, [4]byte{192, 0, 2, 10}, join([]byte{53, 1, 2}, []byte{54, 4, 192, 0, 2, 1}, []byte{51, 4}, be32(86400), []byte{6, 8, 192, 0, 2, 53, 192, 0, 2, 54},
		[]byte{121, 8, 24, 198, 51, 100, 192, 0, 2, 1}, []byte{255}))
	result = mustDecode(state, offer, plainUDP, "")

	if (result.Protocol != dhcpProtocol) || (result.Summary != "DHCP Offer - Transaction ID 0x3903f326, your address 192.0.2.10") || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of DHCP failed, the Offer should sniff as DHCP, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the DHCP Offer", result, map[string]string{"dhcp.option.time": "86400 (1d)", "dhcp.option.route": "198.51.100.0/24 via 192.0.2.1", "dhcp.option.ip#1": "192.0.2.53"})
	options := find(result.Tree, "dhcp.option")

	if (len(options) != 5) || (options[3].Value != "192.0.2.53, 192.0.2.54") {
		state.Errorf("Test of DHCP failed, the Offer should have 5 options, options: %+v", options)
	}

	duid := join(be16(1), be16(1), be32(0x2a000000), []byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56})
	solicit := join([]byte{1, 0x12, 0x34, 0x56}, be16(1), be16(uint16(len(duid))), duid, be16(3), be16(12), be32(7), be32(3600), be32(5400), be16(6), be16(4), be16(23), be16(24), be16(8), be16(2), be16(5))
	result = mustDecode(state, solicit, dhcpv6UDP, "")

	if (result.Protocol != dhcpv6Protocol) || (result.Summary != "Solicit XID: 0x123456") || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of DHCPv6 failed, the Solicit should decode by its port, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the DHCPv6 Solicit", result, map[string]string{"dhcpv6.duid.linklayer": "52:54:00:12:34:56", "dhcpv6.iaid.t1": "3600 (1h)", "dhcpv6.requested_option_code#1": "Domain Search List (24)", "dhcpv6.elapsed_time": "50 ms"})
	reply := join([]byte{7, 0x12, 0x34, 0x56}, be16(13), be16(4), be16(0), []byte("ok"), be16(23), be16(16), []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1})
	relayed := join([]byte{13, 0}, make([]byte, 16), []byte{0xfe, 0x80, 15: 2}, be16(9), be16(uint16(len(reply))), reply)
	result = mustDecode(state, relayed, plainUDP, "")

	if (result.Protocol != dhcpv6Protocol) || (result.Summary != "Relay-repl peer fe80::2: Reply XID: 0x123456") || (len(errorsOf(result.Tree)) != 0) {
		state.Errorf("Test of DHCPv6 failed, the relayed Reply should sniff as DHCPv6, result: %+v, errors: %v", result, errorsOf(result.Tree))
	}

	checkValues(state, "the DHCPv6 Reply", result, map[string]string{"dhcpv6.status_message": `"ok"`, "dhcpv6.address": "2001:db8::1"})
}

// Test if decode.Decode returns with the expected errors for DHCP: options without End, an option past the message, a DHCPv6 option past its message.
func TestDHCPNegative(state *testing.T) {
	negativeCases := map[string]struct {
		data     []byte
		as       string
		expected string
	}{
		"no end":   {data: dhcpPacket(1, [4]byte{}, []byte{53, 1, 1}), as: "", expected: "the options have no End option"},
		"option":   {data: dhcpPacket(1, [4]byte{}, []byte{12, 9, 'a'}), as: "", expected: "the option runs past its message: 1 of its 9 bytes are there"},
		"v6":       {data: join([]byte{1, 0, 0, 1}, be16(1), be16(20), be16(3)), as: dhcpv6Protocol, expected: "the option runs past its message"},
		"short v4": {data: []byte{1, 1, 6}, as: dhcpProtocol, expected: "the field runs past the end"},
	}

	for name, negative := range negativeCases {
		result := mustDecode(state, negative.data, dhcpUDP, negative.as)

		if !strings.Contains(strings.Join(errorsOf(result.Tree), "; "), negative.expected) {
			state.Errorf("Test of DHCP failed, %s should have the error %q, errors: %v", name, negative.expected, errorsOf(result.Tree))
		}
	}
}

// the nodes of that name directly or below, depth first, but not inside a node of that name
func find(nodes []v1.DecodeNode, name string) (found []v1.DecodeNode) {
	for _, current := range nodes {
		if current.Name == name {
			found = append(found, current)
			continue
		}

		found = append(found, find(current.Children, name)...)
	}

	return
}

// Fuzz if decode.Decode never fails on any bytes as STUN and TURN, as a datagram, a tcp stream and every other udp context.
func FuzzSTUN(fuzz *testing.F) {
	fuzz.Add(mustHex(fuzz, stunRequestHex))
	fuzz.Add(mustHex(fuzz, stunIPv4Hex))
	fuzz.Add(mustHex(fuzz, stunIPv6Hex))
	fuzz.Add(join(be16(0x4001), be16(4), []byte{1, 2, 3, 4}))
	fuzz.Add(join(be16(0x0003), be16(8), be32(stunCookie), bytes.Repeat([]byte{9}, 12), be16(0x0009), be16(4), []byte{0, 0, 4, 1}))

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		fuzzDecodes(state, data, udpContexts, []string{"", stunProtocol})
	})
}

// Fuzz if decode.Decode never fails on any bytes as RTP and RTCP.
func FuzzRTP(fuzz *testing.F) {
	fuzz.Add(join([]byte{0x90, 0x6f}, be16(1), be32(2), be32(3), be16(rtpOneByteProfile), be16(1), []byte{0x10, 1, 0, 0}, []byte("payload")))
	fuzz.Add(join([]byte{0x92, 0x60}, be16(1), be32(2), be32(3), be32(4), be32(5), be16(0x1000), be16(1), []byte{1, 2, 7, 7}))
	fuzz.Add(join([]byte{0x81, 200}, be16(12), make([]byte, 48)))
	fuzz.Add(join([]byte{0x81, 202}, be16(3), be32(1), []byte{1, 3, 'a', 'b', 'c', 0, 0, 0}))
	fuzz.Add(join([]byte{0x81, 203}, be16(2), be32(1), []byte{2, 'o', 'k', 0}))

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		fuzzDecodes(state, data, udpContexts, []string{"", rtpProtocol, rtcpProtocol})
	})
}

// Fuzz if decode.Decode never fails on any bytes as NTP.
func FuzzNTP(fuzz *testing.F) {
	fuzz.Add(ntpRequest(0xe0000000_80000000))
	fuzz.Add(join(ntpRequest(1), be16(0x0104), be16(16), make([]byte, 12), be32(1), make([]byte, 16)))
	fuzz.Add(join([]byte{0x26, 0, 0, 0}, make([]byte, 60)))

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		fuzzDecodes(state, data, udpContexts, []string{"", ntpProtocol})
	})
}

// Fuzz if decode.Decode never fails on any bytes as DHCPv4 and DHCPv6.
func FuzzDHCP(fuzz *testing.F) {
	fuzz.Add(dhcpPacket(1, [4]byte{}, []byte{53, 1, 1, 121, 5, 8, 10, 192, 0, 2, 255}))
	fuzz.Add(join([]byte{1, 0x12, 0x34, 0x56}, be16(3), be16(12), be32(7), be32(3600), be32(5400)))
	fuzz.Add(join([]byte{12, 0}, make([]byte, 32), be16(9), be16(4), []byte{11, 0, 0, 1}))

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		fuzzDecodes(state, data, udpContexts, []string{"", dhcpProtocol, dhcpv6Protocol})
	})
}
