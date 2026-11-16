// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	v1 "github.com/decerter/decerter/api"
)

// one record type: its rdata and the values its fields should have
type recordCase struct {
	rrType   uint16
	rdata    []byte
	label    string
	expected map[string]string
}

// one payload whose tree should have an error
type malformedCase struct {
	data    []byte
	context Context
	message string
}

// Test if decode.Decode returns with the expected output for each record type: the typed fields of A, AAAA, CNAME, NS, PTR, MX, TXT, HINFO, SOA, SRV, CAA,
// HTTPS and SVCB with their parameters, DS, DNSKEY with its key tag, RRSIG, NSEC with its type bitmap, and the rdata in hex of a type it does not know.
func TestRecordTypesPositive(state *testing.T) {
	positiveCases := map[string]recordCase{
		"A":     {rrType: 1, rdata: []byte{192, 0, 2, 1}, label: "example.com: type A, class IN, 192.0.2.1", expected: map[string]string{"dns.a": "192.0.2.1", "dns.rr.type": "A (1)", "dns.rr.ttl": "300 (5m)", "dns.rr.rdlength": "4"}},
		"AAAA":  {rrType: 28, rdata: join([]byte{0x20, 0x01, 0x0d, 0xb8}, make([]byte, 11), []byte{1}), label: "example.com: type AAAA, class IN, 2001:db8::1", expected: map[string]string{"dns.aaaa": "2001:db8::1"}},
		"CNAME": {rrType: 5, rdata: wireName("www.example.net"), label: "example.com: type CNAME, class IN, www.example.net", expected: map[string]string{"dns.cname": "www.example.net"}},
		"NS":    {rrType: 2, rdata: wireName("ns1.example.com"), label: "example.com: type NS, class IN, ns1.example.com", expected: map[string]string{"dns.ns": "ns1.example.com"}},
		"PTR":   {rrType: 12, rdata: wireName("host.example.com"), label: "example.com: type PTR, class IN, host.example.com", expected: map[string]string{"dns.ptr": "host.example.com"}},
		"MX":    {rrType: 15, rdata: join(be16(10), wireName("mail.example.com")), label: "example.com: type MX, class IN, 10 mail.example.com", expected: map[string]string{"dns.mx.preference": "10", "dns.mx.exchange": "mail.example.com"}},
		"TXT":   {rrType: 16, rdata: join(characters("v=spf1 -all"), characters("a\x00b\\")), label: `example.com: type TXT, class IN, "v=spf1 -all" "a\x00b\\"`, expected: map[string]string{"dns.txt#0": "v=spf1 -all", "dns.txt#1": `a\x00b\\`}},
		"HINFO": {rrType: 13, rdata: join(characters("ARM64"), characters("Linux")), label: "example.com: type HINFO, class IN, ARM64 Linux", expected: map[string]string{"dns.hinfo.cpu": "ARM64", "dns.hinfo.os": "Linux"}},
		"SOA": {rrType: 6, rdata: join(wireName("ns1.example.com"), wireName("hostmaster.example.com"), be32(2026111601), be32(7200), be32(3600), be32(1209600), be32(300)), label: "example.com: type SOA, class IN, ns1.example.com",
			expected: map[string]string{"dns.soa.mname": "ns1.example.com", "dns.soa.rname": "hostmaster.example.com", "dns.soa.serial": "2026111601", "dns.soa.refresh": "7200 (2h)", "dns.soa.retry": "3600 (1h)", "dns.soa.expire": "1209600 (14d)", "dns.soa.minimum": "300 (5m)"}},
		"SRV": {rrType: 33, rdata: join(be16(0), be16(5), be16(443), wireName("server.example.com")), label: "example.com: type SRV, class IN, 0 5 443 server.example.com",
			expected: map[string]string{"dns.srv.priority": "0", "dns.srv.weight": "5", "dns.srv.port": "443", "dns.srv.target": "server.example.com"}},
		"CAA": {rrType: 257, rdata: join([]byte{0x80, 5}, []byte("issue"), []byte("letsencrypt.org")), label: `example.com: type CAA, class IN, 128 issue "letsencrypt.org"`,
			expected: map[string]string{"dns.caa.flags": "0x80", "dns.caa.flags.critical": "yes", "dns.caa.tag": "issue", "dns.caa.value": "letsencrypt.org"}},
		"HTTPS": {
			rrType: 65,
			rdata: join(be16(1), wireName(""), be16(0), be16(2), be16(1), be16(1), be16(6), characters("h2"), characters("h3"), be16(3), be16(2), be16(8443), be16(4), be16(4), []byte{192, 0, 2, 1},
				be16(5), be16(2), []byte{1, 2}, be16(6), be16(16), []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, be16(7), be16(16), []byte("/dns-query{?dns}"), be16(65000), be16(1), []byte{0xff}),
			label: "example.com: type HTTPS, class IN, 1 <Root> mandatory=alpn alpn=h2,h3 port=8443 ipv4hint=192.0.2.1 ech=AQI= ipv6hint=2001:db8::1 dohpath=/dns-query{?dns} key65000=ff (service mode)",
			expected: map[string]string{"dns.svcb.priority": "1", "dns.svcb.target": "<Root>", "dns.svcb.param.mandatory.key": "alpn", "dns.svcb.param.alpn#0": "h2", "dns.svcb.param.alpn#1": "h3", "dns.svcb.param.port": "8443",
				"dns.svcb.param.ipv4hint.ip": "192.0.2.1", "dns.svcb.param.ech": "AQI=", "dns.svcb.param.ipv6hint.ip": "2001:db8::1", "dns.svcb.param.dohpath": "/dns-query{?dns}", "dns.svcb.param.value": "ff",
				"dns.svcb.param.key#1": "alpn (1)", "dns.svcb.param.length#1": "6"},
		},
		"SVCB": {rrType: 64, rdata: join(be16(0), wireName("svc.example.net")), label: "example.com: type SVCB, class IN, 0 svc.example.net (alias mode)", expected: map[string]string{"dns.svcb.priority": "0", "dns.svcb.target": "svc.example.net"}},
		"DS": {rrType: 43, rdata: join(be16(20326), []byte{8, 2}, bytes.Repeat([]byte{0xab}, 32)), label: "example.com: type DS, class IN, key tag 20326, RSASHA256",
			expected: map[string]string{"dns.ds.key_tag": "20326", "dns.ds.algorithm": "RSASHA256 (8)", "dns.ds.digest_type": "SHA-256 (2)", "dns.ds.digest": strings.Repeat("ab", 32)}},
		// the key tag of 01 01 03 0d aa bb: 0x0101 + 0x030d + 0xaabb = 44745
		"DNSKEY": {rrType: 48, rdata: []byte{0x01, 0x01, 3, 13, 0xaa, 0xbb}, label: "example.com: type DNSKEY, class IN, key tag 44745, ECDSAP256SHA256, KSK",
			expected: map[string]string{"dns.dnskey.flags": "0x0101", "dns.dnskey.flags.zone_key": "yes", "dns.dnskey.flags.secure_entry_point": "yes", "dns.dnskey.flags.key_revoked": "no", "dns.dnskey.protocol": "3",
				"dns.dnskey.algorithm": "ECDSAP256SHA256 (13)", "dns.dnskey.public_key": "qrs=", "dns.dnskey.key_id": "44745"}},
		"RRSIG": {rrType: 46, rdata: join(be16(1), []byte{13, 2}, be32(300), be32(1767225600), be32(1764547200), be16(12345), wireName("example.com"), []byte{1, 2, 3, 4}), label: "example.com: type RRSIG, class IN, A ECDSAP256SHA256, key tag 12345, example.com",
			expected: map[string]string{"dns.rrsig.type_covered": "A (1)", "dns.rrsig.algorithm": "ECDSAP256SHA256 (13)", "dns.rrsig.labels": "2", "dns.rrsig.original_ttl": "300 (5m)", "dns.rrsig.signature_expiration": "2026-01-01T00:00:00Z",
				"dns.rrsig.signature_inception": "2025-12-01T00:00:00Z", "dns.rrsig.key_tag": "12345", "dns.rrsig.signers_name": "example.com", "dns.rrsig.signature": "AQIDBA=="}},
		"NSEC": {rrType: 47, rdata: join(wireName("host.example.com"), []byte{0, 6, 0x40, 0x01, 0, 0, 0, 0x03, 1, 1, 0x40}), label: "example.com: type NSEC, class IN, host.example.com",
			expected: map[string]string{"dns.nsec.next_domain_name": "host.example.com", "dns.nsec.types": "A MX RRSIG NSEC CAA"}},
		"unknown": {rrType: 65280, rdata: []byte{1, 2, 3}, label: "example.com: type TYPE65280, class IN", expected: map[string]string{"dns.rr.type": "TYPE65280 (65280)", "dns.rr.rdata": "010203"}},
	}

	for name, testCase := range positiveCases {
		result := mustDecode(state, answerPacket(testCase.rrType, testCase.rdata), udpContext, "")

		if (result.Protocol != dnsProtocol) || (len(errorsOf(result.Tree)) > 0) {
			state.Errorf("Test of the %s record failed, it should decode as dns without errors, protocol: %s, errors: %v", name, result.Protocol, errorsOf(result.Tree))
			continue
		}

		if record := findNode(result.Tree, "dns.rr"); (record == nil) || (record.Label != testCase.label) {
			state.Errorf("Test of the %s record failed, its label should be %q, record: %+v", name, testCase.label, record)
		}

		checkValues(state, name+" record", result, testCase.expected)
	}
}

// Test if decode.Decode returns with the expected output for an EDNS OPT record: payload size, extended reply code, version, the DO flag and the options
// NSID, Client Subnet, Cookie, TCP Keepalive, Padding, Extended DNS Error and an unknown one in hex.
func TestEDNSPositive(state *testing.T) {
	options := join(
		be16(3), be16(3), []byte("ns1"),
		be16(8), be16(7), be16(1), []byte{24, 0, 192, 0, 2},
		be16(10), be16(8), []byte("12345678"),
		be16(11), be16(2), be16(100),
		be16(12), be16(4), make([]byte, 4),
		be16(15), be16(19), be16(18), []byte("blocked by policy"),
		be16(65001), be16(2), []byte{0xbe, 0xef},
	)
	// a response with reply code 1 (format error) whose OPT says 1 more: 17 is Bad key
	packet := dnsPacket(0x0001, 0x8181, [4]uint16{0, 0, 0, 1}, resource(wireName(""), 41, 1232, 0x01008000, options))
	result := mustDecode(state, packet, udpContext, "dns")

	if errors := errorsOf(result.Tree); len(errors) > 0 {
		state.Fatalf("Test of the EDNS record failed, it should have no errors, errors: %v", errors)
	}

	checkValues(state, "the EDNS record", result, map[string]string{
		"dns.rr.name": "<Root>", "dns.rr.udp_payload_size": "1232", "dns.rr.ext_rcode": "1 (with the header: Bad key (17))", "dns.rr.edns_version": "0", "dns.rr.edns_flags.do": "yes",
		"dns.opt.nsid": "6e7331", "dns.opt.client.family": "IPv4 (1)", "dns.opt.client.netmask": "24", "dns.opt.client.scope": "0", "dns.opt.client.addr": "192.0.2.0/24",
		"dns.opt.cookie.client": "3132333435363738", "dns.opt.tcp_keepalive.timeout": "100", "dns.opt.padding": "4 bytes", "dns.opt.ede.info_code": "18", "dns.opt.ede.extra_text": "blocked by policy",
		"dns.opt.data": "beef", "dns.opt.code#0": "NSID (3)", "dns.opt.code#6": "Option 65001 (65001)",
	})
	labels := []string{}

	for _, option := range findAll(result.Tree, "dns.opt") {
		labels = append(labels, option.Label+" = "+option.Value)
	}

	expected := []string{"Option: NSID = ns1", "Option: Client Subnet = 192.0.2.0/24", "Option: Cookie = ", "Option: TCP Keepalive = 10.0 s", "Option: Padding = 4 bytes", "Option: Extended DNS Error = Prohibited (18): blocked by policy", "Option: Option 65001 = "}

	if !slices.Equal(labels, expected) {
		state.Errorf("Test of the EDNS options failed, they should be %q, options: %q", expected, labels)
	}
}

// Test if decode.Decode returns with the expected output over each transport: a UDP query and answer, two TCP messages in one read, DoT by ALPN and port,
// a DoH POST body by its content type, the dns parameter of a DoH GET, mDNS with its class flags, sniffing on another port and Decode As over the port.
func TestTransportsPositive(state *testing.T) {
	query := dnsPacket(0xbeef, 0x0100, [4]uint16{1, 0, 0, 0}, question(wireName("example.com"), 1, 1))
	answer := dnsPacket(0xbeef, 0x8180, [4]uint16{1, 1, 0, 0}, question(wireName("example.com"), 1, 1), resource([]byte{0xc0, 0x0c}, 1, 1, 60, []byte{192, 0, 2, 7}))

	// udp: the port, then the sniff
	result := mustDecode(state, query, udpContext, "")
	bases := []v1.DecodeBasis{}

	for _, possible := range result.Candidates {
		bases = append(bases, possible.Basis)
	}

	if (result.Protocol != dnsProtocol) || (result.Summary != "Standard query 0xbeef A example.com") || !slices.Equal(bases, []v1.DecodeBasis{v1.PortDecodeBasis, v1.SniffDecodeBasis}) || (result.Candidates[0].Reason != "udp port 53 is Domain Name System") {
		state.Errorf("Test of the udp query failed, it should be dns by its port, result: %+v", result)
	}

	if name := findNode(result.Tree, "dns.qry.name"); (name == nil) || (name.Value != "example.com") || (name.Offset != 12) || (name.Length != 13) {
		state.Errorf("Test of the udp query failed, the name should be example.com at 12+13, name: %+v", name)
	}

	result = mustDecode(state, answer, udpContext, "")

	if (result.Summary != "Standard query response 0xbeef A example.com A 192.0.2.7") || (findNode(result.Tree, "dns.rr.name").Length != 2) || (findNode(result.Tree, "dns.rr.name").Value != "example.com") {
		state.Errorf("Test of the udp answer failed, the compressed name should read as example.com in 2 bytes, result: %+v", result)
	}

	// tcp: two messages in one read, each with its length
	stream := join(be16(uint16(len(query))), query, be16(uint16(len(answer))), answer)
	result = mustDecode(state, stream, tcpContext, "")
	lengths := findAll(result.Tree, "dns.length")

	if (len(result.Tree) != 2) || (len(lengths) != 2) || (lengths[1].Offset != 2+len(query)) || (result.Tree[1].Offset != 2+len(query)) || (result.Tree[1].Length != 2+len(answer)) ||
		(findAll(result.Tree, "dns.id")[1].Offset != 4+len(query)) || (result.Summary != "Standard query 0xbeef A example.com; Standard query response 0xbeef A example.com A 192.0.2.7") {
		state.Errorf("Test of the tcp stream failed, it should have two messages after their lengths, result: %+v", result)
	}

	// DoT: the ALPN first, then the port
	result = mustDecode(state, join(be16(uint16(len(answer))), answer), dotContext, "")

	if (result.Protocol != dnsProtocol) || (len(result.Candidates) < 2) || (result.Candidates[0].Reason != "TLS ALPN dot is DNS over TLS") || (result.Candidates[1].Reason != "tls port 853 is Domain Name System") {
		state.Errorf("Test of DoT failed, it should be dns by its ALPN and port, result: %+v", result)
	}

	// DoH POST: the content type, no port
	doh := Context{Transport: BodyTransport, Layer: "", Direction: v1.UpDirection, ServerPort: 8443, ALPN: "h2", ContentType: "application/dns-message", Upgrade: "", Method: "POST", Target: "/dns-query", Encoding: "", Extensions: "", Handshake: false}
	result = mustDecode(state, query, doh, "")

	if (result.Protocol != dnsProtocol) || (result.Candidates[0].Basis != v1.ContextDecodeBasis) || (result.Candidates[0].Reason != "content type application/dns-message is DNS over HTTPS") {
		state.Errorf("Test of the DoH body failed, it should be dns by its content type, result: %+v", result)
	}

	// DoH GET: the message is in the target
	doh.Method, doh.ContentType, doh.Target = "GET", "", "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(query)
	data, found := FromTarget(doh, "")

	if !found || !bytes.Equal(data, query) {
		state.Fatalf("Test of decode.FromTarget failed, it should find the query in %s, data: %x", doh.Target, data)
	}

	result = mustDecode(state, data, doh, "")

	if (result.Protocol != dnsProtocol) || (result.Candidates[0].Reason != "the dns parameter of the GET is DNS over HTTPS") {
		state.Errorf("Test of the DoH GET failed, it should be dns by its target, result: %+v", result)
	}

	// mDNS: the top bit of the classes
	mdns := dnsPacket(0, 0x8400, [4]uint16{1, 1, 0, 0}, question(wireName("printer.local"), 255, 0x8001), resource(wireName("printer.local"), 1, 0x8001, 120, []byte{192, 168, 1, 9}))
	result = mustDecode(state, mdns, mdnsContext, "")
	checkValues(state, "mDNS", result, map[string]string{"dns.qry.unicast_response": "yes", "dns.qry.class": "IN (1)", "dns.rr.cache_flush": "yes", "dns.rr.class": "IN (1)", "dns.flags.authoritative": "yes"})

	if result.Tree[0].Label != "Multicast Domain Name System (response)" {
		state.Errorf("Test of mDNS failed, the root should be Multicast Domain Name System, root: %+v", result.Tree[0])
	}

	// another port: the bytes alone
	result = mustDecode(state, answer, otherUDP, "")

	if (result.Protocol != dnsProtocol) || (len(result.Candidates) != 1) || (result.Candidates[0].Basis != v1.SniffDecodeBasis) || (result.Candidates[0].Score != 100) {
		state.Errorf("Test of sniffing failed, the answer should be dns by its bytes, result: %+v", result)
	}

	// Decode As raw over the port
	result = mustDecode(state, query, udpContext, RawProtocol)

	if (result.Protocol != RawProtocol) || (len(result.Tree) != 1) || (result.Tree[0].Length != len(query)) || (result.Candidates[0].Basis != v1.OverrideDecodeBasis) || !slices.Equal(result.Protocols, []string{"dns", "dtls", "grpc", "protobuf", "tls", "websocket", "raw"}) {
		state.Errorf("Test of Decode As raw failed, the tree should be one raw node, result: %+v", result)
	}
}

// Test if decode.Decode returns with the expected errors in the tree, never a failure: a short header, a message that goes on in the next read, a pointer to itself, a pointer
// chain, a name over 255 bytes, a reserved label type, rdata past the end, an A record of 5 bytes, bytes after the rdata and after the last record, more records counted than there are.
func TestMalformedNegative(state *testing.T) {
	chain := []byte{}

	// 40 pointers, each to the next, then the root
	for index := range 40 {
		chain = append(chain, 0xc0, byte(12+2*(index+1)))
	}

	chain = append(chain, 0)
	longName := []byte{}

	for range 5 {
		longName = append(longName, 63)
		longName = append(longName, bytes.Repeat([]byte{'a'}, 63)...)
	}

	longName = append(longName, 0)
	negativeCases := map[string]malformedCase{
		"short header":      {data: []byte{1, 2, 3, 4, 5}, context: udpContext, message: "a DNS header has 12 bytes, the message 5"},
		"next read":         {data: join(be16(100), make([]byte, 30)), context: tcpContext, message: "the message continues in the next read: 30 of its 100 bytes are here"},
		"one length byte":   {data: join(be16(12), make([]byte, 12), []byte{0}), context: tcpContext, message: "1 byte of the 2-byte length"},
		"pointer loop":      {data: dnsPacket(1, 0, [4]uint16{1, 0, 0, 0}, []byte{0xc0, 0x0c}, be16(1), be16(1)), context: udpContext, message: errNameLoop.Error()},
		"pointer chain":     {data: dnsPacket(1, 0, [4]uint16{1, 0, 0, 0}, chain, be16(1), be16(1)), context: udpContext, message: errNameLoop.Error()},
		"long name":         {data: dnsPacket(1, 0, [4]uint16{1, 0, 0, 0}, longName, be16(1), be16(1)), context: udpContext, message: errNameLong.Error()},
		"label type":        {data: dnsPacket(1, 0, [4]uint16{1, 0, 0, 0}, []byte{0x41, 'a', 0}, be16(1), be16(1)), context: udpContext, message: "reserved label type 0x40"},
		"pointer past end":  {data: dnsPacket(1, 0, [4]uint16{1, 0, 0, 0}, []byte{0xc0}), context: udpContext, message: errNameShort.Error()},
		"rdata past end":    {data: dnsPacket(1, 0x8000, [4]uint16{0, 1, 0, 0}, wireName("a"), be16(1), be16(1), be32(1), be16(100), []byte{1, 2, 3, 4}), context: udpContext, message: "the rdata runs past the end of the message: 100 bytes, 4 are left"},
		"A of 5 bytes":      {data: answerPacket(1, []byte{1, 2, 3, 4, 5}), context: udpContext, message: "the address has 4 bytes, the rdata 5"},
		"rdata trailer":     {data: answerPacket(15, join(be16(1), wireName("a"), []byte{9})), context: udpContext, message: "bytes after the end of the rdata fields: 1 bytes"},
		"record trailer":    {data: append(answerPacket(1, []byte{1, 2, 3, 4}), 7, 7), context: udpContext, message: "2 bytes after the last record"},
		"missing records":   {data: dnsPacket(1, 0x8000, [4]uint16{0, 3, 0, 0}, resource(wireName("a"), 1, 1, 1, []byte{1, 2, 3, 4})), context: udpContext, message: errNameShort.Error()},
		"short record":      {data: dnsPacket(1, 0x8000, [4]uint16{0, 1, 0, 0}, wireName("a"), be16(1)), context: udpContext, message: errRecordShort.Error()},
		"short question":    {data: dnsPacket(1, 0, [4]uint16{1, 0, 0, 0}, wireName("a"), be16(1)), context: udpContext, message: "the question runs past the end of the message"},
		"short txt":         {data: answerPacket(16, []byte{9, 'a'}), context: udpContext, message: "Text: " + errFieldShort.Error()},
		"bad subnet":        {data: dnsPacket(1, 0x8000, [4]uint16{0, 0, 0, 1}, resource(wireName(""), 41, 512, 0, join(be16(8), be16(5), be16(1), []byte{24, 0, 1}))), context: udpContext, message: "the address has 1 bytes, the family and source prefix length 24 need 3"},
		"short cookie":      {data: dnsPacket(1, 0x8000, [4]uint16{0, 0, 0, 1}, resource(wireName(""), 41, 512, 0, join(be16(10), be16(3), []byte{1, 2, 3}))), context: udpContext, message: "a cookie has 8 bytes or 16 to 40"},
		"dnskey protocol":   {data: answerPacket(48, []byte{1, 0, 2, 8, 1}), context: udpContext, message: "the protocol is 2"},
		"bitmap window":     {data: answerPacket(47, join(wireName("a"), []byte{1, 1, 0x40, 0, 1, 0x40})), context: udpContext, message: "type bitmap window 0 with 1 bytes"},
		"svcb param length": {data: answerPacket(65, join(be16(1), wireName(""), be16(3), be16(9), be16(1))), context: udpContext, message: "port: " + errFieldShort.Error()},
	}

	for name, testCase := range negativeCases {
		result := mustDecode(state, testCase.data, testCase.context, "dns")
		errors := errorsOf(result.Tree)

		if (result.Protocol != dnsProtocol) || !slices.ContainsFunc(errors, func(text string) bool { return strings.Contains(text, testCase.message) }) {
			state.Errorf("Test of the malformed %s failed, the tree should have the error %q, errors: %v", name, testCase.message, errors)
		}
	}
}

// Test if decode.Decode returns with the expected errors: an as that names no protocol is an error, bytes no decoder takes are raw, a port takes too little only with an override.
func TestDecodeNegative(state *testing.T) {
	_, err := Decode([]byte{1}, udpContext, "nosuch")

	if (err == nil) || !strings.Contains(err.Error(), `as "nosuch", valid values: dns, dtls, grpc, protobuf, tls, websocket, raw`) {
		state.Errorf("Test of decode.Decode failed, an unknown as should be an error, error: %v", err)
	}

	for name, data := range map[string][]byte{"text": []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), "short": {0, 1, 2}, "empty": {}} {
		result := mustDecode(state, data, otherUDP, "")

		if (result.Protocol != RawProtocol) || (len(result.Candidates) != 1) || (result.Candidates[0].Basis != v1.NoneDecodeBasis) || (result.Tree[0].Length != len(data)) || !strings.HasSuffix(result.Summary, "no decoder took the bytes") {
			state.Errorf("Test of decode.Decode failed, %s should be raw, result: %+v", name, result)
		}
	}

	// the port names dns, but 3 bytes can't be: raw, with the port candidate at score 0
	result := mustDecode(state, []byte{0, 1, 2}, udpContext, "")

	if (result.Protocol != RawProtocol) || (result.Candidates[0].Basis != v1.PortDecodeBasis) || (result.Candidates[0].Score != 0) {
		state.Errorf("Test of decode.Decode failed, 3 bytes on port 53 should be raw, result: %+v", result)
	}

	// as=dns takes them anyway, with the error in the tree
	result = mustDecode(state, []byte{0, 1, 2}, otherUDP, "dns")

	if (result.Protocol != dnsProtocol) || (len(errorsOf(result.Tree)) != 1) || (result.Summary != "Malformed DNS message") {
		state.Errorf("Test of decode.Decode failed, as=dns should decode 3 bytes with an error, result: %+v", result)
	}
}
