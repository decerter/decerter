// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	v1 "github.com/decerter/decerter/api"
)

// golang.org/x/net/dns/dnsmessage is the oracle of these tests only, decerter links none of it

// a message golang.org/x/net/dns/dnsmessage builds with compression: every type it knows in the three sections
func builtMessage(state testing.TB) (packet []byte) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0xa1b2, Response: true, OpCode: 0, Authoritative: true, RecursionDesired: true, RecursionAvailable: true, RCode: dnsmessage.RCodeNameError})
	builder.EnableCompression()
	name := dnsmessage.MustNewName("www.example.com.")
	zone := dnsmessage.MustNewName("example.com.")
	header := func(owner dnsmessage.Name, ttl uint32) (resourceHeader dnsmessage.ResourceHeader) {
		resourceHeader = dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: ttl}
		return
	}
	svcb := dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName("svc.example.com."), Params: nil}
	svcb.SetParam(dnsmessage.SVCParamALPN, []byte("\x02h2\x02h3"))
	svcb.SetParam(dnsmessage.SVCParamPort, []byte{0x20, 0xfb})
	options := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Class: 0, TTL: 0}
	err := options.SetEDNS0(1232, dnsmessage.RCodeSuccess, true)
	steps := []func() error{
		builder.StartQuestions,
		func() error {
			return builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		},
		func() error {
			return builder.Question(dnsmessage.Question{Name: zone, Type: dnsmessage.TypeALL, Class: dnsmessage.ClassINET})
		},
		builder.StartAnswers,
		func() error {
			return builder.CNAMEResource(header(name, 300), dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.example.com.")})
		},
		func() error {
			return builder.AResource(header(name, 60), dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}})
		},
		func() error {
			return builder.AAAAResource(header(name, 60), dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::10").As16()})
		},
		func() error {
			return builder.MXResource(header(zone, 3600), dnsmessage.MXResource{Pref: 20, MX: dnsmessage.MustNewName("mail.example.com.")})
		},
		func() error {
			return builder.TXTResource(header(zone, 3600), dnsmessage.TXTResource{TXT: []string{"v=spf1 -all", "second \"one\""}})
		},
		func() error {
			return builder.SRVResource(header(dnsmessage.MustNewName("_sip._udp.example.com."), 86400), dnsmessage.SRVResource{Priority: 10, Weight: 60, Port: 5060, Target: dnsmessage.MustNewName("sip.example.com.")})
		},
		func() error {
			return builder.HTTPSResource(header(zone, 300), dnsmessage.HTTPSResource{SVCBResource: svcb})
		},
		func() error {
			return builder.PTRResource(header(dnsmessage.MustNewName("10.2.0.192.in-addr.arpa."), 300), dnsmessage.PTRResource{PTR: name})
		},
		func() error {
			return builder.UnknownResource(dnsmessage.ResourceHeader{Name: zone, Type: dnsmessage.Type(65280), Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.UnknownResource{Type: 65280, Data: []byte{1, 2, 3}})
		},
		builder.StartAuthorities,
		func() error {
			return builder.NSResource(header(zone, 172800), dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns1.example.com.")})
		},
		func() error {
			return builder.SOAResource(header(zone, 3600), dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns1.example.com."), MBox: dnsmessage.MustNewName("hostmaster.example.com."), Serial: 7, Refresh: 7200, Retry: 3600, Expire: 1209600, MinTTL: 300})
		},
		builder.StartAdditionals,
		func() error {
			return builder.OPTResource(options, dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 10, Data: []byte("12345678")}, {Code: 12, Data: make([]byte, 3)}}})
		},
	}

	for _, step := range steps {
		if err != nil {
			break
		}

		err = step()
	}

	if err == nil {
		packet, err = builder.Finish()
	}

	if err != nil {
		state.Fatalf("Could not build the message, error: %s", err.Error())
	}

	return
}

// the name as dnsmessage writes it: with the final dot, the root is a dot
func oracleName(name string) (text string) {
	text = name + "."

	if name == "<Root>" {
		text = "."
	}

	return
}

// what is different between the tree of one message and dnsmessage's reading of it
func crossCheck(packet []byte, result v1.Decode) (problems []string) {
	message := dnsmessage.Message{}
	err := message.Unpack(packet)

	if err != nil {
		problems = append(problems, "dnsmessage: "+err.Error())
		return
	}

	expect := func(name string, index int, expected string) {
		found := findAll(result.Tree, name)

		if index >= len(found) {
			problems = append(problems, fmt.Sprintf("no %s #%d", name, index))
			return
		}

		if found[index].Value != expected {
			problems = append(problems, fmt.Sprintf("%s #%d is %q, dnsmessage reads %q", name, index, found[index].Value, expected))
		}
	}
	number := func(value uint16) (text string) {
		text = "(" + strconv.Itoa(int(value)) + ")"
		return
	}
	expect("dns.id", 0, fmt.Sprintf("0x%04x", message.ID))
	expect("dns.flags.response", 0, map[bool]string{false: "Message is a query", true: "Message is a response"}[message.Response])
	expect("dns.flags.recdesired", 0, yesNo(message.RecursionDesired))
	expect("dns.count.queries", 0, strconv.Itoa(len(message.Questions)))
	expect("dns.count.answers", 0, strconv.Itoa(len(message.Answers)))
	expect("dns.count.auth_rr", 0, strconv.Itoa(len(message.Authorities)))
	expect("dns.count.add_rr", 0, strconv.Itoa(len(message.Additionals)))

	if message.Response {
		expect("dns.flags.rcode", 0, nameOf(dnsRcodes, uint16(message.RCode)))
	}

	for index, question := range message.Questions {
		names := findAll(result.Tree, "dns.qry.name")

		if (index < len(names)) && (oracleName(names[index].Value) != question.Name.String()) {
			problems = append(problems, fmt.Sprintf("question %d is %q, dnsmessage reads %q", index, names[index].Value, question.Name.String()))
		}

		if types := findAll(result.Tree, "dns.qry.type"); (index >= len(types)) || !strings.HasSuffix(types[index].Value, number(uint16(question.Type))) {
			problems = append(problems, fmt.Sprintf("question %d should have type %d", index, question.Type))
		}
	}

	records := slices.Concat(message.Answers, message.Authorities, message.Additionals)
	nodes := findAll(result.Tree, "dns.rr")

	if len(nodes) != len(records) {
		problems = append(problems, fmt.Sprintf("%d records, dnsmessage reads %d", len(nodes), len(records)))
		return
	}

	for index, record := range records {
		tree := nodes[index].Children
		field := func(name string) (value string) {
			if found := findNode(tree, name); found != nil {
				value = found.Value
			}

			return
		}

		if oracleName(field("dns.rr.name")) != record.Header.Name.String() || !strings.HasSuffix(field("dns.rr.type"), number(uint16(record.Header.Type))) {
			problems = append(problems, fmt.Sprintf("record %d is %s %s, dnsmessage reads %s %d", index, field("dns.rr.name"), field("dns.rr.type"), record.Header.Name.String(), record.Header.Type))
			continue
		}

		if (record.Header.Type != dnsmessage.TypeOPT) && (!strings.HasSuffix(field("dns.rr.class"), number(uint16(record.Header.Class))) || !strings.HasPrefix(field("dns.rr.ttl"), strconv.FormatUint(uint64(record.Header.TTL), 10))) {
			problems = append(problems, fmt.Sprintf("record %d has class %s and ttl %s, dnsmessage reads %d and %d", index, field("dns.rr.class"), field("dns.rr.ttl"), record.Header.Class, record.Header.TTL))
		}

		expected := map[string]string{}

		switch body := record.Body.(type) {
		case *dnsmessage.AResource:
			expected["dns.a"] = netip.AddrFrom4(body.A).String()
		case *dnsmessage.AAAAResource:
			expected["dns.aaaa"] = netip.AddrFrom16(body.AAAA).String()
		case *dnsmessage.CNAMEResource:
			expected["dns.cname"] = body.CNAME.String()
		case *dnsmessage.NSResource:
			expected["dns.ns"] = body.NS.String()
		case *dnsmessage.PTRResource:
			expected["dns.ptr"] = body.PTR.String()
		case *dnsmessage.MXResource:
			expected["dns.mx.preference"], expected["dns.mx.exchange"] = strconv.Itoa(int(body.Pref)), body.MX.String()
		case *dnsmessage.TXTResource:
			texts := []string{}

			for _, text := range findAll(tree, "dns.txt") {
				texts = append(texts, text.Value)
			}

			if !slices.Equal(texts, body.TXT) {
				problems = append(problems, fmt.Sprintf("record %d has texts %q, dnsmessage reads %q", index, texts, body.TXT))
			}
		case *dnsmessage.SRVResource:
			expected["dns.srv.priority"], expected["dns.srv.weight"], expected["dns.srv.port"], expected["dns.srv.target"] = strconv.Itoa(int(body.Priority)), strconv.Itoa(int(body.Weight)), strconv.Itoa(int(body.Port)), body.Target.String()
		case *dnsmessage.SOAResource:
			expected["dns.soa.mname"], expected["dns.soa.rname"], expected["dns.soa.serial"] = body.NS.String(), body.MBox.String(), strconv.FormatUint(uint64(body.Serial), 10)
		case *dnsmessage.HTTPSResource:
			expected["dns.svcb.priority"], expected["dns.svcb.target"] = strconv.Itoa(int(body.Priority)), body.Target.String()
			keys := []string{}

			for _, param := range findAll(tree, "dns.svcb.param.key") {
				keys = append(keys, param.Value)
			}

			oracle := []string{}

			for _, param := range body.Params {
				oracle = append(oracle, nameOf(svcbKeys, uint16(param.Key)))
			}

			if !slices.Equal(keys, oracle) {
				problems = append(problems, fmt.Sprintf("record %d has params %q, dnsmessage reads %q", index, keys, oracle))
			}
		case *dnsmessage.OPTResource:
			codes := []string{}

			for _, option := range findAll(tree, "dns.opt.code") {
				codes = append(codes, option.Value)
			}

			oracle := []string{}

			for _, option := range body.Options {
				oracle = append(oracle, nameOf(ednsOptions, option.Code))
			}

			expected["dns.rr.udp_payload_size"] = strconv.Itoa(int(record.Header.Class))

			if !slices.Equal(codes, oracle) {
				problems = append(problems, fmt.Sprintf("record %d has options %q, dnsmessage reads %q", index, codes, oracle))
			}
		case *dnsmessage.UnknownResource:
			expected["dns.rr.rdata"] = fmt.Sprintf("%x", body.Data)
		}

		for name, value := range expected {
			got := field(name)

			if strings.HasSuffix(value, ".") && (name != "dns.rr.rdata") {
				got = oracleName(got)
			}

			if got != value {
				problems = append(problems, fmt.Sprintf("record %d %s is %q, dnsmessage reads %q", index, name, got, value))
			}
		}
	}

	return
}

// Test if decode.Decode returns with the expected output against golang.org/x/net/dns/dnsmessage: the header, the questions and every record field of a message
// it builds with compression, and of the handcrafted records it reads too.
func TestDNSMessagePositive(state *testing.T) {
	packets := [][]byte{
		builtMessage(state),
		answerPacket(1, []byte{192, 0, 2, 1}),
		answerPacket(15, join(be16(10), wireName("mail.example.com"))),
		answerPacket(16, join(characters("v=spf1 -all"), characters("a b"))),
		answerPacket(6, join(wireName("ns1.example.com"), wireName("hostmaster.example.com"), be32(1), be32(2), be32(3), be32(4), be32(5))),
		answerPacket(33, join(be16(0), be16(5), be16(443), wireName("server.example.com"))),
		answerPacket(65280, []byte{1, 2, 3}),
		dnsPacket(0xbeef, 0x0100, [4]uint16{1, 0, 0, 0}, question(wireName("example.com"), 28, 1)),
	}

	for index, packet := range packets {
		result := mustDecode(state, packet, udpContext, "")

		if problems := append(errorsOf(result.Tree), crossCheck(packet, result)...); (result.Protocol != dnsProtocol) || (len(problems) > 0) {
			state.Errorf("Test of the dnsmessage cross-check failed, packet %d should read the same, problems: %v", index, problems)
		}
	}
}
