// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"bytes"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	v1 "github.com/decerter/decerter/api"
)

// the seed corpus of FuzzDNS: whole messages, a stream of two, a message cut short, a pointer loop and every record type of the tests
func dnsSeeds(fuzz *testing.F) (seeds [][]byte) {
	query := dnsPacket(0xbeef, 0x0100, [4]uint16{1, 0, 0, 0}, question(wireName("example.com"), 1, 1))
	answer := dnsPacket(0xbeef, 0x8180, [4]uint16{1, 1, 0, 0}, question(wireName("example.com"), 1, 1), resource([]byte{0xc0, 0x0c}, 1, 1, 60, []byte{192, 0, 2, 7}))
	built := builtMessage(fuzz)
	seeds = [][]byte{
		query,
		answer,
		built,
		join(be16(uint16(len(query))), query, be16(uint16(len(answer))), answer),
		join(be16(uint16(len(built))), built[:len(built)/2]),
		dnsPacket(1, 0, [4]uint16{1, 0, 0, 0}, []byte{0xc0, 0x0c}, be16(1), be16(1)),
		dnsPacket(1, 0x8000, [4]uint16{0, 0, 0, 1}, resource(wireName(""), 41, 1232, 0x8000, join(be16(8), be16(7), be16(1), []byte{24, 0, 192, 0, 2}, be16(15), be16(3), be16(18), []byte("x")))),
	}

	for _, rrType := range []uint16{2, 5, 6, 12, 13, 15, 16, 33, 43, 46, 47, 48, 64, 65, 257} {
		seeds = append(seeds, answerPacket(rrType, bytes.Repeat([]byte{1, 0, 3}, 8)))
	}

	return
}

// Fuzz if decode.Decode never fails on any bytes over any transport, with or without as=dns: no error, a tree inside the bytes with printable strings
// only, and the same questions and records as golang.org/x/net/dns/dnsmessage reads when it reads the bytes as a message.
func FuzzDNS(fuzz *testing.F) {
	for _, seed := range dnsSeeds(fuzz) {
		fuzz.Add(seed)
	}

	doh := Context{Transport: BodyTransport, Layer: "", Direction: v1.UpDirection, ServerPort: 443, ALPN: "h2", ContentType: "application/dns-message", Upgrade: "", Method: "POST", Target: "/dns-query", Encoding: "", Extensions: "", Handshake: false, Joined: false}
	contexts := []Context{udpContext, tcpContext, dotContext, mdnsContext, otherUDP, doh}

	fuzz.Fuzz(func(state *testing.T, data []byte) {
		for _, context := range contexts {
			for _, as := range []string{"", dnsProtocol} {
				result, err := Decode(data, context, as)

				if err != nil {
					state.Fatalf("Fuzz of decode.Decode failed, it should take any bytes, error: %s", err.Error())
				}

				if problems := resultProblems(result); len(problems) > 0 {
					state.Fatalf("Fuzz of decode.Decode failed, the tree should fit its bytes, problems: %v", problems)
				}
			}
		}

		target := doh
		target.Method, target.Target = "GET", "/dns-query?dns="+string(data)

		if found, isFound := FromTarget(target, ""); isFound && (len(found) < dnsHeaderBytes) {
			state.Fatalf("Fuzz of decode.FromTarget failed, it should only find whole headers, found: %x", found)
		}

		message, isRead := oracleUnpack(data)

		if !isRead {
			return
		}

		result, _ := Decode(data, otherUDP, dnsProtocol)

		if result.Truncated {
			return
		}

		records := len(message.Answers) + len(message.Authorities) + len(message.Additionals)

		if (len(findAll(result.Tree, "dns.qry")) != len(message.Questions)) || (len(findAll(result.Tree, "dns.rr")) != records) {
			state.Fatalf("Fuzz of decode.Decode failed, dnsmessage reads %d questions and %d records, tree: %+v", len(message.Questions), records, result.Tree)
		}
	})
}

// dnsmessage's reading of data; x/net v0.62 checks the SVCB rdata against the message (v0.53 panicked on it, so the oracle recovered then)
func oracleUnpack(data []byte) (message dnsmessage.Message, isRead bool) {
	isRead = message.Unpack(data) == nil
	return
}
