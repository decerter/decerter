// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package intercept_test

import (
	"bytes"
	"errors"
	"net/netip"
	"syscall"
	"testing"

	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// a TLS flow of curl to example.com whose ClientHello the proxy did not read, its session is known
func tlsTestFlow() (flow intercept.Flow) {
	values := filter.Values{PID: 42, UID: 1001, GID: 1001, Comm: "curl", IPProtocol: syscall.IPPROTO_TCP, Source: netip.MustParseAddrPort("127.0.0.1:40000"), Destination: netip.MustParseAddrPort("93.184.216.34:443"), TLS: filter.UnknownTLSState}
	flow = intercept.Flow{
		ID:          1,
		Cookie:      7,
		IPProtocol:  syscall.IPPROTO_TCP,
		Client:      values.Source,
		Destination: values.Destination,
		Tgid:        42,
		UID:         1001,
		Comm:        "curl",
		Session:     tlsrecord.Session{ServerName: "example.com", Version: tlsrecord.VersionTLS13, CipherSuite: 0x1301},
		Values:      values,
	}
	return
}

// Test if intercept.MatchRule returns with the expected output: bytes and regex, directions, layers and filters.
func TestMatchRulePositive(state *testing.T) {
	flow := tlsTestFlow()
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	positiveCases := []struct {
		Spec      intercept.MatchSpec
		Direction tlsrecord.Direction
		Layer     intercept.Layer
		Plain     []byte
		IsMatch   bool
		Expected  []byte
	}{
		{Spec: intercept.MatchSpec{Find: "GET / ", Replace: "GET /test "}, Direction: tlsrecord.ClientDirection, Layer: intercept.TLSLayer, Plain: request, IsMatch: true, Expected: []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		// every occurrence, hex on both sides
		{Spec: intercept.MatchSpec{FindType: intercept.HexValueType, Find: "61 62", ReplaceType: intercept.HexValueType, Replace: "00ff"}, Direction: tlsrecord.ServerDirection, Layer: intercept.UDPLayer, Plain: []byte("abcab"), IsMatch: true, Expected: []byte("\x00\xffc\x00\xff")},
		// a regex with a group in the template
		{Spec: intercept.MatchSpec{Directions: intercept.UpDirections, FindType: intercept.RegexValueType, Find: `GET /(\S*) `, Replace: "GET /x/$1 "}, Direction: tlsrecord.ClientDirection, Layer: intercept.TCPLayer, Plain: []byte("GET /a HTTP/1.1\r\n"), IsMatch: true, Expected: []byte("GET /x/a HTTP/1.1\r\n")},
		{Spec: intercept.MatchSpec{FindType: intercept.RegexValueType, Find: `(?i)host: (\S+)`, Replace: "Host: ${1}.test"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TLSLayer, Plain: request, IsMatch: true, Expected: []byte("GET / HTTP/1.1\r\nHost: example.com.test\r\n\r\n")},
		// a pattern that matches the empty string only at some places replaces only its matches that are not empty
		{Spec: intercept.MatchSpec{FindType: intercept.RegexValueType, Find: `\b`, Replace: "|"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TCPLayer, Plain: []byte("foo bar"), IsMatch: true, Expected: []byte("foo bar")},
		{Spec: intercept.MatchSpec{FindType: intercept.RegexValueType, Find: `x*\b`, Replace: "X"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TCPLayer, Plain: []byte("xx yy x"), IsMatch: true, Expected: []byte("X yy X")},
		{Spec: intercept.MatchSpec{FindType: intercept.RegexValueType, Find: `\b(?:foo)?`, Replace: "[$0]"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TCPLayer, Plain: []byte("foo bar foo"), IsMatch: true, Expected: []byte("[foo] bar [foo]")},
		// nothing found: the message goes on as it is
		{Spec: intercept.MatchSpec{Find: "POST", Replace: "PUT"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TLSLayer, Plain: request, IsMatch: true, Expected: request},
		// the direction, the layer and the filter decide the match, the session gives the TLS fields
		{Spec: intercept.MatchSpec{Directions: intercept.DownDirections, Find: "GET", Replace: "PUT"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TLSLayer, Plain: request, IsMatch: false, Expected: nil},
		{Spec: intercept.MatchSpec{Layer: intercept.TCPLayer, Find: "GET", Replace: "PUT"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TLSLayer, Plain: request, IsMatch: false, Expected: nil},
		{Spec: intercept.MatchSpec{Filter: `tls.sni == "example.com" && proc.comm == "curl"`, Find: "GET", Replace: "PUT"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TLSLayer, Plain: request, IsMatch: true, Expected: []byte("PUT / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{Spec: intercept.MatchSpec{Filter: `tls.sni == "other.example"`, Find: "GET", Replace: "PUT"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TLSLayer, Plain: request, IsMatch: false, Expected: nil},
		// a plain tcp message is no TLS, a filter on tls does not wait for a ClientHello
		{Spec: intercept.MatchSpec{Filter: "!tls", Find: "GET", Replace: "PUT"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TCPLayer, Plain: request, IsMatch: true, Expected: []byte("PUT / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{Spec: intercept.MatchSpec{Filter: "tls", Find: "GET", Replace: "PUT"}, Direction: tlsrecord.ClientDirection, Layer: intercept.TCPLayer, Plain: request, IsMatch: false, Expected: nil},
	}

	for _, positive := range positiveCases {
		rule, err := intercept.NewMatchRule(positive.Spec)

		if err != nil {
			state.Errorf("Test of intercept.NewMatchRule function failed, spec %+v, error: %s", positive.Spec, err.Error())
			return
		}

		original := bytes.Clone(positive.Plain)
		message := intercept.Message{Flow: flow, ID: 1, Direction: positive.Direction, Layer: positive.Layer, Plain: positive.Plain}
		isMatch := rule.Match(message)

		if isMatch != positive.IsMatch {
			state.Errorf("Test of intercept.MatchRule.Match function failed, spec %+v, match should be %v, match: %v", positive.Spec, positive.IsMatch, isMatch)
			return
		}

		if !isMatch {
			continue
		}

		plain, verdict, err := rule.Apply(state.Context(), message)
		hits := uint64(0)

		if !bytes.Equal(positive.Expected, original) {
			hits = 1
		}

		if (err != nil) || (verdict != intercept.ForwardVerdict) || !bytes.Equal(plain, positive.Expected) || !bytes.Equal(message.Plain, original) || (rule.Hits() != hits) {
			state.Errorf("Test of intercept.MatchRule.Apply function failed, spec %+v, plain should be %q with %d hits and the message unchanged, plain: %q, hits: %d, message: %q, verdict: %s, error: %v", positive.Spec, positive.Expected, hits, plain, rule.Hits(), message.Plain, verdict, err)
			return
		}
	}
}

// Test if intercept.NewMatchRule returns with the expected errors.
func TestMatchRuleNegative(state *testing.T) {
	negativeCases := []struct {
		Spec intercept.MatchSpec
		Err  error
	}{
		{Spec: intercept.MatchSpec{Directions: "sideways", Find: "a"}, Err: intercept.ErrDirections},
		{Spec: intercept.MatchSpec{Layer: "quic", Find: "a"}, Err: intercept.ErrLayer},
		{Spec: intercept.MatchSpec{Find: ""}, Err: intercept.ErrFind},
		{Spec: intercept.MatchSpec{FindType: intercept.HexValueType, Find: "6"}, Err: intercept.ErrFind},
		{Spec: intercept.MatchSpec{FindType: "base64", Find: "YQ=="}, Err: intercept.ErrFind},
		{Spec: intercept.MatchSpec{FindType: intercept.RegexValueType, Find: "a*"}, Err: intercept.ErrFind},
		{Spec: intercept.MatchSpec{FindType: intercept.RegexValueType, Find: "(a"}, Err: intercept.ErrFind},
		{Spec: intercept.MatchSpec{Find: "a", ReplaceType: intercept.RegexValueType, Replace: "b"}, Err: intercept.ErrReplace},
		{Spec: intercept.MatchSpec{Find: "a", ReplaceType: intercept.HexValueType, Replace: "zz"}, Err: intercept.ErrReplace},
		{Spec: intercept.MatchSpec{Filter: "tcp.port ==", Find: "a"}, Err: filter.ErrSyntax},
	}

	for _, negative := range negativeCases {
		_, err := intercept.NewMatchRule(negative.Spec)

		if !errors.Is(err, negative.Err) {
			state.Errorf("Test of intercept.NewMatchRule function failed, spec %+v, error should be %v, error: %v", negative.Spec, negative.Err, err)
			return
		}
	}
}

// Test if intercept.RuleSet returns with the expected output: rules run in their order on what the ones before made, ids are not given twice, a deleted rule is gone.
func TestRuleSetPositive(state *testing.T) {
	ruleSet := intercept.NewRuleSet()
	first, err := intercept.NewMatchRule(intercept.MatchSpec{Find: "a", Replace: "b"})

	if err != nil {
		state.Fatalf("Test of intercept.RuleSet failed, cannot make a rule, error: %s", err.Error())
	}

	second, err := intercept.NewMatchRule(intercept.MatchSpec{Find: "b", Replace: "c"})

	if err != nil {
		state.Fatalf("Test of intercept.RuleSet failed, cannot make a rule, error: %s", err.Error())
	}

	ruleSet.Add(first)
	ruleSet.Add(second)
	message := intercept.Message{Flow: tlsTestFlow(), ID: 1, Direction: tlsrecord.ClientDirection, Layer: intercept.TCPLayer, Plain: []byte("ab")}
	plain, verdict, err := ruleSet.Apply(state.Context(), message)

	if (err != nil) || (verdict != intercept.ForwardVerdict) || (string(plain) != "cc") || !ruleSet.Match(message) || (first.ID != 1) || (second.ID != 2) {
		state.Errorf("Test of intercept.RuleSet.Apply function failed, plain should be %q, plain: %q, ids: %d %d, error: %v", "cc", plain, first.ID, second.ID, err)
		return
	}

	deleted, found := ruleSet.Delete(1)
	_, foundAgain := ruleSet.Delete(1)
	third, err := intercept.NewMatchRule(intercept.MatchSpec{Find: "x", Replace: "y"})

	if err != nil {
		state.Fatalf("Test of intercept.RuleSet failed, cannot make a rule, error: %s", err.Error())
	}

	ruleSet.Add(third)
	plain, _, err = ruleSet.Apply(state.Context(), message)
	rules := ruleSet.List()

	if !found || foundAgain || (deleted != first) || (err != nil) || (string(plain) != "ac") || (len(rules) != 2) || (rules[0] != second) || (third.ID != 3) {
		state.Errorf("Test of intercept.RuleSet.Delete function failed, plain should be %q with rules 2 and 3, plain: %q, rules: %d, third id: %d, error: %v", "ac", plain, len(rules), third.ID, err)
		return
	}
}

// Test if intercept.FilterValues returns with the expected output: a TLS message is TLS with the fields of its session, another one is not.
func TestFilterValuesPositive(state *testing.T) {
	flow := tlsTestFlow()
	tlsValues := intercept.FilterValues(intercept.Message{Flow: flow, Layer: intercept.TLSLayer})
	tcpValues := intercept.FilterValues(intercept.Message{Flow: flow, Layer: intercept.TCPLayer})

	if (tlsValues.TLS != filter.PresentTLSState) || (tlsValues.ServerName != "example.com") || (tlsValues.TLSVersion != tlsrecord.VersionTLS13) || (tcpValues.TLS != filter.AbsentTLSState) || (tcpValues.ServerName != "") {
		state.Errorf("Test of intercept.FilterValues function failed, values tls: %+v, tcp: %+v", tlsValues, tcpValues)
		return
	}

	// a ClientHello the proxy read stays as it was
	flow.Values = flow.Values.WithClientHello(true, tlsrecord.VersionTLS13, "hello.example", nil)
	readValues := intercept.FilterValues(intercept.Message{Flow: flow, Layer: intercept.TLSLayer})

	if readValues.ServerName != "hello.example" {
		state.Errorf("Test of intercept.FilterValues function failed, server name should be %q, values: %+v", "hello.example", readValues)
		return
	}
}
