// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package intercept_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// replaces old with new in every message that contains old
type replaceRule struct {
	old []byte
	new []byte
}

// drops every message that contains a marker
type dropRule struct {
	marker []byte
}

// returns a verdict the pipeline does not know
type badRule struct{}

func (rule replaceRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = bytes.Contains(message.Plain, rule.old)
	return
}

func (rule replaceRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	plain = bytes.ReplaceAll(message.Plain, rule.old, rule.new)
	verdict = intercept.ForwardVerdict
	return
}

func (rule dropRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = bytes.Contains(message.Plain, rule.marker)
	return
}

func (rule dropRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	verdict = intercept.DropVerdict
	return
}

func (rule badRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = true
	return
}

func (rule badRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	plain = []byte("never")
	verdict = "hold"
	return
}

// Test if intercept.Process returns with the expected output.
func TestProcessPositive(state *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rules := []intercept.Rule{intercept.IdentityRule{}, badRule{}, replaceRule{old: []byte("GET / "), new: []byte("GET /test ")}, dropRule{marker: []byte("secret")}}
	positiveCases := []struct {
		Input   string
		Plain   string
		Verdict intercept.Verdict
		Changed bool
	}{
		{Input: "GET / HTTP/1.1\r\n\r\n", Plain: "GET /test HTTP/1.1\r\n\r\n", Verdict: intercept.ForwardVerdict, Changed: true},
		{Input: "GET /index HTTP/1.1\r\n\r\n", Plain: "GET /index HTTP/1.1\r\n\r\n", Verdict: intercept.ForwardVerdict, Changed: false},
		{Input: "GET / secret\r\n", Plain: "", Verdict: intercept.DropVerdict, Changed: true},
	}

	for _, positive := range positiveCases {
		output := &bytes.Buffer{}
		pipeline := intercept.New(rules, output, nil)
		message := pipeline.Message(intercept.Flow{Comm: "curl"}, tlsrecord.ClientDirection, intercept.TCPLayer, []byte(positive.Input))
		result := pipeline.Process(context.Background(), message, logger)

		if (string(result.Plain) != positive.Plain) || (result.Verdict != positive.Verdict) || (result.Changed != positive.Changed) {
			state.Errorf("Test of intercept.Process function failed, input: %q, result should be %q %s %v, result: %q %s %v", positive.Input, positive.Plain, positive.Verdict, positive.Changed, result.Plain, result.Verdict, result.Changed)
			return
		}

		// the header line, the escaped text and the hex dump, nothing of the payload unescaped
		lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")

		if (len(lines) < 3) || !strings.HasPrefix(lines[0], "tcp pid=0 uid=0 comm=curl") || strings.ContainsAny(output.String(), "\r") || !strings.HasPrefix(lines[len(lines)-1], "    000000") {
			state.Errorf("Test of intercept.Print function failed, input: %q, output: %q", positive.Input, output.String())
			return
		}
	}
}

// Test if intercept.HexDump returns with the expected output.
func TestHexDumpPositive(state *testing.T) {
	positiveCases := []struct {
		Input  []byte
		Output string
	}{
		{Input: nil, Output: ""},
		{Input: []byte("GET /\x1b[2J"), Output: "    00000000  47 45 54 20 2f 1b 5b 32  4a                       |GET /.[2J|\n"},
		{Input: []byte("0123456789abcdefg"), Output: "    00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n    00000010  67                                                |g|\n"},
	}

	for _, positive := range positiveCases {
		output := intercept.HexDump(positive.Input)

		if output != positive.Output {
			state.Errorf("Test of intercept.HexDump function failed, input: %q, result should be %q, result: %q", positive.Input, positive.Output, output)
			return
		}
	}
}

// fails on every message
type failingRule struct{}

func (rule failingRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = true
	return
}

func (rule failingRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	err = errors.New("rule failed")
	return
}

// Test if intercept.Process returns with the expected errors: a failing rule and a rule with an unknown verdict are logged and skipped.
func TestProcessNegative(state *testing.T) {
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	rules := []intercept.Rule{failingRule{}, badRule{}, replaceRule{old: []byte("a"), new: []byte("b")}, dropRule{marker: []byte("b")}, replaceRule{old: []byte("b"), new: []byte("c")}}
	pipeline := intercept.New(rules, nil, nil)
	message := pipeline.Message(intercept.Flow{}, tlsrecord.ServerDirection, intercept.UDPLayer, []byte("a"))
	result := pipeline.Process(state.Context(), message, logger)

	// the drop ends the chain, the last rule never runs
	if (result.Plain != nil) || (result.Verdict != intercept.DropVerdict) || !result.Changed {
		state.Errorf("Test of intercept.Process function failed, result should be dropped, result: %q %s %v", result.Plain, result.Verdict, result.Changed)
		return
	}

	warnings := strings.Count(logs.String(), "Could not apply intercept rule")

	if (warnings != 2) || !strings.Contains(logs.String(), "rule failed") || !strings.Contains(logs.String(), intercept.ErrVerdict.Error()) || !strings.Contains(logs.String(), "direction=down") {
		state.Errorf("Test of intercept.Process function failed, logs should have two warnings, logs: %q", logs.String())
		return
	}
}

// Test if intercept.Print returns with the expected output.
func TestPrintPositive(state *testing.T) {
	flow := intercept.Flow{
		Cookie:      7,
		IPProtocol:  6,
		Client:      netip.MustParseAddrPort("127.0.0.1:40000"),
		Destination: netip.MustParseAddrPort("93.184.216.34:443"),
		Tgid:        4242,
		UID:         1001,
		Comm:        "curl",
		Session:     tlsrecord.Session{Version: tlsrecord.VersionTLS13, CipherSuite: 0x1301},
	}
	long := bytes.Repeat([]byte{'x'}, intercept.MaxPrintBytes+10)
	positiveCases := []struct {
		Layer    intercept.Layer
		Plain    []byte
		Result   intercept.Result
		IsPassed bool
		Header   string
		Lines    int
	}{
		{Layer: intercept.TLSLayer, Plain: []byte("GET / HTTP/1.1\r\n"), Result: intercept.Result{Plain: []byte("GET /test HTTP/1.1\r\n"), Verdict: intercept.ForwardVerdict, Changed: true}, IsPassed: false, Header: "tls pid=4242 uid=1001 comm=curl 93.184.216.34:443 client=127.0.0.1:40000 version=TLS1.3 suite=TLS_AES_128_GCM_SHA256 direction=up id=1 length=20 shown=20 original=16", Lines: 2},
		// a drop shows what was dropped
		{Layer: intercept.TLSLayer, Plain: []byte("secret"), Result: intercept.Result{Plain: nil, Verdict: intercept.DropVerdict, Changed: true}, IsPassed: false, Header: "tls pid=4242 uid=1001 comm=curl 93.184.216.34:443 client=127.0.0.1:40000 version=TLS1.3 suite=TLS_AES_128_GCM_SHA256 direction=up id=1 length=6 shown=6 verdict=drop", Lines: 1},
		{Layer: intercept.TCPLayer, Plain: long, Result: intercept.Result{Plain: long, Verdict: intercept.ForwardVerdict, Changed: false}, IsPassed: true, Header: "tcp pid=4242 uid=1001 comm=curl 93.184.216.34:443 client=127.0.0.1:40000 direction=up id=1 length=2058 shown=2048 passed", Lines: 128},
	}

	for _, positive := range positiveCases {
		output := &bytes.Buffer{}
		message := intercept.Message{Flow: flow, ID: 1, Direction: tlsrecord.ClientDirection, Layer: positive.Layer, Plain: positive.Plain}
		intercept.Print(output, message, positive.Result, positive.IsPassed)
		header, _, _ := strings.Cut(output.String(), "\n")
		dumpLines := strings.Count(output.String(), "  |")

		if (header != positive.Header) || (dumpLines != positive.Lines) {
			state.Errorf("Test of intercept.Print function failed, header should be %q, header: %q, hex dump lines: %d", positive.Header, header, dumpLines)
			return
		}
	}

	// a pipeline without output prints nothing, Show marks the message as passed
	output := &bytes.Buffer{}
	intercept.New(nil, nil, nil).Show(intercept.Message{Flow: flow, Layer: intercept.UDPLayer, Plain: []byte("x")})
	intercept.New(nil, output, nil).Show(intercept.Message{Flow: flow, Direction: tlsrecord.ServerDirection, Layer: intercept.DTLSLayer, Plain: []byte("x")})

	if !strings.HasPrefix(output.String(), "dtls pid=4242") || !strings.Contains(output.String(), "direction=down id=0 length=1 shown=1 passed\n") {
		state.Errorf("Test of intercept.Show function failed, output: %q", output.String())
		return
	}
}

// Test if intercept.Escape returns with the expected output.
func TestEscapePositive(state *testing.T) {
	positiveCases := []struct {
		Input  []byte
		Output string
	}{
		{Input: nil, Output: ""},
		{Input: []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), Output: "    GET / HTTP/1.1\\r\\n\n    Host: a\\r\\n\n    \\r\\n\n"},
		// no escape sequence of a peer reaches the terminal, a backslash is doubled so \x1b in the payload can't be mistaken
		{Input: []byte("\x1b[2J\t\\x1b\x00\xff~"), Output: "    \\x1b[2J\\t\\\\x1b\\x00\\xff~\n"},
		{Input: []byte("a\nb"), Output: "    a\\n\n    b\n"},
	}

	for _, positive := range positiveCases {
		output := intercept.Escape(positive.Input)

		if output != positive.Output {
			state.Errorf("Test of intercept.Escape function failed, input: %q, result should be %q, result: %q", positive.Input, positive.Output, output)
			return
		}
	}
}

// Test if intercept.LinePrefix returns with the expected output: a comm a process set to a terminal escape sequence or a line break reaches the line only escaped.
func TestLinePrefixEscapePositive(state *testing.T) {
	flow := intercept.Flow{ID: 1, Cookie: 1, IPProtocol: 6, Client: netip.MustParseAddrPort("127.0.0.1:5000"), Destination: netip.MustParseAddrPort("127.0.0.1:443"), Tgid: 10, UID: 1001, Comm: "\x1b[31mx\n", Session: tlsrecord.Session{}, Values: filter.Values{}}
	prefix := intercept.LinePrefix(flow, intercept.TCPLayer)

	if prefix != "tcp pid=10 uid=1001 comm=\\x1b[31mx\\x0a 127.0.0.1:443 client=127.0.0.1:5000" {
		state.Errorf("Test of intercept.LinePrefix function failed, the comm should be escaped, prefix: %q", prefix)
		return
	}
}

// Test if intercept.FlowOf and intercept.Pipeline.Message return with the expected output.
func TestFlowOfPositive(state *testing.T) {
	flow := redirect.Flow{
		OriginalDestination: netip.MustParseAddrPort("[2001:db8::1]:443"),
		IPProtocol:          17,
		Redirected:          true,
		Tgid:                10,
		UID:                 10092,
		GID:                 10092,
		CgroupID:            99,
		Comm:                "app",
		Mark:                0x10064,
		Client:              netip.AddrPort{},
	}
	client := netip.MustParseAddrPort("[::1]:5000")
	values := filter.Values{PID: 10, UID: 10092, GID: 10092, Comm: "app", TLS: filter.AbsentTLSState}
	expected := intercept.Flow{ID: 5, Cookie: 3, IPProtocol: 17, Client: client, Destination: flow.OriginalDestination, Tgid: 10, UID: 10092, Comm: "app", Session: tlsrecord.Session{}, Values: values}
	interceptFlow := intercept.FlowOf(5, 3, flow, client, values)

	if !reflect.DeepEqual(interceptFlow, expected) {
		state.Errorf("Test of intercept.FlowOf function failed, flow should be %+v, flow: %+v", expected, interceptFlow)
		return
	}

	// one counter for every flow of the pipeline, ids start at 1
	pipeline := intercept.New(nil, nil, nil)

	for expectedID := range uint64(3) {
		message := pipeline.Message(interceptFlow, tlsrecord.ClientDirection, intercept.UDPLayer, nil)

		if message.ID != expectedID+1 {
			state.Errorf("Test of intercept.Pipeline.Message function failed, id should be %d, id: %d", expectedID+1, message.ID)
			return
		}
	}
}
