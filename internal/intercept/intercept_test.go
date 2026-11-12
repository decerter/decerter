// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package intercept_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

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
		pipeline := intercept.New(rules, output)
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
