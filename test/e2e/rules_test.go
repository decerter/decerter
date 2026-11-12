// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bytes"
	"context"

	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

var (
	http1OldGet = []byte("GET / ")
	http1NewGet = []byte("GET /test ")
)

// eproxy's HTTP/1.1 rewrite from socket.InspectPacket: every GET / the client sends becomes GET /test
type getRule struct{}

func (rule getRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = (message.Direction == tlsrecord.ClientDirection) && (message.Layer != intercept.UDPLayer)
	return
}

func (rule getRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	plain = bytes.ReplaceAll(message.Plain, http1OldGet, http1NewGet)
	verdict = intercept.ForwardVerdict
	return
}
