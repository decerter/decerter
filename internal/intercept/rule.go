// SPDX-License-Identifier: AGPL-3.0-only

package intercept

import (
	"context"
	"fmt"
)

// what happens to a message after a rule
type Verdict string

const (
	// the message goes on with the plain the rule returned, any length; empty plain is an empty TLS record, nothing on tcp, an empty datagram on udp
	ForwardVerdict Verdict = "forward"
	// the message does not go on: a TLS record is left out and the later records of its direction take its sequence number, the tcp bytes are not sent, the datagram is not sent
	DropVerdict Verdict = "drop"
)

// a rule sees each message it matches, rules run in their order and each sees what the rules before made of the message
// Apply returns the plain that goes on and the verdict; it must not change message.Plain in place, the proxy compares against it
// a TLS rule sees application data only, handshake messages and alerts never reach it; Apply may block until ctx is done, which holds the direction of the flow
type Rule interface {
	Match(message Message) (isMatch bool)
	Apply(ctx context.Context, message Message) (plain []byte, verdict Verdict, err error)
}

// a rule that knows before a message comes whether it takes messages of a layer at all, so the HTTP layer only waits for whole messages when a rule may want them
type LayerRule interface {
	Takes(layer Layer) (isTaken bool)
}

// a layer a rule or the hold queue asks for and the layer of a message: empty is every record layer (tcp, tls, udp, dtls), http is only taken when it is named
func takesLayer(wanted Layer, layer Layer) (isTaken bool) {
	if wanted == "" {
		isTaken = layer != HTTPLayer
		return
	}

	isTaken = wanted == layer
	return
}

// matches every message and changes nothing, the --intercept flag runs it: every TLS record is still decrypted and sealed again
type IdentityRule struct{}

func (identityRule IdentityRule) Match(message Message) (isMatch bool) {
	isMatch = true
	return
}

func (identityRule IdentityRule) Apply(ctx context.Context, message Message) (plain []byte, verdict Verdict, err error) {
	plain = message.Plain
	verdict = ForwardVerdict
	return
}

func checkVerdict(verdict Verdict) (err error) {
	switch verdict {
	case
		ForwardVerdict,
		DropVerdict:
	default:
		err = fmt.Errorf("%w: %q", ErrVerdict, verdict)
	}

	return
}
