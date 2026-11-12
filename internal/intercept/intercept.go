// SPDX-License-Identifier: AGPL-3.0-only

package intercept

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// what one message of a flow is
type Layer string

const (
	// the application data of one decrypted TLS record, an HTTP request or an HTTP/2 frame can span records
	TLSLayer Layer = "tls"
	// what one read of a plain tcp stream gave, the boundaries are the ones of the socket and mean nothing to the protocol
	TCPLayer Layer = "tcp"
	// one udp datagram
	UDPLayer Layer = "udp"
)

// the intercepted connection a message belongs to: the redirected socket of the app and the original destination
// Session is the TLS session of a TLSLayer flow, Version and CipherSuite are zero for any other
type Flow struct {
	Cookie      uint64
	IPProtocol  uint8
	Client      netip.AddrPort
	Destination netip.AddrPort
	Tgid        uint32
	UID         uint32
	Comm        string
	Session     tlsrecord.Session
}

// one piece of a flow on its way through the proxy, Plain is what the peer sent, decrypted for TLS
// ID counts the messages of the flow in both directions in the order the proxy took them, so a held message can be named (stage 23)
// a message goes on in its direction only after every message before it in that direction, a rule that holds one holds the direction
type Message struct {
	Flow      Flow
	ID        uint64
	Direction tlsrecord.Direction
	Layer     Layer
	Plain     []byte
}

// the rules every message of the intercepted flows goes through, in order, and where the messages are printed, nil prints nothing
// counter gives the message ids of the flows, one shared counter is enough for an id that is unique per flow
type Pipeline struct {
	rules   []Rule
	output  io.Writer
	counter *atomic.Uint64
}

// what the pipeline made of a message: Plain goes on when Verdict is ForwardVerdict, Changed is true when it differs from what the peer sent
type Result struct {
	Plain   []byte
	Verdict Verdict
	Changed bool
}

func New(rules []Rule, output io.Writer) (pipeline *Pipeline) {
	pipeline = &Pipeline{
		rules:   rules,
		output:  output,
		counter: &atomic.Uint64{},
	}
	return
}

// the flow of a redirected socket, the TLS session is added once it is known
func FlowOf(cookie uint64, flow redirect.Flow, client netip.AddrPort) (interceptFlow Flow) {
	interceptFlow = Flow{
		Cookie:      cookie,
		IPProtocol:  flow.IPProtocol,
		Client:      client,
		Destination: flow.OriginalDestination,
		Tgid:        flow.Tgid,
		UID:         flow.UID,
		Comm:        flow.Comm,
		Session:     tlsrecord.Session{},
	}
	return
}

// a message of a flow, with the next id
func (pipeline *Pipeline) Message(flow Flow, direction tlsrecord.Direction, layer Layer, plain []byte) (message Message) {
	message = Message{
		Flow:      flow,
		ID:        pipeline.counter.Add(1),
		Direction: direction,
		Layer:     layer,
		Plain:     plain,
	}
	return
}

// run the rules that match, each on what the one before made of the message, and print the result
// a failing rule is logged and skipped, a drop ends the chain; Apply may block (a hold queue), only the direction of the message waits then
func (pipeline *Pipeline) Process(ctx context.Context, message Message, logger *slog.Logger) (result Result) {
	result = Result{
		Plain:   message.Plain,
		Verdict: ForwardVerdict,
		Changed: false,
	}
	current := message

	for _, rule := range pipeline.rules {
		if !rule.Match(current) {
			continue
		}

		plain, verdict, err := rule.Apply(ctx, current)

		if err == nil {
			err = checkVerdict(verdict)
		}

		if err != nil {
			logger.Warn("Could not apply intercept rule", "error", err, "messageID", message.ID, "direction", DirectionName(message.Direction))
			continue
		}

		result.Verdict = verdict

		if verdict == DropVerdict {
			result.Plain = nil
			break
		}

		result.Plain = plain
		current.Plain = plain
	}

	result.Changed = (result.Verdict == DropVerdict) || !bytes.Equal(result.Plain, message.Plain)

	if pipeline.output != nil {
		Print(pipeline.output, message, result, false)
	}

	return
}

// a message that went on before the rules could see it, the secrets of its TLS session came too late: only printed
func (pipeline *Pipeline) Show(message Message) {
	if pipeline.output == nil {
		return
	}

	Print(pipeline.output, message, Result{Plain: message.Plain, Verdict: ForwardVerdict, Changed: false}, true)
}

func DirectionName(direction tlsrecord.Direction) (name string) {
	name = "down"

	if direction == tlsrecord.ClientDirection {
		name = "up"
	}

	return
}
