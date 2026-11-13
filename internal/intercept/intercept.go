// SPDX-License-Identifier: AGPL-3.0-only

package intercept

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
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
	// the application data of one decrypted DTLS record, a datagram can carry several
	DTLSLayer Layer = "dtls"
	// one whole HTTP request or response, assembled from the messages of a tcp or TLS flow after their rules: on HTTP/1 the head as it came and the body without its chunk framing,
	// on HTTP/2 one "name: value" line per field (pseudo-header fields first, CR LF), a blank line and the body of its DATA frames without padding
	HTTPLayer Layer = "http"
)

// the intercepted connection a message belongs to: the redirected socket of the app and the original destination
// Session is the TLS session of a TLSLayer or DTLSLayer flow, Version and CipherSuite are zero for any other
// ID names the flow in the API's history, 0 without one; Values is what the scope filter knew of the flow when it was decided, the filters of API rules and of the hold queue are tested on it
type Flow struct {
	ID          uint64
	Cookie      uint64
	IPProtocol  uint8
	Client      netip.AddrPort
	Destination netip.AddrPort
	Tgid        uint32
	UID         uint32
	Comm        string
	Session     tlsrecord.Session
	Values      filter.Values
}

// one piece of a flow on its way through the proxy, Plain is what the peer sent, decrypted for TLS
// ID counts the messages of the flow in both directions in the order the proxy took them, so a held message can be named (stage 23)
// a message goes on in its direction only after every message before it in that direction, a rule that holds one holds the direction
// Exchange is the exchange of the history an HTTPLayer message belongs to, 0 for any other layer or without a history
type Message struct {
	Flow      Flow
	ID        uint64
	Direction tlsrecord.Direction
	Layer     Layer
	Plain     []byte
	Exchange  uint64
}

// how a message reached the recorder of a pipeline
type Origin string

const (
	// the message went through the rules
	RulesOrigin Origin = "rules"
	// the message went on before the rules could see it, the secrets of its TLS session came too late
	PassedOrigin Origin = "passed"
	// a decrypted copy of what the relay sent on unchanged (--decrypt), no rule saw it
	ObservedOrigin Origin = "observed"
)

// gets every message of a pipeline after the rules, with what they made of it; it must not block and must not keep message.Plain or result.Plain without a copy
type Recorder func(message Message, result Result, origin Origin)

// the rules every message of the intercepted flows goes through, in order, and where the messages are printed, nil prints nothing
// counter gives the message ids of the flows, one shared counter makes an id unique in the process; recorder gets every message after the rules, nil is none
type Pipeline struct {
	rules    []Rule
	output   io.Writer
	recorder Recorder
	counter  *atomic.Uint64
}

// what the pipeline made of a message: Plain goes on when Verdict is ForwardVerdict, Changed is true when it differs from what the peer sent
type Result struct {
	Plain   []byte
	Verdict Verdict
	Changed bool
}

func New(rules []Rule, output io.Writer, recorder Recorder) (pipeline *Pipeline) {
	pipeline = &Pipeline{
		rules:    rules,
		output:   output,
		recorder: recorder,
		counter:  &atomic.Uint64{},
	}
	return
}

// a pipeline for the HTTP layer of the same flows: other rules, nothing printed or recorded, the message ids from the same counter, so a hold id names one message of either pipeline
func (pipeline *Pipeline) Derive(rules []Rule) (derived *Pipeline) {
	derived = &Pipeline{
		rules:    rules,
		output:   nil,
		recorder: nil,
		counter:  pipeline.counter,
	}
	return
}

// whether a rule of the pipeline may take messages of the layer; a rule that can't tell is asked by its Match
func (pipeline *Pipeline) Wants(layer Layer) (isWanted bool) {
	isWanted = slices.ContainsFunc(pipeline.rules, func(rule Rule) bool {
		layerRule, isLayerRule := rule.(LayerRule)
		return !isLayerRule || layerRule.Takes(layer)
	})
	return
}

// whether a rule of the pipeline matches the message, before it runs
func (pipeline *Pipeline) Matches(message Message) (isMatch bool) {
	isMatch = slices.ContainsFunc(pipeline.rules, func(rule Rule) bool {
		return rule.Match(message)
	})
	return
}

// whether a rule of the pipeline may wait in Apply for the message, a hold of the hold queue
func (pipeline *Pipeline) Blocks(message Message) (isBlocking bool) {
	isBlocking = slices.ContainsFunc(pipeline.rules, func(rule Rule) bool {
		blockingRule, isBlockingRule := rule.(BlockingRule)
		return isBlockingRule && blockingRule.Blocks(message)
	})
	return
}

// the flow of a redirected socket, the TLS session is added once it is known; id is the flow of the API's history, 0 without one
func FlowOf(id uint64, cookie uint64, flow redirect.Flow, client netip.AddrPort, values filter.Values) (interceptFlow Flow) {
	interceptFlow = Flow{
		ID:          id,
		Cookie:      cookie,
		IPProtocol:  flow.IPProtocol,
		Client:      client,
		Destination: flow.OriginalDestination,
		Tgid:        flow.Tgid,
		UID:         flow.UID,
		Comm:        flow.Comm,
		Session:     tlsrecord.Session{},
		Values:      values,
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
		Exchange:  0,
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

	if pipeline.recorder != nil {
		pipeline.recorder(message, result, RulesOrigin)
	}

	return
}

// a message that went on before the rules could see it, the secrets of its TLS session came too late: only printed and recorded
func (pipeline *Pipeline) Show(message Message) {
	result := Result{Plain: message.Plain, Verdict: ForwardVerdict, Changed: false}

	if pipeline.output != nil {
		Print(pipeline.output, message, result, true)
	}

	if pipeline.recorder != nil {
		pipeline.recorder(message, result, PassedOrigin)
	}
}

func DirectionName(direction tlsrecord.Direction) (name string) {
	name = "down"

	if direction == tlsrecord.ClientDirection {
		name = "up"
	}

	return
}
