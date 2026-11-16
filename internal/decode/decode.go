// SPDX-License-Identifier: AGPL-3.0-only

// the decoders of payloads into trees of fields with their byte ranges, like Wireshark's packet details: written from the RFCs, run only on request
// a protocol is one file that adds its decoder to the registry in init: its ports, a hint from the context, a sniff score and the decode itself
package decode

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	v1 "github.com/decerter/decerter/api"
)

// the decoders, each file of a protocol adds its own in init
var registry = []decoder{}

func register(protocol decoder) {
	registry = append(registry, protocol)
	slices.SortStableFunc(registry, func(a decoder, b decoder) int { return cmp.Compare(a.Protocol, b.Protocol) })
}

// the values as= takes: every protocol of the registry and raw
func Protocols() (protocols []string) {
	for _, protocol := range registry {
		protocols = append(protocols, protocol.Protocol)
	}

	protocols = append(protocols, RawProtocol)
	return
}

// an as= value as= takes: empty (choose), raw or a protocol of the registry
func CheckProtocol(as string) (err error) {
	if (as == "") || slices.Contains(Protocols(), as) {
		return
	}

	err = fmt.Errorf("%w: as %q, valid values: %s", ErrProtocol, as, strings.Join(Protocols(), ", "))
	return
}

// the PDU a request target carries when its body is empty (the dns parameter of a DoH GET): the first protocol that finds one, or as's alone when as names one
func FromTarget(context Context, as string) (data []byte, found bool) {
	for _, protocol := range registry {
		if (protocol.fromTarget == nil) || ((as != "") && (as != protocol.Protocol)) {
			continue
		}

		if data, found = protocol.fromTarget(context.Target); found {
			return
		}
	}

	return
}

// data as a tree: the protocol as names, or the first the context, the port or the bytes name (in that order), raw when none takes them
// only an as that names no protocol is an error; a decoder that panics gives the raw tree with the panic in Error
func Decode(data []byte, context Context, as string) (result v1.Decode, err error) {
	err = CheckProtocol(as)

	if err != nil {
		return
	}

	limit := MaxInputBytes

	if context.Joined {
		limit = MaxStreamBytes
	}

	input := data[:min(len(data), limit)]
	result = v1.Decode{
		MessageID:  0,
		ExchangeID: 0,
		Side:       "",
		FlowID:     0,
		Direction:  "",
		Cut:        false,
		Note:       "",
		Segments:   nil,
		Source:     "",
		Protocol:   RawProtocol,
		Summary:    "",
		Length:     len(input),
		Total:      len(data),
		Truncated:  len(input) < len(data),
		Candidates: []v1.DecodeCandidate{},
		Tree:       []v1.DecodeNode{},
		Data:       nil,
		Error:      "",
		Protocols:  Protocols(),
	}
	protocol := ""

	// the decoders read untrusted bytes: a bug in one ends this decode with the raw tree, never decerter; protocol is empty while the decoders sniff
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Error = sanitize(fmt.Sprintf("the %s decoder failed: %v", protocol, recovered))

			if protocol == "" {
				result.Error = sanitize(fmt.Sprintf("sniffing failed: %v", recovered))
			}

			setRaw(&result, input, "the decoder failed")
		}
	}()

	candidates := candidatesOf(input, context, as)

	for _, possible := range candidates {
		result.Candidates = append(result.Candidates, v1.DecodeCandidate{Protocol: possible.Protocol, Basis: possible.Basis, Reason: sanitize(possible.Reason), Score: possible.Score})
	}

	protocol = choose(candidates)
	chosen, isFound := lookup(protocol)

	if !isFound {
		reason := "no decoder took the bytes"

		if as == RawProtocol {
			reason = "Decode As raw"
		}

		if len(result.Candidates) == 0 {
			result.Candidates = append(result.Candidates, v1.DecodeCandidate{Protocol: RawProtocol, Basis: v1.NoneDecodeBasis, Reason: reason, Score: 0})
		}

		setRaw(&result, input, reason)
		return
	}

	tree := newTree()

	if (chosen.frame != nil) && (context.Transport == StreamTransport) {
		decodeFramed(tree, input, context, chosen)
	} else {
		chosen.decode(tree, input, context)
	}

	result.Protocol = chosen.Protocol
	result.Tree = tree.view()
	result.Summary = sanitize(tree.summaryText())
	result.Truncated = result.Truncated || tree.isFull

	if tree.isFull {
		result.Tree = append(result.Tree, v1.DecodeNode{Name: "decode.truncated", Label: "Decode stopped", Value: "", Offset: 0, Length: 0, Mask: 0, Error: fmt.Sprintf("the tree reached its limit: %d nodes, %d levels or %d bytes", MaxNodes, MaxDepth, MaxOutputBytes), Children: nil})
	}

	return
}

// the protocols that might be the payload's, in the order of the choice: as, the context, the port, then sniffing by score; one per protocol and basis
// a hint or a port is kept with its sniff score, choose skips it when the score is 0
func candidatesOf(data []byte, context Context, as string) (candidates []candidate) {
	if as == RawProtocol {
		candidates = append(candidates, candidate{Protocol: RawProtocol, Basis: v1.OverrideDecodeBasis, Reason: "Decode As raw", Score: 0})
		return
	}

	scores := map[string]int{}
	sniffed := data

	// a joined stream is sniffed by its start
	if context.Joined {
		sniffed = data[:min(len(data), sniffStreamBytes)]
	}

	for _, protocol := range registry {
		scores[protocol.Protocol] = protocol.sniff(sniffed, context)
	}

	if as != "" {
		candidates = append(candidates, candidate{Protocol: as, Basis: v1.OverrideDecodeBasis, Reason: "Decode As " + as, Score: scores[as]})
	}

	for _, protocol := range registry {
		if reason := protocol.hint(context); reason != "" {
			candidates = append(candidates, candidate{Protocol: protocol.Protocol, Basis: v1.ContextDecodeBasis, Reason: reason, Score: scores[protocol.Protocol]})
		}
	}

	for _, protocol := range registry {
		for _, port := range protocol.Ports {
			if (context.Transport != BodyTransport) && (port.Layer == context.Layer) && (port.Number == context.ServerPort) {
				candidates = append(candidates, candidate{Protocol: protocol.Protocol, Basis: v1.PortDecodeBasis, Reason: string(port.Layer) + " port " + strconv.Itoa(int(port.Number)) + " is " + protocol.Title, Score: scores[protocol.Protocol]})
				break
			}
		}
	}

	bySniff := []candidate{}

	for _, protocol := range registry {
		if score := scores[protocol.Protocol]; score >= sniffThreshold {
			bySniff = append(bySniff, candidate{Protocol: protocol.Protocol, Basis: v1.SniffDecodeBasis, Reason: "the bytes read as " + protocol.Title, Score: score})
		}
	}

	slices.SortStableFunc(bySniff, func(a candidate, b candidate) int { return cmp.Compare(b.Score, a.Score) })
	candidates = append(candidates, bySniff...)
	return
}

// the protocol taken: an override always, a hint or a port when the bytes could be the protocol at all, a sniff by its score; raw when none is left
func choose(candidates []candidate) (protocol string) {
	protocol = RawProtocol

	for _, possible := range candidates {
		if (possible.Basis == v1.OverrideDecodeBasis) || (possible.Score > 0) {
			protocol = possible.Protocol
			return
		}
	}

	return
}

func lookup(name string) (protocol decoder, isFound bool) {
	for _, known := range registry {
		if known.Protocol == name {
			protocol, isFound = known, true
			return
		}
	}

	return
}

// the raw tree: one node over the bytes, the summary says why
func setRaw(result *v1.Decode, data []byte, reason string) {
	result.Protocol = RawProtocol
	result.Summary = fmt.Sprintf("%d bytes, %s", len(data), reason)
	result.Tree = []v1.DecodeNode{{Name: RawProtocol, Label: "Data", Value: fmt.Sprintf("%d bytes", len(data)), Offset: 0, Length: len(data), Mask: 0, Error: "", Children: nil}}
}
