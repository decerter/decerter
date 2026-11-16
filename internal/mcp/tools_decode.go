// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"context"
	"net/url"
	"regexp"
	"strconv"

	v1 "github.com/decerter/decerter/api"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// the reasons decerter's decoders give for a candidate: Decode As, the port, the bytes, a content type, an ALPN, an Upgrade or the kept handshake records
// decerter mcp shows them outside the untrusted marker, so a reason in any other words is withheld
var reasonPattern = regexp.MustCompile(`^(?:Decode As [a-z0-9-]{1,32}|no decoder took the bytes|(?:tcp|tls|udp|dtls) port [0-9]{1,5} is [A-Za-z0-9 .-]{1,64}|the bytes read as [A-Za-z0-9 .-]{1,64}|` +
	`content type [a-z0-9.+/-]{1,64} is [A-Za-z0-9 .-]{1,64}|TLS ALPN [a-z0-9.-]{1,32} is [A-Za-z0-9 .-]{1,64}|the dns parameter of the GET is DNS over HTTPS|` +
	`the flow switched to WebSocket with an HTTP Upgrade|the :protocol websocket of the HTTP/2 extended CONNECT|the handshake records decerter kept of the (?:TLS|DTLS) flow)$`)

// the decode tree of a message's payload: decerter's fields as metadata, the summary and the tree as JSON in the marker m<id>-decode
func decodeMessage(client Client) (handle sdk.ToolHandlerFor[DecodeMessageInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input DecodeMessageInput) (result *sdk.CallToolResult, output any, err error) {
		query := decodeQuery(input.As, input.Original)
		decoded := v1.Decode{}
		err = client.getJSON(ctx, "/messages/"+strconv.FormatUint(input.ID, 10)+"/decode", query, &decoded)

		if err != nil {
			return
		}

		metadata, tree := splitDecode(decoded, input.MaxNodes)
		payloads, err := decodePayloads("m"+strconv.FormatUint(decoded.MessageID, 10), tree)

		if err != nil {
			return
		}

		result, err = untrustedResult(metadata, payloads, true)
		return
	}
	return
}

// the decode tree of one side's body of an exchange, like decode_message; the bytes of a request target it decoded are escaped in the marker x<id>-request-target
func decodeExchangeBody(client Client) (handle sdk.ToolHandlerFor[DecodeExchangeBodyInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input DecodeExchangeBodyInput) (result *sdk.CallToolResult, output any, err error) {
		side := input.Side

		if side == "" {
			side = v1.RequestSide
		}

		query := decodeQuery(input.As, input.Original)
		query.Set("side", string(side))
		decoded := v1.Decode{}
		err = client.getJSON(ctx, "/exchanges/"+strconv.FormatUint(input.ID, 10)+"/decode", query, &decoded)

		if err != nil {
			return
		}

		metadata, tree := splitDecode(decoded, input.MaxNodes)
		id := "x" + strconv.FormatUint(decoded.ExchangeID, 10) + "-" + string(side)
		payloads, err := decodePayloads(id, tree)

		if err != nil {
			return
		}

		if decoded.Data != nil {
			data, windowErr := apiWindow(*decoded.Data)

			if err = windowErr; err != nil {
				return
			}

			metadata.Data = new(data.metadata(input.Hex))
			payloads = append(payloads, Wrap(id+"-target", data.PayloadEscaped))
		}

		result, err = untrustedResult(metadata, payloads, true)
		return
	}
	return
}

// the decode tree of one direction of a flow, its handshake records or its joined stream, in the marker f<id>-<direction>-decode; the bytes only with data,
// escaped in the marker f<id>-<direction>-handshake or f<id>-<direction>-stream
func decodeFlow(client Client) (handle sdk.ToolHandlerFor[DecodeFlowInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input DecodeFlowInput) (result *sdk.CallToolResult, output any, err error) {
		direction, part := input.Direction, input.Part

		if direction == "" {
			direction = v1.UpDirection
		}

		if part == "" {
			part = v1.HandshakeFlowPart
		}

		query := decodeQuery(input.As, input.Original && (part == v1.StreamFlowPart))
		query.Set("part", string(part))
		query.Set("direction", string(direction))

		if part == v1.StreamFlowPart {
			query.Set("offset", strconv.Itoa(input.Offset))

			if input.Length > 0 {
				query.Set("length", strconv.Itoa(input.Length))
			}
		}
		decoded := v1.Decode{}
		err = client.getJSON(ctx, "/flows/"+strconv.FormatUint(input.ID, 10)+"/decode", query, &decoded)

		if err != nil {
			return
		}

		metadata, tree := splitDecode(decoded, input.MaxNodes)
		id := "f" + strconv.FormatUint(decoded.FlowID, 10) + "-" + string(direction)
		payloads, err := decodePayloads(id, tree)

		if err != nil {
			return
		}

		if input.Data && (decoded.Data != nil) {
			data, windowErr := apiWindow(*decoded.Data)

			if err = windowErr; err != nil {
				return
			}

			metadata.Data = new(data.metadata(input.Hex))
			payloads = append(payloads, Wrap(id+"-"+string(part), data.PayloadEscaped))
		}

		result, err = untrustedResult(metadata, payloads, true)
		return
	}
	return
}

func decodeQuery(as string, isOriginal bool) (query url.Values) {
	query = url.Values{}

	if as != "" {
		query.Set("as", as)
	}

	if isOriginal {
		query.Set("original", "true")
	}

	return
}

// the decode as decerter's metadata and the tree from the traffic, at most maxNodes nodes of it in tree order; every string escaped again here
func splitDecode(decoded v1.Decode, maxNodes int) (metadata DecodeResult, tree DecodeTree) {
	budget := maxNodes
	metadata = DecodeResult{
		MessageID:    decoded.MessageID,
		ExchangeID:   decoded.ExchangeID,
		Side:         decoded.Side,
		FlowID:       decoded.FlowID,
		Direction:    decoded.Direction,
		HandshakeCut: decoded.Cut,
		Note:         escapeDecoded(decoded.Note),
		Segments:     decoded.Segments,
		Source:       decoded.Source,
		Protocol:     escapeDecoded(decoded.Protocol),
		Length:       decoded.Length,
		Total:        decoded.Total,
		Truncated:    decoded.Truncated,
		Nodes:        0,
		Cut:          false,
		Candidates:   []v1.DecodeCandidate{},
		Error:        escapeDecoded(decoded.Error),
		Protocols:    []string{},
		Data:         nil,
	}

	for _, candidate := range decoded.Candidates {
		metadata.Candidates = append(metadata.Candidates, v1.DecodeCandidate{Protocol: escapeDecoded(candidate.Protocol), Basis: v1.DecodeBasis(escapeDecoded(string(candidate.Basis))), Reason: ownReason(candidate.Reason), Score: candidate.Score})
	}

	for _, protocol := range decoded.Protocols {
		metadata.Protocols = append(metadata.Protocols, escapeDecoded(protocol))
	}

	tree = DecodeTree{Summary: escapeDecoded(decoded.Summary), Tree: escapeNodes(decoded.Tree, &budget, &metadata)}

	if tree.Tree == nil {
		tree.Tree = []v1.DecodeNode{}
	}

	return
}

// the nodes while the budget lasts, depth first; metadata counts them and is cut when one is left out
func escapeNodes(nodes []v1.DecodeNode, budget *int, metadata *DecodeResult) (escaped []v1.DecodeNode) {
	for _, node := range nodes {
		if *budget <= 0 {
			metadata.Cut = true
			return
		}

		*budget--
		metadata.Nodes++
		escaped = append(escaped, v1.DecodeNode{
			Name:     escapeDecoded(node.Name),
			Label:    escapeDecoded(node.Label),
			Value:    escapeDecoded(node.Value),
			Offset:   node.Offset,
			Length:   node.Length,
			Mask:     node.Mask,
			Error:    escapeDecoded(node.Error),
			Children: escapeNodes(node.Children, budget, metadata),
		})
	}

	return
}

// the tree as JSON in its marker
func decodePayloads(id string, tree DecodeTree) (payloads []string, err error) {
	text, err := jsonText(tree)

	if err != nil {
		return
	}

	payloads = []string{Wrap(id+"-decode", text)}
	return
}

// a candidate's reason as decerter's decoders word it, or that it was withheld
func ownReason(reason string) (kept string) {
	kept = withheldReason

	if reasonPattern.MatchString(reason) {
		kept = reason
	}

	return
}
