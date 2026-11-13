// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	v1 "github.com/decerter/decerter/api"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// the write tools, one per non-GET operation of api/openapi.yaml, registered only with decerter mcp --allow-write; drop_held, delete_rule and stop_capture are destructive
// tool name, operationId: set_intercept setIntercept, edit_held editHold, forward_held forwardHold, drop_held dropHold, add_rule addRule, delete_rule deleteRule,
// start_capture startCapture, stop_capture stopCapture
func addWriteTools(server *sdk.Server, client Client) (err error) {
	directions := []any{v1.UpDirection, v1.DownDirection, v1.BothDirection}
	layers := []any{v1.TCPLayer, v1.TLSLayer, v1.UDPLayer, v1.DTLSLayer, v1.HTTPLayer}
	err = addTool(server, writeTool("set_intercept", "Set intercept", "Turn holding on or off. On, the messages of direction (up by default) and layer whose flow the filter takes are held until forward_held, drop_held or decerter's hold timeout (which forwards them as they are); with layer http a held message is a whole HTTP/1 request or response, its edit keeps the head as written and decerter fixes Content-Length and chunking. A new filter, direction or layer applies to the messages after it. Off forwards every held message as it is. Needs decerter run --intercept. Returns the new intercept state.", false, true), setIntercept(client), nil, []enumProperty{{Name: "direction", Values: directions}, {Name: "layer", Values: layers}})

	if err != nil {
		return
	}

	err = addTool(server, writeTool("edit_held", "Edit held message", "Replace the whole payload of a held message; it goes on with the new payload when forwarded or at its hold timeout. payload is the escaped form of list_held's payload_escaped (\\\\ \\n \\r \\t \\xNN are bytes) or hex with format hex. Returns the held message with a window of its new payload inside an <untrusted-traffic> marker.", false, true), editHeld(client), nil, []enumProperty{{Name: "format", Values: []any{EscapedPayloadFormat, HexPayloadFormat}}})

	if err != nil {
		return
	}

	err = addTool(server, writeTool("forward_held", "Forward held message", "Let a held message go on, with its edit if it has one.", false, true), decideHeld(client, "forward", ForwardedOutcome), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, writeTool("drop_held", "Drop held message", "Drop a held message: it never reaches its peer. A TLS record is left out, TCP bytes are not sent, a datagram is lost; the peers are not told, an HTTP client waits until its own timeout.", true, true), decideHeld(client, "drop", DroppedOutcome), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, writeTool("add_rule", "Add rule", "Add a match-and-replace rule after the existing ones: every occurrence of find in a message of direction, layer and the flows of filter becomes replace. A message is one TLS or DTLS record, one read of a plain TCP stream or one UDP datagram, so a value that spans two messages is not found; with layer http it is one whole HTTP/1 request or response (body without chunk framing, Content-Length and chunking fixed after the replace). text values are the characters as they are (a JSON \\r\\n is CR LF), not the escaped form of the read tools. Needs decerter run --intercept. Returns the rule with its id.", false, false), addRule(client), nil, []enumProperty{{Name: "direction", Values: directions}, {Name: "layer", Values: layers}, {Name: "find.type", Values: []any{v1.TextValueType, v1.HexValueType, v1.RegexValueType}}, {Name: "replace.type", Values: []any{v1.TextValueType, v1.HexValueType}}})

	if err != nil {
		return
	}

	err = addTool(server, writeTool("delete_rule", "Delete rule", "Delete a rule of the API; a message it is working on is finished first, the next ones are not changed by it.", true, true), deleteRule(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, writeTool("start_capture", "Start capture", "Start a capture into a file: the packets of the flows in scope the filter takes (on decerter run the proxy's upstream packets, the wire side after the edits), with their TLS secrets, or synthesized decrypted packets with plaintext. Stop it with stop_capture, then download_pcap writes the file into the output directory. Returns the running capture.", false, false), startCapture(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, writeTool("stop_capture", "Stop capture", "Stop a running capture and finish its file; flows that still wait for their TLS secrets are written without them, the capture takes no more packets. Stopping a stopped capture changes nothing. Returns the stopped capture.", true, true), stopCapture(client), nil, nil)
	return
}

// a tool that changes decerter's state; closed-world like the read tools, it only talks to the api
func writeTool(name string, title string, description string, isDestructive bool, isIdempotent bool) (tool *sdk.Tool) {
	tool = &sdk.Tool{
		Name:        name,
		Title:       title,
		Description: description,
		Annotations: &sdk.ToolAnnotations{
			Title:           title,
			ReadOnlyHint:    false,
			IdempotentHint:  isIdempotent,
			DestructiveHint: new(isDestructive),
			OpenWorldHint:   new(false),
		},
	}
	return
}

func setIntercept(client Client) (handle sdk.ToolHandlerFor[SetInterceptInput, v1.InterceptState]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input SetInterceptInput) (result *sdk.CallToolResult, state v1.InterceptState, err error) {
		err = client.sendJSON(ctx, http.MethodPut, "/intercept", v1.InterceptRequest{Enabled: input.Enabled, Filter: input.Filter, Direction: input.Direction, Layer: input.Layer}, &state)
		return
	}
	return
}

// the payload is decoded here and goes to the api as hex; the answer's payload is escaped again from its hex like list_held's
func editHeld(client Client) (handle sdk.ToolHandlerFor[EditHeldInput, HeldMessage]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input EditHeldInput) (result *sdk.CallToolResult, held HeldMessage, err error) {
		data, err := Unescape(input.Payload)

		if input.Format == HexPayloadFormat {
			data, err = unhex(input.Payload)
		}

		if err != nil {
			return
		}

		hold := v1.Hold{}
		err = client.sendJSON(ctx, http.MethodPut, "/holds/"+strconv.FormatUint(input.ID, 10), v1.EditRequest{Payload: v1.Value{Type: v1.HexValueType, Value: hex.EncodeToString(data)}}, &hold)

		if err != nil {
			return
		}

		held = HeldMessage{
			ID:             hold.ID,
			FlowID:         hold.FlowID,
			ExchangeID:     hold.ExchangeID,
			Direction:      hold.Direction,
			Layer:          hold.Layer,
			HeldAt:         hold.HeldAt,
			Deadline:       hold.Deadline,
			Edited:         hold.Edited,
			Length:         hold.Length,
			OriginalLength: hold.OriginalLength,
			Payload:        nil,
			PayloadOmitted: false,
		}
		metadata := held
		payloads := []string{}

		if hold.Payload != nil {
			edited, decodeErr := hex.DecodeString(hold.Payload.Hex)

			if err = decodeErr; err != nil {
				err = fmt.Errorf("%w: %w", ErrHex, err)
				return
			}

			payload := window(edited, 0, defaultPayloadBytes)
			held.Payload = &payload
			metadata.Payload = new(payload.withoutData())
			payloads = append(payloads, Wrap("h"+strconv.FormatUint(hold.ID, 10), payload.PayloadEscaped))
		}

		result, err = untrustedResult(metadata, payloads)
		return
	}
	return
}

// forward_held and drop_held: POST /holds/{id}/<action>, the api answers 204
func decideHeld(client Client, action string, outcome Outcome) (handle sdk.ToolHandlerFor[HoldInput, OutcomeResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input HoldInput) (result *sdk.CallToolResult, done OutcomeResult, err error) {
		err = client.sendJSON(ctx, http.MethodPost, "/holds/"+strconv.FormatUint(input.ID, 10)+"/"+action, nil, nil)

		if err != nil {
			return
		}

		done = OutcomeResult{ID: input.ID, Outcome: outcome}
		return
	}
	return
}

func addRule(client Client) (handle sdk.ToolHandlerFor[AddRuleInput, v1.Rule]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input AddRuleInput) (result *sdk.CallToolResult, rule v1.Rule, err error) {
		ruleRequest := v1.RuleRequest{
			Filter:    input.Filter,
			Direction: input.Direction,
			Layer:     input.Layer,
			Find:      v1.Value{Type: input.Find.Type, Value: input.Find.Value},
			Replace:   v1.Value{Type: input.Replace.Type, Value: input.Replace.Value},
		}
		err = client.sendJSON(ctx, http.MethodPost, "/rules", ruleRequest, &rule)
		return
	}
	return
}

func deleteRule(client Client) (handle sdk.ToolHandlerFor[RuleInput, OutcomeResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input RuleInput) (result *sdk.CallToolResult, done OutcomeResult, err error) {
		err = client.sendJSON(ctx, http.MethodDelete, "/rules/"+strconv.FormatUint(input.ID, 10), nil, nil)

		if err != nil {
			return
		}

		done = OutcomeResult{ID: input.ID, Outcome: DeletedOutcome}
		return
	}
	return
}

func startCapture(client Client) (handle sdk.ToolHandlerFor[StartCaptureInput, v1.Capture]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input StartCaptureInput) (result *sdk.CallToolResult, capture v1.Capture, err error) {
		err = client.sendJSON(ctx, http.MethodPost, "/captures", v1.CaptureRequest{Filter: input.Filter, Plaintext: input.Plaintext}, &capture)
		return
	}
	return
}

func stopCapture(client Client) (handle sdk.ToolHandlerFor[CaptureInput, v1.Capture]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input CaptureInput) (result *sdk.CallToolResult, capture v1.Capture, err error) {
		err = client.sendJSON(ctx, http.MethodPost, "/captures/"+strconv.FormatUint(input.ID, 10)+"/stop", nil, &capture)
		return
	}
	return
}
