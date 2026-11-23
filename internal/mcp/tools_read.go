// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// the read tools, one per GET operation of api/openapi.yaml except streamCapture; each is annotated read-only and closed-world
// tool name, operationId: status getStatus, list_flows listFlows, get_flow getFlow, list_messages listMessages, get_message getMessage, tail_events streamEvents,
// list_held listHolds, decode_held decodeHold, list_rules listRules, export_keylog exportKeylog, export_pcap exportPcap, list_captures listCaptures, download_pcap downloadCapture,
// list_exchanges listExchanges, get_exchange getExchange, get_exchange_body getExchangeBody, decode_message decodeMessage, decode_exchange_body decodeExchangeBody,
// decode_flow decodeFlow
func addReadTools(server *sdk.Server, client Client, output Output) (err error) {
	payloadBounds := []integerProperty{
		{Name: "offset", Minimum: 0, Maximum: -1, Default: 0},
		{Name: "length", Minimum: 1, Maximum: maxPayloadBytes, Default: defaultPayloadBytes},
	}
	err = addTool(server, readTool("status", "Status", "The running decerter: mode (run: flows go through decerter's proxy; capture: decerter capture only records packets, so list_messages and list_exchanges are empty there), processing (relay: no payloads in the history; decrypt: --decrypt, decrypted copies; intercept: --intercept, messages go through the rules and can be held; record: decerter capture), version, platform, scope filter, intercept state, rule count, history usage and limits, captures. The history counts are what it keeps now; ids are never reused, so an id can be above its count."), status(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_flows", "List flows", "Flows of the history, newest first, with 5-tuple, process, TLS ClientHello fields and counts (bytes and datagrams are known when the flow closes, 0 while it is open; messages count as they come); no socket cookie or TLS client random, get_flow has them. filter takes the decerter filter language (proc.comm, proc.uid, ip.dst, tcp.dstport, tls, tls.sni, ...). Paged with cursor. "+trafficText), listFlows(client), []integerProperty{{Name: "limit", Minimum: 1, Maximum: maxFlows, Default: defaultFlows}}, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("get_flow", "Get flow", "One flow: 5-tuple, socket cookie, process, TLS version, cipher suite, SNI, ALPN, client random, byte and message counts (bytes and datagrams are known when the flow closes). "+trafficText), getFlow(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_messages", "List messages", "Messages of a flow, oldest first: direction, layer, time, origin (rules: it went through decerter's rules and hold queue, also when nothing changed it; passed: it went on before the rules could see it, the TLS secrets came late; observed: a decrypted copy of a relayed flow, --decrypt), verdict, edited flag and lengths; no payloads, read them with get_message. Empty on decerter capture, which keeps no messages."), listMessages(client), []integerProperty{{Name: "limit", Minimum: 1, Maximum: maxMessages, Default: defaultMessages}}, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("get_message", "Get message", "One message with a window of its payload (and of the original payload when a rule or an edit changed it), 4 KiB by default; page with offset and next_offset. The payload is escaped text inside its <untrusted-traffic> marker, hex in payload_hex only with hex. "+trafficText), getMessage(client), payloadBounds, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_exchanges", "List exchanges", "HTTP/1.1 and HTTP/2 exchanges of a flow, oldest first: method, URL, status, the HTTP/2 stream (and the stream that pushed it), how far request and response came, body lengths, the count of gRPC messages, edited flag and notes; no header fields or bodies, read them with get_exchange and get_exchange_body. Paged with cursor. Empty on decerter capture. "+trafficText), listExchanges(client), []integerProperty{{Name: "limit", Minimum: 1, Maximum: maxExchanges, Default: defaultExchanges}}, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("get_exchange", "Get exchange", "One HTTP exchange: request, 1xx and response heads with every header field in order (HTTP/2 pseudo-header fields included; and the original head when a rule or an edit of layer http changed it), framing, state, trailers, body lengths, the HTTP/2 stream id, and for a gRPC body the offset, length and compressed flag of each length-prefixed message (not decoded). "+trafficText), getExchange(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("get_exchange_body", "Get exchange body", "A window of the request or response body of an exchange without chunk framing (and of the original body when it was edited), 4 KiB by default; page with offset and next_offset. The body is escaped text inside its <untrusted-traffic> marker, hex in payload_hex only with hex. "+trafficText), getExchangeBody(client), payloadBounds, []enumProperty{{Name: "side", Values: []any{v1.RequestSide, v1.ResponseSide}}})

	if err != nil {
		return
	}

	err = addTool(server, readTool("decode_message", "Decode message", "One message's payload decoded like Wireshark's packet details, on request: the protocol decerter chose and why (candidates: as, the context such as the TLS ALPN, the server port, sniffing the bytes; protocols lists what as takes), "+
		"then in the marker m<id>-decode the summary line and the tree as JSON, each node with a filter-style name (dns.qry.name), label, value, offset and length in the payload's bytes (get_message's offsets), its error and children. "+
		"Bytes no decoder takes are a raw node. A tcp or tls message is a stream read: DNS over TCP and TLS takes the 2-byte length of each message; after an HTTP Upgrade to websocket the reads are WebSocket frames, unmasked, a binary one decoded as the protocol its bytes sniff as. "+trafficText), decodeMessage(client), []integerProperty{{Name: "max_nodes", Minimum: 1, Maximum: maxDecodeNodes, Default: defaultDecodeNodes}}, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("decode_exchange_body", "Decode exchange body", "The request or response body of an HTTP exchange decoded like decode_message, by its content type (application/dns-message is DoH, application/grpc* gRPC with schema-less protobuf messages, application/x-protobuf protobuf) or the :protocol websocket of an HTTP/2 extended CONNECT: the offsets are get_exchange_body's. "+
		"A request without a body whose target carries the message (the dns parameter of a DoH GET) is decoded from there, source is target and those bytes are escaped in the marker x<id>-request-target, the offsets count from their first byte. "+trafficText), decodeExchangeBody(client), []integerProperty{{Name: "max_nodes", Minimum: 1, Maximum: maxDecodeNodes, Default: defaultDecodeNodes}}, []enumProperty{{Name: "side", Values: []any{v1.RequestSide, v1.ResponseSide}}})

	if err != nil {
		return
	}

	err = addTool(server, readTool("decode_flow", "Decode flow", "One direction of a flow decoded like decode_message. part=handshake (default): the handshake records decerter kept of a TLS or DTLS flow (up: ClientHello; down: ServerHello, certificates, the TLS 1.3 messages decerter decrypted, alerts): "+
		"version, random, session id, cipher suites by IANA name, every extension (server_name, ALPN, supported_versions, supported_groups, signature_algorithms, key_share, pre_shared_key, early_data, ECH, status_request, ...), JA3, JA3S and JA4, and each certificate's subject, issuer, validity and names; not found for a flow without handshake records. "+
		"part=stream: the payloads of the tcp or tls messages of the direction joined in order (at most 4 MiB), so a message split over several reads (a large DNS answer over tcp, a Redis bulk string, a PostgreSQL row) decodes as one; segments map the stream offsets back to message ids and their offsets. "+
		"The tree is in the marker f<id>-<direction>-decode, the offsets count in the handshake bytes or the joined stream, which come only with data. "+trafficText), decodeFlow(client), []integerProperty{{Name: "max_nodes", Minimum: 1, Maximum: maxDecodeNodes, Default: defaultDecodeNodes}, payloadBounds[0], payloadBounds[1]}, []enumProperty{{Name: "direction", Values: []any{v1.UpDirection, v1.DownDirection}}, {Name: "part", Values: []any{v1.HandshakeFlowPart, v1.StreamFlowPart}}})

	if err != nil {
		return
	}

	err = addTool(server, readTool("tail_events", "Tail events", "Listen to decerter's live event stream from now on (no replay) for up to seconds or max_events events, then return them: flows opened and closed, messages, holds, rules, intercept changes, exchanges (an exchange comes when its head is read and again when it is complete). By default each event in a short form: type, time, ids, a flow's protocol, destination, comm and server name, a message's or hold's direction, layer and length, an exchange's method, URL, status and states. With full the whole events: a flow with its process command line and TLS fields, an exchange with every header field. Never payloads or bodies. "+trafficText), tailEvents(client), []integerProperty{{Name: "seconds", Minimum: 1, Maximum: maxSeconds, Default: defaultSeconds}, {Name: "max_events", Minimum: 1, Maximum: maxEvents, Default: defaultEvents}}, []enumProperty{{Name: "types", Values: []any{v1.FlowOpenedEventType, v1.FlowClosedEventType, v1.MessageEventType, v1.HeldEventType, v1.HoldEditedEventType, v1.HoldReleasedEventType, v1.RuleAddedEventType, v1.RuleDeletedEventType, v1.InterceptChangedEventType, v1.ExchangeEventType}}})

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_held", "List held messages", "Messages held by intercept, oldest first, waiting for forward, drop or their deadline, at most limit of them (more counts the rest), with a window of each payload; length bytes in all per call (4 KiB by default), a held message past that has payload_omitted, read it with id. Payloads are escaped text inside <untrusted-traffic> markers. "+trafficText), listHeld(client), append(payloadBounds, integerProperty{Name: "limit", Minimum: 1, Maximum: maxHolds, Default: defaultHolds}), nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("decode_held", "Decode held message", "A held message's payload decoded like decode_message, before it is forwarded: the payload that goes on (after edit_held), with original what was held; the offsets are list_held's. The tree is in the marker h<id>-decode. "+trafficText), decodeHeld(client), []integerProperty{{Name: "max_nodes", Minimum: 1, Maximum: maxDecodeNodes, Default: defaultDecodeNodes}}, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_rules", "List rules", "The match-and-replace rules of the API in the order they run; hits counts the messages a rule found its value in and changed, one per message however many replacements it made."), listRules(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("export_keylog", "Export key log", "Write the NSS key log (SSLKEYLOGFILE lines) of the TLS and DTLS flows the filter takes into a new file in decerter mcp's output directory. Returns only the path, size, SHA-256 and the count of sessions and lines, never the secrets; sessions 0 is an empty file (no TLS flow taken, or the secrets are gone). Give the file to Wireshark or tshark."), exportKeylog(client, output), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("export_pcap", "Export pcap", "Write the flows of the history the filter takes (or the one flow of flow_id, to open in Wireshark) as pcapng into a new file in decerter mcp's output directory: format plaintext (synthesized decrypted packets; on decerter run from the history, the app's side) or dsb (packets as captured with their TLS secrets; on decerter run the proxy's upstream packets, the wire side after the edits). Returns only the path, size, SHA-256 and the count of flows taken, packets and sessions with secrets; packets 0 is a file without packets."), exportPcap(client, output), nil, []enumProperty{{Name: "format", Values: []any{v1.PlaintextCaptureFormat, v1.DSBCaptureFormat}}})

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_captures", "List captures", "The captures started over the API, oldest first: id, filter, format, state, size, dropped packets."), listCaptures(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("download_pcap", "Download capture", "Write the pcapng file of a stopped capture into a new file in decerter mcp's output directory. Returns only the path, size, SHA-256 and the count of packets and sessions with secrets."), downloadPcap(client, output), nil, nil)
	return
}

func readTool(name string, title string, description string) (tool *sdk.Tool) {
	tool = &sdk.Tool{
		Name:        name,
		Title:       title,
		Description: description,
		Annotations: &sdk.ToolAnnotations{
			Title:           title,
			ReadOnlyHint:    true,
			IdempotentHint:  false,
			DestructiveHint: new(false),
			OpenWorldHint:   new(false),
		},
	}
	return
}

// add a tool with the input schema of In, its integer properties bounded and defaulted (Maximum -1 is none) and its enum properties (or their items) limited to their values, a.b names property b of object property a
// the SDK checks the arguments against the schema and fills in the defaults before handle runs
func addTool[In any, Out any](server *sdk.Server, tool *sdk.Tool, handle sdk.ToolHandlerFor[In, Out], integers []integerProperty, enums []enumProperty) (err error) {
	schema, err := jsonschema.For[In](&jsonschema.ForOptions{})

	if err != nil {
		err = fmt.Errorf("tool %s: %w", tool.Name, err)
		return
	}

	for _, integer := range integers {
		property, isProperty := schema.Properties[integer.Name]

		if !isProperty {
			err = fmt.Errorf("tool %s: no property %s", tool.Name, integer.Name)
			return
		}

		property.Minimum = new(float64(integer.Minimum))
		property.Maximum = nil

		if integer.Maximum >= 0 {
			property.Maximum = new(float64(integer.Maximum))
		}

		property.Default = json.RawMessage(strconv.Itoa(integer.Default))
	}

	for _, enum := range enums {
		property, isProperty := schema, true

		// a property of an object property is named with dots: find.type
		for name := range strings.SplitSeq(enum.Name, ".") {
			if property, isProperty = property.Properties[name]; !isProperty {
				break
			}
		}

		if !isProperty {
			err = fmt.Errorf("tool %s: no property %s", tool.Name, enum.Name)
			return
		}

		if property.Items != nil {
			property = property.Items
		}

		property.Enum = enum.Values
	}

	tool.InputSchema = schema
	sdk.AddTool(server, tool, withText(handle))
	return
}

// a handler whose structured result, of a tool without traffic data, also comes as JSON text without HTML escaping (the SDK's own text escapes & < >); a handler that made its own result keeps it
func withText[In any, Out any](handle sdk.ToolHandlerFor[In, Out]) (wrapped sdk.ToolHandlerFor[In, Out]) {
	wrapped = func(ctx context.Context, request *sdk.CallToolRequest, input In) (result *sdk.CallToolResult, output Out, err error) {
		result, output, err = handle(ctx, request, input)

		if (err != nil) || (result != nil) {
			return
		}

		text, err := jsonText(output)

		if err != nil {
			return
		}

		result = &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: text}}}
		return
	}
	return
}

// a text result, the fixed note when isTraffic, the metadata and the payloads in their markers; it has no structured result, so every client shows the model the note and the markers
func untrustedResult(metadata any, payloads []string, isTraffic bool) (result *sdk.CallToolResult, err error) {
	text, err := untrustedText(metadata, payloads, isTraffic)

	if err != nil {
		return
	}

	result = &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: text}}}
	return
}

func status(client Client) (handle sdk.ToolHandlerFor[NoInput, v1.Status]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input NoInput) (result *sdk.CallToolResult, status v1.Status, err error) {
		err = client.getJSON(ctx, "/status", nil, &status)
		return
	}
	return
}

func listFlows(client Client) (handle sdk.ToolHandlerFor[ListFlowsInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ListFlowsInput) (result *sdk.CallToolResult, output any, err error) {
		query := url.Values{"limit": {strconv.Itoa(input.Limit)}}

		if input.Filter != "" {
			query.Set("filter", input.Filter)
		}

		if input.Cursor != "" {
			query.Set("cursor", input.Cursor)
		}

		flows := v1.FlowList{}
		err = client.getJSON(ctx, "/flows", query, &flows)

		if err != nil {
			return
		}

		summaries := FlowSummaryList{Flows: []FlowSummary{}, NextCursor: flows.NextCursor}

		for _, flow := range flows.Flows {
			summaries.Flows = append(summaries.Flows, summarizeFlow(escapeFlow(flow)))
		}

		result, err = untrustedResult(summaries, nil, len(summaries.Flows) > 0)
		return
	}
	return
}

// what list_flows shows of an escaped flow
func summarizeFlow(flow v1.Flow) (summary FlowSummary) {
	summary = FlowSummary{
		ID:           flow.ID,
		Protocol:     flow.Protocol,
		State:        flow.State,
		Opened:       flow.Opened,
		Closed:       flow.Closed,
		Client:       flow.Client,
		Destination:  flow.Destination,
		Process:      flow.Process,
		TLS:          nil,
		Layer:        flow.Layer,
		Up:           flow.Up,
		Down:         flow.Down,
		PayloadBytes: flow.PayloadBytes,
		Truncated:    flow.Truncated,
	}

	if flow.TLS != nil {
		tlsInfo := *flow.TLS
		tlsInfo.ClientRandom = ""
		summary.TLS = &tlsInfo
	}

	return
}

func getFlow(client Client) (handle sdk.ToolHandlerFor[GetFlowInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input GetFlowInput) (result *sdk.CallToolResult, output any, err error) {
		flow := v1.Flow{}
		err = client.getJSON(ctx, "/flows/"+strconv.FormatUint(input.ID, 10), nil, &flow)

		if err != nil {
			return
		}

		result, err = untrustedResult(escapeFlow(flow), nil, true)
		return
	}
	return
}

func listMessages(client Client) (handle sdk.ToolHandlerFor[ListMessagesInput, v1.MessageList]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ListMessagesInput) (result *sdk.CallToolResult, messages v1.MessageList, err error) {
		query := url.Values{"limit": {strconv.Itoa(input.Limit)}}

		if input.Cursor != "" {
			query.Set("cursor", input.Cursor)
		}

		err = client.getJSON(ctx, "/flows/"+strconv.FormatUint(input.FlowID, 10)+"/messages", query, &messages)
		return
	}
	return
}

// the window the api cut, escaped again here from its hex; the text has the payload and the original each in its marker
func getMessage(client Client) (handle sdk.ToolHandlerFor[GetMessageInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input GetMessageInput) (result *sdk.CallToolResult, output any, err error) {
		query := url.Values{"offset": {strconv.Itoa(input.Offset)}, "length": {strconv.Itoa(input.Length)}}
		detail := v1.MessageDetail{}
		err = client.getJSON(ctx, "/messages/"+strconv.FormatUint(input.ID, 10), query, &detail)

		if err != nil {
			return
		}

		payload, err := apiWindow(detail.Payload)

		if err != nil {
			return
		}

		id := "m" + strconv.FormatUint(detail.ID, 10)
		payloads := []string{Wrap(id, payload.PayloadEscaped)}
		metadata := MessageResult{Message: detail.Message, Payload: payload.metadata(input.Hex), Original: nil}

		if detail.Original != nil {
			original, windowErr := apiWindow(*detail.Original)

			if err = windowErr; err != nil {
				return
			}

			metadata.Original = new(original.metadata(input.Hex))
			payloads = append(payloads, Wrap(id+"-original", original.PayloadEscaped))
		}

		result, err = untrustedResult(metadata, payloads, true)
		return
	}
	return
}

// the event stream for a bounded time and count; the overflow event that ends a stream is always kept
func tailEvents(client Client) (handle sdk.ToolHandlerFor[TailEventsInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input TailEventsInput) (result *sdk.CallToolResult, output any, err error) {
		tailCtx, cancel := context.WithTimeout(ctx, time.Duration(input.Seconds)*time.Second)
		defer cancel()
		events := EventsResult{Events: []any{}, Stopped: TimeoutStopReason}
		add := func(event v1.Event) {
			if input.Full {
				events.Events = append(events.Events, escapeEvent(event))
			} else {
				events.Events = append(events.Events, summarizeEvent(event))
			}
		}
		isClosed, err := client.events(tailCtx, func(event v1.Event) (isMore bool) {
			if event.Type == v1.OverflowEventType {
				add(event)
				events.Stopped = OverflowStopReason
				return
			}

			if (len(input.Types) > 0) && !slices.Contains(input.Types, event.Type) {
				isMore = true
				return
			}

			add(event)

			if len(events.Events) >= input.MaxEvents {
				events.Stopped = MaxEventsStopReason
				return
			}

			isMore = true
			return
		})

		if err != nil {
			return
		}

		// the caller went away or decerter mcp is stopping, not the tail's own time
		if ctx.Err() != nil {
			err = ctx.Err()
			return
		}

		if isClosed && (events.Stopped == TimeoutStopReason) {
			events.Stopped = ClosedStopReason
		}

		result, err = untrustedResult(events, nil, len(events.Events) > 0)
		return
	}
	return
}

// the api gives a window of length bytes of each payload, the per-call budget of length bytes is spread over them here; at most limit held messages
func listHeld(client Client) (handle sdk.ToolHandlerFor[ListHeldInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ListHeldInput) (result *sdk.CallToolResult, output any, err error) {
		holds := v1.HoldList{}
		query := url.Values{"offset": {strconv.Itoa(input.Offset)}, "length": {strconv.Itoa(input.Length)}}
		err = client.getJSON(ctx, "/holds", query, &holds)

		if err != nil {
			return
		}

		budget := input.Length
		metadata := HeldResult{Holds: []HeldMessage{}, More: 0}
		payloads := []string{}

		for _, hold := range holds.Holds {
			if (input.ID != 0) && (hold.ID != input.ID) {
				continue
			}

			if len(metadata.Holds) >= input.Limit {
				metadata.More++
				continue
			}

			message := heldMessage(hold)

			switch {
			case hold.Payload == nil:
			case budget == 0:
				message.PayloadOmitted = true
			default:
				data, decodeErr := hex.DecodeString(hold.Payload.Hex)

				if err = decodeErr; err != nil {
					err = fmt.Errorf("%w: %w", ErrHex, err)
					return
				}

				payload := newWindow(data[:min(budget, len(data))], hold.Payload.Offset, hold.Payload.Total)
				budget -= payload.Length
				message.Payload = new(payload.metadata(input.Hex))
				payloads = append(payloads, Wrap("h"+strconv.FormatUint(hold.ID, 10), payload.PayloadEscaped))
			}

			metadata.Holds = append(metadata.Holds, message)
		}

		if (input.ID != 0) && (len(metadata.Holds) == 0) {
			err = fmt.Errorf("%w: %d", ErrNoHold, input.ID)
			return
		}

		result, err = untrustedResult(metadata, payloads, len(metadata.Holds) > 0)
		return
	}
	return
}

// a held message of the api without its payload
func heldMessage(hold v1.Hold) (message HeldMessage) {
	message = HeldMessage{
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
	return
}

func listExchanges(client Client) (handle sdk.ToolHandlerFor[ListExchangesInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ListExchangesInput) (result *sdk.CallToolResult, output any, err error) {
		query := url.Values{"limit": {strconv.Itoa(input.Limit)}}

		if input.Cursor != "" {
			query.Set("cursor", input.Cursor)
		}

		exchanges := v1.ExchangeList{}
		err = client.getJSON(ctx, "/flows/"+strconv.FormatUint(input.FlowID, 10)+"/exchanges", query, &exchanges)

		if err != nil {
			return
		}

		summaries := ExchangeSummaryList{Exchanges: []ExchangeSummary{}, NextCursor: exchanges.NextCursor}

		for _, exchange := range exchanges.Exchanges {
			summaries.Exchanges = append(summaries.Exchanges, summarize(escapeExchange(exchange)))
		}

		result, err = untrustedResult(summaries, nil, len(summaries.Exchanges) > 0)
		return
	}
	return
}

// what list_exchanges shows of an escaped exchange
func summarize(exchange v1.Exchange) (summary ExchangeSummary) {
	summary = ExchangeSummary{ID: exchange.ID, FlowID: exchange.FlowID, Protocol: exchange.Protocol, StreamID: exchange.StreamID, PromiseStreamID: exchange.PromiseStreamID}
	notes := []string{}

	if message := exchange.Request; message != nil {
		summary.Method, summary.URL = message.Method, message.URL
		summary.RequestState, summary.RequestBodyLength = message.State, message.BodyLength
		summary.RequestGRPCMessages = len(message.GRPCMessages)
		summary.Edited = message.Edited

		if message.Note != "" {
			notes = append(notes, "request: "+message.Note)
		}
	}

	if message := exchange.Response; message != nil {
		summary.Status = message.Status
		summary.ResponseState, summary.ResponseBodyLength = message.State, message.BodyLength
		summary.ResponseGRPCMessages = len(message.GRPCMessages)
		summary.Edited = summary.Edited || message.Edited

		if message.Note != "" {
			notes = append(notes, "response: "+message.Note)
		}
	}

	summary.Note = strings.Join(notes, "; ")
	return
}

func getExchange(client Client) (handle sdk.ToolHandlerFor[GetExchangeInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input GetExchangeInput) (result *sdk.CallToolResult, output any, err error) {
		exchange := v1.Exchange{}
		err = client.getJSON(ctx, "/exchanges/"+strconv.FormatUint(input.ID, 10), nil, &exchange)

		if err != nil {
			return
		}

		result, err = untrustedResult(escapeExchange(exchange), nil, true)
		return
	}
	return
}

// the window the api cut, escaped again here from its hex like get_message
func getExchangeBody(client Client) (handle sdk.ToolHandlerFor[GetExchangeBodyInput, any]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input GetExchangeBodyInput) (result *sdk.CallToolResult, output any, err error) {
		side := input.Side

		if side == "" {
			side = v1.RequestSide
		}

		query := url.Values{"side": {string(side)}, "offset": {strconv.Itoa(input.Offset)}, "length": {strconv.Itoa(input.Length)}}
		detail := v1.ExchangeBody{}
		err = client.getJSON(ctx, "/exchanges/"+strconv.FormatUint(input.ID, 10)+"/body", query, &detail)

		if err != nil {
			return
		}

		payload, err := apiWindow(detail.Payload)

		if err != nil {
			return
		}

		id := "x" + strconv.FormatUint(detail.ExchangeID, 10) + "-" + string(side)
		payloads := []string{Wrap(id, payload.PayloadEscaped)}
		metadata := ExchangeBodyResult{ExchangeID: detail.ExchangeID, Side: detail.Side, Payload: payload.metadata(input.Hex), Original: nil}

		if detail.Original != nil {
			original, windowErr := apiWindow(*detail.Original)

			if err = windowErr; err != nil {
				return
			}

			metadata.Original = new(original.metadata(input.Hex))
			payloads = append(payloads, Wrap(id+"-original", original.PayloadEscaped))
		}

		result, err = untrustedResult(metadata, payloads, true)
		return
	}
	return
}

func listRules(client Client) (handle sdk.ToolHandlerFor[NoInput, v1.RuleList]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input NoInput) (result *sdk.CallToolResult, rules v1.RuleList, err error) {
		err = client.getJSON(ctx, "/rules", nil, &rules)
		return
	}
	return
}

func exportKeylog(client Client, output Output) (handle sdk.ToolHandlerFor[ExportKeylogInput, KeylogResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ExportKeylogInput) (result *sdk.CallToolResult, file KeylogResult, err error) {
		query := url.Values{}

		if input.Filter != "" {
			query.Set("filter", input.Filter)
		}

		counter := &keylogCounter{sessions: map[string]bool{}, lines: 0, line: nil}
		file.FileResult, _, err = client.download(ctx, "/keylog", query, keylogMediaType, output, "keylog", "txt", counter)
		counter.add()
		file.Sessions, file.Lines = len(counter.sessions), counter.lines
		return
	}
	return
}

func exportPcap(client Client, output Output) (handle sdk.ToolHandlerFor[ExportPcapInput, ExportPcapResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ExportPcapInput) (result *sdk.CallToolResult, file ExportPcapResult, err error) {
		query := url.Values{}

		if input.Filter != "" {
			query.Set("filter", input.Filter)
		}

		if input.Format != "" {
			query.Set("format", string(input.Format))
		}

		name := "flows"

		if input.FlowID != 0 {
			query.Set("flow", strconv.FormatUint(input.FlowID, 10))
			name = "flow-" + strconv.FormatUint(input.FlowID, 10)
		}

		counter := &pcapngCounter{}
		fileResult, header, err := client.download(ctx, "/flows/pcap", query, pcapngMediaType, output, name, "pcapng", counter)
		file.FileResult, file.Packets, file.Sessions = fileResult, counter.packets, counter.secrets

		if err != nil {
			return
		}

		// a decerter older than this decerter mcp does not count them
		flows, parseErr := strconv.Atoi(header.Get(v1.FlowsHeader))
		file.Flows = -1

		if parseErr == nil {
			file.Flows = flows
		}

		return
	}
	return
}

func listCaptures(client Client) (handle sdk.ToolHandlerFor[NoInput, v1.CaptureList]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input NoInput) (result *sdk.CallToolResult, captures v1.CaptureList, err error) {
		err = client.getJSON(ctx, "/captures", nil, &captures)
		return
	}
	return
}

func downloadPcap(client Client, output Output) (handle sdk.ToolHandlerFor[DownloadPcapInput, PcapResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input DownloadPcapInput) (result *sdk.CallToolResult, file PcapResult, err error) {
		id := strconv.FormatUint(input.ID, 10)
		counter := &pcapngCounter{}
		file.FileResult, _, err = client.download(ctx, "/captures/"+id+"/pcap", nil, pcapngMediaType, output, "capture-"+id, "pcapng", counter)
		file.Packets, file.Sessions = counter.packets, counter.secrets
		return
	}
	return
}
