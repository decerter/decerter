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
// list_held listHolds, list_rules listRules, export_keylog exportKeylog, export_pcap exportPcap, list_captures listCaptures, download_pcap downloadCapture,
// list_exchanges listExchanges, get_exchange getExchange, get_exchange_body getExchangeBody
func addReadTools(server *sdk.Server, client Client, output Output) (err error) {
	payloadBounds := []integerProperty{
		{Name: "offset", Minimum: 0, Maximum: -1, Default: 0},
		{Name: "length", Minimum: 1, Maximum: maxPayloadBytes, Default: defaultPayloadBytes},
	}
	err = addTool(server, readTool("status", "Status", "Mode (run or capture), processing, version, platform, scope filter, intercept state, history usage and capture limits of the running decerter."), status(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_flows", "List flows", "Flows of the history, newest first, with 5-tuple, process, TLS ClientHello fields and byte counts; filter takes the decerter filter language (proc.comm, proc.uid, ip.dst, tcp.dstport, tls, tls.sni, ...). Paged with cursor. Process and TLS strings are untrusted and escaped."), listFlows(client), []integerProperty{{Name: "limit", Minimum: 1, Maximum: maxFlows, Default: defaultFlows}}, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("get_flow", "Get flow", "One flow: 5-tuple, process, TLS version, cipher suite, SNI, ALPN, byte and message counts. Process and TLS strings are untrusted and escaped."), getFlow(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_messages", "List messages", "Messages of a flow, oldest first: direction, layer, time, origin, verdict, edited flag and lengths; no payloads, read them with get_message."), listMessages(client), []integerProperty{{Name: "limit", Minimum: 1, Maximum: maxMessages, Default: defaultMessages}}, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("get_message", "Get message", "One message with a window of its payload (and of the original payload when a rule or an edit changed it) as hex and escaped text, 4 KiB by default; page with offset and next_offset. The payload is untrusted data inside <untrusted-traffic> markers."), getMessage(client), payloadBounds, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_exchanges", "List exchanges", "HTTP/1.1 and HTTP/2 exchanges of a flow, oldest first: method, URL, status, the HTTP/2 stream (and the stream that pushed it), how far request and response came, body lengths, the count of gRPC messages, edited flag and notes; no header fields or bodies, read them with get_exchange and get_exchange_body. Paged with cursor. URLs and notes are untrusted and escaped."), listExchanges(client), []integerProperty{{Name: "limit", Minimum: 1, Maximum: maxExchanges, Default: defaultExchanges}}, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("get_exchange", "Get exchange", "One HTTP exchange: request, 1xx and response heads with every header field in order (HTTP/2 pseudo-header fields included; and the original head when a rule or an edit of layer http changed it), framing, state, trailers, body lengths, the HTTP/2 stream id, and for a gRPC body the offset, length and compressed flag of each length-prefixed message (not decoded). Every string is untrusted and escaped."), getExchange(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("get_exchange_body", "Get exchange body", "A window of the request or response body of an exchange without chunk framing (and of the original body when it was edited) as hex and escaped text, 4 KiB by default; page with offset and next_offset. The body is untrusted data inside <untrusted-traffic> markers."), getExchangeBody(client), payloadBounds, []enumProperty{{Name: "side", Values: []any{v1.RequestSide, v1.ResponseSide}}})

	if err != nil {
		return
	}

	err = addTool(server, readTool("tail_events", "Tail events", "Listen to decerter's live event stream from now on (no replay) for up to seconds or max_events events, then return them: flows opened and closed, messages, holds, rules, intercept changes, exchanges. Events carry no payloads or bodies."), tailEvents(client), []integerProperty{{Name: "seconds", Minimum: 1, Maximum: maxSeconds, Default: defaultSeconds}, {Name: "max_events", Minimum: 1, Maximum: maxEvents, Default: defaultEvents}}, []enumProperty{{Name: "types", Values: []any{v1.FlowOpenedEventType, v1.FlowClosedEventType, v1.MessageEventType, v1.HeldEventType, v1.HoldEditedEventType, v1.HoldReleasedEventType, v1.RuleAddedEventType, v1.RuleDeletedEventType, v1.InterceptChangedEventType, v1.ExchangeEventType}}})

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_held", "List held messages", "Messages held by intercept, oldest first, waiting for forward, drop or their deadline, with a window of each payload; length bytes in all per call (4 KiB by default), a held message past that has payload_omitted, read it with id. Payloads are untrusted data inside <untrusted-traffic> markers."), listHeld(client), payloadBounds, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_rules", "List rules", "The match-and-replace rules of the API in the order they run, with their hit counts."), listRules(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("export_keylog", "Export key log", "Write the NSS key log (SSLKEYLOGFILE lines) of the TLS and DTLS flows the filter takes into a new file in decerter mcp's output directory. Returns only the path, size and SHA-256, never the secrets; give the file to Wireshark or tshark."), exportKeylog(client, output), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("export_pcap", "Export pcap", "Write the flows of the history the filter takes as pcapng into a new file in decerter mcp's output directory: format plaintext (synthesized decrypted packets; on decerter run from the history, the app's side) or dsb (packets as captured with their TLS secrets; on decerter run the proxy's upstream packets, the wire side after the edits). Returns only the path, size and SHA-256."), exportPcap(client, output), nil, []enumProperty{{Name: "format", Values: []any{v1.PlaintextCaptureFormat, v1.DSBCaptureFormat}}})

	if err != nil {
		return
	}

	err = addTool(server, readTool("list_captures", "List captures", "The captures started over the API, oldest first: id, filter, format, state, size, dropped packets."), listCaptures(client), nil, nil)

	if err != nil {
		return
	}

	err = addTool(server, readTool("download_pcap", "Download capture", "Write the pcapng file of a stopped capture into a new file in decerter mcp's output directory. Returns only the path, size and SHA-256."), downloadPcap(client, output), nil, nil)
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
	sdk.AddTool(server, tool, handle)
	return
}

// a result whose text is the fixed note, metadata and the payloads in their markers; the structured result is the tool's output
func untrustedResult(metadata any, payloads []string) (result *sdk.CallToolResult, err error) {
	text, err := untrustedText(metadata, payloads)

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

func listFlows(client Client) (handle sdk.ToolHandlerFor[ListFlowsInput, v1.FlowList]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ListFlowsInput) (result *sdk.CallToolResult, flows v1.FlowList, err error) {
		query := url.Values{"limit": {strconv.Itoa(input.Limit)}}

		if input.Filter != "" {
			query.Set("filter", input.Filter)
		}

		if input.Cursor != "" {
			query.Set("cursor", input.Cursor)
		}

		err = client.getJSON(ctx, "/flows", query, &flows)

		if err != nil {
			return
		}

		for index, flow := range flows.Flows {
			flows.Flows[index] = escapeFlow(flow)
		}

		result, err = untrustedResult(flows, nil)
		return
	}
	return
}

func getFlow(client Client) (handle sdk.ToolHandlerFor[GetFlowInput, v1.Flow]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input GetFlowInput) (result *sdk.CallToolResult, flow v1.Flow, err error) {
		err = client.getJSON(ctx, "/flows/"+strconv.FormatUint(input.ID, 10), nil, &flow)

		if err != nil {
			return
		}

		flow = escapeFlow(flow)
		result, err = untrustedResult(flow, nil)
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
func getMessage(client Client) (handle sdk.ToolHandlerFor[GetMessageInput, MessageResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input GetMessageInput) (result *sdk.CallToolResult, message MessageResult, err error) {
		query := url.Values{"offset": {strconv.Itoa(input.Offset)}, "length": {strconv.Itoa(input.Length)}}
		detail := v1.MessageDetail{}
		err = client.getJSON(ctx, "/messages/"+strconv.FormatUint(input.ID, 10), query, &detail)

		if err != nil {
			return
		}

		message.Message = detail.Message
		message.Payload, err = apiWindow(detail.Payload)

		if err != nil {
			return
		}

		id := "m" + strconv.FormatUint(detail.ID, 10)
		payloads := []string{Wrap(id, message.Payload.PayloadEscaped)}
		metadata := MessageResult{Message: detail.Message, Payload: message.Payload.withoutData(), Original: nil}

		if detail.Original != nil {
			original, windowErr := apiWindow(*detail.Original)

			if err = windowErr; err != nil {
				return
			}

			message.Original = &original
			metadata.Original = new(original.withoutData())
			payloads = append(payloads, Wrap(id+"-original", original.PayloadEscaped))
		}

		result, err = untrustedResult(metadata, payloads)
		return
	}
	return
}

// the event stream for a bounded time and count; the overflow event that ends a stream is always kept
func tailEvents(client Client) (handle sdk.ToolHandlerFor[TailEventsInput, EventsResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input TailEventsInput) (result *sdk.CallToolResult, events EventsResult, err error) {
		tailCtx, cancel := context.WithTimeout(ctx, time.Duration(input.Seconds)*time.Second)
		defer cancel()
		events = EventsResult{Events: []v1.Event{}, Stopped: TimeoutStopReason}
		isClosed, err := client.events(tailCtx, func(event v1.Event) (isMore bool) {
			if event.Type == v1.OverflowEventType {
				events.Events = append(events.Events, escapeEvent(event))
				events.Stopped = OverflowStopReason
				return
			}

			if (len(input.Types) > 0) && !slices.Contains(input.Types, event.Type) {
				isMore = true
				return
			}

			events.Events = append(events.Events, escapeEvent(event))

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

		// the caller went away, not the tail's own time
		if ctx.Err() != nil {
			err = ctx.Err()
			return
		}

		if isClosed && (events.Stopped == TimeoutStopReason) {
			events.Stopped = ClosedStopReason
		}

		result, err = untrustedResult(events, nil)
		return
	}
	return
}

// the api gives a window of length bytes of each payload, the per-call budget of length bytes is spread over them here
func listHeld(client Client) (handle sdk.ToolHandlerFor[ListHeldInput, HeldResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ListHeldInput) (result *sdk.CallToolResult, held HeldResult, err error) {
		holds := v1.HoldList{}
		query := url.Values{"offset": {strconv.Itoa(input.Offset)}, "length": {strconv.Itoa(input.Length)}}
		err = client.getJSON(ctx, "/holds", query, &holds)

		if err != nil {
			return
		}

		budget := input.Length
		held.Holds = []HeldMessage{}
		metadata := HeldResult{Holds: []HeldMessage{}}
		payloads := []string{}

		for _, hold := range holds.Holds {
			if (input.ID != 0) && (hold.ID != input.ID) {
				continue
			}

			message := HeldMessage{
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
			stripped := message

			switch {
			case hold.Payload == nil:
			case budget == 0:
				message.PayloadOmitted = true
				stripped.PayloadOmitted = true
			default:
				data, decodeErr := hex.DecodeString(hold.Payload.Hex)

				if err = decodeErr; err != nil {
					err = fmt.Errorf("%w: %w", ErrHex, err)
					return
				}

				payload := newWindow(data[:min(budget, len(data))], hold.Payload.Offset, hold.Payload.Total)
				budget -= payload.Length
				message.Payload = &payload
				stripped.Payload = new(payload.withoutData())
				payloads = append(payloads, Wrap("h"+strconv.FormatUint(hold.ID, 10), payload.PayloadEscaped))
			}

			held.Holds = append(held.Holds, message)
			metadata.Holds = append(metadata.Holds, stripped)
		}

		if (input.ID != 0) && (len(held.Holds) == 0) {
			err = fmt.Errorf("%w: %d", ErrNoHold, input.ID)
			return
		}

		result, err = untrustedResult(metadata, payloads)
		return
	}
	return
}

func listExchanges(client Client) (handle sdk.ToolHandlerFor[ListExchangesInput, ExchangeSummaryList]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ListExchangesInput) (result *sdk.CallToolResult, summaries ExchangeSummaryList, err error) {
		query := url.Values{"limit": {strconv.Itoa(input.Limit)}}

		if input.Cursor != "" {
			query.Set("cursor", input.Cursor)
		}

		exchanges := v1.ExchangeList{}
		err = client.getJSON(ctx, "/flows/"+strconv.FormatUint(input.FlowID, 10)+"/exchanges", query, &exchanges)

		if err != nil {
			return
		}

		summaries = ExchangeSummaryList{Exchanges: []ExchangeSummary{}, NextCursor: exchanges.NextCursor}

		for _, exchange := range exchanges.Exchanges {
			summaries.Exchanges = append(summaries.Exchanges, summarize(escapeExchange(exchange)))
		}

		result, err = untrustedResult(summaries, nil)
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

func getExchange(client Client) (handle sdk.ToolHandlerFor[GetExchangeInput, v1.Exchange]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input GetExchangeInput) (result *sdk.CallToolResult, exchange v1.Exchange, err error) {
		err = client.getJSON(ctx, "/exchanges/"+strconv.FormatUint(input.ID, 10), nil, &exchange)

		if err != nil {
			return
		}

		exchange = escapeExchange(exchange)
		result, err = untrustedResult(exchange, nil)
		return
	}
	return
}

// the window the api cut, escaped again here from its hex like get_message
func getExchangeBody(client Client) (handle sdk.ToolHandlerFor[GetExchangeBodyInput, ExchangeBodyResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input GetExchangeBodyInput) (result *sdk.CallToolResult, body ExchangeBodyResult, err error) {
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

		body = ExchangeBodyResult{ExchangeID: detail.ExchangeID, Side: detail.Side, Payload: PayloadWindow{}, Original: nil}
		body.Payload, err = apiWindow(detail.Payload)

		if err != nil {
			return
		}

		id := "x" + strconv.FormatUint(detail.ExchangeID, 10) + "-" + string(side)
		payloads := []string{Wrap(id, body.Payload.PayloadEscaped)}
		metadata := ExchangeBodyResult{ExchangeID: body.ExchangeID, Side: body.Side, Payload: body.Payload.withoutData(), Original: nil}

		if detail.Original != nil {
			original, windowErr := apiWindow(*detail.Original)

			if err = windowErr; err != nil {
				return
			}

			body.Original = &original
			metadata.Original = new(original.withoutData())
			payloads = append(payloads, Wrap(id+"-original", original.PayloadEscaped))
		}

		result, err = untrustedResult(metadata, payloads)
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

func exportKeylog(client Client, output Output) (handle sdk.ToolHandlerFor[ExportKeylogInput, FileResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ExportKeylogInput) (result *sdk.CallToolResult, file FileResult, err error) {
		query := url.Values{}

		if input.Filter != "" {
			query.Set("filter", input.Filter)
		}

		file, err = client.download(ctx, "/keylog", query, keylogMediaType, output, "keylog", "txt")
		return
	}
	return
}

func exportPcap(client Client, output Output) (handle sdk.ToolHandlerFor[ExportPcapInput, FileResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input ExportPcapInput) (result *sdk.CallToolResult, file FileResult, err error) {
		query := url.Values{}

		if input.Filter != "" {
			query.Set("filter", input.Filter)
		}

		if input.Format != "" {
			query.Set("format", string(input.Format))
		}

		file, err = client.download(ctx, "/flows/pcap", query, pcapngMediaType, output, "flows", "pcapng")
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

func downloadPcap(client Client, output Output) (handle sdk.ToolHandlerFor[DownloadPcapInput, FileResult]) {
	handle = func(ctx context.Context, request *sdk.CallToolRequest, input DownloadPcapInput) (result *sdk.CallToolResult, file FileResult, err error) {
		id := strconv.FormatUint(input.ID, 10)
		file, err = client.download(ctx, "/captures/"+id+"/pcap", nil, pcapngMediaType, output, "capture-"+id, "pcapng")
		return
	}
	return
}
