// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
)

const (
	hexDigits string = "0123456789abcdef"
	// the requests with a body and every answer that is no pcapng, event stream or key log
	jsonMediaType string = "application/json"
)

func getStatus(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	status := v1.Status{
		Mode:       backend.Info.Mode,
		Processing: backend.Info.Processing,
		Version:    v1.Version(),
		Platform:   backend.Info.Platform,
		Scope:      backend.Info.Scope,
		TLSSecrets: backend.Info.HasTLSSecrets,
		Started:    backend.Info.Started,
		Intercept:  interceptView(backend),
		Rules:      0,
		History:    backend.History.Status(),
		Captures:   v1.CaptureStatus{Available: false, Running: 0, Stored: 0, Size: 0, Limits: v1.CaptureLimits{Captures: 0, Running: 0, Size: 0}},
	}

	if backend.Captures != nil {
		status.Captures = backend.Captures.Status()
	}

	if backend.Rules != nil {
		status.Rules = len(backend.Rules.List())
	}

	writeJSON(writer, http.StatusOK, status, logger)
}

func listFlows(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	scope, err := queryFilter(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	limit, err := queryNumber(request, "limit", defaultFlowLimit, 1, maxFlowLimit)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	cursor, err := queryCursor(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	flows, next := backend.History.Flows(scope, cursor, limit)
	writeJSON(writer, http.StatusOK, v1.FlowList{Flows: flows, NextCursor: cursorOf(next)}, logger)
}

func getFlow(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, err := pathID(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	flow, found := backend.History.Flow(id)

	if !found {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: flow %d", ErrNotFound, id), logger)
		return
	}

	writeJSON(writer, http.StatusOK, flow, logger)
}

func listMessages(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, err := pathID(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	limit, err := queryNumber(request, "limit", defaultMessageLimit, 1, maxMessageLimit)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	cursor, err := queryCursor(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	messages, next, found := backend.History.Messages(id, cursor, limit)

	if !found {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: flow %d", ErrNotFound, id), logger)
		return
	}

	writeJSON(writer, http.StatusOK, v1.MessageList{Messages: messages, NextCursor: cursorOf(next)}, logger)
}

func getMessage(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, err := pathID(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	offset, err := queryNumber(request, "offset", 0, 0, maxPayloadOffset)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	length, err := queryNumber(request, "length", defaultPayloadLength, 0, maxPayloadLength)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	message, payload, original, found := backend.History.Message(id)

	if !found {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: message %d", ErrNotFound, id), logger)
		return
	}

	detail := v1.MessageDetail{
		Message:  message,
		Payload:  payloadWindow(payload, offset, length),
		Original: nil,
	}

	if message.Edited {
		window := payloadWindow(original, offset, length)
		detail.Original = &window
	}

	writeJSON(writer, http.StatusOK, detail, logger)
}

func listExchanges(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, err := pathID(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	limit, err := queryNumber(request, "limit", defaultExchangeLimit, 1, maxExchangeLimit)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	cursor, err := queryCursor(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	exchanges, next, found := backend.History.Exchanges(id, cursor, limit)

	if !found {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: flow %d", ErrNotFound, id), logger)
		return
	}

	writeJSON(writer, http.StatusOK, v1.ExchangeList{Exchanges: exchanges, NextCursor: cursorOf(next)}, logger)
}

func getExchange(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, err := pathID(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	exchange, found := backend.History.Exchange(id)

	if !found {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: exchange %d", ErrNotFound, id), logger)
		return
	}

	writeJSON(writer, http.StatusOK, exchange, logger)
}

// a window of the body of the request or the response, without its chunk framing
func getExchangeBody(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, err := pathID(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	side := v1.Side(request.URL.Query().Get("side"))

	switch side {
	case "":
		side = v1.RequestSide
	case
		v1.RequestSide,
		v1.ResponseSide:
	default:
		writeError(writer, http.StatusBadRequest, fmt.Errorf("%w: side %q, valid values: request, response", ErrBadRequest, side), logger)
		return
	}

	offset, err := queryNumber(request, "offset", 0, 0, maxPayloadOffset)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	length, err := queryNumber(request, "length", defaultPayloadLength, 0, maxPayloadLength)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	body, original, isEdited, hasSide, found := backend.History.ExchangeBody(id, side)

	if !found || !hasSide {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: %s of exchange %d", ErrNotFound, side, id), logger)
		return
	}

	detail := v1.ExchangeBody{
		ExchangeID: id,
		Side:       side,
		Payload:    payloadWindow(body, offset, length),
		Original:   nil,
	}

	if isEdited {
		window := payloadWindow(original, offset, length)
		detail.Original = &window
	}

	writeJSON(writer, http.StatusOK, detail, logger)
}

func setIntercept(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	if backend.Holds == nil {
		writeError(writer, http.StatusConflict, ErrNoInterception, logger)
		return
	}

	interceptRequest := v1.InterceptRequest{}
	err := readJSON(writer, request, &interceptRequest)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	directions, err := directionsOf(interceptRequest.Direction, intercept.UpDirections)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	layer, err := layerOf(interceptRequest.Layer)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	var scope *filter.Filter

	if interceptRequest.Filter != "" {
		scope, err = parseFilter(interceptRequest.Filter)

		if err != nil {
			writeError(writer, http.StatusBadRequest, err, logger)
			return
		}
	}

	backend.Holds.Set(interceptRequest.Enabled, scope, directions, layer)
	state := interceptView(backend)
	logger.Info("Intercept changed over the api", "enabled", state.Enabled, "filter", state.Filter, "direction", state.Direction, "layer", state.Layer)
	backend.Bus.Publish(v1.Event{Type: v1.InterceptChangedEventType, Intercept: &state})
	writeJSON(writer, http.StatusOK, state, logger)
}

func listHolds(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	holds := []v1.Hold{}

	if backend.Holds != nil {
		for _, held := range backend.Holds.List() {
			holds = append(holds, holdView(held, true))
		}
	}

	writeJSON(writer, http.StatusOK, v1.HoldList{Holds: holds}, logger)
}

func editHold(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, ok := holdID(backend, writer, request, logger)

	if !ok {
		return
	}

	editRequest := v1.EditRequest{}
	err := readJSON(writer, request, &editRequest)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	plain, err := intercept.DecodeValue(intercept.ValueType(editRequest.Payload.Type), editRequest.Payload.Value)

	if err != nil {
		writeError(writer, http.StatusBadRequest, fmt.Errorf("%w: payload: %w", ErrBadRequest, err), logger)
		return
	}

	held, err := backend.Holds.Edit(id, plain)

	if err != nil {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: %w %d", ErrNotFound, err, id), logger)
		return
	}

	writeJSON(writer, http.StatusOK, holdView(held, true), logger)
}

func forwardHold(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, ok := holdID(backend, writer, request, logger)

	if !ok {
		return
	}

	err := backend.Holds.Forward(id)

	if err != nil {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: %w %d", ErrNotFound, err, id), logger)
		return
	}

	writer.WriteHeader(http.StatusNoContent)
}

func dropHold(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, ok := holdID(backend, writer, request, logger)

	if !ok {
		return
	}

	err := backend.Holds.Drop(id)

	if err != nil {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: %w %d", ErrNotFound, err, id), logger)
		return
	}

	writer.WriteHeader(http.StatusNoContent)
}

// the id of a hold request, ok is false when the answer is written already
func holdID(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) (id uint64, ok bool) {
	if backend.Holds == nil {
		writeError(writer, http.StatusConflict, ErrNoInterception, logger)
		return
	}

	id, err := pathID(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	ok = true
	return
}

func listRules(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	rules := []v1.Rule{}

	if backend.Rules != nil {
		for _, rule := range backend.Rules.List() {
			rules = append(rules, ruleView(rule))
		}
	}

	writeJSON(writer, http.StatusOK, v1.RuleList{Rules: rules}, logger)
}

func addRule(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	if backend.Rules == nil {
		writeError(writer, http.StatusConflict, ErrNoInterception, logger)
		return
	}

	ruleRequest := v1.RuleRequest{}
	err := readJSON(writer, request, &ruleRequest)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	directions, err := directionsOf(ruleRequest.Direction, intercept.BothDirections)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	rule, err := intercept.NewMatchRule(intercept.MatchSpec{
		Filter:      ruleRequest.Filter,
		Directions:  directions,
		Layer:       intercept.Layer(ruleRequest.Layer),
		FindType:    intercept.ValueType(ruleRequest.Find.Type),
		Find:        ruleRequest.Find.Value,
		ReplaceType: intercept.ValueType(ruleRequest.Replace.Type),
		Replace:     ruleRequest.Replace.Value,
	})

	if err != nil {
		writeError(writer, http.StatusBadRequest, fmt.Errorf("%w: rule: %w", ErrBadRequest, withMarker(err)), logger)
		return
	}

	backend.Rules.Add(rule)
	view := ruleView(rule)
	logger.Info("Rule added over the api", "ruleID", view.ID, "filter", view.Filter, "direction", view.Direction, "layer", view.Layer)
	backend.Bus.Publish(v1.Event{Type: v1.RuleAddedEventType, Rule: &view})
	writer.Header().Set("Location", v1.BasePath+"/rules/"+strconv.FormatUint(view.ID, 10))
	writeJSON(writer, http.StatusCreated, view, logger)
}

func deleteRule(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	if backend.Rules == nil {
		writeError(writer, http.StatusConflict, ErrNoInterception, logger)
		return
	}

	id, err := pathID(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	rule, found := backend.Rules.Delete(id)

	if !found {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: rule %d", ErrNotFound, id), logger)
		return
	}

	view := ruleView(rule)
	logger.Info("Rule deleted over the api", "ruleID", view.ID)
	backend.Bus.Publish(v1.Event{Type: v1.RuleDeletedEventType, Rule: &view})
	writer.WriteHeader(http.StatusNoContent)
}

// NSS key log lines of the TLS and DTLS sessions of the history the filter takes, looked up in secrets_map now: a session the map no longer has is left out
// the secrets only go to the client, they are never logged
func exportKeylog(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	if backend.KeyLog == nil {
		writeError(writer, http.StatusConflict, ErrNoSecrets, logger)
		return
	}

	scope, err := queryFilter(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	builder := strings.Builder{}
	sessions, missing := 0, 0

	for _, clientRandom := range backend.History.ClientRandoms(scope) {
		keyLog, found, lookupErr := backend.KeyLog(clientRandom)

		if lookupErr != nil {
			writeError(writer, http.StatusInternalServerError, lookupErr, logger)
			return
		}

		if !found {
			missing++
			continue
		}

		sessions++
		builder.WriteString(keyLog)
	}

	logger.Debug("Key log exported over the api", "sessions", sessions, "missing", missing)
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, writeErr := io.WriteString(writer, builder.String())

	if writeErr != nil {
		logger.Debug("Could not write api response", "error", writeErr)
	}
}

func interceptView(backend *Backend) (state v1.InterceptState) {
	state = v1.InterceptState{
		Available:          backend.Holds != nil,
		Enabled:            false,
		Filter:             "",
		Direction:          v1.UpDirection,
		HoldTimeoutSeconds: backend.Info.HoldTimeout.Seconds(),
		Held:               0,
	}

	if backend.Holds == nil {
		return
	}

	current := backend.Holds.State()
	state.Enabled = current.IsEnabled
	state.Filter = current.Filter
	state.Direction = v1.Direction(current.Directions)
	state.Layer = v1.Layer(current.Layer)
	state.HoldTimeoutSeconds = current.Timeout.Seconds()
	state.Held = current.HeldCount
	return
}

// withPayload adds the whole payload that goes on, events leave it out
func holdView(held intercept.Held, withPayload bool) (hold v1.Hold) {
	hold = v1.Hold{
		ID:             held.Message.ID,
		FlowID:         held.Message.Flow.ID,
		ExchangeID:     held.Message.Exchange,
		Direction:      v1.Direction(intercept.DirectionName(held.Message.Direction)),
		Layer:          v1.Layer(held.Message.Layer),
		HeldAt:         held.HeldAt,
		Deadline:       held.Deadline,
		Edited:         held.IsEdited,
		Length:         len(held.Plain),
		OriginalLength: len(held.Message.Plain),
		Payload:        nil,
	}

	if withPayload {
		payload := payloadWindow(held.Plain, 0, len(held.Plain))
		hold.Payload = &payload
	}

	return
}

func holdEvent(event intercept.HoldEvent) (apiEvent v1.Event) {
	hold := holdView(event.Held, false)
	apiEvent = v1.Event{Type: v1.HeldEventType, Hold: &hold, Reason: string(event.Reason)}

	switch event.Type {
	case intercept.EditedHoldEventType:
		apiEvent.Type = v1.HoldEditedEventType
	case intercept.ReleasedHoldEventType:
		apiEvent.Type = v1.HoldReleasedEventType
	default:
	}

	return
}

func ruleView(rule *intercept.MatchRule) (view v1.Rule) {
	view = v1.Rule{
		ID:        rule.ID,
		Created:   rule.Created,
		Filter:    rule.Spec.Filter,
		Direction: v1.Direction(rule.Spec.Directions),
		Layer:     v1.Layer(rule.Spec.Layer),
		Find:      v1.Value{Type: v1.ValueType(rule.Spec.FindType), Value: rule.Spec.Find},
		Replace:   v1.Value{Type: v1.ValueType(rule.Spec.ReplaceType), Value: rule.Spec.Replace},
		Hits:      rule.Hits(),
	}
	return
}

// at most length bytes of data from offset on, an offset past the end is an empty window
func payloadWindow(data []byte, offset int, length int) (payload v1.Payload) {
	start := min(offset, len(data))
	window := data[start:min(start+length, len(data))]
	payload = v1.Payload{
		Offset:  start,
		Length:  len(window),
		Total:   len(data),
		Hex:     hex.EncodeToString(window),
		Escaped: escape(window),
	}
	return
}

// printable ASCII stays, a backslash is doubled, \n \r \t are written as such and every other byte as \xNN: the text can be read and the bytes can be read back from it
func escape(data []byte) (text string) {
	builder := strings.Builder{}
	builder.Grow(len(data) + len(data)/8)

	for _, value := range data {
		switch {
		case value == '\n':
			builder.WriteString(`\n`)
		case value == '\r':
			builder.WriteString(`\r`)
		case value == '\t':
			builder.WriteString(`\t`)
		case value == '\\':
			builder.WriteString(`\\`)
		case (value >= ' ') && (value <= '~'):
			builder.WriteByte(value)
		default:
			builder.WriteString(`\x`)
			builder.WriteByte(hexDigits[value>>4])
			builder.WriteByte(hexDigits[value&0x0f])
		}
	}

	text = builder.String()
	return
}

// the layer of the hold queue, empty is every record layer
func layerOf(layer v1.Layer) (interceptLayer intercept.Layer, err error) {
	switch layer {
	case
		"",
		v1.TCPLayer,
		v1.TLSLayer,
		v1.UDPLayer,
		v1.DTLSLayer,
		v1.HTTPLayer:
		interceptLayer = intercept.Layer(layer)
	default:
		err = fmt.Errorf("%w: layer %q, valid values: tcp, tls, udp, dtls, http", ErrBadRequest, layer)
	}

	return
}

// empty is the default
func directionsOf(direction v1.Direction, fallback intercept.Directions) (directions intercept.Directions, err error) {
	switch direction {
	case "":
		directions = fallback
	case
		v1.UpDirection,
		v1.DownDirection,
		v1.BothDirection:
		directions = intercept.Directions(direction)
	default:
		err = fmt.Errorf("%w: direction %q, valid values: up, down, both", ErrBadRequest, direction)
	}

	return
}

// the filter query parameter, nil when there is none
func queryFilter(request *http.Request) (scope *filter.Filter, err error) {
	text := request.URL.Query().Get("filter")

	if text == "" {
		return
	}

	scope, err = parseFilter(text)
	return
}

// a parse error carries the filter and a marker under the column of the problem
func parseFilter(text string) (scope *filter.Filter, err error) {
	parsed, parseErr := filter.Parse(text)

	if err = parseErr; err != nil {
		err = fmt.Errorf("%w: filter: %w", ErrBadRequest, withMarker(err))
		return
	}

	scope = &parsed
	return
}

func withMarker(err error) (marked error) {
	marked = err

	if positionErr, ok := errors.AsType[*filter.PositionError](err); ok {
		marked = fmt.Errorf("%w\n%s", err, positionErr.Marker())
	}

	return
}

// an integer query parameter between minimum and maximum, fallback when it is not given
func queryNumber(request *http.Request, name string, fallback int, minimum int, maximum int) (number int, err error) {
	text := request.URL.Query().Get(name)
	number = fallback

	if text == "" {
		return
	}

	parsed, parseErr := strconv.Atoi(text)

	if (parseErr != nil) || (parsed < minimum) || (parsed > maximum) {
		err = fmt.Errorf("%w: %s %q, must be a number from %d to %d", ErrBadRequest, name, text, minimum, maximum)
		return
	}

	number = parsed
	return
}

// the cursor of a page, 0 is the first page
func queryCursor(request *http.Request) (cursor uint64, err error) {
	text := request.URL.Query().Get("cursor")

	if text == "" {
		return
	}

	cursor, err = strconv.ParseUint(text, 10, 64)

	if err != nil {
		err = fmt.Errorf("%w: cursor %q", ErrBadRequest, text)
	}

	return
}

// a cursor of a page, empty for the last one
func cursorOf(next uint64) (cursor string) {
	if next != 0 {
		cursor = strconv.FormatUint(next, 10)
	}

	return
}

func pathID(request *http.Request) (id uint64, err error) {
	text := request.PathValue("id")
	id, err = strconv.ParseUint(text, 10, 64)

	if err != nil {
		err = fmt.Errorf("%w: id %q", ErrBadRequest, text)
	}

	return
}

// one JSON object, unknown fields are an error so a typo does not pass unnoticed
// only application/json: a form or text/plain body is what a web page may send without asking
func readJSON(writer http.ResponseWriter, request *http.Request, target any) (err error) {
	mediaType, _, parseErr := mime.ParseMediaType(request.Header.Get("Content-Type"))

	if (parseErr != nil) || (mediaType != jsonMediaType) {
		err = fmt.Errorf("%w: body: content type %q, expected %s", ErrBadRequest, request.Header.Get("Content-Type"), jsonMediaType)
		return
	}

	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(target)

	if err != nil {
		err = fmt.Errorf("%w: body: %w", ErrBadRequest, err)
		return
	}

	if decoder.More() {
		err = fmt.Errorf("%w: body: more than one json value", ErrBadRequest)
	}

	return
}

func writeJSON(writer http.ResponseWriter, status int, value any, logger *slog.Logger) {
	body, err := json.Marshal(value)

	if err != nil {
		logger.Error("Could not encode api response", "error", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", jsonMediaType)
	writer.WriteHeader(status)
	_, err = writer.Write(append(body, '\n'))

	if err != nil {
		logger.Debug("Could not write api response", "error", err)
	}
}

func writeError(writer http.ResponseWriter, status int, err error, logger *slog.Logger) {
	logger.Debug("Api request failed", "error", err, "status", status)
	writeJSON(writer, status, v1.Error{Error: err.Error()}, logger)
}
