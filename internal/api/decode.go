// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/decode"
)

// the payload of a message as a tree, decoded now: the offsets are the payload's, as in GET /messages/{id}; original=true decodes what the peer sent
func decodeMessage(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
	id, err := pathID(request)

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	isOriginal, err := queryBool(request, "original")

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	message, payload, original, found := backend.History.Message(id)

	if !found {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: message %d", ErrNotFound, id), logger)
		return
	}

	if isOriginal && message.Edited {
		payload = original
	}

	flow, _ := backend.History.Flow(message.FlowID)
	context := decode.Context{
		Transport:   decode.DatagramTransport,
		Layer:       message.Layer,
		Direction:   message.Direction,
		ServerPort:  portOf(flow.Destination),
		ALPN:        "",
		ContentType: "",
		Upgrade:     "",
		Method:      "",
		Target:      "",
	}

	if (message.Layer == v1.TCPLayer) || (message.Layer == v1.TLSLayer) {
		context.Transport = decode.StreamTransport
	}

	if flow.TLS != nil {
		context.ALPN = flow.TLS.ALPN
	}

	result, err := decode.Decode(payload, context, request.URL.Query().Get("as"))

	if err != nil {
		writeError(writer, http.StatusBadRequest, fmt.Errorf("%w: %w", ErrBadRequest, err), logger)
		return
	}

	if result.Error != "" {
		logger.Warn("Could not decode message", "error", result.Error, "messageID", id)
	}

	result.MessageID = id
	result.Source = v1.PayloadDecodeSource
	writeJSON(writer, http.StatusOK, result, logger)
}

// the body of one side of an exchange as a tree, the offsets are the body's as in GET /exchanges/{id}/body; a request without a body whose target carries
// the PDU (the dns parameter of a DoH GET) is decoded from there, the bytes are in data then
func decodeExchangeBody(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger) {
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

	isOriginal, err := queryBool(request, "original")

	if err != nil {
		writeError(writer, http.StatusBadRequest, err, logger)
		return
	}

	as := request.URL.Query().Get("as")
	err = decode.CheckProtocol(as)

	if err != nil {
		writeError(writer, http.StatusBadRequest, fmt.Errorf("%w: %w", ErrBadRequest, err), logger)
		return
	}

	body, original, isEdited, hasSide, found := backend.History.ExchangeBody(id, side)
	exchange, _ := backend.History.Exchange(id)

	if !found || !hasSide {
		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: %s of exchange %d", ErrNotFound, side, id), logger)
		return
	}

	if isOriginal && isEdited {
		body = original
	}

	context := decode.Context{
		Transport:   decode.BodyTransport,
		Layer:       "",
		Direction:   v1.UpDirection,
		ServerPort:  0,
		ALPN:        "",
		ContentType: "",
		Upgrade:     "",
		Method:      "",
		Target:      "",
	}
	head := exchange.Request

	if side == v1.ResponseSide {
		context.Direction = v1.DownDirection
		head = exchange.Response
	}

	if head != nil {
		context.ContentType = headerOf(head.Headers, "Content-Type")
		context.Upgrade = headerOf(head.Headers, "Upgrade")
	}

	if exchange.Request != nil {
		context.Method = exchange.Request.Method
		context.Target = exchange.Request.Target
	}

	if flow, isFlow := backend.History.Flow(exchange.FlowID); isFlow {
		context.ServerPort = portOf(flow.Destination)

		if flow.TLS != nil {
			context.ALPN = flow.TLS.ALPN
		}
	}

	source := v1.BodyDecodeSource
	data := body

	if (side == v1.RequestSide) && (len(body) == 0) {
		if fromTarget, isFound := decode.FromTarget(context, as); isFound {
			data, source = fromTarget, v1.TargetDecodeSource
		}
	}

	result, err := decode.Decode(data, context, as)

	if err != nil {
		writeError(writer, http.StatusBadRequest, fmt.Errorf("%w: %w", ErrBadRequest, err), logger)
		return
	}

	if result.Error != "" {
		logger.Warn("Could not decode exchange body", "error", result.Error, "exchangeID", id, "side", side)
	}

	result.ExchangeID = id
	result.Side = side
	result.Source = source

	if source == v1.TargetDecodeSource {
		window := payloadWindow(data, 0, len(data))
		result.Data = &window
	}

	writeJSON(writer, http.StatusOK, result, logger)
}

// the port of a flow's destination address:port, 0 when it has none
func portOf(destination string) (port uint16) {
	addressPort, parseErr := netip.ParseAddrPort(destination)

	if parseErr == nil {
		port = addressPort.Port()
	}

	return
}

// the first value of a header field, names compared without case (HTTP/2 names are lower case, HTTP/1 names as they came)
func headerOf(headers []v1.Header, name string) (value string) {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			value = header.Value
			return
		}
	}

	return
}

// a boolean query parameter: true, false or absent (false)
func queryBool(request *http.Request, name string) (value bool, err error) {
	switch text := request.URL.Query().Get(name); text {
	case
		"",
		"false":
	case "true":
		value = true
	default:
		err = fmt.Errorf("%w: %s %q, valid values: true, false", ErrBadRequest, name, text)
	}

	return
}
