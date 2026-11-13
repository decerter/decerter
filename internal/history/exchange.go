// SPDX-License-Identifier: AGPL-3.0-only

package history

import (
	"slices"
	"strings"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/filter"
)

// the HTTP layer of the proxy calls these, a nil history and an id of 0 record nothing

// a new exchange of a flow, from the head of a request or of a response that came without one; id is 0 when the flow is gone or keeps no more exchanges
func (history *History) OpenExchange(flowID uint64, protocol string, side api.Side, message api.HTTPMessage) (id uint64) {
	if history == nil {
		return
	}

	view, found := history.openExchange(flowID, protocol, side, message)

	if found {
		id = view.ID
		history.publish(api.Event{Type: api.ExchangeEventType, Exchange: &view})
	}

	return
}

func (history *History) openExchange(flowID uint64, protocol string, side api.Side, message api.HTTPMessage) (view api.Exchange, found bool) {
	history.mutex.Lock()
	defer history.mutex.Unlock()
	flow, found := history.flows[flowID]

	if !found {
		return
	}

	for len(history.exchanges) >= history.limits.Exchanges {
		if !history.evict(flowID) {
			break
		}
	}

	if (len(flow.exchangeIDs) >= history.limits.FlowExchanges) || (len(history.exchanges) >= history.limits.Exchanges) {
		flow.isTruncated = true
		found = false
		return
	}

	history.nextExchangeID++
	record := &exchangeRecord{
		id:       history.nextExchangeID,
		flowID:   flowID,
		protocol: protocol,
		messages: map[api.Side]*httpRecord{},
		interim:  nil,
		bytes:    0,
	}
	history.exchanges[record.id] = record
	flow.exchangeIDs = append(flow.exchangeIDs, record.id)
	history.setHead(flow, record, side, message, false)
	view = exchangeView(record)
	return
}

// the head of a response of the exchange, interim for a 1xx before the final one
func (history *History) AddHead(id uint64, side api.Side, message api.HTTPMessage, isInterim bool) {
	if (history == nil) || (id == 0) {
		return
	}

	view, found := history.addHead(id, side, message, isInterim)

	if found {
		history.publish(api.Event{Type: api.ExchangeEventType, Exchange: &view})
	}
}

func (history *History) addHead(id uint64, side api.Side, message api.HTTPMessage, isInterim bool) (view api.Exchange, found bool) {
	history.mutex.Lock()
	defer history.mutex.Unlock()
	record, flow, found := history.exchangeOf(id)

	if !found {
		return
	}

	history.setHead(flow, record, side, message, isInterim)
	view = exchangeView(record)
	return
}

// a head is always kept, the bodies make room for it; the flow's http fields get its values
func (history *History) setHead(flow *flowRecord, record *exchangeRecord, side api.Side, message api.HTTPMessage, isInterim bool) {
	size := headBytes(message.HTTPHead)
	history.makeRoom(flow, size)
	record.bytes += size
	flow.exchangeBytes += size
	history.exchangeBytes += size

	if isInterim {
		record.interim = append(record.interim, message)
		return
	}

	record.messages[side] = &httpRecord{view: message, body: nil, original: nil}
	addHTTPValues(flow, message)
}

// body bytes of a message as they went on, without chunk framing; what does not fit is counted but not kept
func (history *History) AppendBody(id uint64, side api.Side, data []byte) {
	if (history == nil) || (id == 0) || (len(data) == 0) {
		return
	}

	history.mutex.Lock()
	defer history.mutex.Unlock()
	record, flow, found := history.exchangeOf(id)

	if !found || (record.messages[side] == nil) {
		return
	}

	message := record.messages[side]
	message.view.BodyLength += len(data)
	message.view.OriginalBodyLength = message.view.BodyLength
	message.body = append(message.body, history.keepExchange(flow, record, data)...)
}

// the message ended, or the HTTP layer stopped reading it; an edit replaces its head and body, what came before is kept as the original
func (history *History) EndMessage(id uint64, side api.Side, end HTTPEnd) {
	if (history == nil) || (id == 0) {
		return
	}

	view, found := history.endMessage(id, side, end)

	if found {
		history.publish(api.Event{Type: api.ExchangeEventType, Exchange: &view})
	}
}

func (history *History) endMessage(id uint64, side api.Side, end HTTPEnd) (view api.Exchange, found bool) {
	history.mutex.Lock()
	defer history.mutex.Unlock()
	record, flow, found := history.exchangeOf(id)

	if !found || (record.messages[side] == nil) {
		found = false
		return
	}

	message := record.messages[side]
	message.view.State = end.State
	message.view.Trailers = end.Trailers
	message.view.Note = end.Note

	if end.Edit != nil {
		original := message.view.HTTPHead
		message.view.Original = &original
		message.view.Edited = true
		message.view.Verdict = end.Edit.Verdict
		message.original = message.body
		message.body = nil
		message.view.BodyLength = 0

		if end.Edit.Verdict != api.DropVerdict {
			message.view.HTTPHead = end.Edit.Head
			message.view.URL = end.Edit.URL
			message.view.BodyLength = len(end.Edit.Body)
			message.body = history.keepExchange(flow, record, end.Edit.Body)
			size := headBytes(end.Edit.Head)
			history.makeRoom(flow, size)
			record.bytes += size
			flow.exchangeBytes += size
			history.exchangeBytes += size
			addHTTPValues(flow, message.view)
		}
	}

	view = exchangeView(record)
	return
}

// the exchanges of a flow, oldest first, at most limit of them with an id above cursor; next is the cursor of the following page, 0 on the last one
func (history *History) Exchanges(flowID uint64, cursor uint64, limit int) (exchanges []api.Exchange, next uint64, found bool) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	flow, found := history.flows[flowID]

	if !found {
		return
	}

	start, isFound := slices.BinarySearch(flow.exchangeIDs, cursor)

	if isFound {
		start++
	}

	exchanges = []api.Exchange{}

	for _, exchangeID := range flow.exchangeIDs[start:] {
		if len(exchanges) == limit {
			next = exchanges[len(exchanges)-1].ID
			return
		}

		exchanges = append(exchanges, exchangeView(history.exchanges[exchangeID]))
	}

	return
}

func (history *History) Exchange(id uint64) (exchange api.Exchange, found bool) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	record, found := history.exchanges[id]

	if found {
		exchange = exchangeView(record)
	}

	return
}

// what the history kept of the body of a side: body went on, original is what the peer sent when it was edited, nil otherwise
// hasSide is false when the exchange has no such message (yet); the slices are never changed, the caller must not change them either
func (history *History) ExchangeBody(id uint64, side api.Side) (body []byte, original []byte, isEdited bool, hasSide bool, found bool) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	record, found := history.exchanges[id]

	if !found {
		return
	}

	message := record.messages[side]

	if message == nil {
		return
	}

	hasSide = true
	body = message.body
	original = message.original
	isEdited = message.view.Edited
	return
}

// the exchange and its flow under the mutex
func (history *History) exchangeOf(id uint64) (record *exchangeRecord, flow *flowRecord, found bool) {
	record, found = history.exchanges[id]

	if !found {
		return
	}

	flow, found = history.flows[record.flowID]
	return
}

// older flows go until size fits the total, the flow itself is never evicted
func (history *History) makeRoom(flow *flowRecord, size int64) {
	for history.exchangeBytes+size > history.limits.ExchangeBytes {
		if !history.evict(flow.id) {
			break
		}
	}
}

// what of data the flow and the total limits let the exchange keep, a copy; a cut leaves the flow truncated
func (history *History) keepExchange(flow *flowRecord, record *exchangeRecord, data []byte) (kept []byte) {
	history.makeRoom(flow, int64(len(data)))
	room := max(0, min(history.limits.FlowExchangeBytes-flow.exchangeBytes, history.limits.ExchangeBytes-history.exchangeBytes))
	kept, _ = keep(data, room)
	size := int64(len(kept))
	record.bytes += size
	flow.exchangeBytes += size
	history.exchangeBytes += size

	if len(kept) < len(data) {
		flow.isTruncated = true
	}

	return
}

// the bytes a head takes in the history, roughly as it came on the wire
func headBytes(head api.HTTPHead) (size int64) {
	size = int64(len(head.Method) + len(head.Target) + len(head.Version) + len(head.Reason) + 16)

	for _, header := range head.Headers {
		size += int64(len(header.Name) + len(header.Value) + 4)
	}

	return
}

// the flow's http fields get the method, target, Host and User-Agent of a request, the status of a final response; each distinct value once, up to maxFlowHTTPValues per field
func addHTTPValues(flow *flowRecord, message api.HTTPMessage) {
	if flow.http == nil {
		flow.http = &filter.HTTPValues{Methods: nil, URIs: nil, Hosts: nil, Codes: nil, UserAgents: nil}
	}

	if message.Status != 0 {
		if !slices.Contains(flow.http.Codes, uint16(message.Status)) && (len(flow.http.Codes) < maxFlowHTTPValues) {
			flow.http.Codes = append(flow.http.Codes, uint16(message.Status))
		}

		return
	}

	flow.http.Methods = addValue(flow.http.Methods, message.Method)
	flow.http.URIs = addValue(flow.http.URIs, message.Target)
	flow.http.Hosts = addValue(flow.http.Hosts, headerValue(message.HTTPHead, "Host"))
	flow.http.UserAgents = addValue(flow.http.UserAgents, headerValue(message.HTTPHead, "User-Agent"))
}

func addValue(values []string, value string) (result []string) {
	result = values

	if (value != "") && !slices.Contains(values, value) && (len(values) < maxFlowHTTPValues) {
		result = append(result, value)
	}

	return
}

// the first value of a header field, names are compared without case
func headerValue(head api.HTTPHead, name string) (value string) {
	for _, header := range head.Headers {
		if strings.EqualFold(header.Name, name) {
			value = header.Value
			return
		}
	}

	return
}

func exchangeView(record *exchangeRecord) (exchange api.Exchange) {
	exchange = api.Exchange{
		ID:       record.id,
		FlowID:   record.flowID,
		Protocol: record.protocol,
		Request:  nil,
		Interim:  slices.Clone(record.interim),
		Response: nil,
	}

	if message := record.messages[api.RequestSide]; message != nil {
		exchange.Request = new(messageOf(message))
	}

	if message := record.messages[api.ResponseSide]; message != nil {
		exchange.Response = new(messageOf(message))
	}

	return
}

func messageOf(record *httpRecord) (message api.HTTPMessage) {
	message = record.view
	message.StoredLength = len(record.body)
	message.Headers = slices.Clone(message.Headers)
	message.Trailers = slices.Clone(message.Trailers)

	if message.Headers == nil {
		message.Headers = []api.Header{}
	}

	return
}
