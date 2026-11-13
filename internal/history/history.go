// SPDX-License-Identifier: AGPL-3.0-only

package history

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// notify nil publishes nothing
func New(limits Limits, notify func(event api.Event)) (history *History) {
	history = &History{
		mutex:          &sync.RWMutex{},
		limits:         limits,
		flows:          map[uint64]*flowRecord{},
		order:          nil,
		messages:       map[uint64]*messageRecord{},
		exchanges:      map[uint64]*exchangeRecord{},
		nextFlowID:     0,
		nextMessageID:  0,
		nextExchangeID: 0,
		payloadBytes:   0,
		exchangeBytes:  0,
		openFlows:      0,
		evictedFlows:   0,
		notify:         notify,
	}
	return
}

// a nil history records nothing, the proxy calls these without checking

// a flow in scope starts, id names it in the API; values are the ones its scope was decided with, clientRandom the one of its ClientHello, zero without one
func (history *History) OpenFlow(cookie uint64, values filter.Values, clientRandom [32]byte) (id uint64) {
	if history == nil {
		return
	}

	flow := history.openFlow(cookie, values, clientRandom)
	id = flow.ID
	history.publish(api.Event{Type: api.FlowOpenedEventType, Flow: &flow})
	return
}

func (history *History) openFlow(cookie uint64, values filter.Values, clientRandom [32]byte) (flow api.Flow) {
	history.mutex.Lock()
	defer history.mutex.Unlock()

	for len(history.order) >= history.limits.Flows {
		if !history.evict(0) {
			break
		}
	}

	history.nextFlowID++
	record := &flowRecord{
		id:            history.nextFlowID,
		cookie:        cookie,
		values:        values,
		clientRandom:  clientRandom,
		session:       tlsrecord.Session{},
		layer:         "",
		opened:        time.Now(),
		closed:        time.Time{},
		isOpen:        true,
		traffic:       [2]api.Traffic{},
		messageIDs:    nil,
		payloadBytes:  0,
		isTruncated:   false,
		exchangeIDs:   nil,
		exchangeBytes: 0,
		http:          nil,
	}
	history.flows[record.id] = record
	history.order = append(history.order, record.id)
	history.openFlows++
	flow = flowView(record)
	return
}

// the flow ended, up and down are what the proxy sent on in each direction; a flow that was evicted meanwhile is gone
func (history *History) CloseFlow(id uint64, up Counters, down Counters) {
	if history == nil {
		return
	}

	flow, found := history.closeFlow(id, up, down)

	if found {
		history.publish(api.Event{Type: api.FlowClosedEventType, Flow: &flow})
	}
}

func (history *History) closeFlow(id uint64, up Counters, down Counters) (flow api.Flow, found bool) {
	history.mutex.Lock()
	defer history.mutex.Unlock()
	record, found := history.flows[id]

	if !found || !record.isOpen {
		found = false
		return
	}

	record.isOpen = false
	record.closed = time.Now()
	history.openFlows--

	for direction, counters := range [2]Counters{up, down} {
		record.traffic[direction].Bytes = counters.Bytes
		record.traffic[direction].Datagrams = counters.Datagrams
	}

	flow = flowView(record)
	return
}

// the recorder of the intercept pipeline: a message after the rules; the payloads are copied
func (history *History) Record(message intercept.Message, result intercept.Result, origin intercept.Origin) {
	if history == nil {
		return
	}

	view, found := history.record(message, result, origin)

	if found {
		history.publish(api.Event{Type: api.MessageEventType, Message: &view})
	}
}

// --decrypt: a decrypted copy of what the relay sent on, it gets the next id of the history
func (history *History) Observe(flow intercept.Flow, direction tlsrecord.Direction, layer intercept.Layer, plain []byte) {
	if history == nil {
		return
	}

	message := intercept.Message{
		Flow:      flow,
		ID:        history.nextObservedID(),
		Direction: direction,
		Layer:     layer,
		Plain:     plain,
	}
	history.Record(message, intercept.Result{Plain: plain, Verdict: intercept.ForwardVerdict, Changed: false}, intercept.ObservedOrigin)
}

func (history *History) nextObservedID() (id uint64) {
	history.mutex.Lock()
	defer history.mutex.Unlock()
	history.nextMessageID++
	id = history.nextMessageID
	return
}

// a message is kept while its flow and the total limits allow it, older flows make room first; what does not fit leaves the flow truncated
func (history *History) record(message intercept.Message, result intercept.Result, origin intercept.Origin) (view api.Message, found bool) {
	history.mutex.Lock()
	defer history.mutex.Unlock()
	flow, found := history.flows[message.Flow.ID]

	if !found {
		return
	}

	if message.Flow.Session.Version != 0 {
		flow.session = message.Flow.Session
	}

	flow.layer = message.Layer
	record := &messageRecord{
		id:             message.ID,
		flowID:         flow.id,
		direction:      message.Direction,
		layer:          message.Layer,
		time:           time.Now(),
		origin:         origin,
		verdict:        result.Verdict,
		isEdited:       result.Changed,
		length:         len(result.Plain),
		originalLength: len(message.Plain),
		payload:        nil,
		original:       nil,
	}
	view = messageView(record)

	for len(history.messages) >= history.limits.Messages {
		if !history.evict(flow.id) {
			break
		}
	}

	if (len(flow.messageIDs) >= history.limits.FlowMessages) || (len(history.messages) >= history.limits.Messages) {
		flow.isTruncated = true
		return
	}

	// what goes on first, then what the peer sent; a drop only has the latter
	wanted := int64(len(result.Plain))

	if record.isEdited {
		wanted += int64(len(message.Plain))
	}

	for history.payloadBytes+wanted > history.limits.PayloadBytes {
		if !history.evict(flow.id) {
			break
		}
	}

	room := max(0, min(history.limits.FlowPayloadBytes-flow.payloadBytes, history.limits.PayloadBytes-history.payloadBytes))
	record.payload, room = keep(result.Plain, room)

	if record.isEdited {
		record.original, _ = keep(message.Plain, room)
	}

	kept := int64(len(record.payload) + len(record.original))
	flow.payloadBytes += kept
	history.payloadBytes += kept

	if kept < wanted {
		flow.isTruncated = true
	}

	history.messages[record.id] = record
	index, _ := slices.BinarySearch(flow.messageIDs, record.id)
	flow.messageIDs = slices.Insert(flow.messageIDs, index, record.id)
	flow.traffic[record.direction].Messages++
	view = messageView(record)
	return
}

// at most room bytes of data as a copy of its own, left is the room after it
func keep(data []byte, room int64) (kept []byte, left int64) {
	length := min(int64(len(data)), room)
	kept = bytes.Clone(data[:length])
	left = room - length
	return
}

// remove the oldest flow that is not except with its messages, isEvicted is false when there is none
func (history *History) evict(except uint64) (isEvicted bool) {
	index := slices.IndexFunc(history.order, func(id uint64) bool {
		return id != except
	})

	if index < 0 {
		return
	}

	record := history.flows[history.order[index]]

	for _, messageID := range record.messageIDs {
		delete(history.messages, messageID)
	}

	for _, exchangeID := range record.exchangeIDs {
		delete(history.exchanges, exchangeID)
	}

	history.exchangeBytes -= record.exchangeBytes

	if record.isOpen {
		history.openFlows--
	}

	history.payloadBytes -= record.payloadBytes
	delete(history.flows, record.id)
	history.evictedFlows++

	if index == 0 {
		history.order = history.order[1:]
	} else {
		history.order = slices.Delete(history.order, index, index+1)
	}

	isEvicted = true
	return
}

func (history *History) publish(event api.Event) {
	if history.notify != nil {
		history.notify(event)
	}
}

// the flows a filter takes, newest first, at most limit of them with an id below cursor (0 is from the newest); next is the cursor of the following page, 0 on the last one
// scope nil takes every flow
func (history *History) Flows(scope *filter.Filter, cursor uint64, limit int) (flows []api.Flow, next uint64) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	end := len(history.order)

	if cursor != 0 {
		end, _ = slices.BinarySearch(history.order, cursor)
	}

	flows = []api.Flow{}

	for index := end - 1; index >= 0; index-- {
		record := history.flows[history.order[index]]

		if (scope != nil) && (scope.Evaluate(flowValues(record)) != filter.TrueResult) {
			continue
		}

		if len(flows) == limit {
			next = flows[len(flows)-1].ID
			return
		}

		flows = append(flows, flowView(record))
	}

	return
}

func (history *History) Flow(id uint64) (flow api.Flow, found bool) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	record, found := history.flows[id]

	if found {
		flow = flowView(record)
	}

	return
}

// the messages of a flow, oldest first, at most limit of them with an id above cursor; next is the cursor of the following page, 0 on the last one
func (history *History) Messages(flowID uint64, cursor uint64, limit int) (messages []api.Message, next uint64, found bool) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	record, found := history.flows[flowID]

	if !found {
		return
	}

	start, isFound := slices.BinarySearch(record.messageIDs, cursor)

	if isFound {
		start++
	}

	messages = []api.Message{}

	for _, messageID := range record.messageIDs[start:] {
		if len(messages) == limit {
			next = messages[len(messages)-1].ID
			return
		}

		messages = append(messages, messageView(history.messages[messageID]))
	}

	return
}

// a message with what the history kept of it: payload went on, original is what the peer sent when it was changed, nil otherwise
// the slices are never changed, the caller must not change them either
func (history *History) Message(id uint64) (message api.Message, payload []byte, original []byte, found bool) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	record, found := history.messages[id]

	if !found {
		return
	}

	message = messageView(record)
	payload = record.payload
	original = record.original
	return
}

// the client randoms of the TLS and DTLS flows a filter takes, oldest first, each once
func (history *History) ClientRandoms(scope *filter.Filter) (clientRandoms [][32]byte) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	seen := map[[32]byte]bool{}

	for _, id := range history.order {
		record := history.flows[id]
		clientRandom := record.clientRandom

		if clientRandom == [32]byte{} {
			clientRandom = record.session.ClientRandom
		}

		if (clientRandom == [32]byte{}) || seen[clientRandom] {
			continue
		}

		if (scope != nil) && (scope.Evaluate(flowValues(record)) != filter.TrueResult) {
			continue
		}

		seen[clientRandom] = true
		clientRandoms = append(clientRandoms, clientRandom)
	}

	return
}

// the flows a filter takes with their messages, oldest first; scope nil takes every flow
func (history *History) Export(scope *filter.Filter) (flows []ExportFlow) {
	if history == nil {
		return
	}

	history.mutex.RLock()
	defer history.mutex.RUnlock()

	for _, id := range history.order {
		record := history.flows[id]
		values := flowValues(record)

		if (scope != nil) && (scope.Evaluate(values) != filter.TrueResult) {
			continue
		}

		exported := ExportFlow{
			Flow:         flowView(record),
			Values:       values,
			ClientRandom: record.clientRandom,
			Messages:     make([]ExportMessage, 0, len(record.messageIDs)),
		}

		if exported.ClientRandom == [32]byte{} {
			exported.ClientRandom = record.session.ClientRandom
		}

		for _, messageID := range record.messageIDs {
			message := history.messages[messageID]
			exported.Messages = append(exported.Messages, ExportMessage{Message: messageView(message), Payload: message.payload})
		}

		flows = append(flows, exported)
	}

	return
}

func (history *History) Status() (status api.HistoryStatus) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	status = api.HistoryStatus{
		Flows:         len(history.order),
		OpenFlows:     history.openFlows,
		Messages:      len(history.messages),
		PayloadBytes:  history.payloadBytes,
		Exchanges:     len(history.exchanges),
		ExchangeBytes: history.exchangeBytes,
		EvictedFlows:  history.evictedFlows,
		Limits: api.HistoryLimits{
			Flows:             history.limits.Flows,
			Messages:          history.limits.Messages,
			FlowMessages:      history.limits.FlowMessages,
			PayloadBytes:      history.limits.PayloadBytes,
			FlowPayloadBytes:  history.limits.FlowPayloadBytes,
			Exchanges:         history.limits.Exchanges,
			FlowExchanges:     history.limits.FlowExchanges,
			ExchangeBytes:     history.limits.ExchangeBytes,
			FlowExchangeBytes: history.limits.FlowExchangeBytes,
		},
	}
	return
}

// what a filter sees of a stored flow: a flow is TLS or it is not, never unknown; a session the record layer read counts as a ClientHello the filter did not wait for
// the http fields are every value of its exchanges, a copy that does not change with later ones
func flowValues(record *flowRecord) (values filter.Values) {
	values = record.values
	session := record.session

	if record.http != nil {
		values.HTTP = &filter.HTTPValues{
			Methods:    slices.Clone(record.http.Methods),
			URIs:       slices.Clone(record.http.URIs),
			Hosts:      slices.Clone(record.http.Hosts),
			Codes:      slices.Clone(record.http.Codes),
			UserAgents: slices.Clone(record.http.UserAgents),
			StreamIDs:  slices.Clone(record.http.StreamIDs),
		}
	}

	switch {
	case (values.TLS != filter.PresentTLSState) && (session.Version != 0):
		values = values.WithClientHello(true, session.Version, session.ServerName, session.OfferedProtocols)
	case values.TLS == filter.UnknownTLSState:
		values.TLS = filter.AbsentTLSState
	default:
	}

	return
}

func flowView(record *flowRecord) (flow api.Flow) {
	values := flowValues(record)
	flow = api.Flow{
		ID:          record.id,
		Protocol:    redirect.ProtocolName(values.IPProtocol),
		State:       api.OpenFlowState,
		Opened:      record.opened,
		Closed:      record.closed,
		Client:      unmapped(values.Source),
		Destination: unmapped(values.Destination),
		Cookie:      record.cookie,
		Process: api.Process{
			PID:     values.PID,
			UID:     values.UID,
			GID:     values.GID,
			Comm:    values.Comm,
			Cmdline: values.Cmdline,
			Exe:     values.Exe,
		},
		TLS:          nil,
		Layer:        api.Layer(record.layer),
		Up:           record.traffic[tlsrecord.ClientDirection],
		Down:         record.traffic[tlsrecord.ServerDirection],
		PayloadBytes: record.payloadBytes,
		Truncated:    record.isTruncated,
	}

	if !record.isOpen {
		flow.State = api.ClosedFlowState
	}

	if values.TLS != filter.PresentTLSState {
		return
	}

	clientRandom := record.clientRandom

	if clientRandom == [32]byte{} {
		clientRandom = record.session.ClientRandom
	}

	flow.TLS = &api.TLSInfo{
		OfferedVersion: versionName(values.TLSVersion),
		ServerName:     values.ServerName,
		OfferedALPN:    values.Protocols,
		ClientRandom:   "",
		Version:        versionName(record.session.Version),
		CipherSuite:    "",
		ALPN:           record.session.Protocol,
	}

	if flow.TLS.OfferedALPN == nil {
		flow.TLS.OfferedALPN = []string{}
	}

	if clientRandom != [32]byte{} {
		flow.TLS.ClientRandom = hex.EncodeToString(clientRandom[:])
	}

	if record.session.CipherSuite != 0 {
		flow.TLS.CipherSuite = tlsrecord.CipherSuiteName(record.session.CipherSuite)
	}

	return
}

// the proxy sees IPv4 peers IPv4-mapped (::ffff:127.0.0.1), the API shows them as IPv4
func unmapped(addressPort netip.AddrPort) (text string) {
	text = netip.AddrPortFrom(addressPort.Addr().Unmap(), addressPort.Port()).String()
	return
}

// a version that is not known is empty, not 0x0000
func versionName(version uint16) (name string) {
	if version != 0 {
		name = tlsrecord.VersionName(version)
	}

	return
}

func messageView(record *messageRecord) (message api.Message) {
	message = api.Message{
		ID:             record.id,
		FlowID:         record.flowID,
		Direction:      api.Direction(intercept.DirectionName(record.direction)),
		Layer:          api.Layer(record.layer),
		Time:           record.time,
		Origin:         api.Origin(record.origin),
		Verdict:        api.Verdict(record.verdict),
		Edited:         record.isEdited,
		Length:         record.length,
		OriginalLength: record.originalLength,
		StoredLength:   len(record.payload),
	}
	return
}
