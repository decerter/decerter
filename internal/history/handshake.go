// SPDX-License-Identifier: AGPL-3.0-only

package history

import (
	"github.com/decerter/decerter/internal/tlsrecord"
)

// a record of a flow's TLS or DTLS handshake as the record layer gave it, kept so its hellos and certificates can be decoded on request: handshake,
// alert and change cipher spec records, the plaintext of the decrypted ones (application data is a message); only the bytes are copied here
// an intercepting TLS conn gives a record that goes on at once a second time once it is read, the first one (ForwardAction) is left out; a DTLS record
// of a later epoch that was not decrypted is left out; each direction keeps at most MaxHandshakeBytes, a record past them is cut, and the bytes count in
// the payload limits, so they go with the flow
func (history *History) KeepHandshake(flowID uint64, record tlsrecord.Record, isDTLS bool) {
	if (history == nil) || !isKeptRecord(record, isDTLS) {
		return
	}

	history.mutex.Lock()
	defer history.mutex.Unlock()
	flow, found := history.flows[flowID]

	if !found || flow.isHandshakeCut[record.Direction] {
		return
	}

	kept := tlsrecord.AppendKept(nil, record, isDTLS)
	wanted := int64(len(kept))

	for history.payloadBytes+wanted > history.limits.PayloadBytes {
		if !history.evict(flow.id) {
			break
		}
	}

	room := min(int64(MaxHandshakeBytes-len(flow.handshake[record.Direction])), history.limits.FlowPayloadBytes-flow.payloadBytes, history.limits.PayloadBytes-history.payloadBytes)
	room = max(0, room)

	if room < wanted {
		kept = kept[:room]
		flow.isHandshakeCut[record.Direction] = true
	}

	flow.handshake[record.Direction] = append(flow.handshake[record.Direction], kept...)
	flow.payloadBytes += int64(len(kept))
	history.payloadBytes += int64(len(kept))
}

func isKeptRecord(record tlsrecord.Record, isDTLS bool) (isKept bool) {
	switch record.ContentType {
	case
		tlsrecord.HandshakeContentType,
		tlsrecord.AlertContentType,
		tlsrecord.ChangeCipherSpecContentType:
	default:
		return
	}

	if isDTLS {
		isKept = record.Decrypted || (record.Epoch == 0)
		return
	}

	isKept = record.Action != tlsrecord.ForwardAction
	return
}

// the handshake records one direction of a flow kept, shared with the history and never changed; isCut when a record did not fit
func (history *History) Handshake(flowID uint64, direction tlsrecord.Direction) (data []byte, isCut bool, found bool) {
	history.mutex.RLock()
	defer history.mutex.RUnlock()
	flow, found := history.flows[flowID]

	if !found {
		return
	}

	kept := flow.handshake[direction]
	data, isCut = kept[:len(kept):len(kept)], flow.isHandshakeCut[direction]
	return
}
