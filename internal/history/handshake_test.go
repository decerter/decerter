// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package history_test

import (
	"bytes"
	"testing"

	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/tlsrecord"
)

func handshakeRecord(direction tlsrecord.Direction, contentType tlsrecord.ContentType, payload []byte) (record tlsrecord.Record) {
	record = tlsrecord.Record{Direction: direction, ContentType: contentType, Version: 0x0303, Decrypted: false, Epoch: 0, Sequence: 0, Datagram: 0, Length: len(payload), Payload: payload, Action: tlsrecord.ShowAction, Raw: nil}
	return
}

// Test if history.History keeps the handshake records of a flow by direction in their kept form: handshake, alert and change cipher spec records, not
// application data, not the record an intercepting conn sends on at once, a DTLS record of a later epoch only decrypted; the flow counts them, a direction
// stops at 16 KiB and is cut, and the bytes count in the payload limits.
func TestKeepHandshakePositive(state *testing.T) {
	flows := history.New(history.DefaultLimits(), nil)
	flowID := flows.OpenFlow(1, testValues(443, filter.PresentTLSState), [32]byte{})
	hello := handshakeRecord(tlsrecord.ClientDirection, tlsrecord.HandshakeContentType, []byte{1, 0, 0, 1, 9})
	flows.KeepHandshake(flowID, hello, false)
	forwarded := hello
	forwarded.Action = tlsrecord.ForwardAction
	flows.KeepHandshake(flowID, forwarded, false)
	flows.KeepHandshake(flowID, handshakeRecord(tlsrecord.ClientDirection, tlsrecord.ApplicationDataContentType, []byte("GET /")), false)
	alert := handshakeRecord(tlsrecord.ServerDirection, tlsrecord.AlertContentType, []byte{2, 40})
	alert.Decrypted = true
	flows.KeepHandshake(flowID, alert, false)
	up, isUpCut, found := flows.Handshake(flowID, tlsrecord.ClientDirection)
	down, isDownCut, _ := flows.Handshake(flowID, tlsrecord.ServerDirection)
	flow, _ := flows.Flow(flowID)

	if !found || isUpCut || isDownCut || !bytes.Equal(up, []byte{22, 3, 3, 0, 5, 1, 0, 0, 1, 9}) || !bytes.Equal(down, []byte{21, 3, 3, 0, 2, 2, 40}) || (flow.Up.HandshakeBytes != 10) ||
		(flow.Down.HandshakeBytes != 7) || (flow.PayloadBytes != 17) || (flows.Status().PayloadBytes != 17) {
		state.Fatalf("Test of history.History.KeepHandshake function failed, the records should be kept by direction, up: %x, down: %x, flow: %+v", up, down, flow)
	}

	// a direction stops at MaxHandshakeBytes
	big := bytes.Repeat([]byte{7}, 7000)

	for range 3 {
		flows.KeepHandshake(flowID, handshakeRecord(tlsrecord.ServerDirection, tlsrecord.HandshakeContentType, big), false)
	}

	flows.KeepHandshake(flowID, alert, false)
	down, isDownCut, _ = flows.Handshake(flowID, tlsrecord.ServerDirection)

	if !isDownCut || (len(down) != history.MaxHandshakeBytes) || (cap(down) != len(down)) {
		state.Errorf("Test of history.History.KeepHandshake function failed, the server records should be cut at %d bytes, length: %d, cut: %v", history.MaxHandshakeBytes, len(down), isDownCut)
	}

	// DTLS: epoch 0, and a later epoch only decrypted, with the 13-byte header
	dtlsFlow := flows.OpenFlow(2, testValues(4433, filter.PresentTLSState), [32]byte{})
	first := handshakeRecord(tlsrecord.ClientDirection, tlsrecord.HandshakeContentType, []byte{1})
	first.Version, first.Sequence = 0xfefd, 0x0102030405
	later := first
	later.Epoch = 1
	flows.KeepHandshake(dtlsFlow, first, true)
	flows.KeepHandshake(dtlsFlow, later, true)
	later.Decrypted = true
	flows.KeepHandshake(dtlsFlow, later, true)
	kept, _, _ := flows.Handshake(dtlsFlow, tlsrecord.ClientDirection)

	if !bytes.Equal(kept, []byte{22, 0xfe, 0xfd, 0, 0, 0, 1, 2, 3, 4, 5, 0, 1, 1, 22, 0xfe, 0xfd, 0, 1, 0, 1, 2, 3, 4, 5, 0, 1, 1}) {
		state.Errorf("Test of history.History.KeepHandshake function failed, the DTLS records should be kept with their epoch and sequence number, kept: %x", kept)
	}
}

// Test if history.History keeps no handshake records for a nil history or a flow it doesn't have, keeps none past the payload limits and drops them with
// the flow it evicts.
func TestKeepHandshakeNegative(state *testing.T) {
	var nilHistory *history.History

	nilHistory.KeepHandshake(1, handshakeRecord(tlsrecord.ClientDirection, tlsrecord.HandshakeContentType, []byte{1}), false)
	limits := history.Limits{Flows: 10, Messages: 10, FlowMessages: 10, PayloadBytes: 30, FlowPayloadBytes: 20, Exchanges: 10, FlowExchanges: 10, ExchangeBytes: 100, FlowExchangeBytes: 100}
	flows := history.New(limits, nil)
	flows.KeepHandshake(99, handshakeRecord(tlsrecord.ClientDirection, tlsrecord.HandshakeContentType, []byte{1}), false)

	if _, _, found := flows.Handshake(99, tlsrecord.ClientDirection); found {
		state.Errorf("Test of history.History.Handshake function failed, an unknown flow should not be found")
	}

	oldest := flows.OpenFlow(1, testValues(443, filter.PresentTLSState), [32]byte{})
	flows.KeepHandshake(oldest, handshakeRecord(tlsrecord.ClientDirection, tlsrecord.HandshakeContentType, bytes.Repeat([]byte{1}, 30)), false)
	kept, isCut, _ := flows.Handshake(oldest, tlsrecord.ClientDirection)

	if !isCut || (len(kept) != 20) {
		state.Errorf("Test of history.History.KeepHandshake function failed, the flow should keep 20 bytes and be cut, length: %d, cut: %v", len(kept), isCut)
	}

	// the newer flow needs the room of the oldest one
	newer := flows.OpenFlow(2, testValues(443, filter.PresentTLSState), [32]byte{})
	flows.KeepHandshake(newer, handshakeRecord(tlsrecord.ClientDirection, tlsrecord.HandshakeContentType, bytes.Repeat([]byte{1}, 10)), false)
	_, _, isOldest := flows.Handshake(oldest, tlsrecord.ClientDirection)
	kept, isCut, _ = flows.Handshake(newer, tlsrecord.ClientDirection)

	if isOldest || isCut || (len(kept) != 15) || (flows.Status().PayloadBytes != 15) {
		state.Errorf("Test of history.History.KeepHandshake function failed, the oldest flow should be evicted with its records, oldest: %v, length: %d, status: %+v", isOldest, len(kept), flows.Status())
	}
}
