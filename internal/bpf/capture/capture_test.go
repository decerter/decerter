// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/decerter/decerter/internal/bpf/capture"
)

// Test if capture.ParsePacket returns with the expected output.
func TestParsePacketPositive(state *testing.T) {
	data := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	positiveCases := []struct {
		Record   []byte
		Expected capture.Packet
	}{
		{Record: record(7, 7, 1000, 1500, uint32(len(data)), 1, data, 0), Expected: capture.Packet{Cookie: 7, FlowCookie: 7, TimestampNs: 1000, Length: 1500, IsIngress: true, Data: data}},
		// a ringbuf record can be longer than the packet in it
		{Record: record(8, 8, 2000, 8, uint32(len(data)), 0, data, 5), Expected: capture.Packet{Cookie: 8, FlowCookie: 8, TimestampNs: 2000, Length: 8, IsIngress: false, Data: data}},
		{Record: record(9, 9, 3000, 0, 0, 0, nil, 0), Expected: capture.Packet{Cookie: 9, FlowCookie: 9, TimestampNs: 3000, Length: 0, IsIngress: false, Data: []byte{}}},
		// run mode: an upstream socket of the proxy carries the app's flow
		{Record: record(10, 4, 4000, uint32(len(data)), uint32(len(data)), 0, data, 0), Expected: capture.Packet{Cookie: 10, FlowCookie: 4, TimestampNs: 4000, Length: uint32(len(data)), IsIngress: false, Data: data}},
	}

	for _, positive := range positiveCases {
		packet, err := capture.ParsePacket(positive.Record)

		if (err != nil) || (packet.Cookie != positive.Expected.Cookie) || (packet.FlowCookie != positive.Expected.FlowCookie) || (packet.TimestampNs != positive.Expected.TimestampNs) || (packet.Length != positive.Expected.Length) || (packet.IsIngress != positive.Expected.IsIngress) || !bytes.Equal(packet.Data, positive.Expected.Data) {
			state.Errorf("Test of capture.ParsePacket function failed, packet should be %+v, packet: %+v, error: %v", positive.Expected, packet, err)
			return
		}
	}
}

// Test if capture.ParsePacket returns with the expected errors.
func TestParsePacketNegative(state *testing.T) {
	data := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	negativeCases := [][]byte{
		nil,
		record(7, 7, 1000, 1500, uint32(len(data)), 1, data, 0)[:39],
		// a captured length past the end of the record
		record(7, 7, 1000, 1500, uint32(len(data))+1, 1, data, 0),
	}

	for _, negative := range negativeCases {
		_, err := capture.ParsePacket(negative)

		if !errors.Is(err, capture.ErrShortRecord) {
			state.Errorf("Test of capture.ParsePacket function failed, record of %d bytes, error should be %v, error: %v", len(negative), capture.ErrShortRecord, err)
			return
		}
	}
}

// Test if capture.LoadBpfObjects returns with the expected errors for a snaplen out of range, before anything is loaded.
func TestLoadBpfObjectsNegative(state *testing.T) {
	for _, snaplen := range []uint32{0, capture.MaxSnaplen + 1} {
		_, _, _, err := capture.LoadBpfObjects(snaplen, false, nil, nil, nil)

		if !errors.Is(err, capture.ErrSnaplen) {
			state.Errorf("Test of capture.LoadBpfObjects function failed, snaplen %d, error should be %v, error: %v", snaplen, capture.ErrSnaplen, err)
			return
		}
	}
}

// struct packet_header of capture.h (cookie, flow cookie, boot time, length, captured length, direction, 7 bytes padding), the packet and extra bytes behind it
func record(cookie uint64, flowCookie uint64, timestamp uint64, length uint32, capturedLength uint32, direction uint8, data []byte, extra int) (raw []byte) {
	raw = binary.NativeEndian.AppendUint64(nil, cookie)
	raw = binary.NativeEndian.AppendUint64(raw, flowCookie)
	raw = binary.NativeEndian.AppendUint64(raw, timestamp)
	raw = binary.NativeEndian.AppendUint32(raw, length)
	raw = binary.NativeEndian.AppendUint32(raw, capturedLength)
	raw = append(raw, direction, 0, 0, 0, 0, 0, 0, 0)
	raw = append(raw, data...)
	raw = append(raw, make([]byte, extra)...)
	return
}
