// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/api"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/pcapng"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// Test if capture.packetRing keeps the latest packets up to its limit, oldest first, and finds the packets of a socket, never by the flow its socket carries.
func TestPacketRingPositive(state *testing.T) {
	ring := newPacketRing(100)

	for index := range 10 {
		ring.add(capturebpf.Packet{Cookie: uint64(index % 2), FlowCookie: uint64(10 + index%2), TimestampNs: uint64(index), Length: 30, IsIngress: false, Data: make([]byte, 30)})
	}

	timestamps := func(packets []capturebpf.Packet) (result []uint64) {
		for _, packet := range packets {
			result = append(result, packet.TimestampNs)
		}

		return
	}
	all := ring.packetsOf(map[uint64][32]byte{0: {}, 1: {}})
	bySocket := ring.packetsOf(map[uint64][32]byte{1: {}})
	byFlow := ring.packetsOf(map[uint64][32]byte{10: {}})

	if !slices.Equal(timestamps(all), []uint64{7, 8, 9}) || !slices.Equal(timestamps(bySocket), []uint64{7, 9}) || (len(byFlow) != 0) || (ring.bytes != 90) || (len(ring.packets)-ring.start != 3) {
		state.Errorf("Test of capture.packetRing failed, the ring should keep the last 3 packets, all: %v, socket 1: %v, flow 10: %v, bytes: %d", timestamps(all), timestamps(bySocket), timestamps(byFlow), ring.bytes)
		return
	}

	// a packet larger than the ring pushes everything out, itself too
	ring.add(capturebpf.Packet{Cookie: 0, FlowCookie: 10, TimestampNs: 100, Length: 200, IsIngress: false, Data: make([]byte, 200)})

	if (len(ring.packetsOf(map[uint64][32]byte{0: {}, 1: {}})) != 0) || (ring.bytes != 0) {
		state.Errorf("Test of capture.packetRing failed, a packet over the limit should leave the ring empty, bytes: %d", ring.bytes)
		return
	}
}

// a hub with a history that saw the TLS session of cookie 7 from its start
func exportHub(state *testing.T, session tlsSession) (hub *Hub, packets []capturebpf.Packet) {
	hub, err := NewHub(capturebpf.MaxSnaplen, nil, nil, nil, history.New(history.DefaultLimits(), nil), false, slog.New(slog.DiscardHandler))

	if err != nil {
		state.Fatalf("Test of capture.NewHub failed, error: %s", err.Error())
	}

	hub.gate.lookup = testLookup
	hub.secretsBpfMaps = testBpfMaps
	packets = tcpPackets(7, tlsClient, tlsServer, session.chunks, true)

	for _, packet := range packets {
		err = hub.gate.handle(packet, time.Now(), hub.emit)

		if err != nil {
			state.Fatalf("Test of capture.Hub failed, cannot hand a packet out, error: %s", err.Error())
		}
	}

	return
}

// Test if capture.Hub.Export returns with the expected output: the packets the hub kept of the flow, with the key log of its session in front of them while secrets_map has it, decrypted with plaintext.
func TestHubExportPositive(state *testing.T) {
	for _, session := range testSessions(state) {
		secrets := useTestSecrets(state, true, session)
		hub, packets := exportHub(state, session)
		positiveCases := []struct {
			Name      string
			Found     bool
			Plaintext bool
		}{
			{Name: "with the secrets", Found: true},
			{Name: "without the secrets", Found: false},
			{Name: "plaintext", Found: true, Plaintext: true},
		}

		for _, positive := range positiveCases {
			secrets.setFound(positive.Found)
			output := bytes.Buffer{}
			err := hub.Export(&output, map[uint64][32]byte{7: session.clientRandom}, positive.Plaintext, slog.New(slog.DiscardHandler))

			if err != nil {
				state.Fatalf("Test of capture.Hub.Export failed, case %q %s, error: %s", positive.Name, tlsrecord.VersionName(session.version), err.Error())
			}

			blocks, err := readBlocks(output.Bytes())

			if err != nil {
				state.Fatalf("Test of capture.Hub.Export failed, case %q %s, cannot read output, error: %s", positive.Name, tlsrecord.VersionName(session.version), err.Error())
			}

			if positive.Plaintext {
				streams, _ := streamsOf(blocks)

				if !bytes.Equal(streams[tlsrecord.ClientDirection], session.request) || !bytes.Equal(streams[tlsrecord.ServerDirection], session.response) {
					state.Errorf("Test of capture.Hub.Export failed, case %q %s, the export should have the decrypted streams, streams: %q", positive.Name, tlsrecord.VersionName(session.version), streams)
					return
				}

				continue
			}

			written, keyLogs, _ := capturedOf(blocks)
			expectedKeyLogs := []string(nil)

			if positive.Found {
				expectedKeyLogs = []string{session.keyLog}
			}

			if !slices.Equal(keyLogs, expectedKeyLogs) || !slices.EqualFunc(written, dataOf(packets), bytes.Equal) {
				state.Errorf("Test of capture.Hub.Export failed, case %q %s, the export should have the %d packets and the key logs %q, packets: %d, key logs: %q", positive.Name, tlsrecord.VersionName(session.version), len(packets), expectedKeyLogs, len(written), keyLogs)
				return
			}
		}
	}
}

// Test if capture.Hub.Export returns with the expected output for the udp sessions of one unconnected app socket in run mode: each session has its own
// upstream socket, all of them carry the app's flow cookie; the export of one session has only the packets of its upstream socket.
func TestHubExportSessionsPositive(state *testing.T) {
	hub, err := NewHub(capturebpf.MaxSnaplen, nil, nil, nil, nil, true, slog.New(slog.DiscardHandler))

	if err != nil {
		state.Fatalf("Test of capture.NewHub failed, error: %s", err.Error())
	}

	hub.ring = newPacketRing(1 << 20)
	sessions := map[uint64]Endpoint{21: tlsServer, 22: {Address: netip.MustParseAddr("127.0.0.2"), Port: 53}}

	for socket, server := range sessions {
		data := UDPPacket(nil, tlsClient, server, []byte("query"))
		hub.ring.add(capturebpf.Packet{Cookie: socket, FlowCookie: 1, TimestampNs: socket, Length: uint32(len(data)), IsIngress: false, Data: data})
	}

	output := bytes.Buffer{}
	err = hub.Export(&output, map[uint64][32]byte{22: {}}, false, slog.New(slog.DiscardHandler))

	if err != nil {
		state.Fatalf("Test of capture.Hub.Export failed, error: %s", err.Error())
	}

	blocks, err := readBlocks(output.Bytes())

	if err != nil {
		state.Fatalf("Test of capture.Hub.Export failed, cannot read output, error: %s", err.Error())
	}

	written, _, _ := capturedOf(blocks)

	if (len(written) != 1) || !bytes.Contains(written[0], []byte{127, 0, 0, 2}) {
		state.Errorf("Test of capture.Hub.Export failed, only the packet of the session's upstream socket should be exported, packets: %x", written)
		return
	}
}

// Test if capture.Hub.Export returns with the expected errors: a hub without a history keeps no packets, a snaplen of zero and an output that fails can't be written.
func TestHubExportNegative(state *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	hub := testHub(state, false)
	err := hub.Export(&bytes.Buffer{}, map[uint64][32]byte{}, false, logger)

	if !errors.Is(err, ErrNoPacketHistory) {
		state.Errorf("Test of capture.Hub.Export failed, error should be %v, error: %v", ErrNoPacketHistory, err)
		return
	}

	session := testSessions(state)[1]
	useTestSecrets(state, true, session)
	hub, _ = exportHub(state, session)
	hub.snaplen = 0
	err = hub.Export(&bytes.Buffer{}, map[uint64][32]byte{7: session.clientRandom}, false, logger)

	if !errors.Is(err, pcapng.ErrSnaplen) {
		state.Errorf("Test of capture.Hub.Export failed, error should be %v, error: %v", pcapng.ErrSnaplen, err)
		return
	}

	// more than the buffer of the file, so the output fails before the end
	hub, _ = exportHub(state, session)
	large := tcpPackets(8, Endpoint{Address: tlsClient.Address, Port: 40008}, tlsServer, opaqueChunks(5), false)

	for _, packet := range large {
		err = hub.gate.handle(packet, time.Now(), hub.emit)

		if err != nil {
			state.Fatalf("Test of capture.Hub failed, cannot hand a packet out, error: %s", err.Error())
		}
	}

	for _, plaintext := range []bool{false, true} {
		err = hub.Export(&failingWriter{writes: 0, limit: 0, output: nil}, map[uint64][32]byte{8: {}}, plaintext, logger)

		if !errors.Is(err, pcapng.ErrWrite) {
			state.Errorf("Test of capture.Hub.Export failed, plaintext %v, error should be %v, error: %v", plaintext, pcapng.ErrWrite, err)
			return
		}
	}
}

// Test if capture.WriteHistory returns with the expected output for a UDP flow and a TCP flow between an IPv4 and an IPv6 address: one datagram per message, the bytes the history did not keep as a hole with a comment, and the comments of the flows.
func TestWriteHistoryUDPPositive(state *testing.T) {
	opened := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	udpFlow := history.ExportFlow{
		Flow:         api.Flow{ID: 4, State: api.ClosedFlowState, Opened: opened, Closed: opened.Add(time.Second), Process: api.Process{PID: 7, UID: 0, Comm: "dig"}, TLS: &api.TLSInfo{Version: "DTLS 1.2", CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ALPN: "dot"}, Truncated: true},
		Values:       filter.Values{IPProtocol: syscall.IPPROTO_UDP, Source: netip.MustParseAddrPort("192.0.2.10:5353"), Destination: netip.MustParseAddrPort("[2001:db8::53]:53")},
		ClientRandom: [32]byte{},
		Messages: []history.ExportMessage{
			{Message: api.Message{ID: 1, Direction: api.UpDirection, Time: opened.Add(time.Millisecond), Verdict: api.DropVerdict, Length: 0, OriginalLength: 5}, Payload: nil},
			{Message: api.Message{ID: 2, Direction: api.UpDirection, Time: opened.Add(2 * time.Millisecond), Verdict: api.ForwardVerdict, Edited: true, Length: 5, OriginalLength: 6}, Payload: []byte("query")},
			{Message: api.Message{ID: 3, Direction: api.DownDirection, Time: opened.Add(3 * time.Millisecond), Verdict: api.ForwardVerdict, Length: 6, OriginalLength: 6}, Payload: []byte("answer")},
		},
	}
	tcpFlow := history.ExportFlow{
		Flow:         api.Flow{ID: 5, State: api.OpenFlowState, Opened: opened.Add(10 * time.Millisecond), Process: api.Process{PID: 8, UID: 0, Comm: "nc"}},
		Values:       filter.Values{IPProtocol: syscall.IPPROTO_TCP, Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("192.0.2.20:7")},
		ClientRandom: [32]byte{},
		Messages: []history.ExportMessage{
			// the history kept 4 of the 10 bytes
			{Message: api.Message{ID: 6, Direction: api.UpDirection, Time: opened.Add(11 * time.Millisecond), Verdict: api.ForwardVerdict, Length: 10, OriginalLength: 10}, Payload: []byte("echo")},
			{Message: api.Message{ID: 7, Direction: api.UpDirection, Time: opened.Add(12 * time.Millisecond), Verdict: api.ForwardVerdict, Length: 4, OriginalLength: 4}, Payload: []byte("more")},
		},
	}
	output := bytes.Buffer{}
	err := WriteHistory(&output, []history.ExportFlow{tcpFlow, udpFlow})

	if err != nil {
		state.Fatalf("Test of capture.WriteHistory failed, error: %s", err.Error())
	}

	blocks, err := readBlocks(output.Bytes())

	if err != nil {
		state.Fatalf("Test of capture.WriteHistory failed, cannot read output, error: %s", err.Error())
	}

	// the two datagrams first, between IPv4-mapped and IPv6 addresses; then the TCP flow without a FIN, still open, with a hole of 6 bytes in front of "more"
	expectedComments := []string{
		notePrefix + "flow 4 of dig (pid 7, uid 0), tls DTLS 1.2, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, alpn dot; the history did not keep every message of this flow; message 1 was dropped, 5 bytes the client sent are not on the wire; message 2 was changed, the client sent 6 bytes: GET /api/v1/messages/2 has them",
		notePrefix + "flow 5 of nc (pid 8, uid 0)",
		notePrefix + "the history did not keep 6 bytes of message 6",
	}
	comments := []string{}
	payloads := []string{}

	for _, block := range blocks {
		if block.comment != "" {
			comments = append(comments, block.comment)
		}

		if len(block.payload) > 0 {
			payloads = append(payloads, string(block.payload))
		}
	}

	if (len(blocks) != 7) || !slices.Equal(comments, expectedComments) || !slices.Equal(payloads, []string{"query", "answer", "echo", "more"}) {
		state.Errorf("Test of capture.WriteHistory failed, 7 packets should carry %q with the comments %q, packets: %d, payloads: %q, comments: %q", []string{"query", "answer", "echo", "more"}, expectedComments, len(blocks), payloads, comments)
		return
	}

	if (blocks[0].header.protocol != syscall.IPPROTO_UDP) || (blocks[0].header.source.Address != netip.MustParseAddr("::ffff:192.0.2.10")) || (blocks[6].header.sequence != historyClientSequence+1+10) {
		state.Errorf("Test of capture.WriteHistory failed, the datagrams should be IPv6 from the mapped client and the last segment behind the hole, first: %+v, last: %+v", blocks[0].header, blocks[6].header)
		return
	}
}

// Test if capture.WriteHistory returns with the expected output for a flow with more notes than a pcapng comment holds: 20000 dropped messages give
// a FIN comment within maxNoteBytes that counts the notes it leaves out, and the export is written.
func TestWriteHistoryNotesPositive(state *testing.T) {
	opened := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	flow := history.ExportFlow{
		Flow:   api.Flow{ID: 1, State: api.ClosedFlowState, Opened: opened, Closed: opened.Add(time.Second), Process: api.Process{PID: 8, UID: 0, Comm: "nc"}},
		Values: filter.Values{IPProtocol: syscall.IPPROTO_TCP, Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("192.0.2.20:7")},
	}

	for id := range uint64(20000) {
		flow.Messages = append(flow.Messages, history.ExportMessage{Message: api.Message{ID: id + 1, Direction: api.UpDirection, Time: opened, Verdict: api.DropVerdict, Length: 0, OriginalLength: 5}, Payload: nil})
	}

	output := bytes.Buffer{}
	err := WriteHistory(&output, []history.ExportFlow{flow})

	if err != nil {
		state.Fatalf("Test of capture.WriteHistory failed, the export should be written, error: %s", err.Error())
	}

	blocks, err := readBlocks(output.Bytes())

	if err != nil {
		state.Fatalf("Test of capture.WriteHistory failed, cannot read output, error: %s", err.Error())
	}

	comments := []string{}

	for _, block := range blocks {
		if block.comment != "" {
			comments = append(comments, block.comment)
		}
	}

	// the SYN has the flow, the FIN the notes of the dropped messages
	if (len(blocks) != 6) || (len(comments) != 2) || (len(comments[1]) > len(notePrefix)+maxNoteBytes+64) || !strings.Contains(comments[1], " more notes, the API has every message") {
		state.Errorf("Test of capture.WriteHistory failed, the FIN should carry one comment that counts the notes left out, packets: %d, comments: %d, length of the comments: %d", len(blocks), len(comments), len(strings.Join(comments, "")))
		return
	}
}

// Test if capture.WriteHistory returns with the expected output for UDP messages the history kept only partly, not at all or longer than a datagram:
// each datagram is as long as what is written and its comment says how many bytes of which message are not in it.
func TestWriteHistoryDatagramsPositive(state *testing.T) {
	opened := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	large := bytes.Repeat([]byte("l"), 70000)
	flow := history.ExportFlow{
		Flow:   api.Flow{ID: 3, State: api.ClosedFlowState, Opened: opened, Closed: opened.Add(time.Second), Process: api.Process{PID: 8, UID: 0, Comm: "dig"}},
		Values: filter.Values{IPProtocol: syscall.IPPROTO_UDP, Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("192.0.2.20:53")},
		Messages: []history.ExportMessage{
			{Message: api.Message{ID: 1, Direction: api.UpDirection, Time: opened, Verdict: api.ForwardVerdict, Length: 5, OriginalLength: 5}, Payload: []byte("whole")},
			{Message: api.Message{ID: 2, Direction: api.DownDirection, Time: opened, Verdict: api.ForwardVerdict, Length: 10, OriginalLength: 10}, Payload: []byte("part")},
			{Message: api.Message{ID: 3, Direction: api.UpDirection, Time: opened, Verdict: api.ForwardVerdict, Length: 8, OriginalLength: 8}, Payload: nil},
			{Message: api.Message{ID: 4, Direction: api.DownDirection, Time: opened, Verdict: api.ForwardVerdict, Length: len(large), OriginalLength: len(large)}, Payload: large},
		},
	}
	output := bytes.Buffer{}

	if err := WriteHistory(&output, []history.ExportFlow{flow}); err != nil {
		state.Fatalf("Test of capture.WriteHistory failed, the export should be written, error: %s", err.Error())
	}

	blocks, err := readBlocks(output.Bytes())

	if err != nil {
		state.Fatalf("Test of capture.WriteHistory failed, cannot read output, error: %s", err.Error())
	}

	expected := []struct {
		Length  int
		Comment string
	}{
		{Length: 5, Comment: notePrefix + "flow 3 of dig (pid 8, uid 0)"},
		{Length: 4, Comment: notePrefix + "the history did not keep 6 bytes of message 2"},
		{Length: 0, Comment: notePrefix + "the history did not keep 8 bytes of message 3"},
		{Length: maxHistoryDatagram, Comment: notePrefix + fmt.Sprintf("%d bytes of message 4 do not fit the datagram", len(large)-maxHistoryDatagram)},
	}

	if len(blocks) != len(expected) {
		state.Errorf("Test of capture.WriteHistory failed, there should be %d datagrams, blocks: %d", len(expected), len(blocks))
		return
	}

	for index, block := range blocks {
		if (block.header.protocol != syscall.IPPROTO_UDP) || (len(block.payload) != expected[index].Length) || (block.comment != expected[index].Comment) {
			state.Errorf("Test of capture.WriteHistory failed, datagram %d should have %d bytes and the comment %q, length: %d, comment: %q", index, expected[index].Length, expected[index].Comment, len(block.payload), block.comment)
			return
		}
	}
}

// Test if capture.packetNote returns with the expected output: notes joined, the ones past maxNoteBytes counted with the default or its own words,
// empty after it was taken.
func TestPacketNotePositive(state *testing.T) {
	note := packetNote{}
	empty := note.take()
	note.add("first")
	note.add("second")
	joined := note.take()
	note.add(strings.Repeat("n", maxNoteBytes))
	note.add("left out")
	note.add("left out too")
	counted := note.take()
	history := packetNote{text: "", omitted: 0, more: historyMoreNotes}
	history.add(strings.Repeat("n", maxNoteBytes))
	history.add("left out")

	if (empty != "") || (joined != notePrefix+"first; second") || !strings.HasSuffix(counted, "n; 2 more notes") || !strings.HasSuffix(history.take(), "; 1 "+historyMoreNotes) || !note.isEmpty() {
		state.Errorf("Test of capture.packetNote failed, notes: %q %q %q", empty, joined, counted)
	}
}

// Test if capture.WriteHistory returns with the expected errors: an output that fails.
func TestWriteHistoryNegative(state *testing.T) {
	opened := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	large := history.ExportFlow{
		Flow:   api.Flow{ID: 1, State: api.OpenFlowState, Opened: opened, Process: api.Process{PID: 8, UID: 0, Comm: "nc"}},
		Values: filter.Values{IPProtocol: syscall.IPPROTO_TCP, Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("192.0.2.20:7")},
		Messages: []history.ExportMessage{
			{Message: api.Message{ID: 2, Direction: api.UpDirection, Time: opened, Verdict: api.ForwardVerdict, Length: 100000, OriginalLength: 100000}, Payload: bytes.Repeat([]byte("x"), 100000)},
		},
	}
	negativeCases := []struct {
		Name  string
		Flows []history.ExportFlow
	}{
		// the file is written at its end
		{Name: "empty history", Flows: nil},
		// more than the buffer of the file
		{Name: "large flow", Flows: []history.ExportFlow{large}},
	}

	for _, negative := range negativeCases {
		err := WriteHistory(&failingWriter{writes: 0, limit: 0, output: nil}, negative.Flows)

		if !errors.Is(err, pcapng.ErrWrite) || !strings.Contains(err.Error(), errTestWrite.Error()) {
			state.Errorf("Test of capture.WriteHistory failed, case %q, error should be %v, error: %v", negative.Name, pcapng.ErrWrite, err)
			return
		}
	}
}
