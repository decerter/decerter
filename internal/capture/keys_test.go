// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/pcapng"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
)

// the packets of the blocks as they were captured and the key logs of the DSBs, in their order: "p" for a packet, "k" for a DSB
func capturedOf(blocks []pcapBlock) (packets [][]byte, keyLogs []string, order string) {
	for _, block := range blocks {
		if block.blockType == decryptionSecretsBlockType {
			keyLogs = append(keyLogs, string(block.data))
			order += "k"
			continue
		}

		packets = append(packets, block.data)
		order += "p"
	}

	return
}

// the data of the packets
func dataOf(packets []capturebpf.Packet) (data [][]byte) {
	for _, packet := range packets {
		data = append(data, packet.Data)
	}

	return
}

// Test if the recorder returns with the expected output for TLS sessions with their secrets: every packet as it was captured, the key log of the session in a DSB in front of its ClientHello.
func TestRecorderKeysPositive(state *testing.T) {
	positiveCases := []struct {
		Name    string
		Chunks  func(session tlsSession) []sessionChunk
		FoundAt int
		// the session started before the writer, its first packet is the first one of the request
		IsKnown bool
	}{
		{Name: "at once", Chunks: func(session tlsSession) []sessionChunk { return session.chunks }, FoundAt: 0},
		{Name: "behind the response", Chunks: func(session tlsSession) []sessionChunk { return session.chunks }, FoundAt: -4},
		{Name: "client hello in two segments", Chunks: splitHello, FoundAt: 0},
		{Name: "session started before the writer", Chunks: func(session tlsSession) []sessionChunk { return session.chunks }, FoundAt: 0, IsKnown: true},
	}

	for _, session := range testSessions(state) {
		for _, positive := range positiveCases {
			packets := tcpPackets(1, tlsClient, tlsServer, positive.Chunks(session), true)
			// the DSB comes in front of the ClientHello, which is behind the handshake
			expectedOrder := "ppp" + "k" + string(bytes.Repeat([]byte("p"), len(packets)-3))
			known := map[uint64][32]byte(nil)

			if positive.IsKnown {
				packets = packets[3+len(session.chunks)-2:]
				expectedOrder = "k" + string(bytes.Repeat([]byte("p"), len(packets)))
				known = map[uint64][32]byte{1: session.clientRandom}
			}

			run := recording{plaintext: false, packets: packets, otherHeld: 0, tick: 0, foundAt: positive.FoundAt, known: known, scope: nil, isKeyless: false}

			if run.foundAt < 0 {
				run.foundAt += len(run.packets)
			}

			secrets := useTestSecrets(state, false, session)
			blocks, current, err := run.blocks(secrets)

			if err != nil {
				state.Fatalf("Test of capture recorder failed, case %q %s, error: %s", positive.Name, tlsrecord.VersionName(session.version), err.Error())
			}

			written, keyLogs, order := capturedOf(blocks)

			if (order != expectedOrder) || !slices.Equal(keyLogs, []string{session.keyLog}) || !slices.EqualFunc(written, dataOf(packets), bytes.Equal) {
				state.Errorf("Test of capture recorder failed, case %q %s, blocks should be %q with the key log of the session and the packets as they were captured, blocks: %q, key logs: %q", positive.Name, tlsrecord.VersionName(session.version), expectedOrder, order, keyLogs)
				return
			}

			if (current.keyedSessions != 1) || (current.keylessSessions != 0) || (current.heldBytes != 0) || (len(current.holding) != 0) || (current.packets != uint64(len(packets))) {
				state.Errorf("Test of capture recorder failed, case %q %s, one session should have secrets and nothing should wait, sessions: %d and %d, held: %d, packets: %d", positive.Name, tlsrecord.VersionName(session.version), current.keyedSessions, current.keylessSessions, current.heldBytes, current.packets)
				return
			}

			err = run.checkWriteErrors(secrets, len(blocks))

			if err != nil {
				state.Errorf("Test of capture recorder failed, case %q %s, error: %s", positive.Name, tlsrecord.VersionName(session.version), err.Error())
				return
			}
		}
	}
}

// Test if the recorder returns with the expected errors for TLS sessions whose secrets it can't write: every packet is written as it was captured, without a DSB, when the secrets did not come, too much waited, or the ClientHello can't be read.
func TestRecorderKeysNegative(state *testing.T) {
	session := testSessions(state)[1]
	sessionPackets := tcpPackets(1, tlsClient, tlsServer, session.chunks, true)
	cutPackets := slices.Clone(sessionPackets)
	cutPackets[3].Length += 10
	// a ClientHello whose body is not there: the record is whole, the handshake message in it is empty
	badHello := []byte{byte(tlsrecord.HandshakeContentType), 3, 1, 0, 4, 1, 0, 0, 0}
	negativeCases := []struct {
		Name      string
		Packets   []capturebpf.Packet
		LookErr   error
		OtherHeld int
		Tick      time.Duration
		// a capture without the secrets uprobe
		IsKeyless bool
		// the lookups of the secrets of the session
		IsLookedUp bool
		// the session counts as one without secrets
		IsWithoutSecrets bool
	}{
		{Name: "no secrets before the capture stopped", Packets: sessionPackets, LookErr: errors.New("secrets_map is not there"), IsLookedUp: true, IsWithoutSecrets: true},
		{Name: "no secrets before the hold timeout", Packets: tcpPackets(1, tlsClient, tlsServer, session.chunks, false), Tick: holdTimeout + time.Second, IsLookedUp: true, IsWithoutSecrets: true},
		{Name: "too many bytes wait for the secrets", Packets: tcpPackets(1, tlsClient, tlsServer, slices.Concat(session.chunks, opaqueChunks(maxHoldBytes/16384+1)), true), IsLookedUp: true, IsWithoutSecrets: true},
		{Name: "too many bytes of all flows wait for secrets", Packets: sessionPackets, OtherHeld: maxTotalHoldBytes, IsLookedUp: true, IsWithoutSecrets: true},
		{Name: "client hello that can't be read", Packets: tcpPackets(1, tlsClient, tlsServer, []sessionChunk{{direction: tlsrecord.ClientDirection, data: badHello}}, true), IsWithoutSecrets: true},
		{Name: "client hello the snaplen cut", Packets: cutPackets},
		{Name: "no secrets uprobe", Packets: sessionPackets, IsKeyless: true},
	}

	for _, negative := range negativeCases {
		secrets := useTestSecrets(state, false, session)
		secrets.setErr(negative.LookErr)
		run := recording{plaintext: false, packets: negative.Packets, otherHeld: negative.OtherHeld, tick: negative.Tick, foundAt: -1, known: nil, scope: nil, isKeyless: negative.IsKeyless}
		blocks, current, err := run.blocks(secrets)

		if err != nil {
			state.Fatalf("Test of capture recorder failed, case %q, error: %s", negative.Name, err.Error())
		}

		written, keyLogs, _ := capturedOf(blocks)

		if (len(keyLogs) != 0) || !slices.EqualFunc(written, dataOf(negative.Packets), bytes.Equal) {
			state.Errorf("Test of capture recorder failed, case %q, the %d packets should be written as they were captured without a DSB, packets: %d, key logs: %q", negative.Name, len(negative.Packets), len(written), keyLogs)
			return
		}

		if ((secrets.lookups > 0) != negative.IsLookedUp) || ((current.keylessSessions == 1) != negative.IsWithoutSecrets) || (current.keyedSessions != 0) || (current.heldBytes != negative.OtherHeld) || (len(current.holding) != 0) {
			state.Errorf("Test of capture recorder failed, case %q, the secrets should be looked up: %v, without secrets: %v, lookups: %d, sessions: %d and %d, held: %d", negative.Name, negative.IsLookedUp, negative.IsWithoutSecrets, secrets.lookups, current.keyedSessions, current.keylessSessions, current.heldBytes-negative.OtherHeld)
			return
		}

		err = run.checkWriteErrors(secrets, len(blocks))

		if err != nil {
			state.Errorf("Test of capture recorder failed, case %q, error: %s", negative.Name, err.Error())
			return
		}
	}
}

// Test if the recorder returns with the expected output for a scope that needs the ClientHello: a flow is written once its first bytes decide it in scope, at the latest after the hold timeout or when the capture stops, a flow out of scope never.
func TestRecorderScopePositive(state *testing.T) {
	session := testSessions(state)[1]
	inScope := tcpPackets(1, tlsClient, tlsServer, session.chunks, true)
	other := tcpPackets(2, Endpoint{Address: tlsClient.Address, Port: 40001}, tlsServer, []sessionChunk{{direction: tlsrecord.ClientDirection, data: []byte("GET / HTTP/1.1\r\n\r\n")}}, true)
	// only the handshake: the first bytes never come
	silent := tcpPackets(3, Endpoint{Address: tlsClient.Address, Port: 40002}, tlsServer, nil, false)
	positiveCases := []struct {
		Name    string
		Scope   string
		Packets []capturebpf.Packet
		Tick    time.Duration
		Written int
		KeyLogs int
	}{
		{Name: "decided by the client hello", Scope: "tls.sni == \"example.com\"", Packets: slices.Concat(other, inScope), Written: len(inScope), KeyLogs: 1},
		{Name: "out of scope after the hold timeout", Scope: "tls.sni == \"example.com\"", Packets: silent, Tick: holdTimeout + time.Second, Written: 0},
		{Name: "in scope after the hold timeout", Scope: "!(tls.sni == \"other.com\")", Packets: silent, Tick: holdTimeout + time.Second, Written: len(silent)},
		{Name: "in scope when the capture stopped", Scope: "!(tls.sni == \"other.com\")", Packets: slices.Concat(silent, inScope), Written: len(silent) + len(inScope), KeyLogs: 1},
	}

	for _, positive := range positiveCases {
		scope, err := filter.Parse(positive.Scope)

		if err != nil {
			state.Fatalf("Test of capture recorder failed, case %q, cannot parse filter, error: %s", positive.Name, err.Error())
		}

		secrets := useTestSecrets(state, false, session)
		run := recording{plaintext: false, packets: positive.Packets, otherHeld: 0, tick: positive.Tick, foundAt: 0, known: nil, scope: &scope, isKeyless: false}
		blocks, current, err := run.blocks(secrets)

		if err != nil {
			state.Fatalf("Test of capture recorder failed, case %q, error: %s", positive.Name, err.Error())
		}

		written, keyLogs, _ := capturedOf(blocks)

		if (len(written) != positive.Written) || (len(current.gate.pending) != 0) || (len(keyLogs) != positive.KeyLogs) {
			state.Errorf("Test of capture recorder failed, case %q, %d packets and %d key logs should be written, nothing should wait for its scope, packets: %d, key logs: %d, pending: %v", positive.Name, positive.Written, positive.KeyLogs, len(written), len(keyLogs), current.gate.pending)
			return
		}

		err = run.checkWriteErrors(secrets, len(blocks))

		if err != nil {
			state.Errorf("Test of capture recorder failed, case %q, error: %s", positive.Name, err.Error())
			return
		}
	}
}

// answer the lookups of isFlowOpen from open, a cookie that is not there fails; the old lookup comes back when the test ends
func useTestFlows(state *testing.T, open map[uint64]bool) {
	oldIsFlowOpen := isFlowOpen
	state.Cleanup(func() {
		isFlowOpen = oldIsFlowOpen
	})
	isFlowOpen = func(cookie uint64, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (found bool, err error) {
		found, ok := open[cookie]

		if !ok {
			err = fmt.Errorf("lookup of cookie %d failed", cookie)
		}

		return
	}
}

// Test if the recorder forgets the flows that were idle for a minute when it sweeps: a plaintext connection or a decrypted DTLS session only when its socket is gone, then with what it still keeps written; a held flow never.
// the sweep fails when the output does
func TestForgetIdleFlowsPositive(state *testing.T) {
	session := testSessions(state)[1]
	dtls := testDTLSSession(state)
	// 1 is an open connection, 3 a decrypted DTLS session, 4 a connection without its socket and 5 one whose lookup fails, 6 is closed, 7 holds its packets
	useTestFlows(state, map[uint64]bool{1: true, 3: true, 4: false})
	connection := func(cookie uint64, port uint16, isClosed bool) (packets []capturebpf.Packet) {
		packets = tcpPackets(cookie, Endpoint{Address: tlsClient.Address, Port: port}, tlsServer, []sessionChunk{{direction: tlsrecord.ClientDirection, data: []byte("plain")}}, isClosed)
		return
	}
	// 4 has bytes behind a hole, they are written when it is forgotten
	client4 := Endpoint{Address: tlsClient.Address, Port: 40004}
	behind := TCPPacket(nil, client4, tlsServer, testClientISN+1+uint32(len("plain"))+10, testServerISN+1, ACKFlag, []byte("behind"))
	packets := slices.Concat(connection(1, 40001, false), connection(4, 40004, false), []capturebpf.Packet{{Cookie: 4, FlowCookie: 4, TimestampNs: 1 << 20, Length: uint32(len(behind)), IsIngress: false, Data: behind}}, connection(5, 40005, false), connection(6, 40006, true), udpPackets(3, dtlsClient, dtlsServer, dtls.chunks))

	for _, isFailing := range []bool{false, true} {
		useTestSecrets(state, true, session, dtls)
		output := &failingWriter{writes: 0, limit: math.MaxInt, output: nil}
		start := time.Now()
		current, err := testRecorder(output, true, start)

		if err != nil {
			state.Fatalf("Test of capture recorder failed, cannot create recorder, error: %s", err.Error())
		}

		current.captureBpfMaps = testBpfMaps
		err = feedRecorder(&current, packets, start, nil)

		if err != nil {
			state.Fatalf("Test of capture recorder failed, error: %s", err.Error())
		}

		// a held flow that is idle too: its packets wait for secrets that never come
		useTestSecrets(state, false, session)
		err = feedRecorder(&current, tcpPackets(7, Endpoint{Address: tlsClient.Address, Port: 40007}, tlsServer, session.chunks[:1], false), start, nil)

		if err != nil {
			state.Fatalf("Test of capture recorder failed, error: %s", err.Error())
		}

		// a sweep before the flows are idle keeps them all
		err = current.tick(start.Add(sweepInterval))

		if (err != nil) || (len(current.flows) != 6) {
			state.Fatalf("Test of capture recorder failed, the flows are not idle yet, flows: %d, error: %v", len(current.flows), err)
		}

		written := len(output.output)
		current.nextSweep = start
		current.flows[7].holdStart = start.Add(flowIdleTimeout)

		if isFailing {
			output.limit = output.writes
		}

		err = current.tick(start.Add(flowIdleTimeout + time.Second))

		if isFailing {
			if !errors.Is(err, pcapng.ErrWrite) {
				state.Errorf("Test of capture recorder failed, the sweep should fail with %v when the output does, error: %v", pcapng.ErrWrite, err)
				return
			}

			continue
		}

		if err != nil {
			state.Fatalf("Test of capture recorder failed, error: %s", err.Error())
		}

		remaining := slices.Sorted(maps.Keys(current.flows))

		if !slices.Equal(remaining, []uint64{1, 3, 7}) || !bytes.Contains(output.output[written:], []byte("behind")) {
			state.Errorf("Test of capture recorder failed, the open connection, the open DTLS session and the held flow should stay and the others be written and forgotten, flows: %v, written: %q", remaining, output.output[written:])
			return
		}
	}
}

// Test if the recorder returns with the expected errors when the file can't be written at its end: the last flush fails.
func TestRecorderFinishNegative(state *testing.T) {
	session := testSessions(state)[0]
	secrets := useTestSecrets(state, false, session)

	for _, plaintext := range []bool{false, true} {
		start := time.Now()
		// a file, not a stream: everything waits in the buffer until the end
		writer, err := pcapng.New(&failingWriter{writes: 0, limit: 0, output: nil}, SynthesizedLength, false)

		if err != nil {
			state.Fatalf("Test of capture recorder failed, cannot create writer, error: %s", err.Error())
		}

		current := newRecorder(&writer, plaintext, 0, nil, testBpfMaps, nil, start, slog.New(slog.DiscardHandler))
		err = feedRecorder(&current, tcpPackets(1, tlsClient, tlsServer, session.chunks[:1], false), start, nil)

		if err == nil {
			err = current.finish()
		}

		if !errors.Is(err, pcapng.ErrWrite) || (secrets.lookups == 0) {
			state.Errorf("Test of capture recorder failed, plaintext %v, the end should fail with %v after the last lookup, lookups: %d, error: %v", plaintext, pcapng.ErrWrite, secrets.lookups, err)
			return
		}
	}
}
