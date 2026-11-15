// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"sync"
	"testing"
	"time"

	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/pcapng"
)

// a writer whose output can be read while the writer runs, it fails once the test says so
type watchedWriter struct {
	mutex  *sync.Mutex
	output *failingWriter
}

func (writer *watchedWriter) Write(data []byte) (count int, err error) {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	count, err = writer.output.Write(data)
	return
}

func (writer *watchedWriter) contains(data []byte) (isThere bool) {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	isThere = bytes.Contains(writer.output.output, data)
	return
}

func newWatchedWriter(limit int) (writer *watchedWriter) {
	writer = &watchedWriter{mutex: &sync.Mutex{}, output: &failingWriter{writes: 0, limit: limit, output: nil}}
	return
}

// a hub of the tests without maps and history, with the maps of the secrets uprobe when isKeyed
func testHub(state *testing.T, isKeyed bool) (hub *Hub) {
	hub, err := NewHub(capturebpf.MaxSnaplen, nil, nil, nil, nil, false, slog.New(slog.DiscardHandler))

	if err != nil {
		state.Fatalf("Test of capture.NewHub failed, error: %s", err.Error())
	}

	if isKeyed {
		hub.secretsBpfMaps = testBpfMaps
	}

	return
}

// Test if capture.Hub.Consume writes the packets the hub kept of an open flow first, looks the secrets of a held session up while no packet comes and writes them once they are there.
func TestHubConsumePositive(state *testing.T) {
	session := testSessions(state)[1]
	secrets := useTestSecrets(state, false, session)
	hub := testHub(state, true)
	output := newWatchedWriter(math.MaxInt)
	current, err := hub.Add(output, ConsumerOptions{Stream: false, IsCut: false, Scope: nil, Plaintext: false, Limit: nil}, slog.New(slog.DiscardHandler))

	if err != nil {
		state.Fatalf("Test of capture.Hub.Add failed, error: %s", err.Error())
	}

	// the hub kept the start of the session, the writer begins with it
	current.replay = tcpPackets(1, tlsClient, tlsServer, session.chunks[:1], false)
	stopChannel := make(chan struct{})
	errChannel := make(chan error, 1)

	// the writer of the test
	go func() {
		errChannel <- hub.Consume(state.Context(), current, stopChannel)
	}()

	// the secrets come while the writer waits, its next lookup writes them and the held packets, then it flushes the file
	deadline := time.Now().Add(10 * time.Second)

	for (secrets.lookupCount() == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	secrets.setFound(true)

	for !output.contains([]byte(session.keyLog)) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	close(stopChannel)
	err = <-errChannel

	if (err != nil) || !output.contains([]byte(session.keyLog)) || !output.contains(session.chunks[0].data) || (hub.Consumers() != 0) {
		state.Errorf("Test of capture.Hub.Consume failed, the writer should write the key log and the kept packets without a packet behind them and leave the hub when it stops, consumers: %d, error: %v", hub.Consumers(), err)
		return
	}
}

// Test if capture.Hub.Consume returns with the expected output when it is ended: by the hub that is done, by a cancelled context during its replay and while it waits, and by a full file.
func TestHubConsumeEndPositive(state *testing.T) {
	limitChannel := make(chan struct{})
	close(limitChannel)
	positiveCases := []struct {
		Name         string
		Limit        <-chan struct{}
		IsDone       bool
		IsCancelled  bool
		HasReplay    bool
		ExpectedErr  error
		IsFileFinish bool
	}{
		{Name: "hub done", IsDone: true, IsFileFinish: true},
		{Name: "context cancelled", IsCancelled: true},
		{Name: "context cancelled during the replay", IsCancelled: true, HasReplay: true},
		{Name: "file full", Limit: limitChannel, ExpectedErr: ErrSizeLimit},
	}

	for _, positive := range positiveCases {
		hub := testHub(state, false)
		output := &lockedWriter{mutex: &sync.Mutex{}, output: &bytes.Buffer{}}
		current, err := hub.Add(output, ConsumerOptions{Stream: false, IsCut: false, Scope: nil, Plaintext: false, Limit: positive.Limit}, slog.New(slog.DiscardHandler))

		if err != nil {
			state.Fatalf("Test of capture.Hub.Add failed, case %q, error: %s", positive.Name, err.Error())
		}

		packets := testFlow(1, hubClient, hubServer, "GET / HTTP/1.1\r\n\r\n")

		if positive.HasReplay {
			current.replay = packets
		}

		ctx, cancel := context.WithCancel(state.Context())

		if positive.IsCancelled {
			cancel()
		}

		if positive.IsDone {
			hub.offerAll(packets[0])
			close(hub.doneChannel)
		}

		err = hub.Consume(ctx, current, nil)
		cancel()

		if !errors.Is(err, positive.ExpectedErr) || ((positive.ExpectedErr == nil) && (err != nil)) {
			state.Errorf("Test of capture.Hub.Consume failed, case %q, error should be %v, error: %v", positive.Name, positive.ExpectedErr, err)
			return
		}

		// a cancelled replay stops after its first packet
		if positive.HasReplay && (current.recorder.packets != 1) {
			state.Errorf("Test of capture.Hub.Consume failed, case %q, the replay should stop after one packet, packets: %d", positive.Name, current.recorder.packets)
			return
		}

		// the hub that is done leaves the writer what waits in its queue, then the file is finished
		if positive.IsFileFinish && !bytes.Contains(output.output.Bytes(), packets[0].Data) {
			state.Errorf("Test of capture.Hub.Consume failed, case %q, the packet in the queue should be in the file", positive.Name)
			return
		}
	}
}

// Test if capture.Hub returns with the expected errors: no writer joins a hub that is done, a writer whose output fails can't join or ends with the error, and a stream ends with its context.
func TestHubConsumeNegative(state *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	options := ConsumerOptions{Stream: false, IsCut: false, Scope: nil, Plaintext: false, Limit: nil}
	packets := testFlow(1, hubClient, hubServer, "GET / HTTP/1.1\r\n\r\n")

	// the hub is done
	hub := testHub(state, false)
	close(hub.doneChannel)
	_, err := hub.Add(io.Discard, options, logger)
	streamErr := hub.Stream(state.Context(), io.Discard, nil, false, logger)

	if !errors.Is(err, ErrStopped) || !errors.Is(streamErr, ErrStopped) {
		state.Errorf("Test of capture.Hub.Add failed, a hub that is done should take no writer, errors: %v, %v", err, streamErr)
		return
	}

	// the section can't be written: a snaplen of zero, an output that fails
	hub = testHub(state, false)
	hub.snaplen = 0
	_, err = hub.Add(io.Discard, options, logger)

	if !errors.Is(err, pcapng.ErrSnaplen) {
		state.Errorf("Test of capture.Hub.Add failed, error should be %v, error: %v", pcapng.ErrSnaplen, err)
		return
	}

	hub = testHub(state, false)
	_, err = hub.Add(&failingWriter{writes: 0, limit: 0, output: nil}, options, logger)

	if !errors.Is(err, pcapng.ErrWrite) {
		state.Errorf("Test of capture.Hub.Add failed, error should be %v, error: %v", pcapng.ErrWrite, err)
		return
	}

	// the output fails behind the section: in the replay, for a packet of the queue, in the drain
	for _, place := range []string{"replay", "queue", "drain"} {
		hub = testHub(state, false)
		// the section header and the interface blocks are the first two writes
		current, addErr := hub.Add(&failingWriter{writes: 0, limit: 2, output: nil}, ConsumerOptions{Stream: true, IsCut: false, Scope: nil, Plaintext: false, Limit: nil}, logger)

		if addErr != nil {
			state.Fatalf("Test of capture.Hub.Add failed, case %q, error: %s", place, addErr.Error())
		}

		switch place {
		case "replay":
			current.replay = packets
			err = hub.Consume(state.Context(), current, nil)
		case "queue":
			hub.offerAll(packets[0])
			err = hub.Consume(state.Context(), current, nil)
		default:
			hub.offerAll(packets[0])
			err = hub.drain(current)
		}

		if !errors.Is(err, pcapng.ErrWrite) || (hub.Consumers() != 0 && place != "drain") {
			state.Errorf("Test of capture.Hub.Consume failed, case %q, error should be %v and the writer gone, consumers: %d, error: %v", place, pcapng.ErrWrite, hub.Consumers(), err)
			return
		}
	}

	// a stream whose reader went away
	hub = testHub(state, false)
	ctx, cancel := context.WithCancel(state.Context())
	cancel()
	err = hub.Stream(ctx, io.Discard, nil, true, logger)

	if (err != nil) || (hub.Consumers() != 0) {
		state.Errorf("Test of capture.Hub.Stream failed, a cancelled stream should end without an error and leave the hub, consumers: %d, error: %v", hub.Consumers(), err)
		return
	}
}
