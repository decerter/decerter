// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"sync/atomic"
	"time"

	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/pcapng"
)

const (
	// what one writer behind the hub may have waiting: packets and their bytes; a writer that falls this far behind loses packets, a stream its place
	consumerQueuePackets int   = 16384
	consumerQueueBytes   int64 = 32 << 20
)

// one writer behind the hub: the -w file, a capture of the API or a stream of the API, with its own filter, format and pcapng section
// packets is its queue and queued the bytes in it; isCut: a writer that lets its queue run full is cut off, overflow is closed then; any other writer loses the packets and counts them in dropped
// limit is closed when its file reached the size limit of the captures, nil otherwise
// replay are the packets the hub kept of the flows that were open when the writer joined, it writes them first, so their sessions are whole
type Consumer struct {
	recorder        recorder
	replay          []capturebpf.Packet
	writer          *pcapng.Writer
	packets         chan capturebpf.Packet
	queued          *atomic.Int64
	dropped         *atomic.Uint64
	isCut           bool
	overflowChannel chan struct{}
	limitChannel    <-chan struct{}
	logger          *slog.Logger
}

// what a writer behind the hub writes and how it is treated
// Stream writes every block through at once; IsCut cuts the writer off when it falls behind instead of dropping its packets
// Scope is its own filter within the --filter, nil takes every flow of the hub; Limit is closed when its file is full, nil when there is no limit
type ConsumerOptions struct {
	Stream    bool
	IsCut     bool
	Scope     *filter.Filter
	Plaintext bool
	Limit     <-chan struct{}
}

// start a writer behind the hub: the section and interface blocks go to output at once, it gets every packet the hub hands out from now on
// a flow that is open already comes with the packets the hub kept of it, from its start as far as the ring reaches back, and its TLS session with its DSB in front of them
// Consume runs it; it fails when the hub stopped already
func (hub *Hub) Add(output io.Writer, options ConsumerOptions, logger *slog.Logger) (current *Consumer, err error) {
	select {
	case <-hub.doneChannel:
		err = ErrStopped
		return
	default:
	}

	writerSnaplen := hub.snaplen

	if options.Plaintext {
		writerSnaplen = max(hub.snaplen, SynthesizedLength)
	}

	writer, writerErr := pcapng.New(output, writerSnaplen, options.Stream)

	if err = writerErr; err != nil {
		return
	}

	// the section and interface blocks are there at once, a capture without packets is a valid file too
	err = writer.Flush()

	if err != nil {
		return
	}

	current = &Consumer{
		recorder:        recorder{},
		replay:          nil,
		writer:          &writer,
		packets:         make(chan capturebpf.Packet, consumerQueuePackets),
		queued:          &atomic.Int64{},
		dropped:         &atomic.Uint64{},
		isCut:           options.IsCut,
		overflowChannel: make(chan struct{}),
		limitChannel:    options.Limit,
		logger:          logger,
	}
	current.recorder = newRecorder(current.writer, options.Plaintext, hub.bootOffset, hub.captureBpfMaps, hub.secretsBpfMaps, options.Scope, time.Now(), logger)
	hub.mutex.Lock()
	defer hub.mutex.Unlock()

	// the plaintext writer can't decrypt a session whose start the ring lost, it writes such a session as it was captured
	if !options.Plaintext {
		current.recorder.known = maps.Clone(hub.sessions)
	}

	if hub.ring != nil {
		open := map[uint64][32]byte{}

		for cookie := range hub.flows {
			open[cookie] = [32]byte{}
		}

		current.replay = hub.ring.packetsOf(open, false)
	}

	hub.consumers[current] = true
	return
}

// write what the hub hands out until the hub is done or stopChannel is closed, then write what still waits and finish the file
// a cancelled context ends it at once, the reader of a stream went away; a full queue of a stream ends it with ErrSlowReader, a full file with ErrSizeLimit; both leave a valid pcapng
func (hub *Hub) Consume(ctx context.Context, current *Consumer, stopChannel <-chan struct{}) (err error) {
	defer hub.remove(current)

	for _, packet := range current.replay {
		err = current.handle(packet)

		if (err != nil) || (ctx.Err() != nil) {
			return
		}
	}

	current.replay = nil
	timer := time.NewTimer(time.Until(current.recorder.nextWake))
	defer timer.Stop()

	for {
		select {
		case packet := <-current.packets:
			current.queued.Add(-int64(len(packet.Data)))
			err = current.handle(packet)
		case <-timer.C:
			err = current.recorder.tick(time.Now())

			// the queue is empty for a moment, so the file is brought up to date
			if err == nil {
				err = current.writer.Flush()
			}
		case <-current.overflowChannel:
			err = ErrSlowReader
			return
		case <-current.limitChannel:
			err = errors.Join(ErrSizeLimit, current.writer.Flush())
			return
		case <-stopChannel:
			err = hub.drain(current)
			return
		case <-hub.doneChannel:
			err = hub.drain(current)
			return
		case <-ctx.Done():
			return
		}

		// the output is gone or full, nothing more can be written
		if err != nil {
			return
		}

		timer.Reset(time.Until(current.recorder.nextWake))
	}
}

// what a writer that falls behind does: a stream is cut off, every other writer loses the packet; called with the mutex held
func (hub *Hub) offer(current *Consumer, packet capturebpf.Packet) {
	size := int64(len(packet.Data))

	if current.queued.Add(size) <= consumerQueueBytes {
		select {
		case current.packets <- packet:
			return
		default:
		}
	}

	current.queued.Add(-size)

	if !current.isCut {
		current.dropped.Add(1)
		return
	}

	delete(hub.consumers, current)
	close(current.overflowChannel)
}

func (hub *Hub) remove(current *Consumer) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	delete(hub.consumers, current)
}

// the writer gets nothing more: it writes what waits in its queue, then the flows it still keeps
func (hub *Hub) drain(current *Consumer) (err error) {
	hub.remove(current)

	for len(current.packets) > 0 {
		err = current.handle(<-current.packets)

		if err != nil {
			return
		}
	}

	current.recorder.dropped = current.dropped.Load()
	err = current.recorder.finish()
	return
}

// one packet, and the lookups of the held flows when they are due: under steady traffic the timer never fires
func (current *Consumer) handle(packet capturebpf.Packet) (err error) {
	now := time.Now()
	err = current.recorder.handle(packet, now)

	if (err == nil) && !now.Before(current.recorder.nextWake) {
		err = current.recorder.tick(now)
	}

	return
}

// the writers behind the hub now
func (hub *Hub) Consumers() (count int) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	count = len(hub.consumers)
	return
}

// the packets the writer lost so far because its queue was full
func (current *Consumer) Dropped() (dropped uint64) {
	dropped = current.dropped.Load()
	return
}

// the live pcapng stream of the API: the flows in scope that scope takes, decrypted with plaintext, until the context is cancelled or the stream falls behind
func (hub *Hub) Stream(ctx context.Context, output io.Writer, scope *filter.Filter, plaintext bool, logger *slog.Logger) (err error) {
	current, addErr := hub.Add(output, ConsumerOptions{Stream: true, IsCut: true, Scope: scope, Plaintext: plaintext, Limit: nil}, logger)

	if err = addErr; err != nil {
		return
	}

	err = hub.Consume(ctx, current, nil)
	return
}
