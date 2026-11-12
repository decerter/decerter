// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
)

const (
	// bytes that wait to be sent in one direction of an intercepted flow before its reader stops reading
	maxSendQueueBytes int = 4 << 20
	// held records wait this long for the secrets before they go on raw: a client that runs its handshake inside its first write has them right after it, a client without them pays it once
	interceptGrace time.Duration = 250 * time.Millisecond
	// the secrets poll of an intercepted flow, it starts again when a record is held; a timer under a millisecond fires after one, the netpoller sleeps in milliseconds
	interceptPollStart time.Duration = time.Millisecond
	interceptPollMax   time.Duration = 20 * time.Millisecond
	// a held record mostly waits only for the return of the client's handshake call, microseconds, so the lookups spin this long first
	interceptSpin time.Duration = 500 * time.Microsecond
)

// how an intercepted tcp flow is relayed
type interceptMode string

const (
	// the first client bytes don't tell yet if the flow is TLS
	undecidedInterceptMode interceptMode = "undecided"
	// TLS records through the record layer: held, decrypted, through the rules and sealed again
	tlsInterceptMode interceptMode = "tls"
	// plain tcp chunks through the rules
	tcpInterceptMode interceptMode = "tcp"
	// relayed as it is: TLS without the secrets object, or after the record layer gave up
	rawInterceptMode interceptMode = "raw"
)

// what one item of a send queue is
type sendKind string

const (
	// bytes that go on as they are, which is only valid while the direction kept the sequence numbers of its TLS records
	rawSendKind sendKind = "raw"
	// plain tcp bytes for the rules
	chunkSendKind sendKind = "chunk"
	// a TLS record and what to do with it
	recordSendKind sendKind = "record"
)

type sendItem struct {
	kind    sendKind
	data    []byte
	record  tlsrecord.Record
	session tlsrecord.Session
}

// what the sender of one direction did with the TLS records, only it writes them, they are read once it is done
type sendStats struct {
	sealed    int
	written   int
	identical int
	changed   int
	dropped   int
	split     int
	forwarded int
	passed    int
}

// one intercepted tcp flow: the two readers feed the record layer under mutex, the sender of each direction takes its queue in order, runs the rules, seals and writes
// a slow peer or a held message stops only its own direction; wake is signalled on every change of the queues or the record layer
// holdDeadline ends the wait for the secrets, graceDeadline lets held records go on raw before it
type interception struct {
	mutex          *sync.Mutex
	wake           *sync.Cond
	flow           intercept.Flow
	pipeline       *intercept.Pipeline
	secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map
	mode           interceptMode
	wasTLS         bool
	prefix         []byte
	conn           tlsrecord.Conn
	queues         [2][]sendItem
	queuedBytes    [2]int
	ended          [2]bool
	aborted        bool
	finished       bool
	isHolding      bool
	holdDeadline   time.Time
	graceDeadline  time.Time
	pollPause      time.Duration
	pollTimer      *time.Timer
	isPollPending  bool
	spinGroup      *sync.WaitGroup
	stats          [2]sendStats
	logger         *slog.Logger
}

// relay an intercepted tcp flow until both directions are done, written is what went to each destination
// TLS needs secretsBpfMaps, without them a TLS flow is relayed raw; plain tcp goes through the rules either way
// opening are the bytes read before the scope was decided, they are taken first in the order they came
func interceptTCP(ctx context.Context, client *net.TCPConn, upstream *net.TCPConn, opening []TLSChunk, flow intercept.Flow, pipeline *intercept.Pipeline, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, logger *slog.Logger) (upBytes int64, downBytes int64) {
	mutex := &sync.Mutex{}
	interception := &interception{
		mutex:          mutex,
		wake:           sync.NewCond(mutex),
		flow:           flow,
		pipeline:       pipeline,
		secretsBpfMaps: secretsBpfMaps,
		mode:           undecidedInterceptMode,
		conn:           tlsrecord.New(maxHoldBytes, true),
		pollPause:      interceptPollStart,
		spinGroup:      &sync.WaitGroup{},
		logger:         logger,
	}
	interception.pollTimer = time.AfterFunc(time.Hour, interception.poll)
	interception.pollTimer.Stop()
	abortOnce := sync.Once{}
	abort := func() {
		abortOnce.Do(func() {
			// a deadline in the past unblocks the reads and writes without closing the sockets twice
			deadlineErr := errors.Join(client.SetDeadline(time.Unix(1, 0)), upstream.SetDeadline(time.Unix(1, 0)))

			if deadlineErr != nil {
				logger.Debug("Could not abort tcp flow", "error", deadlineErr)
			}

			interception.mutex.Lock()
			defer interception.mutex.Unlock()
			interception.aborted = true
			interception.wake.Broadcast()
		})
	}
	stop := context.AfterFunc(ctx, abort)
	defer stop()

	for _, chunk := range opening {
		interception.take(chunk.direction, chunk.data)
	}

	waitGroup := sync.WaitGroup{}

	// client reader
	waitGroup.Go(func() {
		interception.read(client, tlsrecord.ClientDirection, abort, logger.With("direction", "up"))
	})

	// upstream reader
	waitGroup.Go(func() {
		interception.read(upstream, tlsrecord.ServerDirection, abort, logger.With("direction", "down"))
	})

	// sender to upstream
	waitGroup.Go(func() {
		upBytes = interception.send(ctx, upstream, tlsrecord.ClientDirection, abort, logger.With("direction", "up"))
	})

	downBytes = interception.send(ctx, client, tlsrecord.ServerDirection, abort, logger.With("direction", "down"))
	waitGroup.Wait()
	interception.spinGroup.Wait()
	interception.finish()
	return
}

func (interception *interception) read(source *net.TCPConn, direction tlsrecord.Direction, abort func(), logger *slog.Logger) {
	buffer := make([]byte, copyBufferLength)

	for {
		readCount, readErr := source.Read(buffer)

		if (readCount > 0) && !interception.take(direction, buffer[:readCount]) {
			return
		}

		if errors.Is(readErr, io.EOF) {
			interception.end(direction)
			return
		}

		if readErr != nil {
			logger.Debug("Could not read tcp stream", "error", readErr)
			abort()
			return
		}
	}
}

// the next bytes of a direction, goOn is false once the flow is aborted
func (interception *interception) take(direction tlsrecord.Direction, data []byte) (goOn bool) {
	interception.mutex.Lock()
	defer interception.mutex.Unlock()

	for (interception.queuedBytes[direction] >= maxSendQueueBytes) && !interception.aborted {
		interception.wake.Wait()
	}

	if interception.aborted {
		return
	}

	goOn = true

	switch interception.mode {
	case undecidedInterceptMode:
		interception.detect(direction, data)
	case tlsInterceptMode:
		interception.feed(direction, data)
	case tcpInterceptMode:
		interception.push(direction, sendItem{kind: chunkSendKind, data: bytes.Clone(data)})
	case rawInterceptMode:
		interception.push(direction, sendItem{kind: rawSendKind, data: bytes.Clone(data)})
	}

	interception.wake.Broadcast()
	return
}

// TLS starts with a ClientHello as the first client bytes; a server that speaks first, or anything else, is a plain tcp flow
func (interception *interception) detect(direction tlsrecord.Direction, data []byte) {
	if direction == tlsrecord.ServerDirection {
		interception.mode = tcpInterceptMode
		interception.flushPrefix()
		interception.push(direction, sendItem{kind: chunkSendKind, data: bytes.Clone(data)})
		return
	}

	interception.prefix = append(interception.prefix, data...)
	isClientHello, isDecided := tlsrecord.IsClientHello(interception.prefix)

	if !isDecided {
		return
	}

	if !isClientHello {
		interception.mode = tcpInterceptMode
		interception.flushPrefix()
		return
	}

	prefix := interception.prefix
	interception.prefix = nil
	interception.wasTLS = true

	if interception.secretsBpfMaps == nil {
		interception.logger.Debug("Tcp flow is tls but there are no secrets, relaying raw")
		interception.mode = rawInterceptMode
		interception.push(direction, sendItem{kind: rawSendKind, data: prefix})
		return
	}

	interception.mode = tlsInterceptMode
	interception.feed(direction, prefix)
}

// the client bytes taken while the flow was undecided, as one plain chunk
func (interception *interception) flushPrefix() {
	if len(interception.prefix) == 0 {
		return
	}

	interception.push(tlsrecord.ClientDirection, sendItem{kind: chunkSendKind, data: interception.prefix})
	interception.prefix = nil
}

// the record layer takes the bytes; when a record starts to wait for the secrets they are looked up at once, the handshake call of the client may have returned already
func (interception *interception) feed(direction tlsrecord.Direction, data []byte) {
	wasWaiting := interception.conn.Waiting()
	wasHolding := interception.conn.Holding()
	records, err := interception.conn.Feed(direction, data)
	interception.pushRecords(records)

	if err != nil {
		interception.giveUp(err)
		return
	}

	isHeldNow := interception.conn.Holding() && !wasHolding

	if interception.conn.Waiting() && (!wasWaiting || isHeldNow) {
		interception.lookup(false)
	}

	if isHeldNow && interception.conn.Holding() {
		clientRandom := interception.conn.Session().ClientRandom

		// secrets spin, ends after interceptSpin or with the secrets
		interception.spinGroup.Go(func() {
			interception.spin(clientRandom)
		})
	}

	interception.watch()
}

// look the secrets up in a tight loop for a short while, without the mutex, and set them once they are there
func (interception *interception) spin(clientRandom [32]byte) {
	deadline := time.Now().Add(interceptSpin)

	for time.Now().Before(deadline) {
		_, found, lookupErr := secrets.Lookup(clientRandom, interception.secretsBpfMaps)

		if lookupErr != nil {
			return
		}

		if found {
			interception.mutex.Lock()
			defer interception.mutex.Unlock()

			if !interception.finished && !interception.aborted && (interception.mode == tlsInterceptMode) && interception.conn.Waiting() {
				interception.lookup(false)
				interception.watch()
				interception.wake.Broadcast()
			}

			return
		}

		runtime.Gosched()
	}
}

// keep the deadlines and the poll in step with the record layer
func (interception *interception) watch() {
	if (interception.mode != tlsInterceptMode) || !interception.conn.Waiting() {
		interception.isHolding = false
		return
	}

	now := time.Now()

	if interception.holdDeadline.IsZero() {
		interception.holdDeadline = now.Add(holdTimeout)
	}

	holding := interception.conn.Holding()

	if holding && !interception.isHolding {
		interception.graceDeadline = now.Add(interceptGrace)
		interception.pollPause = interceptPollStart
		interception.isPollPending = false
	}

	interception.isHolding = holding

	if !interception.isPollPending {
		interception.isPollPending = true
		interception.pollTimer.Reset(interception.pollPause)
	}
}

// secrets poll, runs on its own timer while a record waits for them
func (interception *interception) poll() {
	interception.mutex.Lock()
	defer interception.mutex.Unlock()
	interception.isPollPending = false

	if interception.finished || interception.aborted || (interception.mode != tlsInterceptMode) {
		return
	}

	now := time.Now()
	interception.lookup(now.After(interception.holdDeadline))

	// nothing was changed without the secrets, so the held records can go on as they came
	if (interception.mode == tlsInterceptMode) && interception.conn.Holding() && now.After(interception.graceDeadline) {
		interception.logger.Debug("Tls secrets are late, held records go on raw")
		interception.pushRecords(interception.conn.Release())
	}

	interception.pollPause = min(2*interception.pollPause, interceptPollMax)
	interception.watch()
	interception.wake.Broadcast()
}

// ask secrets_map for the session and let the held records go on if they are there, isLast makes missing secrets the end of the interception
func (interception *interception) lookup(isLast bool) {
	sessionSecrets, found, lookupErr := secrets.Lookup(interception.conn.Session().ClientRandom, interception.secretsBpfMaps)

	if lookupErr != nil {
		interception.giveUp(lookupErr)
		return
	}

	if !found {
		if isLast {
			interception.giveUp(ErrNoSecrets)
		}

		return
	}

	records, secretsErr := interception.conn.SetSecrets(sessionSecrets)
	interception.pushRecords(records)

	if secretsErr != nil {
		interception.giveUp(secretsErr)
	}
}

// the record layer can't go on: what it did not send yet goes on raw and so does the rest of the flow, the senders refuse that once a direction changed its record count
func (interception *interception) giveUp(reason error) {
	session := interception.conn.Session()
	interception.logger.Warn("Could not intercept tls flow, relaying raw", "error", reason, "serverName", session.ServerName, "version", tlsrecord.VersionName(session.Version), "cipherSuite", tlsrecord.CipherSuiteName(session.CipherSuite))
	unsent := interception.conn.Unsent()

	for index, data := range unsent {
		if len(data) > 0 {
			interception.push(tlsrecord.Direction(index), sendItem{kind: rawSendKind, data: data})
		}
	}

	interception.mode = rawInterceptMode
}

// records with something to send or to print go to the queue of their direction
func (interception *interception) pushRecords(records []tlsrecord.Record) {
	session := interception.conn.Session()

	for _, record := range records {
		isApplicationData := record.Decrypted && (record.ContentType == tlsrecord.ApplicationDataContentType)

		if (record.Action == tlsrecord.ShowAction) && !isApplicationData {
			continue
		}

		interception.push(record.Direction, sendItem{kind: recordSendKind, record: record, session: session})
	}
}

func (interception *interception) push(direction tlsrecord.Direction, item sendItem) {
	interception.queues[direction] = append(interception.queues[direction], item)
	interception.queuedBytes[direction] += itemSize(item)
}

func itemSize(item sendItem) (size int) {
	size = max(len(item.data), len(item.record.Raw), len(item.record.Payload))
	return
}

// the reader of a direction saw the end of its stream; the start of a TLS record that never completed is not sent, the receiver could not read it either
func (interception *interception) end(direction tlsrecord.Direction) {
	interception.mutex.Lock()
	defer interception.mutex.Unlock()
	interception.ended[direction] = true

	if interception.mode == undecidedInterceptMode {
		interception.mode = tcpInterceptMode
		interception.flushPrefix()
	}

	interception.wake.Broadcast()
}

// held records of the direction still wait in the record layer, they come with the secrets or the release
func (interception *interception) isPending(direction tlsrecord.Direction) (isPending bool) {
	isPending = (interception.mode == tlsInterceptMode) && interception.conn.HoldingFor(direction)
	return
}

// the items of a direction, waits for them; isEnd is true when nothing comes after them, isAborted when the flow is aborted
func (interception *interception) next(direction tlsrecord.Direction) (items []sendItem, isEnd bool, isAborted bool) {
	interception.mutex.Lock()
	defer interception.mutex.Unlock()

	for (len(interception.queues[direction]) == 0) && !interception.aborted && (!interception.ended[direction] || interception.isPending(direction)) {
		interception.wake.Wait()
	}

	if interception.aborted {
		isAborted = true
		return
	}

	items = interception.queues[direction]
	interception.queues[direction] = nil
	isEnd = interception.ended[direction] && !interception.isPending(direction)
	return
}

// the items were sent, their bytes make room for the reader
func (interception *interception) sent(direction tlsrecord.Direction, size int) {
	interception.mutex.Lock()
	defer interception.mutex.Unlock()
	interception.queuedBytes[direction] -= size
	interception.wake.Broadcast()
}

// write the queue of one direction in order until its stream ended, an item that can't go on aborts the flow
func (interception *interception) send(ctx context.Context, destination *net.TCPConn, direction tlsrecord.Direction, abort func(), logger *slog.Logger) (written int64) {
	encrypter := tlsrecord.NewEncrypter()

	for {
		items, isEnd, isAborted := interception.next(direction)

		if isAborted {
			return
		}

		buffers := net.Buffers{}
		size := 0

		for _, item := range items {
			size += itemSize(item)
			wire, err := interception.prepare(ctx, direction, item, &encrypter, logger)

			if err != nil {
				logger.Warn("Could not intercept tcp flow, aborting it", "error", err)
				abort()
				return
			}

			if len(wire) > 0 {
				buffers = append(buffers, wire)
			}
		}

		count, writeErr := buffers.WriteTo(destination)
		written += count
		interception.sent(direction, size)

		if writeErr != nil {
			logger.Debug("Could not write tcp stream", "error", writeErr)
			abort()
			return
		}

		if !isEnd {
			continue
		}

		closeErr := destination.CloseWrite()

		if closeErr != nil {
			logger.Debug("Could not half-close tcp stream", "error", closeErr)
			abort()
		}

		return
	}
}

// what goes on for one item: raw bytes only while the direction kept its record count, plain chunks and held records through the rules
func (interception *interception) prepare(ctx context.Context, direction tlsrecord.Direction, item sendItem, encrypter *tlsrecord.Encrypter, logger *slog.Logger) (wire []byte, err error) {
	stats := &interception.stats[direction]

	switch item.kind {
	case rawSendKind:
		if encrypter.Offset() != 0 {
			err = fmt.Errorf("%w: offset %d", ErrChangedStream, encrypter.Offset())
			return
		}

		wire = item.data
	case chunkSendKind:
		result := interception.pipeline.Process(ctx, interception.pipeline.Message(interception.flow, direction, intercept.TCPLayer, item.data), logger)

		if result.Verdict == intercept.ForwardVerdict {
			wire = result.Plain
		}
	case recordSendKind:
		wire, err = interception.prepareRecord(ctx, direction, item, encrypter, stats, logger)
	}

	return
}

func (interception *interception) prepareRecord(ctx context.Context, direction tlsrecord.Direction, item sendItem, encrypter *tlsrecord.Encrypter, stats *sendStats, logger *slog.Logger) (wire []byte, err error) {
	record := item.record
	flow := interception.flow
	flow.Session = item.session

	switch record.Action {
	case tlsrecord.ShowAction:
		// application data that went on raw before the secrets came, the rules never saw it
		stats.passed++
		interception.pipeline.Show(interception.pipeline.Message(flow, direction, intercept.TLSLayer, record.Payload))
	case tlsrecord.ForwardAction:
		if encrypter.Offset() != 0 {
			err = fmt.Errorf("%w: offset %d", ErrChangedStream, encrypter.Offset())
			return
		}

		stats.forwarded++
		wire = record.Raw
	case tlsrecord.SealAction:
		plain := record.Payload

		// only application data goes through the rules, handshake messages and alerts are sealed again as they came
		if record.ContentType == tlsrecord.ApplicationDataContentType {
			result := interception.pipeline.Process(ctx, interception.pipeline.Message(flow, direction, intercept.TLSLayer, record.Payload), logger)

			if result.Verdict == intercept.DropVerdict {
				stats.dropped++
				encrypter.Drop(record)
				return
			}

			if result.Changed {
				stats.changed++
			}

			plain = result.Plain
		}

		sealed, count, sealErr := encrypter.Seal(record, plain)

		if err = sealErr; err != nil {
			return
		}

		stats.sealed++
		stats.written += count

		if count > 1 {
			stats.split++
		}

		if bytes.Equal(sealed, record.Raw) {
			stats.identical++
		}

		wire = sealed
	}

	return
}

// the flow is over: the poll stops, a TLS flow gets one line with what happened to its records in each direction
func (interception *interception) finish() {
	interception.mutex.Lock()
	defer interception.mutex.Unlock()
	interception.finished = true
	interception.pollTimer.Stop()

	if !interception.wasTLS {
		return
	}

	flow := interception.flow
	flow.Session = interception.conn.Session()
	text := fmt.Sprintf("%s sni=%q alpn=%q records up=%s down=%s\n", intercept.LinePrefix(flow, intercept.TLSLayer), flow.Session.ServerName, flow.Session.Protocol, statsText(interception.stats[tlsrecord.ClientDirection]), statsText(interception.stats[tlsrecord.ServerDirection]))
	// stdout is the output of the tool as in printFlow, a failed write has nowhere to go
	_, _ = os.Stdout.WriteString(text)
}

// sealed records in, records written for them, identical to what came, changed by the rules, dropped, split, forwarded raw, passed before the secrets
func statsText(stats sendStats) (text string) {
	text = fmt.Sprintf("sealed:%d,written:%d,identical:%d,changed:%d,dropped:%d,split:%d,forwarded:%d,passed:%d", stats.sealed, stats.written, stats.identical, stats.changed, stats.dropped, stats.split, stats.forwarded, stats.passed)
	return
}
