// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
)

// one item of the send queue of a direction: a datagram that goes on as it came, or a DTLS record and what to do with it
type dtlsItem struct {
	datagram []byte
	record   tlsrecord.Record
	session  tlsrecord.Session
}

// the DTLS session of one udp session: both relays hand their datagrams over and the record layer reads them under mutex
// without a pipeline it only observes: the relays send the datagrams on themselves and the application data is printed (-decrypt)
// with a pipeline it intercepts: the sender of each direction takes its queue in order, runs the rules on the application data, seals the records again and writes the datagrams
// isRaw is true once the record layer gave up, every datagram goes on as it came from then on
// holdDeadline ends the wait for the secrets, graceDeadline lets held records go on raw before it
// session is the udp session it belongs to, a record in the rules keeps it busy; recorder gets the observed application data, nil records nothing
type dtlsInterception struct {
	mutex            *sync.Mutex
	wake             *sync.Cond
	session          *UDPSession
	bpfFlow          redirect.Flow
	flow             intercept.Flow
	pipeline         *intercept.Pipeline
	recorder         *history.History
	secretsBpfMaps   map[bpf.BpfMapName]*ebpf.Map
	conn             tlsrecord.DTLSConn
	isRaw            bool
	isSessionPrinted bool
	isClosed         bool
	queues           [2][]dtlsItem
	queuedBytes      [2]int
	isHolding        bool
	holdDeadline     time.Time
	graceDeadline    time.Time
	pollPause        time.Duration
	pollTimer        *time.Timer
	isPollPending    bool
	stats            [2]sendStats
	senders          *sync.WaitGroup
	logger           *slog.Logger
}

// a DTLS session found by the ClientHello in the first datagram of a udp session, pipeline nil only observes it
func newDTLSInterception(session *UDPSession, pipeline *intercept.Pipeline, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, recorder *history.History, logger *slog.Logger) (dtls *dtlsInterception) {
	mutex := &sync.Mutex{}
	dtls = &dtlsInterception{
		mutex:          mutex,
		wake:           sync.NewCond(mutex),
		session:        session,
		bpfFlow:        session.flow,
		flow:           session.interceptFlow,
		pipeline:       pipeline,
		recorder:       recorder,
		secretsBpfMaps: secretsBpfMaps,
		conn:           tlsrecord.NewDTLS(maxHoldBytes, pipeline != nil),
		pollPause:      interceptPollStart,
		senders:        &sync.WaitGroup{},
		logger:         logger,
	}
	dtls.pollTimer = time.AfterFunc(time.Hour, dtls.poll)
	dtls.pollTimer.Stop()
	return
}

// intercept: start the sender of each direction, writers send one datagram to the server and to the client
func (dtls *dtlsInterception) start(ctx context.Context, writers [2]func(datagram []byte) error) {
	for index, write := range writers {
		direction := tlsrecord.Direction(index)

		// dtls sender of one direction
		dtls.senders.Go(func() {
			dtls.send(ctx, direction, write, dtls.logger.With("direction", intercept.DirectionName(direction)))
		})
	}
}

// the udp session is over: the senders end after what they have, a held record that never got its secrets is not sent, then one line with what happened to the records
func (dtls *dtlsInterception) close() {
	dtls.mutex.Lock()
	dtls.isClosed = true
	dtls.pollTimer.Stop()
	dtls.wake.Broadcast()
	flow := dtls.flow
	flow.Session = dtls.conn.Session()
	dtls.mutex.Unlock()
	dtls.senders.Wait()

	if dtls.pipeline == nil {
		return
	}

	text := fmt.Sprintf("%s sni=%q alpn=%q records up=%s down=%s\n", intercept.LinePrefix(flow, intercept.DTLSLayer), flow.Session.ServerName, flow.Session.Protocol, statsText(dtls.stats[tlsrecord.ClientDirection]), statsText(dtls.stats[tlsrecord.ServerDirection]))
	// stdout is the output of the tool as in printFlow, a failed write has nowhere to go
	_, _ = os.Stdout.WriteString(text)
}

// observe: the datagram went on, its decrypted application data is printed; a session that can't be read is left alone with one log line
func (dtls *dtlsInterception) observe(direction tlsrecord.Direction, datagram []byte) {
	dtls.mutex.Lock()
	defer dtls.mutex.Unlock()

	if dtls.isRaw || dtls.isClosed {
		return
	}

	wasWaiting := dtls.conn.Waiting()
	records, err := dtls.conn.Feed(direction, datagram)
	dtls.show(records)

	if err != nil {
		dtls.giveUp(err)
		return
	}

	if dtls.conn.Waiting() && !wasWaiting {
		dtls.lookup(false)
	}

	dtls.watch()
}

// intercept: the next datagram of a direction goes into the record layer, isTaken is false when the queue of the direction is full and the datagram is lost, as on a congested path
func (dtls *dtlsInterception) take(direction tlsrecord.Direction, datagram []byte) (isTaken bool) {
	dtls.mutex.Lock()
	defer dtls.mutex.Unlock()

	if dtls.isClosed || (dtls.queuedBytes[direction] >= maxSendQueueBytes) {
		return
	}

	isTaken = true

	if dtls.isRaw {
		dtls.push(direction, dtlsItem{datagram: bytes.Clone(datagram)})
		dtls.wake.Broadcast()
		return
	}

	wasWaiting := dtls.conn.Waiting()
	wasHolding := dtls.conn.Holding()
	records, err := dtls.conn.Feed(direction, datagram)
	dtls.pushRecords(records)

	if err != nil {
		// the records of the datagram that came out went on, the rest of it can't be read
		dtls.giveUp(err)
	} else if dtls.conn.Waiting() && (!wasWaiting || (dtls.conn.Holding() && !wasHolding)) {
		dtls.lookup(false)
	}

	dtls.watch()
	dtls.wake.Broadcast()
	return
}

// keep the deadlines and the poll in step with the record layer
func (dtls *dtlsInterception) watch() {
	if dtls.isRaw || !dtls.conn.Waiting() {
		dtls.isHolding = false
		return
	}

	now := time.Now()

	if dtls.holdDeadline.IsZero() {
		dtls.holdDeadline = now.Add(holdTimeout)
	}

	holding := dtls.conn.Holding()

	if holding && !dtls.isHolding {
		dtls.graceDeadline = now.Add(interceptGrace)
		dtls.pollPause = interceptPollStart
		dtls.isPollPending = false
	}

	dtls.isHolding = holding

	if !dtls.isPollPending {
		dtls.isPollPending = true
		dtls.pollTimer.Reset(dtls.pollPause)
	}
}

// secrets poll, runs on its own timer while a record waits for them
func (dtls *dtlsInterception) poll() {
	dtls.mutex.Lock()
	defer dtls.mutex.Unlock()
	dtls.isPollPending = false

	if dtls.isClosed || dtls.isRaw {
		return
	}

	now := time.Now()
	dtls.lookup(now.After(dtls.holdDeadline))

	// nothing was changed without the secrets, so the held records can go on as they came
	if !dtls.isRaw && dtls.conn.Holding() && now.After(dtls.graceDeadline) {
		dtls.logger.Debug("Dtls secrets are late, held records go on raw")
		dtls.pushRecords(dtls.conn.Release())
	}

	dtls.pollPause = min(2*dtls.pollPause, interceptPollMax)
	dtls.watch()
	dtls.wake.Broadcast()
}

// ask secrets_map for the session and let the held records go on if they are there, isLast makes missing secrets the end of the decryption
func (dtls *dtlsInterception) lookup(isLast bool) {
	sessionSecrets, found, lookupErr := secretsByRandom(dtls.conn.Session().ClientRandom, dtls.secretsBpfMaps)

	if lookupErr != nil {
		dtls.giveUp(lookupErr)
		return
	}

	if !found {
		if isLast {
			dtls.giveUp(ErrNoSecrets)
		}

		return
	}

	records, secretsErr := dtls.conn.SetSecrets(sessionSecrets)

	if dtls.pipeline == nil {
		dtls.show(records)
	} else {
		dtls.pushRecords(records)
	}

	if secretsErr != nil {
		dtls.giveUp(secretsErr)
	}
}

// the record layer can't go on: held records go on as they came and so does every later datagram; a record whose number a split gave away is lost then
func (dtls *dtlsInterception) giveUp(reason error) {
	session := dtls.conn.Session()
	dtls.isRaw = true

	if dtls.pipeline == nil {
		dtls.logger.Warn("Could not decrypt dtls session, relaying without decryption", "error", reason, "version", tlsrecord.VersionName(session.Version), "cipherSuite", tlsrecord.CipherSuiteName(session.CipherSuite))
		return
	}

	dtls.logger.Warn("Could not intercept dtls session, relaying raw", "error", reason, "version", tlsrecord.VersionName(session.Version), "cipherSuite", tlsrecord.CipherSuiteName(session.CipherSuite))
	dtls.pushRecords(dtls.conn.Unsent())
}

// observe: print the decrypted application data, the session line in front of the first record
func (dtls *dtlsInterception) show(records []tlsrecord.Record) {
	session := dtls.conn.Session()

	for _, record := range records {
		if !record.Decrypted || (record.ContentType != tlsrecord.ApplicationDataContentType) {
			continue
		}

		if !dtls.isSessionPrinted {
			dtls.isSessionPrinted = true
			printSession(dtls.bpfFlow, dtls.flow.Client, session)
		}

		printRecord(dtls.bpfFlow, dtls.flow.Client, session, record)
		flow := dtls.flow
		flow.Session = session
		dtls.recorder.Observe(flow, record.Direction, intercept.DTLSLayer, record.Payload)
	}
}

// records with something to send or to print go to the queue of their direction
func (dtls *dtlsInterception) pushRecords(records []tlsrecord.Record) {
	session := dtls.conn.Session()

	for _, record := range records {
		isApplicationData := record.Decrypted && (record.ContentType == tlsrecord.ApplicationDataContentType)

		if (record.Action == tlsrecord.ShowAction) && !isApplicationData {
			continue
		}

		dtls.push(record.Direction, dtlsItem{record: record, session: session})
	}
}

func (dtls *dtlsInterception) push(direction tlsrecord.Direction, item dtlsItem) {
	dtls.queues[direction] = append(dtls.queues[direction], item)
	dtls.queuedBytes[direction] += dtlsItemSize(item)
}

func dtlsItemSize(item dtlsItem) (size int) {
	size = max(len(item.datagram), len(item.record.Raw), len(item.record.Payload))
	return
}

// the items of a direction, waits for them; isEnd is true once the session is closed and its queue is empty
func (dtls *dtlsInterception) next(direction tlsrecord.Direction) (items []dtlsItem, isEnd bool) {
	dtls.mutex.Lock()
	defer dtls.mutex.Unlock()

	for (len(dtls.queues[direction]) == 0) && !dtls.isClosed {
		dtls.wake.Wait()
	}

	items = dtls.queues[direction]
	dtls.queues[direction] = nil
	isEnd = (len(items) == 0) && dtls.isClosed
	return
}

// the items were sent, their bytes make room in the queue
func (dtls *dtlsInterception) sent(direction tlsrecord.Direction, size int) {
	dtls.mutex.Lock()
	defer dtls.mutex.Unlock()
	dtls.queuedBytes[direction] -= size
}

// write the queue of one direction in order: the records of one datagram that came go on in one datagram again, a datagram may grow to MinDatagramLength or to the bytes its records took
// what doesn't fit goes into the next datagram, a record that doesn't fit alone is split; a datagram that can't be sent is lost, as udp would lose it
func (dtls *dtlsInterception) send(ctx context.Context, direction tlsrecord.Direction, write func(datagram []byte) error, logger *slog.Logger) {
	encrypter := tlsrecord.NewDTLSEncrypter()
	var datagram []byte

	flush := func() {
		if len(datagram) == 0 {
			return
		}

		writeErr := write(datagram)

		if writeErr != nil {
			logger.Debug("Could not send dtls datagram", "error", writeErr)
		}

		datagram = nil
	}

	for {
		items, isEnd := dtls.next(direction)

		if isEnd {
			return
		}

		size := 0
		limits := datagramLimits(items)

		for index, item := range items {
			size += dtlsItemSize(item)

			if item.datagram != nil {
				flush()
				datagram = item.datagram
				flush()
				continue
			}

			// a record of another datagram than the one before starts a datagram of its own
			if (index > 0) && (items[index-1].datagram == nil) && (items[index-1].record.Datagram != item.record.Datagram) {
				flush()
			}

			wires := dtls.prepare(ctx, direction, item, &encrypter, limits[index], logger)

			for _, wire := range wires {
				if len(datagram)+len(wire) > limits[index] {
					flush()
				}

				datagram = append(datagram, wire...)
			}
		}

		flush()
		dtls.sent(direction, size)
	}
}

// the most bytes of the datagram each record goes into: MinDatagramLength, or what the records of its datagram in this batch took when that is more
func datagramLimits(items []dtlsItem) (limits []int) {
	limits = make([]int, len(items))

	for start := 0; start < len(items); {
		end := start + 1
		taken := len(items[start].record.Raw)

		for (end < len(items)) && (items[start].datagram == nil) && (items[end].datagram == nil) && (items[end].record.Datagram == items[start].record.Datagram) {
			taken += len(items[end].record.Raw)
			end++
		}

		for index := start; index < end; index++ {
			limits[index] = max(tlsrecord.MinDatagramLength, taken)
		}

		start = end
	}

	return
}

// what goes on for one record: raw while its sequence number is free, held records through the rules and sealed again, records that went on before the secrets only printed
func (dtls *dtlsInterception) prepare(ctx context.Context, direction tlsrecord.Direction, item dtlsItem, encrypter *tlsrecord.DTLSEncrypter, limit int, logger *slog.Logger) (wires [][]byte) {
	record := item.record
	stats := &dtls.stats[direction]
	flow := dtls.flow
	flow.Session = item.session

	switch record.Action {
	case tlsrecord.ShowAction:
		// application data that went on raw before the secrets came, the rules never saw it
		stats.passed++
		dtls.pipeline.Show(dtls.pipeline.Message(flow, direction, intercept.DTLSLayer, record.Payload))
	case tlsrecord.ForwardAction:
		// only after a split and a record-layer error: the receiver has seen this number already
		if !encrypter.Forward(record) {
			logger.Debug("Could not relay raw dtls record, its sequence number was given to a split record", "epoch", record.Epoch, "sequence", record.Sequence)
			return
		}

		stats.forwarded++
		wires = [][]byte{record.Raw}
	case tlsrecord.SealAction:
		plain := record.Payload

		// only application data goes through the rules, the Finished and the alerts are sealed again as they came
		if record.ContentType == tlsrecord.ApplicationDataContentType {
			result := dtls.session.process(ctx, dtls.pipeline, dtls.pipeline.Message(flow, direction, intercept.DTLSLayer, record.Payload), logger)

			// the receiver sees a gap in the sequence numbers, which its replay window takes
			if result.Verdict == intercept.DropVerdict {
				stats.dropped++
				return
			}

			if result.Changed {
				stats.changed++
			}

			plain = result.Plain
		}

		sealed, sealErr := encrypter.Seal(record, plain, limit)

		if sealErr != nil {
			logger.Warn("Could not seal dtls record, it is lost", "error", sealErr, "epoch", record.Epoch, "sequence", record.Sequence)
			return
		}

		stats.sealed++
		stats.written += len(sealed)

		if len(sealed) > 1 {
			stats.split++
		}

		if (len(sealed) == 1) && bytes.Equal(sealed[0], record.Raw) {
			stats.identical++
		}

		wires = sealed
	}

	return
}
