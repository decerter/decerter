// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
)

// the cookie tells a new socket on a reused client port apart, the destination the servers of one unconnected socket
type UDPSessionKey struct {
	client      netip.AddrPort
	cookie      uint64
	destination netip.AddrPort
}

// one client socket to one original destination over one upstream socket
// dtls reads a DTLS session, it is nil for any other datagrams; isRaw relays a DTLS session that can't be decrypted past the rules, they would only see ciphertext, and a session out of scope
// isInScope is the decision of the scope filter, a session out of scope prints no flow line and is not in the history
// interceptFlow is the flow the rules and the history see; upQueue takes the client's datagrams for the rules when they run on plain datagrams, nil otherwise
// upstreamCookie is the cookie of the upstream socket in upstream_map of the capture, 0 when it is not captured
// busy counts the datagrams in the rules right now, a held one keeps the session from going idle
type UDPSession struct {
	key                 UDPSessionKey
	flow                redirect.Flow
	cmdline             string
	interceptFlow       intercept.Flow
	upstream            *net.UDPConn
	upstreamCookie      uint64
	dtls                *dtlsInterception
	upQueue             *udpQueue
	isRaw               bool
	isInScope           bool
	replyControlMessage []byte
	startTime           time.Time
	lastActive          atomic.Int64
	busy                atomic.Int64
	upDatagrams         atomic.Int64
	upBytes             atomic.Int64
	downDatagrams       atomic.Int64
	downBytes           atomic.Int64
}

// the client's datagrams of one session that wait for the rules, its sender takes them in order: a rule that holds one holds only this session, not the reader of the proxy socket
// past maxSendQueueBytes a new datagram is lost, as on a congested path
type udpQueue struct {
	mutex       *sync.Mutex
	wake        *sync.Cond
	datagrams   [][]byte
	queuedBytes int
	isClosed    bool
	sender      *sync.WaitGroup
}

// sessions by key, the mutex also orders the idle check against a new datagram of the same session
type UDPSessions struct {
	mutex    *sync.Mutex
	sessions map[UDPSessionKey]*UDPSession
}

// a copy of what one direction of a tcp flow relayed
type TLSChunk struct {
	direction tlsrecord.Direction
	data      []byte
}

// reads the TLS session of one tcp flow next to its relay: the relay hands over copies and goes on, it never waits for the observer
// active is true while copies are wanted, it goes false for good when the flow is not TLS or can't be decrypted, the relay then stops copying
// queuedBytes are the copies the observer has not taken yet
// interceptFlow is the flow the history records the decrypted records under, recorder nil records nothing
type TLSObserver struct {
	flow           redirect.Flow
	client         netip.AddrPort
	interceptFlow  intercept.Flow
	recorder       *history.History
	secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map
	chunks         chan TLSChunk
	queuedBytes    atomic.Int64
	active         atomic.Bool
	stopOnce       *sync.Once
}

func NewTLSObserver(flow redirect.Flow, client netip.AddrPort, interceptFlow intercept.Flow, recorder *history.History, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map) (observer *TLSObserver) {
	observer = &TLSObserver{
		flow:           flow,
		client:         client,
		interceptFlow:  interceptFlow,
		recorder:       recorder,
		secretsBpfMaps: secretsBpfMaps,
		chunks:         make(chan TLSChunk, observerQueueLength),
		queuedBytes:    atomic.Int64{},
		active:         atomic.Bool{},
		stopOnce:       &sync.Once{},
	}
	observer.active.Store(true)
	return
}

func (observer *TLSObserver) Active() (active bool) {
	active = observer.active.Load()
	return
}

// called by the relay with the bytes it is about to forward, never blocks: an observer that is too far behind is stopped instead
func (observer *TLSObserver) Observe(direction tlsrecord.Direction, data []byte, logger *slog.Logger) {
	if !observer.Active() {
		return
	}

	if observer.queuedBytes.Add(int64(len(data))) > maxObserverBytes {
		observer.Stop(ErrObserverBehind, logger)
		return
	}

	select {
	case observer.chunks <- TLSChunk{direction: direction, data: bytes.Clone(data)}:
	default:
		observer.Stop(ErrObserverBehind, logger)
	}
}

// the relay goes on untouched, only the look inside ends, logged once per flow; a flow that is not TLS is no failure
func (observer *TLSObserver) Stop(reason error, logger *slog.Logger) {
	observer.stopOnce.Do(func() {
		observer.active.Store(false)

		if reason == nil {
			logger.Debug("Tcp flow is not tls, relaying without decryption")
			return
		}

		logger.Warn("Could not decrypt tls flow, relaying without decryption", "error", reason)
	})
}

// the relay is done, the observer ends after the copies it still has
func (observer *TLSObserver) Close() {
	close(observer.chunks)
}

func NewUDPSessions() (udpSessions UDPSessions) {
	udpSessions = UDPSessions{
		mutex:    &sync.Mutex{},
		sessions: map[UDPSessionKey]*UDPSession{},
	}
	return
}

// a session that is found is active now, so a running idle check can't remove it before the datagram is sent
func (udpSessions *UDPSessions) Get(key UDPSessionKey) (session *UDPSession) {
	udpSessions.mutex.Lock()
	defer udpSessions.mutex.Unlock()
	session = udpSessions.sessions[key]

	if session != nil {
		session.lastActive.Store(time.Now().UnixNano())
	}

	return
}

func (udpSessions *UDPSessions) Add(session *UDPSession) {
	udpSessions.mutex.Lock()
	defer udpSessions.mutex.Unlock()
	udpSessions.sessions[session.key] = session
}

// the session is removed if nothing went either way for idleTimeout, otherwise it keeps running; a datagram held in the rules counts as going, the idle time starts again
func (udpSessions *UDPSessions) Expire(session *UDPSession, idleTimeout time.Duration) (expired bool) {
	udpSessions.mutex.Lock()
	defer udpSessions.mutex.Unlock()

	if session.busy.Load() > 0 {
		session.lastActive.Store(time.Now().UnixNano())
		return
	}

	if time.Since(time.Unix(0, session.lastActive.Load())) < idleTimeout {
		return
	}

	if udpSessions.sessions[session.key] == session {
		delete(udpSessions.sessions, session.key)
	}

	expired = true
	return
}

func (udpSessions *UDPSessions) Remove(session *UDPSession) {
	udpSessions.mutex.Lock()
	defer udpSessions.mutex.Unlock()

	if udpSessions.sessions[session.key] == session {
		delete(udpSessions.sessions, session.key)
	}
}

// a message of the session through the rules, which may hold it: the session is busy meanwhile and active once it is through
func (session *UDPSession) process(ctx context.Context, pipeline *intercept.Pipeline, message intercept.Message, logger *slog.Logger) (result intercept.Result) {
	session.busy.Add(1)

	defer func() {
		session.lastActive.Store(time.Now().UnixNano())
		session.busy.Add(-1)
	}()

	result = pipeline.Process(ctx, message, logger)
	return
}

func newUDPQueue() (queue *udpQueue) {
	mutex := &sync.Mutex{}
	queue = &udpQueue{
		mutex:       mutex,
		wake:        sync.NewCond(mutex),
		datagrams:   nil,
		queuedBytes: 0,
		isClosed:    false,
		sender:      &sync.WaitGroup{},
	}
	return
}

// isTaken is false when the queue is full or closed, the datagram is lost then
func (queue *udpQueue) take(datagram []byte) (isTaken bool) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()

	if queue.isClosed || (queue.queuedBytes >= maxSendQueueBytes) {
		return
	}

	queue.datagrams = append(queue.datagrams, bytes.Clone(datagram))
	queue.queuedBytes += len(datagram)
	queue.wake.Broadcast()
	isTaken = true
	return
}

// the datagrams that wait, waits for them; isEnd is true once the queue is closed and empty
func (queue *udpQueue) next() (datagrams [][]byte, isEnd bool) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()

	for (len(queue.datagrams) == 0) && !queue.isClosed {
		queue.wake.Wait()
	}

	datagrams = queue.datagrams
	queue.datagrams = nil
	isEnd = (len(datagrams) == 0) && queue.isClosed
	return
}

func (queue *udpQueue) sent(size int) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()
	queue.queuedBytes -= size
}

// the sender ends after the datagrams it has, close waits for it
func (queue *udpQueue) close() {
	queue.mutex.Lock()
	queue.isClosed = true
	queue.wake.Broadcast()
	queue.mutex.Unlock()
	queue.sender.Wait()
}
