// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decerter/decerter/internal/bpf/redirect"
)

// the cookie tells a new socket on a reused client port apart, the destination the servers of one unconnected socket
type UDPSessionKey struct {
	client      netip.AddrPort
	cookie      uint64
	destination netip.AddrPort
}

// one client socket to one original destination over one upstream socket
type UDPSession struct {
	key                 UDPSessionKey
	flow                redirect.Flow
	cmdline             string
	upstream            *net.UDPConn
	replyControlMessage []byte
	startTime           time.Time
	lastActive          atomic.Int64
	upDatagrams         atomic.Int64
	upBytes             atomic.Int64
	downDatagrams       atomic.Int64
	downBytes           atomic.Int64
}

// sessions by key, the mutex also orders the idle check against a new datagram of the same session
type UDPSessions struct {
	mutex    *sync.Mutex
	sessions map[UDPSessionKey]*UDPSession
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

// the session is removed if nothing went either way for idleTimeout, otherwise it keeps running
func (udpSessions *UDPSessions) Expire(session *UDPSession, idleTimeout time.Duration) (expired bool) {
	udpSessions.mutex.Lock()
	defer udpSessions.mutex.Unlock()

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
