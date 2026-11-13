// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	maxDatagramSize int           = 65535
	readBackoff     time.Duration = 100 * time.Millisecond
)

// one dual-stack socket for IPv4 and IPv6 clients, IPv4 peers show up IPv4-mapped (::ffff:127.0.0.1)
func ListenUDP(ctx context.Context, port uint16) (connection *net.UDPConn, err error) {
	listenConfig := net.ListenConfig{
		Control: controlUDP,
	}
	packetConnection, listenErr := listenConfig.ListenPacket(ctx, "udp", net.JoinHostPort("::", strconv.Itoa(int(port))))

	if err = listenErr; err != nil {
		err = fmt.Errorf("%w: udp %d: %w", ErrListen, port, err)
		return
	}

	connection = packetConnection.(*net.UDPConn)
	return
}

// SO_BINDTODEVICE lo keeps the socket unreachable from the network
// IPV6_RECVPKTINFO gives the destination address of every datagram, IPv4-mapped for IPv4 ones, the reply is sent from exactly that address
func controlUDP(network, address string, rawConnection syscall.RawConn) (err error) {
	controlErr := rawConnection.Control(func(fileDescriptor uintptr) {
		err = errors.Join(
			unix.SetsockoptInt(int(fileDescriptor), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0),
			unix.SetsockoptString(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo"),
			unix.SetsockoptInt(int(fileDescriptor), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1),
		)
	})
	err = errors.Join(err, controlErr)
	return
}

// read until the socket is closed by the context, every session relays its replies in its own goroutine on waitGroup
// pipeline runs every datagram of both directions through its rules, nil relays them as they are; the client's datagrams go through them in a sender per session, so a held one stops only its session
// a session whose first datagram has a DTLS ClientHello is read by the DTLS record layer with the secrets of secretsBpfMaps: intercepted with a pipeline, observed and printed without one
// scope decides each session when it starts, with the DTLS ClientHello of its first datagram: one out of scope is relayed as it is, without the record layer, rules or a flow line; nil is every session in scope
// recorder is the API's history, every session in scope goes into it; nil records nothing
// captureBpfMaps are the maps of the capture object: every upstream socket goes into its upstream_map, so the API captures what goes on the wire; nil captures nothing
func ServeUDP(ctx context.Context, connection *net.UDPConn, idleTimeout time.Duration, bpfMaps map[bpf.BpfMapName]*ebpf.Map, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, pipeline *intercept.Pipeline, scope *filter.Filter, recorder *history.History, waitGroup *sync.WaitGroup, logger *slog.Logger) {
	// socket closer
	stop := context.AfterFunc(ctx, func() {
		closeErr := connection.Close()

		if closeErr != nil {
			logger.Error("Could not close udp socket", "error", closeErr)
		}
	})
	defer stop()
	sessions := NewUDPSessions()
	buffer := make([]byte, maxDatagramSize)
	controlMessage := make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))

	for {
		datagramSize, controlMessageSize, _, client, readErr := connection.ReadMsgUDPAddrPort(buffer, controlMessage)

		if readErr != nil {
			if errors.Is(readErr, net.ErrClosed) {
				logger.Debug("Udp socket closed")
				return
			}

			// temporary errors like ENOBUFS, try again after a short pause
			logger.Error("Could not read udp datagram", "error", readErr)

			select {
			case <-ctx.Done():
				return
			case <-time.After(readBackoff):
			}

			continue
		}

		local, localErr := datagramDestination(controlMessage[:controlMessageSize])

		if localErr != nil {
			logger.Warn("Could not read destination of datagram", "error", localErr, "client", client)
			continue
		}

		session, sessionErr := udpSessionOf(ctx, connection, client, local, buffer[:datagramSize], &sessions, idleTimeout, bpfMaps, secretsBpfMaps, captureBpfMaps, pipeline, scope, recorder, waitGroup, logger)

		if sessionErr != nil {
			continue
		}

		// the sender of the DTLS session writes what the record layer makes of the datagram
		if isDTLSIntercepted(session) {
			if !session.dtls.take(tlsrecord.ClientDirection, buffer[:datagramSize]) {
				logger.Debug("Could not queue dtls datagram, it is lost", "client", client, "destination", session.key.destination)
			}

			continue
		}

		// the sender of the session runs the rules and writes
		if session.upQueue != nil {
			if !session.upQueue.take(buffer[:datagramSize]) {
				logger.Debug("Could not queue udp datagram, it is lost", "client", client, "destination", session.key.destination)
			}

			continue
		}

		if session.dtls != nil {
			session.dtls.observe(tlsrecord.ClientDirection, buffer[:datagramSize])
		}

		datagram, isSent := interceptDatagram(ctx, pipeline, session, tlsrecord.ClientDirection, buffer[:datagramSize], logger)

		if !isSent {
			continue
		}

		_, writeErr := session.upstream.Write(datagram)

		if writeErr != nil {
			// an ICMP error of an earlier datagram shows up here as ECONNREFUSED, the datagram is lost like without the proxy
			logger.Debug("Could not send datagram to original destination", "error", writeErr, "client", client, "destination", session.key.destination)
			continue
		}

		session.upDatagrams.Add(1)
		session.upBytes.Add(int64(len(datagram)))
	}
}

// struct in6_pktinfo: 16 byte destination address, then the interface index
func datagramDestination(controlMessage []byte) (local netip.Addr, err error) {
	messages, parseErr := unix.ParseSocketControlMessage(controlMessage)

	if err = parseErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrPacketInfo, err)
		return
	}

	for _, message := range messages {
		if (message.Header.Level != unix.IPPROTO_IPV6) || (message.Header.Type != unix.IPV6_PKTINFO) || (len(message.Data) < unix.SizeofInet6Pktinfo) {
			continue
		}

		local = netip.AddrFrom16([16]byte(message.Data[:16]))
		return
	}

	err = ErrPacketInfo
	return
}

// the flow is looked up for every datagram: a new socket on the same client port or a new destination of an unconnected socket gets its own session
// the datagram that starts a session tells if it is DTLS
func udpSessionOf(ctx context.Context, connection *net.UDPConn, client netip.AddrPort, local netip.Addr, datagram []byte, sessions *UDPSessions, idleTimeout time.Duration, bpfMaps map[bpf.BpfMapName]*ebpf.Map, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, pipeline *intercept.Pipeline, scope *filter.Filter, recorder *history.History, waitGroup *sync.WaitGroup, logger *slog.Logger) (session *UDPSession, err error) {
	cookie, flow, lookupErr := redirect.FlowByClient(client, syscall.IPPROTO_UDP, bpfMaps)

	if err = lookupErr; err != nil {
		logger.Warn("Could not find flow of client", "error", err, "client", client)
		return
	}

	key := UDPSessionKey{
		client:      client,
		cookie:      cookie,
		destination: flow.OriginalDestination,
	}
	session = sessions.Get(key)

	if session != nil {
		return
	}

	logger = logger.With("client", client, "cookie", cookie, "destination", flow.OriginalDestination)
	localAddressPort := connection.LocalAddr().(*net.UDPAddr).AddrPort()

	if isLoop(flow.OriginalDestination, localAddressPort) {
		err = ErrLoop
		logger.Warn("Could not proxy flow", "error", err)
		return
	}

	cmdline, processErr := processCmdline(flow.Tgid)

	if processErr != nil {
		logger.Debug("Could not read process info", "error", processErr, "tgid", flow.Tgid)
	}

	// the first datagram is all the session has when it is decided, a DTLS ClientHello fragmented over more datagrams counts as one without fields
	// a DTLS ClientHello that can not be read is TLS without its fields
	hello, _, _ := tlsrecord.ReadDTLSClientHello(datagram)
	values := scopeValues(flow, cmdline, client, scope, recorder != nil).WithClientHello(tlsrecord.IsDTLSClientHello(datagram), hello.Version, hello.ServerName, hello.Protocols)
	result := isInScope(scope, values)

	if cmdline == "" {
		cmdline = "?"
	}

	// the own tgid is excluded in connect4/6, so this socket is not redirected again
	upstreamConnection, upstreamCookie, dialErr := dialUpstream(ctx, "udp", flow, cookie, 0, captureBpfMaps, logger)

	if err = dialErr; err != nil {
		logger.Warn("Could not dial original destination", "error", err)
		return
	}

	upstream := upstreamConnection.(*net.UDPConn)

	// a connected client only accepts the address it connected to, which is the proxy address the datagram went to
	session = &UDPSession{
		key:                 key,
		flow:                flow,
		cmdline:             cmdline,
		upstream:            upstream,
		upstreamCookie:      upstreamCookie,
		replyControlMessage: unix.PktInfo6(&unix.Inet6Pktinfo{Addr: local.As16(), Ifindex: 0}),
		startTime:           time.Now(),
		isInScope:           result == filter.TrueResult,
	}
	session.lastActive.Store(session.startTime.UnixNano())

	// out of scope the datagrams go on as they are, past the rules and the history
	if session.isInScope {
		flowID := recorder.OpenFlow(cookie, values, hello.ClientRandom)
		session.interceptFlow = intercept.FlowOf(flowID, cookie, flow, client, values)
		startDTLS(ctx, connection, session, datagram, secretsBpfMaps, pipeline, recorder, logger)
	} else {
		session.isRaw = true
		logger.Debug("Udp session is out of scope, relaying it as it is")
	}

	// plain datagrams through the rules: the client's go through a sender of the session
	if (pipeline != nil) && !session.isRaw && (session.dtls == nil) {
		session.upQueue = newUDPQueue()

		// udp sender of the session
		session.upQueue.sender.Go(func() {
			sendUDP(ctx, pipeline, session, logger)
		})
	}

	sessions.Add(session)

	// udp reply relay
	waitGroup.Go(func() {
		relayUDP(ctx, connection, session, sessions, idleTimeout, captureBpfMaps, pipeline, recorder, logger)
	})

	return
}

// copy replies from upstream to the client until the session is idle for idleTimeout or the context is cancelled
func relayUDP(ctx context.Context, connection *net.UDPConn, session *UDPSession, sessions *UDPSessions, idleTimeout time.Duration, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, pipeline *intercept.Pipeline, recorder *history.History, logger *slog.Logger) {
	// a deadline in the past unblocks the upstream read
	stop := context.AfterFunc(ctx, func() {
		deadlineErr := session.upstream.SetReadDeadline(time.Unix(1, 0))

		if deadlineErr != nil {
			logger.Debug("Could not abort udp session", "error", deadlineErr)
		}
	})
	defer stop()

	defer func() {
		sessions.Remove(session)

		// the senders of a DTLS session and of plain datagrams write to the upstream socket until they are done
		if session.dtls != nil {
			session.dtls.close()
		}

		if session.upQueue != nil {
			session.upQueue.close()
		}

		closeErr := session.upstream.Close()

		if closeErr != nil {
			logger.Error("Could not close upstream socket", "error", closeErr)
		}

		releaseUpstream(session.upstreamCookie, captureBpfMaps, logger)

		up := strconv.FormatInt(session.upDatagrams.Load(), 10) + "dgram/" + strconv.FormatInt(session.upBytes.Load(), 10) + "B"
		down := strconv.FormatInt(session.downDatagrams.Load(), 10) + "dgram/" + strconv.FormatInt(session.downBytes.Load(), 10) + "B"

		if !session.isInScope {
			return
		}

		recorder.CloseFlow(session.interceptFlow.ID, history.Counters{Bytes: session.upBytes.Load(), Datagrams: session.upDatagrams.Load()}, history.Counters{Bytes: session.downBytes.Load(), Datagrams: session.downDatagrams.Load()})
		printFlow(session.flow, session.cmdline, session.key.client, up, down, time.Since(session.startTime))
	}()

	buffer := make([]byte, maxDatagramSize)

	for {
		deadlineErr := session.upstream.SetReadDeadline(time.Unix(0, session.lastActive.Load()).Add(idleTimeout))

		if deadlineErr != nil {
			logger.Debug("Could not set upstream read deadline", "error", deadlineErr)
			return
		}

		// checked after the deadline is set, so a cancel in between is not overwritten
		if ctx.Err() != nil {
			return
		}

		datagramSize, readErr := session.upstream.Read(buffer)

		if readErr != nil {
			switch {
			case ctx.Err() != nil:
				return
			case errors.Is(readErr, os.ErrDeadlineExceeded):
				if sessions.Expire(session, idleTimeout) {
					return
				}
			case errors.Is(readErr, syscall.ECONNREFUSED):
				// ICMP port unreachable from the original destination, the client only sees a missing reply
				logger.Debug("Original destination refused datagram", "error", readErr)
			default:
				logger.Debug("Could not read upstream datagram", "error", readErr)
				return
			}

			continue
		}

		session.lastActive.Store(time.Now().UnixNano())

		if isDTLSIntercepted(session) {
			if !session.dtls.take(tlsrecord.ServerDirection, buffer[:datagramSize]) {
				logger.Debug("Could not queue dtls datagram, it is lost")
			}

			continue
		}

		if session.dtls != nil {
			session.dtls.observe(tlsrecord.ServerDirection, buffer[:datagramSize])
		}

		datagram, isSent := interceptDatagram(ctx, pipeline, session, tlsrecord.ServerDirection, buffer[:datagramSize], logger)

		if !isSent {
			continue
		}

		_, _, writeErr := connection.WriteMsgUDPAddrPort(datagram, session.replyControlMessage, session.key.client)

		if writeErr != nil {
			if errors.Is(writeErr, net.ErrClosed) {
				return
			}

			logger.Debug("Could not send datagram to client", "error", writeErr)
			continue
		}

		session.downDatagrams.Add(1)
		session.downBytes.Add(int64(len(datagram)))
	}
}

// a datagram after the rules of the pipeline, isSent is false when a rule dropped it; without a pipeline it goes on as it is
func interceptDatagram(ctx context.Context, pipeline *intercept.Pipeline, session *UDPSession, direction tlsrecord.Direction, datagram []byte, logger *slog.Logger) (result []byte, isSent bool) {
	result = datagram
	isSent = true

	if (pipeline == nil) || session.isRaw {
		return
	}

	processed := session.process(ctx, pipeline, pipeline.Message(session.interceptFlow, direction, intercept.UDPLayer, datagram), logger)
	result = processed.Plain
	isSent = processed.Verdict == intercept.ForwardVerdict
	return
}

// the client's datagrams of one session through the rules and to the server, in order, until the session is over
func sendUDP(ctx context.Context, pipeline *intercept.Pipeline, session *UDPSession, logger *slog.Logger) {
	for {
		datagrams, isEnd := session.upQueue.next()

		if isEnd {
			return
		}

		size := 0

		for _, datagram := range datagrams {
			size += len(datagram)
			result, isSent := interceptDatagram(ctx, pipeline, session, tlsrecord.ClientDirection, datagram, logger)

			if !isSent {
				continue
			}

			_, writeErr := session.upstream.Write(result)

			if writeErr != nil {
				// an ICMP error of an earlier datagram shows up here as ECONNREFUSED, the datagram is lost like without the proxy
				logger.Debug("Could not send datagram to original destination", "error", writeErr, "client", session.key.client, "destination", session.key.destination)
				continue
			}

			session.upDatagrams.Add(1)
			session.upBytes.Add(int64(len(result)))
		}

		session.upQueue.sent(size)
	}
}

// a session whose first datagram has a DTLS ClientHello gets the DTLS record layer when there are secrets, and is relayed past the rules without them
// intercepting, a sender per direction writes the datagrams: to the server over the upstream socket, to the client from the proxy address it sent to
func startDTLS(ctx context.Context, connection *net.UDPConn, session *UDPSession, datagram []byte, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, pipeline *intercept.Pipeline, recorder *history.History, logger *slog.Logger) {
	if !tlsrecord.IsDTLSClientHello(datagram) {
		return
	}

	if secretsBpfMaps == nil {
		session.isRaw = true
		logger.Debug("Udp session is dtls but there are no secrets, relaying raw")
		return
	}

	session.dtls = newDTLSInterception(session, pipeline, secretsBpfMaps, recorder, logger)

	if pipeline == nil {
		return
	}

	writers := [2]func(datagram []byte) error{
		func(datagram []byte) (err error) {
			_, err = session.upstream.Write(datagram)

			if err != nil {
				return
			}

			session.upDatagrams.Add(1)
			session.upBytes.Add(int64(len(datagram)))
			return
		},
		func(datagram []byte) (err error) {
			_, _, err = connection.WriteMsgUDPAddrPort(datagram, session.replyControlMessage, session.key.client)

			if err != nil {
				return
			}

			session.downDatagrams.Add(1)
			session.downBytes.Add(int64(len(datagram)))
			return
		},
	}
	session.dtls.start(ctx, writers)
}

// the datagrams of the session go through the senders of its DTLS session
func isDTLSIntercepted(session *UDPSession) (isIntercepted bool) {
	isIntercepted = (session.dtls != nil) && (session.dtls.pipeline != nil)
	return
}
