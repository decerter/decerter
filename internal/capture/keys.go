// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"bytes"
	"log/slog"
	"slices"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/pcapng"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
)

const (
	// hold queue: the bytes and the time the packets of one flow may wait for the secrets of its session, the same as in the proxy
	maxHoldBytes int           = 1 << 20
	holdTimeout  time.Duration = 10 * time.Second
	// the packets of all flows together that may wait, the flow that goes over it is written without keys
	maxTotalHoldBytes int = 64 << 20
	// the secrets of a flow are looked up with a growing pause while its packets wait
	holdPollStart time.Duration = time.Millisecond
	holdPollMax   time.Duration = 100 * time.Millisecond
	// a flow without a packet for this long is forgotten, the writer is not told when a socket closes
	flowIdleTimeout time.Duration = time.Minute
	// how often idle flows are forgotten and the drop counter is read
	sweepInterval time.Duration = 10 * time.Second
)

// IP header fields the writer reads to find the TCP payload
const (
	ipv4Version           uint8 = 4
	ipv6Version           uint8 = 6
	ipv4MinHeaderLength   int   = 20
	ipv4ProtocolOffset    int   = 9
	ipv4FragmentOffset    int   = 6
	ipv4FragmentMask      uint8 = 0x1F
	ipv6HeaderLength      int   = 40
	ipv6NextHeaderOffset  int   = 6
	ipv6ExtensionUnit     int   = 8
	ipv6HopByHop          uint8 = 0
	ipv6Routing           uint8 = 43
	ipv6DestinationOption uint8 = 60
	ipv6MaxExtensions     int   = 8
	tcpMinHeaderLength    int   = 20
	tcpDataOffsetOffset   int   = 12
)

// why the packets of a flow were written without its secrets
const (
	timeoutReason     string = "no secrets before the hold timeout"
	holdLimitReason   string = "too many bytes waited for the secrets"
	totalLimitReason  string = "too many bytes of all flows waited for secrets"
	stoppedReason     string = "no secrets before the capture stopped"
	clientHelloReason string = "could not read the client hello"
)

type flowState uint8

const (
	watchedFlowState flowState = 0 // no ClientHello seen yet, the packets are written as they come
	heldFlowState    flowState = 1 // ClientHello seen, the packets wait for the secrets of the session
	passedFlowState  flowState = 2 // the secrets are written or given up, the packets are written as they come and not looked at
)

// what the writer keeps of one recorded socket
// conn reads the ClientHello and is nil once the client_random is known
// held are the packets that wait from the ClientHello on, heldBytes their length
// pollPause and nextPoll spread the lookups of the secrets, holdStart is when the ClientHello came
type flow struct {
	state           flowState
	conn            *tlsrecord.Conn
	hasClientRandom bool
	clientRandom    [32]byte
	serverName      string
	held            []pcapng.Packet
	heldBytes       int
	holdStart       time.Time
	pollPause       time.Duration
	nextPoll        time.Time
	lastPacket      time.Time
}

// the state of the capture writer, only the goroutine of Write uses it
// holding are the cookies of the held flows in the order their hold started, heldBytes the packets of all of them
// nextWake is when tick has to run again: the next lookup of a held flow, or idleWake away when nothing is held
type recorder struct {
	writer          *pcapng.Writer
	bootOffset      int64
	captureBpfMaps  map[bpf.BpfMapName]*ebpf.Map
	secretsBpfMaps  map[bpf.BpfMapName]*ebpf.Map
	flows           map[uint64]*flow
	holding         []uint64
	heldBytes       int
	nextWake        time.Time
	nextSweep       time.Time
	packets         uint64
	bytes           uint64
	keyedSessions   uint64
	keylessSessions uint64
	dropped         uint64
	logger          *slog.Logger
}

func newRecorder(writer *pcapng.Writer, bootOffset int64, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, now time.Time, logger *slog.Logger) (newRecorder recorder) {
	newRecorder = recorder{
		writer:          writer,
		bootOffset:      bootOffset,
		captureBpfMaps:  captureBpfMaps,
		secretsBpfMaps:  secretsBpfMaps,
		flows:           map[uint64]*flow{},
		holding:         nil,
		heldBytes:       0,
		nextWake:        now.Add(idleWake),
		nextSweep:       now.Add(sweepInterval),
		packets:         0,
		bytes:           0,
		keyedSessions:   0,
		keylessSessions: 0,
		dropped:         0,
		logger:          logger,
	}
	return
}

// write the packet, or keep it while its flow waits for the secrets of its TLS session
// Wireshark uses the secrets only for the packets behind them in the file and has to have them when it reads the ServerHello, so a flow is held from its ClientHello on
func (recorder *recorder) handle(packet capturebpf.Packet, now time.Time) (err error) {
	currentFlow, ok := recorder.flows[packet.Cookie]

	if !ok {
		currentFlow = &flow{
			state:           watchedFlowState,
			conn:            nil,
			hasClientRandom: false,
			clientRandom:    [32]byte{},
			serverName:      "",
			held:            nil,
			heldBytes:       0,
			holdStart:       time.Time{},
			pollPause:       0,
			nextPoll:        time.Time{},
			lastPacket:      now,
		}

		// without the secrets uprobe there is nothing to wait for
		if recorder.secretsBpfMaps == nil {
			currentFlow.state = passedFlowState
		}

		recorder.flows[packet.Cookie] = currentFlow
	}

	currentFlow.lastPacket = now
	direction := pcapng.OutboundDirection

	if packet.IsIngress {
		direction = pcapng.InboundDirection
	}

	// the same offset for every packet, so the order of the timestamps is the one of the kernel
	pcapPacket := pcapng.Packet{
		Timestamp:      uint64(int64(packet.TimestampNs) + recorder.bootOffset),
		Direction:      direction,
		OriginalLength: packet.Length,
		Data:           packet.Data,
	}
	var payload []byte

	// only client flows are recorded, so what the socket sends is the client side of the session
	if !packet.IsIngress && ((currentFlow.state == watchedFlowState) || ((currentFlow.state == heldFlowState) && !currentFlow.hasClientRandom)) {
		payload = tcpPayload(packet.Data)
	}

	// a ClientHello at the start of any segment the client sends: a session can start in the middle of a flow, behind STARTTLS or a CONNECT to a proxy
	// one that the snaplen cut is not waited for, nothing can decrypt a session with a part of its handshake missing
	if (currentFlow.state == watchedFlowState) && (len(payload) > 0) && (uint32(len(packet.Data)) == packet.Length) {
		isClientHello, _ := tlsrecord.IsClientHello(payload)

		if isClientHello {
			recorder.hold(packet.Cookie, currentFlow, now)
		}
	}

	if currentFlow.state != heldFlowState {
		err = recorder.write(pcapPacket)
		return
	}

	// the record of the reader is used again for the next packet
	pcapPacket.Data = bytes.Clone(packet.Data)
	currentFlow.held = append(currentFlow.held, pcapPacket)
	currentFlow.heldBytes += len(pcapPacket.Data)
	recorder.heldBytes += len(pcapPacket.Data)

	if !currentFlow.hasClientRandom && (len(payload) > 0) {
		err = recorder.readClientHello(packet.Cookie, currentFlow, payload)

		if (err != nil) || (currentFlow.state != heldFlowState) {
			return
		}
	}

	// a last lookup before the flow is given up
	switch {
	case currentFlow.heldBytes > maxHoldBytes:
		err = recorder.release(packet.Cookie, currentFlow, recorder.lookup(packet.Cookie, currentFlow), holdLimitReason)
	case recorder.heldBytes > maxTotalHoldBytes:
		err = recorder.release(packet.Cookie, currentFlow, recorder.lookup(packet.Cookie, currentFlow), totalLimitReason)
	default:
	}

	return
}

// start to keep the packets of the flow, its first lookup is due at once
func (recorder *recorder) hold(cookie uint64, heldFlow *flow, now time.Time) {
	conn := tlsrecord.New(maxHoldBytes)
	heldFlow.state = heldFlowState
	heldFlow.conn = &conn
	heldFlow.holdStart = now
	heldFlow.pollPause = holdPollStart
	heldFlow.nextPoll = now
	recorder.holding = append(recorder.holding, cookie)

	if now.Before(recorder.nextWake) {
		recorder.nextWake = now
	}
}

// feed the client bytes to the record layer until the ClientHello is whole, it can be longer than one segment
// the segments are taken in the order they were sent, a ClientHello that had to be sent again is not read and its flow is written without keys
func (recorder *recorder) readClientHello(cookie uint64, heldFlow *flow, payload []byte) (err error) {
	_, feedErr := heldFlow.conn.Feed(tlsrecord.ClientDirection, payload)

	if feedErr != nil {
		recorder.logger.Debug("Could not read client hello", "error", feedErr, "cookie", cookie)
		err = recorder.release(cookie, heldFlow, "", clientHelloReason)
		return
	}

	session := heldFlow.conn.Session()

	// the random of a ClientHello that was read is never all zero
	if session.ClientRandom == [32]byte{} {
		return
	}

	heldFlow.hasClientRandom = true
	heldFlow.clientRandom = session.ClientRandom
	heldFlow.serverName = session.ServerName
	heldFlow.conn = nil
	return
}

// look the secrets of the held flows up and write the flows whose secrets are there or whose time is over, then forget idle flows and count the drops when that is due
// the secrets are polled from secrets_map and not read from its ringbuf: a session can be in the map before or after its ClientHello is read here, the two ringbufs have no common order, and an event lost to a full ringbuf would leave a flow without keys
func (recorder *recorder) tick(now time.Time) (err error) {
	for _, cookie := range slices.Clone(recorder.holding) {
		heldFlow := recorder.flows[cookie]

		if !now.Before(heldFlow.nextPoll) {
			keyLog := recorder.lookup(cookie, heldFlow)

			if keyLog != "" {
				err = recorder.release(cookie, heldFlow, keyLog, "")

				if err != nil {
					return
				}

				continue
			}

			heldFlow.pollPause = min(2*heldFlow.pollPause, holdPollMax)
			heldFlow.nextPoll = now.Add(heldFlow.pollPause)
		}

		if now.Sub(heldFlow.holdStart) >= holdTimeout {
			err = recorder.release(cookie, heldFlow, recorder.lookup(cookie, heldFlow), timeoutReason)

			if err != nil {
				return
			}
		}
	}

	if !now.Before(recorder.nextSweep) {
		recorder.nextSweep = now.Add(sweepInterval)
		recorder.forgetIdleFlows(now)
		recorder.countDropped()
	}

	recorder.nextWake = now.Add(idleWake)

	for _, cookie := range recorder.holding {
		if recorder.flows[cookie].nextPoll.Before(recorder.nextWake) {
			recorder.nextWake = recorder.flows[cookie].nextPoll
		}
	}

	return
}

// the key log lines of the session of a held flow, empty while the uprobe has not seen its complete secrets
func (recorder *recorder) lookup(cookie uint64, heldFlow *flow) (keyLog string) {
	if !heldFlow.hasClientRandom {
		return
	}

	keyLog, found, lookupErr := secrets.LookupKeyLog(heldFlow.clientRandom, recorder.secretsBpfMaps)

	if lookupErr != nil {
		recorder.logger.Debug("Could not look up tls secrets", "error", lookupErr, "cookie", cookie)
	}

	if !found {
		keyLog = ""
	}

	return
}

// write the packets of a held flow, behind the key log of its session if there is one, the flow is not looked at again
func (recorder *recorder) release(cookie uint64, heldFlow *flow, keyLog string, reason string) (err error) {
	waited := time.Since(heldFlow.holdStart).Round(time.Millisecond)

	if keyLog != "" {
		err = recorder.writer.WriteSecrets([]byte(keyLog))

		if err != nil {
			return
		}

		recorder.keyedSessions++
		recorder.logger.Info("Wrote tls secrets", "cookie", cookie, "serverName", heldFlow.serverName, "heldPackets", len(heldFlow.held), "heldBytes", heldFlow.heldBytes, "waited", waited)
	} else {
		recorder.keylessSessions++
		recorder.logger.Warn("Could not find tls secrets, the flow is written without keys", "reason", reason, "cookie", cookie, "serverName", heldFlow.serverName, "heldPackets", len(heldFlow.held), "heldBytes", heldFlow.heldBytes, "waited", waited)
	}

	for _, heldPacket := range heldFlow.held {
		err = recorder.write(heldPacket)

		if err != nil {
			return
		}
	}

	recorder.heldBytes -= heldFlow.heldBytes
	recorder.holding = slices.DeleteFunc(recorder.holding, func(heldCookie uint64) bool {
		return heldCookie == cookie
	})
	heldFlow.state = passedFlowState
	heldFlow.conn = nil
	heldFlow.held = nil
	heldFlow.heldBytes = 0
	return
}

func (recorder *recorder) write(packet pcapng.Packet) (err error) {
	err = recorder.writer.WritePacket(packet)

	if err != nil {
		return
	}

	recorder.packets++
	recorder.bytes += uint64(len(packet.Data))
	return
}

// a held flow is never idle here, its hold ends after holdTimeout
// a flow that sends again later starts as a new one, which only matters for a ClientHello and that is looked for in every flow
func (recorder *recorder) forgetIdleFlows(now time.Time) {
	for cookie, idleFlow := range recorder.flows {
		if (idleFlow.state != heldFlowState) && (now.Sub(idleFlow.lastPacket) >= flowIdleTimeout) {
			delete(recorder.flows, cookie)
		}
	}
}

// warn when packets were lost since the last look, the reader was slower than the recorded sockets
func (recorder *recorder) countDropped() {
	dropped, readErr := capturebpf.ReadDropped(recorder.captureBpfMaps)

	if readErr != nil {
		recorder.logger.Warn("Could not read dropped packets", "error", readErr)
		return
	}

	if dropped > recorder.dropped {
		recorder.logger.Warn("Dropped packets, packet_map was full", "dropped", dropped-recorder.dropped, "droppedTotal", dropped)
	}

	recorder.dropped = dropped
}

// the capture stops: the held flows get a last lookup and are written, then the file is flushed
func (recorder *recorder) finish() (err error) {
	for _, cookie := range slices.Clone(recorder.holding) {
		heldFlow := recorder.flows[cookie]
		err = recorder.release(cookie, heldFlow, recorder.lookup(cookie, heldFlow), stoppedReason)

		if err != nil {
			return
		}
	}

	err = recorder.writer.Flush()

	if err != nil {
		return
	}

	recorder.countDropped()
	recorder.logger.Info("Capture written", "packets", recorder.packets, "bytes", recorder.bytes, "sessionsWithSecrets", recorder.keyedSessions, "sessionsWithoutSecrets", recorder.keylessSessions, "droppedPackets", recorder.dropped)
	return
}

// the TCP payload of a packet that starts at its IP header, nil for everything else: not TCP, a later fragment, cut off by the snaplen
func tcpPayload(data []byte) (payload []byte) {
	if len(data) == 0 {
		return
	}

	tcpOffset := 0

	switch data[0] >> 4 {
	case ipv4Version:
		headerLength := int(data[0]&0x0F) * 4

		if (headerLength < ipv4MinHeaderLength) || (len(data) < headerLength) || (data[ipv4ProtocolOffset] != syscall.IPPROTO_TCP) {
			return
		}

		// only the first fragment has the TCP header
		if (data[ipv4FragmentOffset]&ipv4FragmentMask != 0) || (data[ipv4FragmentOffset+1] != 0) {
			return
		}

		tcpOffset = headerLength
	case ipv6Version:
		if len(data) < ipv6HeaderLength {
			return
		}

		nextHeader := data[ipv6NextHeaderOffset]
		tcpOffset = ipv6HeaderLength

		// the options a socket can set come before the TCP header: next header, then the length in units of 8 bytes without the first unit
		for range ipv6MaxExtensions {
			if (nextHeader != ipv6HopByHop) && (nextHeader != ipv6Routing) && (nextHeader != ipv6DestinationOption) {
				break
			}

			if len(data) < tcpOffset+ipv6ExtensionUnit {
				return
			}

			nextHeader = data[tcpOffset]
			tcpOffset += (int(data[tcpOffset+1]) + 1) * ipv6ExtensionUnit
		}

		if nextHeader != syscall.IPPROTO_TCP {
			return
		}
	default:
		return
	}

	if len(data) < tcpOffset+tcpMinHeaderLength {
		return
	}

	payloadOffset := tcpOffset + int(data[tcpOffset+tcpDataOffsetOffset]>>4)*4

	if (payloadOffset < tcpOffset+tcpMinHeaderLength) || (len(data) <= payloadOffset) {
		return
	}

	payload = data[payloadOffset:]
	return
}
