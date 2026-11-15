// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"bytes"
	"fmt"
	"slices"
	"syscall"
	"time"

	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/pcapng"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// the bytes of one direction of a connection that may wait behind a hole for a segment that comes late, the receive window of the usual socket buffers fits
	maxStreamBytes int = 8 << 20
	// what a mark costs, counted with the bytes that wait
	markOverhead int = 16
	// the longest packet whose length fits the 16 bit length fields of the IP and UDP headers that are built
	maxDatagramLength uint32 = 65535
	// every comment of a synthesized packet starts with this
	notePrefix string = "decerter: "
	// the comment of a hole: how many bytes of which side
	missingFormat string = "%d bytes the %s sent were not captured"
)

// why a TLS session was not decrypted to its end
const (
	closedReason  string = "the connection closed before the secrets were there"
	partialReason string = "the connection ended inside a tls record"
)

// the bytes of a direction up to end came with the packet of this timestamp, end counts from the ClientHello on
type mark struct {
	end       uint64
	timestamp uint64
}

// what the plaintext writer keeps of one recorded TCP connection, the arrays are indexed by the direction: the client is the recorded socket
// streams put the captured segments in order, sequence is the next sequence number of the synthesized packets, it moves with the bytes that are written and not with the ones on the wire
// note is the comment the next synthesized packet of the connection carries, missing the bytes of each direction that were not captured since the last one, they are part of the comment
// pending are the bytes given to the record layer that did not come out as a record: all of them from the ClientHello on until the secrets are there, so a session without secrets is written whole, later only the record that is not complete
// pendingOffset is where pending starts, read how far the records reach, marks the timestamps of the bytes in pending
type connection struct {
	endpoints     [2]Endpoint
	streams       [2]Stream
	sequence      [2]uint32
	hasSYN        [2]bool
	hasFIN        [2]bool
	isClosed      bool
	hasGap        bool
	isDescribed   bool
	note          string
	missing       [2]uint64
	lastTimestamp uint64
	pending       [2][]byte
	pendingOffset [2]uint64
	read          [2]uint64
	marks         [2][]mark
}

func newConnection(client Endpoint, server Endpoint) (newConnection *connection) {
	newConnection = &connection{
		endpoints:     [2]Endpoint{client, server},
		streams:       [2]Stream{NewStream(maxStreamBytes), NewStream(maxStreamBytes)},
		sequence:      [2]uint32{},
		hasSYN:        [2]bool{},
		hasFIN:        [2]bool{},
		isClosed:      false,
		hasGap:        false,
		isDescribed:   false,
		note:          "",
		missing:       [2]uint64{},
		lastTimestamp: 0,
		pending:       [2][]byte{},
		pendingOffset: [2]uint64{},
		read:          [2]uint64{},
		marks:         [2][]mark{},
	}
	return
}

// the stream of a direction starts at next, the synthesized SYN gets the sequence number in front of it
func (connection *connection) start(direction tlsrecord.Direction, next uint32) {
	if connection.streams[direction].IsStarted() {
		return
	}

	connection.streams[direction].Start(next)
	connection.sequence[direction] = next - 1
}

func (connection *connection) addNote(text string) {
	if connection.note != "" {
		connection.note += "; "
	}

	connection.note += text
}

func (connection *connection) hasNote() (hasNote bool) {
	hasNote = (connection.note != "") || (connection.missing != [2]uint64{})
	return
}

// the comment of the next packet, with one line for all the holes since the last one: with a small snaplen every packet is a hole
func (connection *connection) takeNote() (note string) {
	for direction, missing := range connection.missing {
		if missing > 0 {
			connection.addNote(fmt.Sprintf(missingFormat, missing, directionName(tlsrecord.Direction(direction))))
		}
	}

	note = connection.note
	connection.note = ""
	connection.missing = [2]uint64{}
	return
}

// the bytes the connection keeps: out of order behind a hole and in front of the record layer
func (connection *connection) held() (held int) {
	for direction := range connection.streams {
		held += connection.streams[direction].Held() + len(connection.pending[direction]) + markOverhead*len(connection.marks[direction])
	}

	return
}

// the timestamp of the packet that brought the byte in front of offset, the marks before it are not needed again: records come out in the order of the stream
func (connection *connection) timestampAt(direction tlsrecord.Direction, offset uint64) (timestamp uint64) {
	marks := connection.marks[direction]

	for (len(marks) > 1) && (marks[0].end < offset) {
		marks = marks[1:]
	}

	connection.marks[direction] = marks
	timestamp = connection.lastTimestamp

	if len(marks) > 0 {
		timestamp = marks[0].timestamp
	}

	return
}

// forget the bytes that came out as records
func (connection *connection) trim() {
	for direction := range connection.pending {
		connection.pending[direction] = connection.pending[direction][connection.read[direction]-connection.pendingOffset[direction]:]
		connection.pendingOffset[direction] = connection.read[direction]
		connection.timestampAt(tlsrecord.Direction(direction), connection.read[direction])
	}
}

// nothing more is written for the connection, a packet that comes late is not looked at
func (connection *connection) close() {
	connection.isClosed = true
	connection.streams = [2]Stream{}
	connection.pending = [2][]byte{}
	connection.marks = [2][]mark{}
}

func otherDirection(direction tlsrecord.Direction) (other tlsrecord.Direction) {
	other = tlsrecord.ClientDirection

	if direction == tlsrecord.ClientDirection {
		other = tlsrecord.ServerDirection
	}

	return
}

func directionName(direction tlsrecord.Direction) (name string) {
	name = "server"

	if direction == tlsrecord.ClientDirection {
		name = "client"
	}

	return
}

func isTLS(currentFlow *flow) (isTLS bool) {
	isTLS = (currentFlow.state == heldFlowState) || (currentFlow.state == decryptedFlowState)
	return
}

// the comment of the first decrypted packet of a session
func describe(session tlsrecord.Session) (text string) {
	layer := "tls"

	if session.Version == tlsrecord.VersionDTLS12 {
		layer = "dtls"
	}

	text = "decrypted " + layer + " session: " + tlsrecord.VersionName(session.Version) + ", " + tlsrecord.CipherSuiteName(session.CipherSuite)

	if session.ServerName != "" {
		text += ", server name " + session.ServerName
	}

	if session.Protocol != "" {
		text += ", alpn " + session.Protocol
	}

	return
}

// plaintext mode: write a synthesized packet for what the captured packet brings instead of the packet
// a UDP datagram is built again with its payload as it is or with the records of its DTLS session, a TCP segment goes through the stream of its direction, everything else is written as it was captured
func (recorder *recorder) synthesize(cookie uint64, currentFlow *flow, packet capturebpf.Packet, pcapPacket pcapng.Packet, now time.Time) (err error) {
	header, ok := parsePacket(packet.Data)

	switch {
	case ok && (header.protocol == syscall.IPPROTO_TCP):
		err = recorder.synthesizeTCP(cookie, currentFlow, packet, header, pcapPacket.Timestamp, now)
	case ok && (header.protocol == syscall.IPPROTO_UDP) && (uint32(len(packet.Data)) == packet.Length) && (packet.Length <= maxDatagramLength):
		err = recorder.synthesizeUDP(cookie, currentFlow, packet, pcapPacket, now)
	default:
		// nothing a packet can be built from: another protocol, a fragment, a packet the snaplen cut inside its headers or a cut datagram
		err = recorder.write(pcapPacket)
	}

	return
}

// one captured TCP packet: it starts the streams, acknowledges the stream of the other direction and adds its payload to the stream of its own
func (recorder *recorder) synthesizeTCP(cookie uint64, currentFlow *flow, packet capturebpf.Packet, header packetHeader, timestamp uint64, now time.Time) (err error) {
	direction := tlsrecord.ClientDirection

	// only client flows are recorded, so what the socket sends is the client side
	if packet.IsIngress {
		direction = tlsrecord.ServerDirection
	}

	other := otherDirection(direction)

	if currentFlow.connection == nil {
		if direction == tlsrecord.ClientDirection {
			currentFlow.connection = newConnection(header.source, header.destination)
		} else {
			currentFlow.connection = newConnection(header.destination, header.source)
		}
	}

	connection := currentFlow.connection

	if connection.isClosed {
		return
	}

	connection.lastTimestamp = timestamp
	isSYN := header.flags&SYNFlag != 0
	isACK := header.flags&ACKFlag != 0
	isFIN := header.flags&FINFlag != 0
	sequence := header.sequence

	if header.flags&RSTFlag != 0 {
		err = recorder.reset(cookie, currentFlow, direction, header, timestamp, now)
		return
	}

	// the SYN takes one sequence number, data in a SYN (TCP fast open) is behind it
	if isSYN {
		sequence++
	}

	// a connection that was open before the capture starts where its first packet is
	connection.start(direction, sequence)

	if isACK || !isSYN {
		connection.start(other, header.acknowledgment)
	}

	err = recorder.open(connection, timestamp)

	if err != nil {
		return
	}

	if isACK {
		recorder.parts = connection.streams[other].Acknowledge(header.acknowledgment, recorder.parts[:0])
		err = recorder.deliver(cookie, currentFlow, other, recorder.parts, timestamp, now)

		if err != nil {
			return
		}
	}

	// the length of a GSO packet is not in its IP header, the programs give the one of the skb
	payloadLength := uint32(0)

	if packet.Length > uint32(header.payloadOffset) {
		payloadLength = packet.Length - uint32(header.payloadOffset)
	}

	if !connection.isClosed && ((payloadLength > 0) || isFIN) {
		captured := packet.Data[min(header.payloadOffset, len(packet.Data)):]
		recorder.parts = connection.streams[direction].Add(sequence, captured, payloadLength, isFIN, recorder.parts[:0])
		err = recorder.deliver(cookie, currentFlow, direction, recorder.parts, timestamp, now)

		if err != nil {
			return
		}
	}

	err = recorder.limit(cookie, currentFlow, timestamp, now)
	return
}

// write the packets of the synthetic handshake as far as the streams are started: the SYN with the stream of the client, the SYN-ACK and the ACK with the one of the server
// a connection that was open before the capture gets all three in front of its first packet
func (recorder *recorder) open(connection *connection, timestamp uint64) (err error) {
	if !connection.hasSYN[tlsrecord.ClientDirection] && connection.streams[tlsrecord.ClientDirection].IsStarted() {
		connection.hasSYN[tlsrecord.ClientDirection] = true
		err = recorder.writeSegment(connection, tlsrecord.ClientDirection, SYNFlag, nil, timestamp)

		if err != nil {
			return
		}
	}

	if !connection.hasSYN[tlsrecord.ServerDirection] && connection.hasSYN[tlsrecord.ClientDirection] && connection.streams[tlsrecord.ServerDirection].IsStarted() {
		connection.hasSYN[tlsrecord.ServerDirection] = true
		err = recorder.writeSegment(connection, tlsrecord.ServerDirection, SYNFlag|ACKFlag, nil, timestamp)

		if err != nil {
			return
		}

		err = recorder.writeSegment(connection, tlsrecord.ClientDirection, ACKFlag, nil, timestamp)
	}

	return
}

// what a stream gives in its order: bytes, a hole, the FIN
func (recorder *recorder) deliver(cookie uint64, currentFlow *flow, direction tlsrecord.Direction, parts []Part, timestamp uint64, now time.Time) (err error) {
	for _, part := range parts {
		switch {
		case part.Missing > 0:
			err = recorder.gap(cookie, currentFlow, direction, part.Missing)
		case part.IsFIN:
			err = recorder.closeDirection(cookie, currentFlow, direction, timestamp)
		default:
			err = recorder.payload(cookie, currentFlow, direction, part.Data, timestamp, now)
		}

		if err != nil {
			return
		}
	}

	return
}

// the next bytes of a direction: written as they are, or given to the record layer from the ClientHello of the client on
// a session can start in the middle of a connection, behind STARTTLS or a CONNECT to a proxy, so the start of everything the client sends is looked at
func (recorder *recorder) payload(cookie uint64, currentFlow *flow, direction tlsrecord.Direction, data []byte, timestamp uint64, now time.Time) (err error) {
	connection := currentFlow.connection

	if (currentFlow.state == watchedFlowState) && (direction == tlsrecord.ClientDirection) {
		isClientHello, _ := tlsrecord.IsClientHello(data)

		if isClientHello {
			recorder.hold(cookie, currentFlow, false, now)
		}
	}

	// too much waits for the secrets, giveUp looks a last time for them
	if (currentFlow.state == heldFlowState) && (len(connection.pending[tlsrecord.ClientDirection])+len(connection.pending[tlsrecord.ServerDirection])+len(data) > maxHoldBytes) {
		err = recorder.giveUp(cookie, currentFlow, holdLimitReason)

		if err != nil {
			return
		}
	}

	if !isTLS(currentFlow) {
		err = recorder.writeData(connection, direction, data, timestamp)
		return
	}

	connection.pending[direction] = append(connection.pending[direction], data...)
	connection.marks[direction] = append(connection.marks[direction], mark{
		end:       connection.pendingOffset[direction] + uint64(len(connection.pending[direction])),
		timestamp: timestamp,
	})
	records, feedErr := currentFlow.conn.Feed(direction, data)
	err = recorder.writeRecords(currentFlow, records)

	if err != nil {
		return
	}

	// not TLS the record layer can read, or a record that does not decrypt
	if feedErr != nil {
		err = recorder.abandon(cookie, currentFlow, feedErr.Error())
		return
	}

	if !currentFlow.hasClientRandom {
		session := currentFlow.conn.Session()

		// the random of a ClientHello that was read is never all zero
		if session.ClientRandom != [32]byte{} {
			currentFlow.hasClientRandom = true
			currentFlow.clientRandom = session.ClientRandom
			currentFlow.serverName = session.ServerName
		}
	}

	return
}

// write the application data of the records, the handshake, the alerts and everything else of the record layer is not part of the plaintext
// a packet takes the timestamp of the captured packet that completed its record
func (recorder *recorder) writeRecords(currentFlow *flow, records []tlsrecord.Record) (err error) {
	connection := currentFlow.connection

	for _, record := range records {
		connection.read[record.Direction] += uint64(record.Length)

		if (record.ContentType != tlsrecord.ApplicationDataContentType) || !record.Decrypted || (len(record.Payload) == 0) {
			continue
		}

		if !connection.isDescribed {
			connection.isDescribed = true
			connection.addNote(describe(currentFlow.conn.Session()))
		}

		err = recorder.writeData(connection, record.Direction, record.Payload, connection.timestampAt(record.Direction, connection.read[record.Direction]))

		if err != nil {
			return
		}
	}

	// until the secrets are there everything is kept, the session may have to be written as it was captured
	if currentFlow.state == decryptedFlowState {
		connection.trim()
	}

	return
}

// look the secrets of a session up and give them to its record layer, the records that waited for them are written
func (recorder *recorder) unlock(cookie uint64, heldFlow *flow) (err error) {
	if !heldFlow.hasClientRandom {
		return
	}

	if heldFlow.isDTLS {
		err = recorder.unlockDatagrams(cookie, heldFlow)
		return
	}

	sessionSecrets, found, lookupErr := secretsByRandom(heldFlow.clientRandom, recorder.secretsBpfMaps)

	if lookupErr != nil {
		recorder.logger.Debug("Could not look up tls secrets", "error", lookupErr, "cookie", cookie)
	}

	if !found {
		return
	}

	records, secretsErr := heldFlow.conn.SetSecrets(sessionSecrets)
	recorder.holding = slices.DeleteFunc(recorder.holding, func(heldCookie uint64) bool {
		return heldCookie == cookie
	})
	heldFlow.state = decryptedFlowState
	recorder.keyedSessions++
	recorder.logger.Info("Decrypting tls session", "cookie", cookie, "serverName", heldFlow.serverName, "waited", time.Since(heldFlow.holdStart).Round(time.Millisecond))
	err = recorder.writeRecords(heldFlow, records)

	if err != nil {
		return
	}

	// the secrets do not fit the session or a record that waited does not decrypt
	if secretsErr != nil {
		err = recorder.abandon(cookie, heldFlow, secretsErr.Error())
		return
	}

	recorder.account(heldFlow)
	return
}

// the session is not decrypted, or not any further: what the record layer did not give back is written as it was captured, in the order of its packets, and so is the rest of the connection
// a session that never had its secrets is written whole from its ClientHello on
func (recorder *recorder) abandon(cookie uint64, currentFlow *flow, reason string) (err error) {
	if currentFlow.isDTLS {
		err = recorder.abandonDatagrams(cookie, currentFlow, reason)
		return
	}

	connection := currentFlow.connection

	if currentFlow.state == heldFlowState {
		recorder.holding = slices.DeleteFunc(recorder.holding, func(heldCookie uint64) bool {
			return heldCookie == cookie
		})
		recorder.keylessSessions++
		connection.addNote("tls session not decrypted: " + reason)
		recorder.logger.Warn("Could not decrypt tls session, the flow is written encrypted", "reason", reason, "cookie", cookie, "serverName", currentFlow.serverName)
	} else {
		connection.addNote("tls decryption stopped, the rest of the connection is written encrypted: " + reason)
		recorder.logger.Warn("Could not decrypt tls session further, the rest of the flow is written encrypted", "reason", reason, "cookie", cookie, "serverName", currentFlow.serverName)
	}

	currentFlow.state = passedFlowState
	currentFlow.conn = nil
	pending := connection.pending
	marks := connection.marks
	position := connection.pendingOffset
	connection.pending = [2][]byte{}
	connection.marks = [2][]mark{}

	for {
		direction := tlsrecord.ClientDirection

		for index := range marks {
			for (len(marks[index]) > 0) && (marks[index][0].end <= position[index]) {
				marks[index] = marks[index][1:]
			}
		}

		// the direction whose next bytes came first
		switch {
		case (len(marks[tlsrecord.ClientDirection]) == 0) && (len(marks[tlsrecord.ServerDirection]) == 0):
			recorder.account(currentFlow)
			return
		case len(marks[tlsrecord.ClientDirection]) == 0:
			direction = tlsrecord.ServerDirection
		case (len(marks[tlsrecord.ServerDirection]) > 0) && (marks[tlsrecord.ServerDirection][0].timestamp < marks[tlsrecord.ClientDirection][0].timestamp):
			direction = tlsrecord.ServerDirection
		default:
		}

		next := marks[direction][0]
		err = recorder.writeData(connection, direction, pending[direction][position[direction]-connection.pendingOffset[direction]:next.end-connection.pendingOffset[direction]], next.timestamp)

		if err != nil {
			return
		}

		position[direction] = next.end
	}
}

// bytes of a direction were never captured: a session can't be decrypted behind them, the synthesized sequence numbers leave the same hole so a reader sees that bytes are missing
func (recorder *recorder) gap(cookie uint64, currentFlow *flow, direction tlsrecord.Direction, missing uint32) (err error) {
	connection := currentFlow.connection
	recorder.missingBytes += uint64(missing)

	// the records in front of the hole can still be decrypted
	if currentFlow.state == heldFlowState {
		err = recorder.unlock(cookie, currentFlow)

		if err != nil {
			return
		}
	}

	if isTLS(currentFlow) {
		err = recorder.abandon(cookie, currentFlow, fmt.Sprintf(missingFormat, missing, directionName(direction)))

		if err != nil {
			return
		}
	} else {
		connection.missing[direction] += uint64(missing)

		// one line per connection
		if !connection.hasGap {
			recorder.logger.Warn("Could not capture every byte of a tcp flow", "missing", missing, "direction", directionName(direction), "cookie", cookie)
		}
	}

	connection.hasGap = true
	connection.sequence[direction] += missing
	return
}

// the FIN of a direction: the same in the synthesized connection, with the ACK of the other side
func (recorder *recorder) closeDirection(cookie uint64, currentFlow *flow, direction tlsrecord.Direction, timestamp uint64) (err error) {
	connection := currentFlow.connection

	// records can only be written in front of the FIN, so the secrets are looked up a last time
	if currentFlow.state == heldFlowState {
		err = recorder.unlock(cookie, currentFlow)

		if err != nil {
			return
		}
	}

	switch {
	case currentFlow.state == heldFlowState:
		err = recorder.abandon(cookie, currentFlow, closedReason)
	case (currentFlow.state == decryptedFlowState) && (len(connection.pending[direction]) > 0):
		err = recorder.abandon(cookie, currentFlow, partialReason)
	default:
	}

	if err != nil {
		return
	}

	connection.hasFIN[direction] = true
	err = recorder.writeSegment(connection, direction, FINFlag|ACKFlag, nil, timestamp)

	if err != nil {
		return
	}

	err = recorder.writeSegment(connection, otherDirection(direction), ACKFlag, nil, timestamp)

	if connection.hasFIN[tlsrecord.ClientDirection] && connection.hasFIN[tlsrecord.ServerDirection] {
		recorder.shut(currentFlow)
	}

	return
}

// the RST of a connection: what still waits is written, then the RST, the synthesized connection ends as the real one did
func (recorder *recorder) reset(cookie uint64, currentFlow *flow, direction tlsrecord.Direction, header packetHeader, timestamp uint64, now time.Time) (err error) {
	connection := currentFlow.connection
	err = recorder.end(cookie, currentFlow, timestamp, closedReason, now)

	// a FIN that waited behind a hole can close the connection first
	if (err != nil) || connection.isClosed {
		return
	}

	// a refused connection has no stream of the server, its RST has the sequence number of the real one
	if !connection.streams[direction].IsStarted() {
		connection.sequence[direction] = header.sequence
	}

	err = recorder.writeSegment(connection, direction, header.flags&(RSTFlag|ACKFlag), nil, timestamp)
	recorder.shut(currentFlow)
	return
}

// nothing more comes for the connection: the secrets are looked up a last time, the bytes behind a hole are written and a session that is not complete is written as it was captured
// reason is why a session that still waits for its secrets is given up
func (recorder *recorder) end(cookie uint64, currentFlow *flow, timestamp uint64, reason string, now time.Time) (err error) {
	connection := currentFlow.connection

	if (connection == nil) || connection.isClosed {
		return
	}

	if currentFlow.state == heldFlowState {
		err = recorder.unlock(cookie, currentFlow)

		if err != nil {
			return
		}
	}

	err = recorder.flush(cookie, currentFlow, timestamp, now)

	if (err != nil) || connection.isClosed {
		return
	}

	switch {
	case currentFlow.state == heldFlowState:
		err = recorder.abandon(cookie, currentFlow, reason)
	case (currentFlow.state == decryptedFlowState) && (len(connection.pending[tlsrecord.ClientDirection])+len(connection.pending[tlsrecord.ServerDirection]) > 0):
		err = recorder.abandon(cookie, currentFlow, partialReason)
	default:
	}

	return
}

// the connection is over without a packet that says so, the capture stopped or its socket is gone: no closing packet is made up, a comment that still waits gets an ACK of its own
// a DTLS session that still waits for its secrets gets a last lookup and is written
func (recorder *recorder) leave(cookie uint64, currentFlow *flow, reason string, now time.Time) (err error) {
	if currentFlow.isDTLS {
		if currentFlow.state == heldFlowState {
			err = recorder.giveUp(cookie, currentFlow, reason)
		}

		return
	}

	connection := currentFlow.connection

	if (connection == nil) || connection.isClosed {
		return
	}

	err = recorder.end(cookie, currentFlow, connection.lastTimestamp, reason, now)

	if (err != nil) || connection.isClosed {
		return
	}

	if connection.hasNote() {
		err = recorder.writeSegment(connection, tlsrecord.ClientDirection, ACKFlag, nil, connection.lastTimestamp)
	}

	recorder.shut(currentFlow)
	return
}

// give the holes of both streams up and write what waited behind them
func (recorder *recorder) flush(cookie uint64, currentFlow *flow, timestamp uint64, now time.Time) (err error) {
	connection := currentFlow.connection

	for _, direction := range []tlsrecord.Direction{tlsrecord.ClientDirection, tlsrecord.ServerDirection} {
		if connection.isClosed {
			return
		}

		recorder.parts = connection.streams[direction].Flush(recorder.parts[:0])
		err = recorder.deliver(cookie, currentFlow, direction, recorder.parts, timestamp, now)

		if err != nil {
			return
		}
	}

	return
}

// the connection is closed and keeps nothing
func (recorder *recorder) shut(currentFlow *flow) {
	currentFlow.connection.close()
	currentFlow.state = passedFlowState
	currentFlow.conn = nil
	recorder.account(currentFlow)
}

// count what the connection keeps, when all flows together keep too much this one gives up what it waits for
func (recorder *recorder) limit(cookie uint64, currentFlow *flow, timestamp uint64, now time.Time) (err error) {
	recorder.account(currentFlow)

	if recorder.heldBytes <= maxTotalHoldBytes {
		return
	}

	if currentFlow.state == heldFlowState {
		err = recorder.giveUp(cookie, currentFlow, totalLimitReason)

		if err != nil {
			return
		}
	}

	err = recorder.flush(cookie, currentFlow, timestamp, now)
	recorder.account(currentFlow)
	return
}

func (recorder *recorder) account(currentFlow *flow) {
	held := 0

	if !currentFlow.connection.isClosed {
		held = currentFlow.connection.held()
	}

	recorder.heldBytes += held - currentFlow.heldBytes
	currentFlow.heldBytes = held
}

// write bytes of a direction as synthesized packets of at most the MSS, the last one has PSH
func (recorder *recorder) writeData(connection *connection, direction tlsrecord.Direction, data []byte, timestamp uint64) (err error) {
	maxLength := segmentLength(connection.endpoints[direction].Address)

	for len(data) > 0 {
		length := min(len(data), maxLength)
		flags := ACKFlag

		if length == len(data) {
			flags |= PSHFlag
		}

		err = recorder.writeSegment(connection, direction, flags, data[:length], timestamp)

		if err != nil {
			return
		}

		data = data[length:]
	}

	return
}

// write one synthesized packet of a connection: it acknowledges everything the other direction has written so far and carries the comment that waits
func (recorder *recorder) writeSegment(connection *connection, direction tlsrecord.Direction, flags uint8, payload []byte, timestamp uint64) (err error) {
	other := otherDirection(direction)
	acknowledgment := uint32(0)

	// nothing to acknowledge before the other side is known
	if !connection.hasSYN[other] {
		flags &^= ACKFlag
	}

	if flags&ACKFlag != 0 {
		acknowledgment = connection.sequence[other]
	}

	recorder.buffer = TCPPacket(recorder.buffer[:0], connection.endpoints[direction], connection.endpoints[other], connection.sequence[direction], acknowledgment, flags, payload)
	packet := pcapng.Packet{
		Timestamp:      timestamp,
		Direction:      pcapng.OutboundDirection,
		OriginalLength: uint32(len(recorder.buffer)),
		Data:           recorder.buffer,
		Comment:        "",
	}

	if direction == tlsrecord.ServerDirection {
		packet.Direction = pcapng.InboundDirection
	}

	if connection.hasNote() {
		packet.Comment = notePrefix + connection.takeNote()
	}

	connection.sequence[direction] += uint32(len(payload))

	// SYN and FIN take a sequence number each
	if flags&(SYNFlag|FINFlag) != 0 {
		connection.sequence[direction]++
	}

	err = recorder.write(packet)
	return
}

// one captured UDP datagram in plaintext mode: a DTLS ClientHello from the client starts to hold the session until its secrets are there, a decrypted session gives one datagram per application data record
// every other datagram is built again with its payload as it is, an egress datagram has no checksum yet and the new one has
func (recorder *recorder) synthesizeUDP(cookie uint64, currentFlow *flow, packet capturebpf.Packet, pcapPacket pcapng.Packet, now time.Time) (err error) {
	payload, _ := transportPayload(packet.Data)

	if (currentFlow.state == watchedFlowState) && !packet.IsIngress && tlsrecord.IsDTLSClientHello(payload) {
		recorder.hold(cookie, currentFlow, true, now)
	}

	if !currentFlow.isDTLS {
		err = recorder.writeDatagram(pcapPacket, packet.Data, "")
		return
	}

	switch currentFlow.state {
	case heldFlowState:
		err = recorder.holdDatagram(cookie, currentFlow, packet, pcapPacket)
	case decryptedFlowState:
		err = recorder.decryptDatagram(cookie, currentFlow, pcapPacket)
	default:
		err = recorder.writeDatagram(pcapPacket, packet.Data, takeFlowNote(currentFlow))
	}

	return
}

// keep a datagram of a DTLS session until its secrets are there, the client's datagrams are read until the ClientHello is whole
func (recorder *recorder) holdDatagram(cookie uint64, heldFlow *flow, packet capturebpf.Packet, pcapPacket pcapng.Packet) (err error) {
	// the record of the reader is used again for the next packet
	pcapPacket.Data = bytes.Clone(packet.Data)
	heldFlow.held = append(heldFlow.held, pcapPacket)
	heldFlow.heldBytes += len(pcapPacket.Data)
	recorder.heldBytes += len(pcapPacket.Data)

	if !heldFlow.hasClientRandom && !packet.IsIngress {
		payload, _ := transportPayload(packet.Data)
		dropped := droppedRecords(heldFlow.conn, tlsrecord.ClientDirection)
		_, feedErr := heldFlow.conn.Feed(tlsrecord.ClientDirection, payload)

		// the record layer drops what it can't read, the client's datagrams before its ClientHello is whole have to be read
		if (feedErr == nil) && (droppedRecords(heldFlow.conn, tlsrecord.ClientDirection) != dropped) {
			feedErr = ErrUnreadableDatagram
		}

		if feedErr != nil {
			err = recorder.abandonDatagrams(cookie, heldFlow, clientHelloReason+": "+feedErr.Error())
			return
		}

		session := heldFlow.conn.Session()

		// the random of a ClientHello that was read is never all zero
		if session.ClientRandom != [32]byte{} {
			heldFlow.hasClientRandom = true
			heldFlow.clientRandom = session.ClientRandom
			heldFlow.serverName = session.ServerName
		}
	}

	switch {
	case heldFlow.heldBytes > maxHoldBytes:
		err = recorder.giveUp(cookie, heldFlow, holdLimitReason)
	case recorder.heldBytes > maxTotalHoldBytes:
		err = recorder.giveUp(cookie, heldFlow, totalLimitReason)
	default:
	}

	return
}

// the secrets of a held DTLS session are there: a new record layer gets them first and then the held datagrams, so every record is written with the timestamp of its own datagram
func (recorder *recorder) unlockDatagrams(cookie uint64, heldFlow *flow) (err error) {
	sessionSecrets, found, lookupErr := secretsByRandom(heldFlow.clientRandom, recorder.secretsBpfMaps)

	if lookupErr != nil {
		recorder.logger.Debug("Could not look up tls secrets", "error", lookupErr, "cookie", cookie)
	}

	if !found {
		return
	}

	conn := tlsrecord.NewDTLS(maxHoldBytes, false)
	_, err = conn.SetSecrets(sessionSecrets)

	if err != nil {
		return
	}

	held := heldFlow.held
	recorder.dropHeld(cookie, heldFlow)
	heldFlow.conn = &conn
	heldFlow.state = decryptedFlowState
	recorder.keyedSessions++
	recorder.logger.Info("Decrypting dtls session", "cookie", cookie, "waited", time.Since(heldFlow.holdStart).Round(time.Millisecond))

	for _, heldPacket := range held {
		err = recorder.decryptDatagram(cookie, heldFlow, heldPacket)

		if err != nil {
			return
		}
	}

	return
}

// the held datagrams of a DTLS session without its secrets are written as they came, so is every later datagram of the flow
func (recorder *recorder) abandonDatagrams(cookie uint64, currentFlow *flow, reason string) (err error) {
	held := currentFlow.held

	if currentFlow.state == heldFlowState {
		recorder.keylessSessions++
		addFlowNote(currentFlow, "dtls session not decrypted: "+reason)
		recorder.logger.Warn("Could not decrypt dtls session, the flow is written encrypted", "reason", reason, "cookie", cookie)
	} else {
		addFlowNote(currentFlow, "dtls decryption stopped, the rest of the flow is written encrypted: "+reason)
		recorder.logger.Warn("Could not decrypt dtls session further, the rest of the flow is written encrypted", "reason", reason, "cookie", cookie)
	}

	recorder.dropHeld(cookie, currentFlow)
	currentFlow.state = passedFlowState
	currentFlow.conn = nil

	for _, heldPacket := range held {
		err = recorder.writeDatagram(heldPacket, heldPacket.Data, takeFlowNote(currentFlow))

		if err != nil {
			return
		}
	}

	return
}

// the flow keeps no packets and is not held any more
func (recorder *recorder) dropHeld(cookie uint64, heldFlow *flow) {
	recorder.heldBytes -= heldFlow.heldBytes
	recorder.holding = slices.DeleteFunc(recorder.holding, func(heldCookie uint64) bool {
		return heldCookie == cookie
	})
	heldFlow.held = nil
	heldFlow.heldBytes = 0
}

// one datagram of a decrypted DTLS session: a synthesized datagram with the same addresses and timestamp for each application data record, nothing for the handshake and the alerts
// a datagram that can't be read ends the decryption, it and the rest of the flow are written as they came
func (recorder *recorder) decryptDatagram(cookie uint64, currentFlow *flow, pcapPacket pcapng.Packet) (err error) {
	header, ok := parsePacket(pcapPacket.Data)

	if !ok {
		err = recorder.write(pcapPacket)
		return
	}

	direction := tlsrecord.ClientDirection

	if pcapPacket.Direction == pcapng.InboundDirection {
		direction = tlsrecord.ServerDirection
	}

	dropped := droppedRecords(currentFlow.conn, direction)
	records, feedErr := currentFlow.conn.Feed(direction, pcapPacket.Data[header.payloadOffset:])

	for _, record := range records {
		if !record.Decrypted || (record.ContentType != tlsrecord.ApplicationDataContentType) {
			continue
		}

		if !currentFlow.isDescribed {
			currentFlow.isDescribed = true
			addFlowNote(currentFlow, describe(currentFlow.conn.Session()))
		}

		recorder.buffer = UDPPacket(recorder.buffer[:0], header.source, header.destination, record.Payload)
		packet := pcapPacket
		packet.OriginalLength = uint32(len(recorder.buffer))
		packet.Data = recorder.buffer
		packet.Comment = takeFlowNote(currentFlow)
		err = recorder.write(packet)

		if err != nil {
			return
		}
	}

	switch {
	case feedErr != nil:
		err = recorder.abandonDatagrams(cookie, currentFlow, feedErr.Error())

		if err != nil {
			return
		}

		err = recorder.writeDatagram(pcapPacket, pcapPacket.Data, takeFlowNote(currentFlow))
	// a record an endpoint drops too (a datagram that does not frame, another epoch, a failed MAC): the datagram is written as it came
	case droppedRecords(currentFlow.conn, direction) != dropped:
		addFlowNote(currentFlow, droppedRecordNote)
		err = recorder.writeDatagram(pcapPacket, pcapPacket.Data, takeFlowNote(currentFlow))
	default:
	}

	return
}

// the records a DTLS record layer dropped in a direction (tlsrecord.DTLSConn.Feed), a TLS one drops none
func droppedRecords(conn recordLayer, direction tlsrecord.Direction) (dropped uint64) {
	if dtlsConn, ok := conn.(*tlsrecord.DTLSConn); ok {
		dropped = dtlsConn.Dropped()[direction]
	}

	return
}

// a captured UDP datagram built again with its payload as it is, comment is the one of the packet
func (recorder *recorder) writeDatagram(pcapPacket pcapng.Packet, data []byte, comment string) (err error) {
	header, ok := parsePacket(data)

	if !ok || (header.protocol != syscall.IPPROTO_UDP) {
		pcapPacket.Comment = comment
		err = recorder.write(pcapPacket)
		return
	}

	recorder.buffer = UDPPacket(recorder.buffer[:0], header.source, header.destination, data[header.payloadOffset:])
	pcapPacket.OriginalLength = uint32(len(recorder.buffer))
	pcapPacket.Data = recorder.buffer
	pcapPacket.Comment = comment
	err = recorder.write(pcapPacket)
	return
}

func addFlowNote(currentFlow *flow, text string) {
	if currentFlow.note != "" {
		currentFlow.note += "; "
	}

	currentFlow.note += text
}

// the comment of the next packet of a DTLS flow, empty when there is none
func takeFlowNote(currentFlow *flow) (comment string) {
	if currentFlow.note == "" {
		return
	}

	comment = notePrefix + currentFlow.note
	currentFlow.note = ""
	return
}
