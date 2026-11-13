// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"cmp"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/decerter/decerter/api"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/pcapng"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// the packets of the flows in scope the capture hub keeps for the pcap export of the history, the oldest go first
	historyPacketBytes int = 64 << 20
	// the first sequence numbers of the synthesized connections of the history export, the server's are this far from the client's
	historyClientSequence uint32 = 1000
	historyServerSequence uint32 = 1 << 31
	// the most payload one synthesized datagram of the history export carries
	maxHistoryDatagram int = 65535 - 48
)

// the latest packets the capture hub handed out, at most limit bytes of them; packets[start:] are kept, the slice is compacted when half of it is gone
type packetRing struct {
	packets []capturebpf.Packet
	start   int
	bytes   int
	limit   int
}

func newPacketRing(limit int) (ring *packetRing) {
	ring = &packetRing{packets: nil, start: 0, bytes: 0, limit: limit}
	return
}

// the bytes of the packet are shared with the writers, nobody changes them
func (ring *packetRing) add(packet capturebpf.Packet) {
	ring.packets = append(ring.packets, packet)
	ring.bytes += len(packet.Data)

	for (ring.bytes > ring.limit) && (ring.start < len(ring.packets)) {
		ring.bytes -= len(ring.packets[ring.start].Data)
		ring.packets[ring.start] = capturebpf.Packet{}
		ring.start++
	}

	if ring.start > len(ring.packets)/2 {
		ring.packets = slices.Delete(ring.packets, 0, ring.start)
		ring.start = 0
	}
}

// the packets of the cookies, oldest first: the cookies of their sockets, or with isByFlow of the flows they belong to, which in run mode are the app's sockets the history knows
func (ring *packetRing) packetsOf(cookies map[uint64][32]byte, isByFlow bool) (packets []capturebpf.Packet) {
	for _, packet := range ring.packets[ring.start:] {
		cookie := packet.Cookie

		if isByFlow {
			cookie = packet.FlowCookie
		}

		if _, ok := cookies[cookie]; ok {
			packets = append(packets, packet)
		}
	}

	return
}

// the pcap export of the captured packets: the packets the hub still keeps of the flows, as a pcapng with a DSB in front of each TLS session or, plaintext, with synthesized decrypted packets
// flows maps the cookies of the flows of the history to the client randoms of their sessions, zero for a flow without one; a session whose secrets are gone from secrets_map is written without keys
// in run mode the packets are the ones of the proxy's upstream sockets, a TLS session there has the client random and the keys of the app's session, the proxy sealed its edits with them
func (hub *Hub) Export(output io.Writer, flows map[uint64][32]byte, plaintext bool, logger *slog.Logger) (err error) {
	if hub.ring == nil {
		err = ErrNoPacketHistory
		return
	}

	hub.mutex.Lock()
	packets := hub.ring.packetsOf(flows, true)
	hub.mutex.Unlock()
	writerSnaplen := hub.snaplen

	if plaintext {
		writerSnaplen = max(hub.snaplen, SynthesizedLength)
	}

	writer, writerErr := pcapng.New(output, writerSnaplen, false)

	if err = writerErr; err != nil {
		return
	}

	recorder := newRecorder(&writer, plaintext, hub.bootOffset, hub.captureBpfMaps, hub.secretsBpfMaps, nil, time.Now(), logger)

	// the DSB of a session goes in front of its first packet, also when the ring lost its ClientHello
	if !plaintext {
		recorder.known = map[uint64][32]byte{}

		// the writer knows a session by the socket of its packets
		for _, packet := range packets {
			if clientRandom := flows[packet.FlowCookie]; clientRandom != [32]byte{} {
				recorder.known[packet.Cookie] = clientRandom
			}
		}
	}

	for _, packet := range packets {
		now := time.Now()
		err = recorder.handle(packet, now)

		// the secrets are there by now, a held session is written as soon as it is looked up
		if (err == nil) && !now.Before(recorder.nextWake) {
			err = recorder.tick(now)
		}

		if err != nil {
			return
		}
	}

	err = recorder.finish()
	return
}

// run mode's pcap export: synthesized packets of the flows of the history, ordered by time, with the payload of every message as it went on
// a TCP flow gets a handshake when it opened and a FIN from both sides when it closed, its sequence numbers move with the payload; a UDP flow gets one datagram per message
// a dropped message is not on the wire and only named in a comment, so is an edited one: the comment names the message, whose original the API has; the bytes the history did not keep are a gap in the sequence numbers
func WriteHistory(output io.Writer, flows []history.ExportFlow) (err error) {
	writer, writerErr := pcapng.New(output, capturebpf.MaxSnaplen, false)

	if err = writerErr; err != nil {
		return
	}

	packets := []pcapng.Packet{}

	for _, flow := range flows {
		packets = appendHistoryFlow(packets, flow)
	}

	slices.SortStableFunc(packets, func(left pcapng.Packet, right pcapng.Packet) int {
		return cmp.Compare(left.Timestamp, right.Timestamp)
	})

	for _, packet := range packets {
		err = writer.WritePacket(packet)

		if err != nil {
			return
		}
	}

	err = writer.Flush()
	return
}

// the synthesized connection of one flow of the history, the arrays are by tlsrecord.Direction
type historyConnection struct {
	endpoints [2]Endpoint
	sequence  [2]uint32
	isTCP     bool
	note      string
	packets   []pcapng.Packet
}

func appendHistoryFlow(packets []pcapng.Packet, flow history.ExportFlow) (result []pcapng.Packet) {
	client, server := historyEndpoints(flow.Values.Source, flow.Values.Destination)
	connection := historyConnection{
		endpoints: [2]Endpoint{client, server},
		sequence:  [2]uint32{historyClientSequence, historyServerSequence},
		isTCP:     flow.Values.IPProtocol == syscall.IPPROTO_TCP,
		note:      describeHistoryFlow(flow),
		packets:   packets,
	}
	opened := timestampOf(flow.Flow.Opened)

	if connection.isTCP {
		connection.segment(tlsrecord.ClientDirection, SYNFlag, nil, opened)
		connection.segment(tlsrecord.ServerDirection, SYNFlag|ACKFlag, nil, opened)
		connection.segment(tlsrecord.ClientDirection, ACKFlag, nil, opened)
	}

	for _, message := range flow.Messages {
		connection.message(message)
	}

	if connection.isTCP && (flow.Flow.State == api.ClosedFlowState) {
		closed := timestampOf(flow.Flow.Closed)
		connection.segment(tlsrecord.ClientDirection, FINFlag|ACKFlag, nil, closed)
		connection.segment(tlsrecord.ServerDirection, FINFlag|ACKFlag, nil, closed)
		connection.segment(tlsrecord.ClientDirection, ACKFlag, nil, closed)
	}

	// a note that no packet carried, a UDP flow without messages has no packet at all
	result = connection.packets
	return
}

// the payload of one message as it went on, in segments of the MSS or as one datagram
func (connection *historyConnection) message(message history.ExportMessage) {
	view := message.Message
	direction := tlsrecord.ClientDirection

	if view.Direction == api.DownDirection {
		direction = tlsrecord.ServerDirection
	}

	if view.Verdict == api.DropVerdict {
		connection.addNote(fmt.Sprintf("message %d was dropped, %d bytes the %s sent are not on the wire", view.ID, view.OriginalLength, directionName(direction)))
		return
	}

	if view.Edited {
		connection.addNote(fmt.Sprintf("message %d was changed, the %s sent %d bytes: GET /api/v1/messages/%d has them", view.ID, directionName(direction), view.OriginalLength, view.ID))
	}

	timestamp := timestampOf(view.Time)
	payload := message.Payload

	if !connection.isTCP {
		connection.datagram(direction, payload[:min(len(payload), maxHistoryDatagram)], timestamp)
		return
	}

	maxLength := segmentLength(connection.endpoints[direction].Address)

	for len(payload) > 0 {
		length := min(len(payload), maxLength)
		flags := ACKFlag

		if length == len(payload) {
			flags |= PSHFlag
		}

		connection.segment(direction, flags, payload[:length], timestamp)
		payload = payload[length:]
	}

	// the bytes the history did not keep went on too, they are a hole in front of the next segment
	if missing := view.Length - len(message.Payload); missing > 0 {
		connection.sequence[direction] += uint32(missing)
		connection.addNote(fmt.Sprintf("the history did not keep %d bytes of message %d", missing, view.ID))
	}
}

// one synthesized TCP packet, it acknowledges everything the other side sent so far
func (connection *historyConnection) segment(direction tlsrecord.Direction, flags uint8, payload []byte, timestamp uint64) {
	other := otherDirection(direction)
	acknowledgment := uint32(0)

	if flags&ACKFlag != 0 {
		acknowledgment = connection.sequence[other]
	}

	data := TCPPacket(nil, connection.endpoints[direction], connection.endpoints[other], connection.sequence[direction], acknowledgment, flags, payload)
	connection.sequence[direction] += uint32(len(payload))

	// SYN and FIN take a sequence number each
	if flags&(SYNFlag|FINFlag) != 0 {
		connection.sequence[direction]++
	}

	connection.add(direction, data, timestamp)
}

func (connection *historyConnection) datagram(direction tlsrecord.Direction, payload []byte, timestamp uint64) {
	data := UDPPacket(nil, connection.endpoints[direction], connection.endpoints[otherDirection(direction)], payload)
	connection.add(direction, data, timestamp)
}

// the packet carries the note that waits
func (connection *historyConnection) add(direction tlsrecord.Direction, data []byte, timestamp uint64) {
	packet := pcapng.Packet{
		Timestamp:      timestamp,
		Direction:      pcapng.OutboundDirection,
		OriginalLength: uint32(len(data)),
		Data:           data,
		Comment:        "",
	}

	if direction == tlsrecord.ServerDirection {
		packet.Direction = pcapng.InboundDirection
	}

	if connection.note != "" {
		packet.Comment = notePrefix + connection.note
		connection.note = ""
	}

	connection.packets = append(connection.packets, packet)
}

func (connection *historyConnection) addNote(text string) {
	if connection.note != "" {
		connection.note += "; "
	}

	connection.note += text
}

// the client is IPv4-mapped in run mode, a synthesized packet needs one family: IPv4 when both are, IPv6 otherwise
func historyEndpoints(source netip.AddrPort, destination netip.AddrPort) (client Endpoint, server Endpoint) {
	client = Endpoint{Address: source.Addr().Unmap(), Port: source.Port()}
	server = Endpoint{Address: destination.Addr().Unmap(), Port: destination.Port()}

	if client.Address.Is4() != server.Address.Is4() {
		client.Address = netip.AddrFrom16(client.Address.As16())
		server.Address = netip.AddrFrom16(server.Address.As16())
	}

	return
}

// the comment of the first packet of a flow: its id in the history, the process and the TLS session
func describeHistoryFlow(flow history.ExportFlow) (text string) {
	text = fmt.Sprintf("flow %d of %s (pid %d, uid %d)", flow.Flow.ID, flow.Flow.Process.Comm, flow.Flow.Process.PID, flow.Flow.Process.UID)

	if tls := flow.Flow.TLS; tls != nil {
		text += ", tls"

		if tls.Version != "" {
			text += " " + tls.Version
		}

		if tls.CipherSuite != "" {
			text += ", " + tls.CipherSuite
		}

		if tls.ServerName != "" {
			text += ", sni " + tls.ServerName
		}

		if tls.ALPN != "" {
			text += ", alpn " + tls.ALPN
		}
	}

	if flow.Flow.Truncated {
		text += "; the history did not keep every message of this flow"
	}

	return
}

func timestampOf(moment time.Time) (timestamp uint64) {
	timestamp = uint64(moment.UnixNano())
	return
}
