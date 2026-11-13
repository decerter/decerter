// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/api"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
)

var (
	hubClient = Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: 40000}
	hubServer = Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: 80}
	hubOther  = Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: 8080}
)

// a writer behind the hub in a test: its output and what Consume returned
type testConsumer struct {
	consumer    *Consumer
	output      *bytes.Buffer
	stopChannel chan struct{}
	errChannel  chan error
}

// Test if capture.Hub hands every packet to each writer with its own filter and pcapng section, a writer that is not read is cut off (a stream) or loses packets (a file) without slowing the others.
func TestHubFanOutPositive(state *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	hub, err := NewHub(capturebpf.MaxSnaplen, nil, nil, nil, nil, false, logger)

	if err != nil {
		state.Fatalf("Test of capture.NewHub failed, error: %s", err.Error())
	}

	onlyHTTP, err := filter.Parse("tcp.dstport == 80")

	if err != nil {
		state.Fatalf("Test of capture.Hub failed, cannot parse filter, error: %s", err.Error())
	}

	all := startTestConsumer(state, hub, ConsumerOptions{Stream: false, IsCut: false, Scope: nil, Plaintext: false, Limit: nil}, logger)
	http := startTestConsumer(state, hub, ConsumerOptions{Stream: true, IsCut: false, Scope: &onlyHTTP, Plaintext: true, Limit: nil}, logger)
	// the filter of a writer looks the flow up in flow_map
	http.consumer.recorder.gate.lookup = testLookup
	// never read: a stream and a file
	stream, err := hub.Add(io.Discard, ConsumerOptions{Stream: true, IsCut: true, Scope: nil, Plaintext: false, Limit: nil}, logger)

	if err != nil {
		state.Fatalf("Test of capture.Hub.Add failed, error: %s", err.Error())
	}

	file, err := hub.Add(io.Discard, ConsumerOptions{Stream: false, IsCut: false, Scope: nil, Plaintext: false, Limit: nil}, logger)

	if err != nil {
		state.Fatalf("Test of capture.Hub.Add failed, error: %s", err.Error())
	}

	packets := slices.Concat(testFlow(1, hubClient, hubServer, "GET /one HTTP/1.1\r\n\r\n"), testFlow(2, hubClient, hubOther, "GET /two HTTP/1.1\r\n\r\n"))

	for _, packet := range packets {
		err = hub.gate.handle(packet, time.Now(), hub.emit)

		if err != nil {
			state.Fatalf("Test of capture.Hub failed, cannot hand a packet out, error: %s", err.Error())
		}
	}

	for _, current := range []testConsumer{all, http} {
		close(current.stopChannel)

		if consumeErr := <-current.errChannel; consumeErr != nil {
			state.Fatalf("Test of capture.Hub.Consume failed, error: %s", consumeErr.Error())
		}
	}

	// the writer without a filter has every packet as it was captured, the one of port 80 a synthesized handshake and the request of its flow
	allPackets, err := readPackets(all.output.Bytes())

	if (err != nil) || (len(allPackets) != len(packets)) || !bytes.Contains(all.output.Bytes(), []byte("GET /two")) {
		state.Errorf("Test of capture.Hub failed, the writer without a filter should have the %d packets, packets: %d, error: %v", len(packets), len(allPackets), err)
		return
	}

	httpPackets, err := readPackets(http.output.Bytes())

	if (err != nil) || (len(httpPackets) == 0) || bytes.Contains(http.output.Bytes(), []byte("GET /two")) || !bytes.Contains(http.output.Bytes(), []byte("GET /one")) {
		state.Errorf("Test of capture.Hub failed, the writer of port 80 should only have the first flow, packets: %d, error: %v", len(httpPackets), err)
		return
	}

	for _, written := range httpPackets {
		if written.Header.destination.Port != hubServer.Port && written.Header.source.Port != hubServer.Port {
			state.Errorf("Test of capture.Hub failed, the writer of port 80 has a packet of port %d", written.Header.destination.Port)
			return
		}
	}

	// a flood: the stream is cut off once its queue is full, the file loses what does not fit
	flood := consumerQueuePackets + 100

	for index := range flood {
		packet := testFlow(3, hubClient, hubServer, "x")[3]
		packet.TimestampNs = uint64(index)
		hub.offerAll(packet)
	}

	select {
	case <-stream.overflowChannel:
	default:
		state.Errorf("Test of capture.Hub failed, a stream %d packets behind should be cut off", flood)
		return
	}

	hub.mutex.Lock()
	_, isStreamThere := hub.consumers[stream]
	hub.mutex.Unlock()
	expectedDropped := uint64(flood + len(packets) - consumerQueuePackets)

	if isStreamThere || (file.Dropped() != expectedDropped) {
		state.Errorf("Test of capture.Hub failed, the stream should be gone and the file should drop %d packets, stream there: %v, dropped: %d", expectedDropped, isStreamThere, file.Dropped())
		return
	}

	err = hub.Consume(state.Context(), stream, nil)

	if !errors.Is(err, ErrSlowReader) {
		state.Errorf("Test of capture.Hub.Consume failed, a cut stream should end with %v, error: %v", ErrSlowReader, err)
		return
	}
}

// Test if capture.Hub reads the opening of every flow when it keeps a history: the flow is in the history with its ClientHello, a writer that joins later knows its session, and the export writes its packets.
func TestHubHistoryPositive(state *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	flows := history.New(history.DefaultLimits(), nil)
	hub, err := NewHub(capturebpf.MaxSnaplen, nil, nil, nil, flows, false, logger)

	if err != nil {
		state.Fatalf("Test of capture.NewHub failed, error: %s", err.Error())
	}

	hub.gate.lookup = testLookup
	hello, err := clientHello("example.com")

	if err != nil {
		state.Fatalf("Test of capture.Hub failed, cannot make a ClientHello, error: %s", err.Error())
	}

	packets := testFlow(7, hubClient, Endpoint{Address: hubServer.Address, Port: 443}, string(hello))

	for _, packet := range packets {
		err = hub.gate.handle(packet, time.Now(), hub.emit)

		if err != nil {
			state.Fatalf("Test of capture.Hub failed, cannot hand a packet out, error: %s", err.Error())
		}
	}

	listed, _ := flows.Flows(nil, 0, 10)

	if (len(listed) != 1) || (listed[0].TLS == nil) || (listed[0].TLS.ServerName != "example.com") || (listed[0].Process.Comm != "curl") || (listed[0].Cookie != 7) {
		state.Fatalf("Test of capture.Hub failed, the history should have the TLS flow of curl to example.com, flows: %+v", listed)
	}

	clientRandom := [32]byte(hello[11:43])
	late, err := hub.Add(io.Discard, ConsumerOptions{Stream: true, IsCut: true, Scope: nil, Plaintext: false, Limit: nil}, logger)

	if err != nil {
		state.Fatalf("Test of capture.Hub.Add failed, error: %s", err.Error())
	}

	plaintext, err := hub.Add(io.Discard, ConsumerOptions{Stream: true, IsCut: true, Scope: nil, Plaintext: true, Limit: nil}, logger)

	if err != nil {
		state.Fatalf("Test of capture.Hub.Add failed, error: %s", err.Error())
	}

	if (late.recorder.known[7] != clientRandom) || (len(plaintext.recorder.known) != 0) || (len(late.replay) != len(packets)) || (len(plaintext.replay) != len(packets)) {
		state.Errorf("Test of capture.Hub.Add failed, a writer that joins later should get the %d packets of the open flow and, with secrets, know its session, replay: %d, known: %v, plaintext known: %v", len(packets), len(late.replay), late.recorder.known, plaintext.recorder.known)
		return
	}

	// the export writes the packets the ring keeps of the flows of the history
	output := bytes.Buffer{}
	err = hub.Export(&output, map[uint64][32]byte{7: clientRandom}, false, logger)

	if err != nil {
		state.Fatalf("Test of capture.Hub.Export failed, error: %s", err.Error())
	}

	exported, err := readPackets(output.Bytes())

	if (err != nil) || (len(exported) != len(packets)) || !bytes.Contains(output.Bytes(), hello) {
		state.Errorf("Test of capture.Hub.Export failed, the export should have the %d packets with the ClientHello, packets: %d, error: %v", len(packets), len(exported), err)
		return
	}

	// the socket is gone: the flow is closed in the history with its counters
	hub.captureBpfMaps = nil
	hub.forgetFlows(func(cookie uint64) (isOpen bool, err error) {
		return
	})
	listed, _ = flows.Flows(nil, 0, 10)

	if (listed[0].State != api.ClosedFlowState) || (listed[0].Up.Bytes != int64(len(hello))) || (len(hub.sessions) != 0) {
		state.Errorf("Test of capture.Hub failed, the flow should be closed with %d bytes up and its session forgotten, flow: %+v, sessions: %d", len(hello), listed[0], len(hub.sessions))
		return
	}
}

// Test if capture.Hub in run mode decides the packets of an upstream socket of the proxy with the app's flow it carries, leaves the history to the proxy and exports the packets by the flow of the history.
func TestHubProxiedPositive(state *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	flows := history.New(history.DefaultLimits(), nil)
	scope, err := filter.Parse("tcp.dstport == 443 && proc.comm == \"curl\"")

	if err != nil {
		state.Fatalf("Test of capture.Hub failed, cannot parse filter, error: %s", err.Error())
	}

	hub, err := NewHub(capturebpf.MaxSnaplen, nil, nil, &scope, flows, true, logger)

	if err != nil {
		state.Fatalf("Test of capture.NewHub failed, error: %s", err.Error())
	}

	looked := []uint64{}
	hub.gate.lookup = func(cookie uint64) (flow redirect.Flow, err error) {
		looked = append(looked, cookie)
		flow, err = testLookup(cookie)
		return
	}
	hello, err := clientHello("example.com")

	if err != nil {
		state.Fatalf("Test of capture.Hub failed, cannot make a ClientHello, error: %s", err.Error())
	}

	// the proxy opened the app's flow 7 in the history, its upstream socket 20 carries it on the wire
	clientRandom := [32]byte(hello[11:43])
	flowID := flows.OpenFlow(7, filter.Values{Comm: "curl", IPProtocol: syscall.IPPROTO_TCP, Destination: netip.AddrPortFrom(hubServer.Address, 443)}, clientRandom)
	packets := testFlow(20, Endpoint{Address: hubClient.Address, Port: 50000}, Endpoint{Address: hubServer.Address, Port: 443}, string(hello))

	for index := range packets {
		packets[index].FlowCookie = 7
	}

	for _, packet := range packets {
		err = hub.gate.handle(packet, time.Now(), hub.emit)

		if err != nil {
			state.Fatalf("Test of capture.Hub failed, cannot hand a packet out, error: %s", err.Error())
		}
	}

	listed, _ := flows.Flows(nil, 0, 10)

	if !slices.Equal(looked, []uint64{7}) || (len(listed) != 1) || (listed[0].ID != flowID) || (hub.sessions[20] != clientRandom) || (hub.flows[20] == nil) {
		state.Fatalf("Test of capture.Hub failed, the upstream socket should be decided once with the app's flow and only the proxy's flow should be in the history, looked up: %v, flows: %+v, sessions: %v", looked, listed, hub.sessions)
	}

	output := bytes.Buffer{}
	err = hub.Export(&output, map[uint64][32]byte{7: clientRandom}, false, logger)

	if err != nil {
		state.Fatalf("Test of capture.Hub.Export failed, error: %s", err.Error())
	}

	exported, err := readPackets(output.Bytes())

	if (err != nil) || (len(exported) != len(packets)) || !bytes.Contains(output.Bytes(), hello) {
		state.Errorf("Test of capture.Hub.Export failed, the export of the app's flow should have the %d packets of its upstream socket, packets: %d, error: %v", len(packets), len(exported), err)
		return
	}

	// the upstream socket is gone: the hub forgets it, the flow of the proxy stays open in the history until the proxy closes it
	hub.forgetFlows(func(cookie uint64) (isOpen bool, err error) {
		return
	})
	listed, _ = flows.Flows(nil, 0, 10)

	if (listed[0].State != api.OpenFlowState) || (len(hub.flows) != 0) {
		state.Errorf("Test of capture.Hub failed, the hub should forget the upstream socket and leave the flow of the proxy open, flow: %+v, hub flows: %d", listed[0], len(hub.flows))
		return
	}
}

// Test if capture.Hub in run mode returns with the expected output for packets it must not take: an export by the cookie of the upstream socket has none, and an upstream socket whose app's flow is out of scope is not handed out.
func TestHubProxiedNegative(state *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	flows := history.New(history.DefaultLimits(), nil)
	scope, err := filter.Parse("tcp.dstport == 443")

	if err != nil {
		state.Fatalf("Test of capture.Hub failed, cannot parse filter, error: %s", err.Error())
	}

	hub, err := NewHub(capturebpf.MaxSnaplen, nil, nil, &scope, flows, true, logger)

	if err != nil {
		state.Fatalf("Test of capture.NewHub failed, error: %s", err.Error())
	}

	hub.gate.lookup = testLookup
	hello, err := clientHello("example.com")

	if err != nil {
		state.Fatalf("Test of capture.Hub failed, cannot make a ClientHello, error: %s", err.Error())
	}

	// socket 21 carries flow 7 (port 443 in flow_map), socket 22 flow 2, whose original destination is port 8080 although the packets go to 443
	inScope := testFlow(21, hubClient, Endpoint{Address: hubServer.Address, Port: 443}, string(hello))
	outOfScope := testFlow(22, Endpoint{Address: hubClient.Address, Port: 40001}, Endpoint{Address: hubServer.Address, Port: 443}, string(hello))

	for index := range inScope {
		inScope[index].FlowCookie = 7
		outOfScope[index].FlowCookie = 2
	}

	for _, packet := range slices.Concat(inScope, outOfScope) {
		err = hub.gate.handle(packet, time.Now(), hub.emit)

		if err != nil {
			state.Fatalf("Test of capture.Hub failed, cannot hand a packet out, error: %s", err.Error())
		}
	}

	listed, _ := flows.Flows(nil, 0, 10)

	if (hub.flows[22] != nil) || (hub.flows[21] == nil) || (len(listed) != 0) {
		state.Fatalf("Test of capture.Hub failed, only the socket of the flow in scope should be handed out and nothing opened in the history, hub flows: %v, flows: %+v", hub.flows, listed)
	}

	output := bytes.Buffer{}
	err = hub.Export(&output, map[uint64][32]byte{21: [32]byte(hello[11:43])}, false, logger)

	if err != nil {
		state.Fatalf("Test of capture.Hub.Export failed, error: %s", err.Error())
	}

	exported, err := readPackets(output.Bytes())

	if (err != nil) || (len(exported) != 0) {
		state.Errorf("Test of capture.Hub.Export failed, an export by the cookie of the upstream socket should have no packet, packets: %d, error: %v", len(exported), err)
		return
	}
}

// Test if capture.WriteHistory returns with the expected output: a TCP flow with its handshake, the edited request as it went on, the response, a dropped message only as a comment and the FIN of both sides.
func TestWriteHistoryPositive(state *testing.T) {
	opened := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	request := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	response := bytes.Repeat([]byte("0123456789"), 300)
	flow := history.ExportFlow{
		Flow:         api.Flow{ID: 3, State: api.ClosedFlowState, Opened: opened, Closed: opened.Add(time.Second), Process: api.Process{PID: 42, UID: 1001, Comm: "curl"}, TLS: &api.TLSInfo{Version: "TLS 1.3", ServerName: "example.com"}},
		Values:       filter.Values{IPProtocol: syscall.IPPROTO_TCP, Source: netip.MustParseAddrPort("[::ffff:127.0.0.1]:40000"), Destination: netip.MustParseAddrPort("127.0.0.1:443")},
		ClientRandom: [32]byte{},
		Messages: []history.ExportMessage{
			{Message: api.Message{ID: 10, Direction: api.UpDirection, Time: opened.Add(10 * time.Millisecond), Verdict: api.ForwardVerdict, Edited: true, Length: len(request), OriginalLength: len(request) - 5}, Payload: request},
			{Message: api.Message{ID: 11, Direction: api.DownDirection, Time: opened.Add(20 * time.Millisecond), Verdict: api.DropVerdict, Edited: true, Length: 0, OriginalLength: 4}, Payload: nil},
			{Message: api.Message{ID: 12, Direction: api.DownDirection, Time: opened.Add(30 * time.Millisecond), Verdict: api.ForwardVerdict, Length: len(response), OriginalLength: len(response)}, Payload: response},
		},
	}
	output := bytes.Buffer{}
	err := WriteHistory(&output, []history.ExportFlow{flow})

	if err != nil {
		state.Fatalf("Test of capture.WriteHistory failed, error: %s", err.Error())
	}

	written, err := readPackets(output.Bytes())

	if err != nil {
		state.Fatalf("Test of capture.WriteHistory failed, cannot read output, error: %s", err.Error())
	}

	streams := [2][]byte{}
	next := [2]uint32{historyClientSequence, historyServerSequence}
	flags := []uint8{}
	comments := []string{}

	for index, packet := range written {
		direction := 0

		if packet.Header.source.Port == 443 {
			direction = 1
		}

		if (packet.Header.sequence != next[direction]) || (packet.Header.source.Address != hubClient.Address) {
			state.Fatalf("Test of capture.WriteHistory failed, packet %d should have sequence %d from 127.0.0.1, packet: %+v", index, next[direction], packet.Header)
		}

		streams[direction] = append(streams[direction], packet.Payload...)
		next[direction] += uint32(len(packet.Payload))

		if packet.Header.flags&(SYNFlag|FINFlag) != 0 {
			next[direction]++
		}

		flags = append(flags, packet.Header.flags)

		if packet.Comment != "" {
			comments = append(comments, packet.Comment)
		}
	}

	if !bytes.Equal(streams[0], request) || !bytes.Equal(streams[1], response) {
		state.Errorf("Test of capture.WriteHistory failed, the streams should be the edited request and the response, streams: %q, %d bytes", streams[0], len(streams[1]))
		return
	}

	// handshake, request, three response segments, FIN from both and the last ACK
	expectedFlags := []uint8{SYNFlag, SYNFlag | ACKFlag, ACKFlag, ACKFlag | PSHFlag, ACKFlag, ACKFlag, ACKFlag | PSHFlag, FINFlag | ACKFlag, FINFlag | ACKFlag, ACKFlag}
	expectedComments := []string{
		notePrefix + "flow 3 of curl (pid 42, uid 1001), tls TLS 1.3, sni example.com",
		notePrefix + "message 10 was changed, the client sent 36 bytes: GET /api/v1/messages/10 has them",
		notePrefix + "message 11 was dropped, 4 bytes the server sent are not on the wire",
	}

	if !slices.Equal(flags, expectedFlags) || !slices.Equal(comments, expectedComments) {
		state.Errorf("Test of capture.WriteHistory failed, flags should be %v with comments %q, flags: %v, comments: %q", expectedFlags, expectedComments, flags, comments)
		return
	}
}

// the hub hands a packet to every writer, as emit does after the scope
func (hub *Hub) offerAll(packet capturebpf.Packet) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()

	for current := range hub.consumers {
		hub.offer(current, packet)
	}
}

// add a writer to the hub that writes into a buffer and run it until stopChannel is closed
func startTestConsumer(state *testing.T, hub *Hub, options ConsumerOptions, logger *slog.Logger) (current testConsumer) {
	output := &bytes.Buffer{}
	added, err := hub.Add(&lockedWriter{mutex: &sync.Mutex{}, output: output}, options, logger)

	if err != nil {
		state.Fatalf("Test of capture.Hub.Add failed, error: %s", err.Error())
	}

	current = testConsumer{consumer: added, output: output, stopChannel: make(chan struct{}), errChannel: make(chan error, 1)}

	// the writer of the test
	go func() {
		current.errChannel <- hub.Consume(state.Context(), added, current.stopChannel)
	}()

	return
}

// the buffer is read after the writer stopped, the lock keeps the race detector quiet
type lockedWriter struct {
	mutex  *sync.Mutex
	output *bytes.Buffer
}

func (writer *lockedWriter) Write(data []byte) (count int, err error) {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	count, err = writer.output.Write(data)
	return
}

// a whole TCP connection as the capture programs see it: handshake, the request from the client, an empty response and both FINs
func testFlow(cookie uint64, client Endpoint, server Endpoint, request string) (packets []capturebpf.Packet) {
	captured := func(isIngress bool, sequence uint32, acknowledgment uint32, flags uint8, payload []byte) (packet capturebpf.Packet) {
		data := TCPPacket(nil, client, server, sequence, acknowledgment, flags, payload)

		if isIngress {
			data = TCPPacket(nil, server, client, sequence, acknowledgment, flags, payload)
		}

		packet = capturebpf.Packet{Cookie: cookie, FlowCookie: cookie, TimestampNs: uint64(len(packets)) * 1000, Length: uint32(len(data)), IsIngress: isIngress, Data: data}
		return
	}
	length := uint32(len(request))
	packets = []capturebpf.Packet{
		captured(false, 100, 0, SYNFlag, nil),
		captured(true, 500, 101, SYNFlag|ACKFlag, nil),
		captured(false, 101, 501, ACKFlag, nil),
		captured(false, 101, 501, ACKFlag|PSHFlag, []byte(request)),
		captured(true, 501, 101+length, ACKFlag, nil),
		captured(false, 101+length, 501, FINFlag|ACKFlag, nil),
		captured(true, 501, 102+length, FINFlag|ACKFlag, nil),
		captured(false, 102+length, 502, ACKFlag, nil),
	}
	return
}

// flow_map of the test: every socket is curl of uid 1001, the destination comes from nowhere so a filter on the port uses the packet's
func testLookup(cookie uint64) (flow redirect.Flow, err error) {
	port := hubServer.Port

	switch cookie {
	case 2:
		port = hubOther.Port
	case 7:
		port = 443
	default:
	}

	flow = redirect.Flow{
		OriginalDestination: netip.AddrPortFrom(hubServer.Address, port),
		IPProtocol:          syscall.IPPROTO_TCP,
		Redirected:          false,
		Tgid:                42,
		UID:                 1001,
		GID:                 1001,
		CgroupID:            0,
		Comm:                "curl",
		Mark:                0,
		Client:              netip.AddrPort{},
	}
	return
}

// the first record crypto/tls sends for serverName, a ClientHello
func clientHello(serverName string) (hello []byte, err error) {
	clientConnection, serverConnection := net.Pipe()
	doneChannel := make(chan struct{})

	// the client of the test, its handshake fails when the pipe is closed
	go func() {
		defer close(doneChannel)
		_ = tls.Client(clientConnection, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}).Handshake()
	}()

	defer func() {
		err = errors.Join(err, serverConnection.Close(), clientConnection.Close())
		<-doneChannel
	}()

	header := make([]byte, 5)
	_, err = io.ReadFull(serverConnection, header)

	if err != nil {
		return
	}

	body := make([]byte, binary.BigEndian.Uint16(header[3:]))
	_, err = io.ReadFull(serverConnection, body)

	if err != nil {
		return
	}

	hello = slices.Concat(header, body)

	if hello[5] != 1 {
		err = fmt.Errorf("the first record is no ClientHello: %x", hello[:6])
	}

	return
}
