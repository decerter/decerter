// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	testIdleTimeout time.Duration = 100 * time.Millisecond
)

// the flow every client of the proxy has, nil is a client without a flow; the proxy reads it in its own goroutine, so it is swapped atomically
func dynamicFlow(state *testing.T) (flow *atomic.Pointer[redirect.Flow]) {
	flow = &atomic.Pointer[redirect.Flow]{}
	useFlows(state, func(client netip.AddrPort, ipProtocol uint8, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (cookie uint64, found redirect.Flow, err error) {
		current := flow.Load()

		if current == nil {
			err = errTestLookup
			return
		}

		cookie = 1
		found = *current
		found.IPProtocol = ipProtocol
		found.Client = client
		return
	})
	return
}

// a udp server on loopback that answers every datagram with what answer makes of it; it keeps what it got
type udpServer struct {
	connection  *net.UDPConn
	mutex       *sync.Mutex
	received    [][]byte
	doneChannel chan struct{}
}

func startUDPServer(state *testing.T, answer func(datagram []byte) [][]byte) (server *udpServer) {
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})

	if err != nil {
		state.Fatalf("Test of the udp proxy failed, cannot listen, error: %s", err.Error())
	}

	server = &udpServer{connection: connection, mutex: &sync.Mutex{}, received: nil, doneChannel: make(chan struct{})}

	// test server
	go func() {
		defer close(server.doneChannel)
		buffer := make([]byte, maxDatagramSize)

		for {
			size, client, readErr := connection.ReadFromUDPAddrPort(buffer)

			if readErr != nil {
				return
			}

			server.mutex.Lock()
			server.received = append(server.received, bytes.Clone(buffer[:size]))
			server.mutex.Unlock()

			for _, reply := range answer(buffer[:size]) {
				_, writeErr := connection.WriteToUDPAddrPort(reply, client)

				if writeErr != nil {
					return
				}
			}
		}
	}()

	state.Cleanup(func() {
		if closeErr := connection.Close(); closeErr != nil {
			state.Errorf("Test of the udp proxy failed, cannot close server, error: %s", closeErr.Error())
		}

		<-server.doneChannel
	})
	return
}

func (server *udpServer) address() (address netip.AddrPort) {
	address = server.connection.LocalAddr().(*net.UDPAddr).AddrPort()
	return
}

func (server *udpServer) datagrams() (received [][]byte) {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	received = slices.Clone(server.received)
	return
}

// a proxy that runs ServeUDP on connection until stop
func startUDPProxy(state *testing.T, connection *net.UDPConn, secretsMaps map[bpf.BpfMapName]*ebpf.Map, pipeline *intercept.Pipeline, scope *filter.Filter, recorder *history.History, logger *slog.Logger) (stop func()) {
	ctx, cancel := context.WithCancel(state.Context())
	waitGroup := &sync.WaitGroup{}
	doneChannel := make(chan struct{})

	// udp proxy
	go func() {
		ServeUDP(ctx, connection, testIdleTimeout, nil, secretsMaps, nil, pipeline, scope, recorder, waitGroup, logger)
		close(doneChannel)
	}()

	stop = func() {
		cancel()
		<-doneChannel
		waitGroup.Wait()
	}
	return
}

// a proxy socket from ListenUDP and its IPv4 address
func listenTestUDP(state *testing.T) (connection *net.UDPConn, address netip.AddrPort) {
	connection, err := ListenUDP(state.Context(), 0)

	if err != nil {
		state.Fatalf("Test of proxy.ListenUDP failed, cannot listen, error: %s", err.Error())
	}

	address = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), connection.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	return
}

// a connected client socket to the proxy
func dialTestUDP(state *testing.T, address netip.AddrPort) (client *net.UDPConn) {
	client, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(address))

	if err != nil {
		state.Fatalf("Test of the udp proxy failed, cannot dial, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			state.Errorf("Test of the udp proxy failed, cannot close client, error: %s", closeErr.Error())
		}
	})
	return
}

// send each datagram and read count replies after it, the replies in the order they came
func exchangeUDP(client *net.UDPConn, datagrams [][]byte, counts []int) (replies [][]byte, err error) {
	buffer := make([]byte, maxDatagramSize)

	for index, datagram := range datagrams {
		_, err = client.Write(datagram)

		if err != nil {
			return
		}

		for range counts[index] {
			err = client.SetReadDeadline(time.Now().Add(5 * time.Second))

			if err != nil {
				return
			}

			size, readErr := client.Read(buffer)

			if err = readErr; err != nil {
				return
			}

			replies = append(replies, bytes.Clone(buffer[:size]))
		}
	}

	return
}

// the flows of the history are all closed
func allClosed(recorder *history.History) (isClosed bool) {
	flows, _ := recorder.Flows(nil, 0, 100)
	isClosed = (len(flows) != 0) && !slices.ContainsFunc(flows, func(flow api.Flow) bool { return flow.State != api.ClosedFlowState })
	return
}

// Test if proxy.ListenUDP returns with the expected errors: a port in use is ErrListen.
func TestListenUDPNegative(state *testing.T) {
	connection, _ := listenTestUDP(state)

	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			state.Errorf("Test of proxy.ListenUDP failed, cannot close socket, error: %s", closeErr.Error())
		}
	}()

	second, err := ListenUDP(state.Context(), uint16(connection.LocalAddr().(*net.UDPAddr).Port))

	if !errors.Is(err, ErrListen) || !errors.Is(err, syscall.EADDRINUSE) || (second != nil) {
		state.Errorf("Test of proxy.ListenUDP function failed, error should be %v, error: %v", ErrListen, err)
		return
	}
}

// Test if proxy.ServeUDP returns with the expected output: plain datagrams both ways, through the rules, out of scope and a DTLS session without secrets;
// a session in scope prints its flow line and goes into the history once it is idle.
func TestServeUDPPositive(state *testing.T) {
	fixture := readDTLSFixture(state)
	hello := fixture.datagrams[0].data
	rules := []intercept.Rule{replaceRule{old: []byte("ping"), new: []byte("PING")}, replaceRule{old: []byte("pong"), new: []byte("PONG")}, dropRule{word: []byte("drop")}}
	positiveCases := []struct {
		Name      string
		Rules     []intercept.Rule
		Scope     string
		Tgid      uint32
		Datagrams [][]byte
		Counts    []int
		Server    [][]byte
		Replies   [][]byte
		Line      string
	}{
		{Name: "plain", Rules: nil, Scope: "", Tgid: 0, Datagrams: [][]byte{[]byte("ping"), []byte("ping2")}, Counts: []int{1, 1}, Server: [][]byte{[]byte("ping"), []byte("ping2")}, Replies: [][]byte{[]byte("pong:ping"), []byte("pong:ping2")}, Line: " up=2dgram/9B down=2dgram/19B "},
		{Name: "rules", Rules: rules, Scope: "", Tgid: 0, Datagrams: [][]byte{[]byte("drop"), []byte("ping")}, Counts: []int{0, 1}, Server: [][]byte{[]byte("PING")}, Replies: [][]byte{[]byte("PONG:PING")}, Line: " up=1dgram/4B down=1dgram/9B "},
		{Name: "out of scope", Rules: rules, Scope: "udp.dstport == 1", Tgid: 0, Datagrams: [][]byte{[]byte("ping")}, Counts: []int{1}, Server: [][]byte{[]byte("ping")}, Replies: [][]byte{[]byte("pong:ping")}, Line: ""},
		{Name: "process gone", Rules: nil, Scope: "", Tgid: 0x3fffffff, Datagrams: [][]byte{[]byte("ping")}, Counts: []int{1}, Server: [][]byte{[]byte("ping")}, Replies: [][]byte{[]byte("pong:ping")}, Line: "cmdline=\"?\""},
		{Name: "dtls without secrets", Rules: rules, Scope: "", Tgid: 0, Datagrams: [][]byte{hello}, Counts: []int{1}, Server: [][]byte{hello}, Replies: [][]byte{append([]byte("pong:"), hello...)}, Line: " up=1dgram/"},
	}

	for _, positive := range positiveCases {
		server := startUDPServer(state, func(datagram []byte) (replies [][]byte) {
			// the server answers what the rules made of ping with a reply the rules drop first
			if string(datagram) == "PING" {
				replies = [][]byte{[]byte("drop"), []byte("pong:PING")}
				return
			}

			replies = [][]byte{append([]byte("pong:"), datagram...)}
			return
		})
		flow := dynamicFlow(state)
		destination := testFlow
		destination.OriginalDestination = server.address()

		if positive.Tgid != 0 {
			destination.Tgid = positive.Tgid
		}

		flow.Store(&destination)
		var scope *filter.Filter

		if positive.Scope != "" {
			parsed, err := filter.Parse(positive.Scope)

			if err != nil {
				state.Fatalf("Test of proxy.ServeUDP failed, cannot parse filter, error: %s", err.Error())
			}

			scope = &parsed
		}

		var pipeline *intercept.Pipeline

		if positive.Rules != nil {
			pipeline = intercept.New(positive.Rules, nil, nil)
		}

		recorder := history.New(history.DefaultLimits(), nil)
		logger, logs := bufferLogger()
		var replies [][]byte
		var err error
		output := captureStdout(state, func() {
			connection, address := listenTestUDP(state)
			stop := startUDPProxy(state, connection, nil, pipeline, scope, recorder, logger)
			client := dialTestUDP(state, address)
			replies, err = exchangeUDP(client, positive.Datagrams, positive.Counts)

			// the session ends when it is idle
			if (positive.Line != "") && !waitFor(func() bool { return allClosed(recorder) }) {
				err = errors.Join(err, errors.New("the session did not end when it was idle"))
			}

			stop()
		})

		if (err != nil) || !slices.EqualFunc(replies, positive.Replies, bytes.Equal) || !slices.EqualFunc(server.datagrams(), positive.Server, bytes.Equal) {
			state.Errorf("Test of proxy.ServeUDP function failed, case %q, the server should get %q and the client %q, they got %q and %q, error: %v, logs: %s", positive.Name, positive.Server, positive.Replies, server.datagrams(), replies, err, logs.String())
			return
		}

		if ((positive.Line == "") && (output != "")) || !strings.Contains(output, positive.Line) {
			state.Errorf("Test of proxy.ServeUDP function failed, case %q, the output should have %q, output: %q", positive.Name, positive.Line, output)
			return
		}
	}
}

// Test if proxy.ServeUDP returns with the expected errors: a client without a flow, a flow to the proxy itself, a destination that can't be dialed
// and a socket without the destination of its datagrams lose the datagram; a destination that refuses only misses its replies.
func TestServeUDPNegative(state *testing.T) {
	refused, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})

	if err != nil {
		state.Fatalf("Test of proxy.ServeUDP failed, cannot listen, error: %s", err.Error())
	}

	refusedAddress := refused.LocalAddr().(*net.UDPAddr).AddrPort()
	err = refused.Close()

	if err != nil {
		state.Fatalf("Test of proxy.ServeUDP failed, cannot close socket, error: %s", err.Error())
	}

	negativeCases := []struct {
		Name    string
		NoFlow  bool
		Loop    bool
		Plain   bool
		Address netip.AddrPort
		Warning string
	}{
		{Name: "no flow", NoFlow: true, Loop: false, Plain: false, Address: netip.AddrPort{}, Warning: "Could not find flow of client"},
		{Name: "loop", NoFlow: false, Loop: true, Plain: false, Address: netip.AddrPort{}, Warning: ErrLoop.Error()},
		{Name: "no destination", NoFlow: false, Loop: false, Plain: false, Address: netip.AddrPort{}, Warning: "Could not dial original destination"},
		{Name: "refused", NoFlow: false, Loop: false, Plain: false, Address: refusedAddress, Warning: "Original destination refused datagram"},
		{Name: "no packet info", NoFlow: false, Loop: false, Plain: true, Address: refusedAddress, Warning: "Could not read destination of datagram"},
	}

	for _, negative := range negativeCases {
		flow := dynamicFlow(state)
		logger, logs := bufferLogger()
		output := captureStdout(state, func() {
			connection, address := listenTestUDP(state)

			if negative.Plain {
				// a socket without IPV6_RECVPKTINFO
				err = connection.Close()

				if err != nil {
					state.Fatalf("Test of proxy.ServeUDP failed, cannot close socket, error: %s", err.Error())
				}

				connection, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})

				if err != nil {
					state.Fatalf("Test of proxy.ServeUDP failed, cannot listen, error: %s", err.Error())
				}

				address = connection.LocalAddr().(*net.UDPAddr).AddrPort()
			}

			destination := testFlow
			destination.OriginalDestination = negative.Address

			if negative.Loop {
				destination.OriginalDestination = address
			}

			if !negative.NoFlow {
				flow.Store(&destination)
			}

			stop := startUDPProxy(state, connection, nil, nil, nil, nil, logger)
			client := dialTestUDP(state, address)

			// the second datagram of a refused session finds the error of the first one
			for range 2 {
				_, writeErr := client.Write([]byte("ping"))

				if writeErr != nil {
					state.Errorf("Test of proxy.ServeUDP failed, cannot send, error: %s", writeErr.Error())
				}

				waitFor(func() bool {
					return strings.Contains(logs.String(), negative.Warning)
				})
			}

			stop()
		})

		if !strings.Contains(logs.String(), negative.Warning) || (!negative.Plain && (negative.Address == refusedAddress) != strings.Contains(output, " up=")) {
			state.Errorf("Test of proxy.ServeUDP function failed, case %q, the warning should be %q, output: %q, logs: %s", negative.Name, negative.Warning, output, logs.String())
			return
		}
	}
}

// Test if proxy.ServeUDP returns with the expected output for DTLS sessions with secrets: observed, the application data goes into the history;
// intercepted, it goes through the rules and is sealed again, both ends see the session they expect.
func TestServeDTLSPositive(state *testing.T) {
	fixture := readDTLSFixture(state)

	for _, isIntercepted := range []bool{false, true} {
		useSecrets(state, newKeyLogLookup(fixture.keyLog, tlsrecord.VersionDTLS12, true).lookup)
		// the server answers each datagram of the client with the datagrams after it in the fixture
		var runs [][][]byte
		var datagrams [][]byte
		var counts []int

		for _, datagram := range fixture.datagrams {
			if datagram.direction == tlsrecord.ClientDirection {
				datagrams = append(datagrams, datagram.data)
				counts = append(counts, 0)
				runs = append(runs, nil)
				continue
			}

			counts[len(counts)-1]++
			runs[len(runs)-1] = append(runs[len(runs)-1], datagram.data)
		}

		answered := &atomic.Int64{}
		server := startUDPServer(state, func(datagram []byte) (replies [][]byte) {
			index := int(answered.Add(1) - 1)

			if index < len(runs) {
				replies = runs[index]
			}

			return
		})
		flow := dynamicFlow(state)
		destination := testFlow
		destination.OriginalDestination = server.address()
		flow.Store(&destination)
		var pipeline *intercept.Pipeline

		if isIntercepted {
			pipeline = intercept.New([]intercept.Rule{replaceRule{old: []byte("hello"), new: []byte("HELLO")}}, nil, nil)
		}

		recorder := history.New(history.DefaultLimits(), nil)
		logger, logs := bufferLogger()
		var replies [][]byte
		var err error
		output := captureStdout(state, func() {
			connection, address := listenTestUDP(state)
			stop := startUDPProxy(state, connection, testSecretsMaps, pipeline, nil, recorder, logger)
			client := dialTestUDP(state, address)
			replies, err = exchangeUDP(client, datagrams, counts)

			if !waitFor(func() bool { return allClosed(recorder) }) {
				err = errors.Join(err, errors.New("the session did not end when it was idle"))
			}

			stop()
		})

		// what both ends got, in the order of the session
		var session []TLSChunk
		received := server.datagrams()
		replyIndex := 0

		for index := range received {
			session = append(session, TLSChunk{direction: tlsrecord.ClientDirection, data: received[index]})

			for range counts[min(index, len(counts)-1)] {
				if replyIndex < len(replies) {
					session = append(session, TLSChunk{direction: tlsrecord.ServerDirection, data: replies[replyIndex]})
				}

				replyIndex++
			}
		}

		plain, plainErr := dtlsPlain(fixture, session)
		expected := fixture.lines

		if isIntercepted {
			expected = [2]string{strings.Replace(expected[0], "hello", "HELLO", 1), strings.Replace(expected[1], "hello", "HELLO", 1)}
		}

		if (err != nil) || (plainErr != nil) || (string(plain[0]) != expected[0]) || (string(plain[1]) != expected[1]) || (len(received) != len(datagrams)) {
			state.Errorf("Test of proxy.ServeUDP function failed, intercepted %v, the ends should read %q, they read %q, error: %v, logs: %s", isIntercepted, expected, plain, errors.Join(err, plainErr), logs.String())
			return
		}

		payloads, _ := historyPayloads(recorder, 1)
		line := fmt.Sprintf(" up=%ddgram/", len(datagrams))

		if !strings.Contains(output, line) || !strings.Contains(output, "dtls pid=") || (!isIntercepted && ((string(payloads[0]) != fixture.lines[0]) || (string(payloads[1]) != fixture.lines[1]))) {
			state.Errorf("Test of proxy.ServeUDP function failed, intercepted %v, the output should have %q and the history the lines, payloads: %q, output: %q", isIntercepted, line, payloads, output)
			return
		}
	}
}

// Test if proxy.udpQueue returns with the expected output: it takes datagrams until it is full or closed and gives them in order.
func TestUDPQueuePositive(state *testing.T) {
	queue := newUDPQueue()
	datagram := make([]byte, maxDatagramSize)
	count := 0

	for queue.take(datagram) {
		count++
	}

	datagrams, isEnd := queue.next()
	queue.sent(len(datagrams) * maxDatagramSize)

	if (count != (maxSendQueueBytes+maxDatagramSize-1)/maxDatagramSize) || (len(datagrams) != count) || isEnd || !queue.take([]byte("again")) {
		state.Errorf("Test of proxy.udpQueue function failed, the queue should take %d datagrams and more once they were sent, took: %d, given: %d", (maxSendQueueBytes+maxDatagramSize-1)/maxDatagramSize, count, len(datagrams))
		return
	}

	queue.close()
	datagrams, isEnd = queue.next()

	if (len(datagrams) != 1) || isEnd || queue.take([]byte("late")) {
		state.Errorf("Test of proxy.udpQueue function failed, a closed queue should give what it has and take nothing, given: %d", len(datagrams))
		return
	}

	datagrams, isEnd = queue.next()

	if (len(datagrams) != 0) || !isEnd {
		state.Errorf("Test of proxy.udpQueue function failed, a closed empty queue should end")
		return
	}
}

// Test if proxy.UDPSessions.Expire returns with the expected output: a session with a datagram in the rules is not idle.
func TestUDPSessionsBusyPositive(state *testing.T) {
	sessions := NewUDPSessions()
	session := &UDPSession{key: UDPSessionKey{client: testClient, cookie: 1, destination: testFlow.OriginalDestination}}
	sessions.Add(session)
	session.busy.Add(1)

	if sessions.Expire(session, 0) || (sessions.Get(session.key) != session) {
		state.Errorf("Test of proxy.UDPSessions.Expire function failed, a busy session should stay")
		return
	}
}
