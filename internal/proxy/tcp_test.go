// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
)

// one end of a test flow: what it does with its connection and what it read
type tcpEnd func(connection *net.TCPConn) (received []byte, err error)

// one flow through ServeTCP: the app's end, the server's end and what the proxy has
// Tgid replaces the test's own process when it is not 0
type tcpCase struct {
	Name       string
	Scope      string
	IsRecorded bool
	HasSecrets bool
	Pipeline   *intercept.Pipeline
	HTTP       *HTTPLayer
	Tgid       uint32
	Lookup     *keyLogLookup
	Client     tcpEnd
	Server     tcpEnd
}

// what one flow through ServeTCP left
type tcpResult struct {
	client   []byte
	server   []byte
	output   string
	recorder *history.History
	logs     *lockedBuffer
}

// send request, half-close and read until the end
func plainClient(request []byte) (end tcpEnd) {
	end = func(connection *net.TCPConn) (received []byte, err error) {
		_, err = connection.Write(request)

		if err != nil {
			return
		}

		err = connection.CloseWrite()

		if err != nil {
			return
		}

		received, err = io.ReadAll(connection)
		return
	}
	return
}

// read until the end, answer with response and half-close
func plainServer(response []byte) (end tcpEnd) {
	end = func(connection *net.TCPConn) (received []byte, err error) {
		received, err = io.ReadAll(connection)

		if err != nil {
			return
		}

		_, err = connection.Write(response)

		if err != nil {
			return
		}

		err = connection.CloseWrite()
		return
	}
	return
}

// a server that speaks first: banner, then it reads until the end
func bannerServer(banner []byte) (end tcpEnd) {
	end = func(connection *net.TCPConn) (received []byte, err error) {
		_, err = connection.Write(banner)

		if err != nil {
			return
		}

		received, err = io.ReadAll(connection)
		err = errors.Join(err, connection.CloseWrite())
		return
	}
	return
}

// a client that waits for the banner of the server, then sends request and reads until the end
func bannerClient(bannerLength int, request []byte) (end tcpEnd) {
	end = func(connection *net.TCPConn) (received []byte, err error) {
		received = make([]byte, bannerLength)
		_, err = io.ReadFull(connection, received)

		if err != nil {
			return
		}

		_, err = connection.Write(request)

		if err != nil {
			return
		}

		err = connection.CloseWrite()

		if err != nil {
			return
		}

		rest, readErr := io.ReadAll(connection)
		received = append(received, rest...)
		err = readErr
		return
	}
	return
}

// a TLS client that sends request, closes its side with close_notify and reads until the server's
func tlsClient(config *tls.Config, request []byte) (end tcpEnd) {
	end = func(connection *net.TCPConn) (received []byte, err error) {
		client := tls.Client(connection, config)
		_, err = client.Write(request)

		if err != nil {
			return
		}

		err = client.CloseWrite()

		if err != nil {
			return
		}

		received, err = io.ReadAll(client)
		return
	}
	return
}

// a TLS server that reads until close_notify and answers with response
func tlsServer(config *tls.Config, response []byte) (end tcpEnd) {
	end = func(connection *net.TCPConn) (received []byte, err error) {
		server := tls.Server(connection, config)
		received, err = io.ReadAll(server)

		if err != nil {
			return
		}

		_, err = server.Write(response)
		err = errors.Join(err, server.CloseWrite(), connection.CloseWrite())
		return
	}
	return
}

// a test server on loopback for one connection, its result comes on the channel
func startServer(state *testing.T, end tcpEnd) (address netip.AddrPort, resultChannel chan tcpEndResult) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})

	if err != nil {
		state.Fatalf("Test of the tcp proxy failed, cannot listen, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if closeErr := listener.Close(); (closeErr != nil) && !errors.Is(closeErr, net.ErrClosed) {
			state.Errorf("Test of the tcp proxy failed, cannot close listener, error: %s", closeErr.Error())
		}
	})

	address = listener.Addr().(*net.TCPAddr).AddrPort()
	resultChannel = make(chan tcpEndResult, 1)

	// test server
	go func() {
		connection, acceptErr := listener.AcceptTCP()

		if acceptErr != nil {
			resultChannel <- tcpEndResult{received: nil, err: acceptErr}
			return
		}

		received, endErr := end(connection)
		resultChannel <- tcpEndResult{received: received, err: errors.Join(endErr, connection.Close())}
	}()

	return
}

type tcpEndResult struct {
	received []byte
	err      error
}

// a proxy on ListenTCP that runs ServeTCP until stop
func startTCPProxy(state *testing.T, secretsMaps map[bpf.BpfMapName]*ebpf.Map, pipeline *intercept.Pipeline, httpLayer *HTTPLayer, scope *filter.Filter, recorder *history.History, logger *slog.Logger) (address netip.AddrPort, stop func()) {
	ctx, cancel := context.WithCancel(state.Context())
	listener, err := ListenTCP(ctx, 0)

	if err != nil {
		cancel()
		state.Fatalf("Test of proxy.ListenTCP failed, cannot listen, error: %s", err.Error())
	}

	address = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), listener.Addr().(*net.TCPAddr).AddrPort().Port())
	waitGroup := &sync.WaitGroup{}
	doneChannel := make(chan struct{})

	// tcp proxy
	go func() {
		ServeTCP(ctx, listener, nil, secretsMaps, nil, pipeline, httpLayer, scope, recorder, waitGroup, logger)
		close(doneChannel)
	}()

	stop = func() {
		cancel()
		<-doneChannel
		waitGroup.Wait()
	}
	return
}

// one flow of a case through ServeTCP, the proxy is stopped when both ends are done
func runTCPCase(state *testing.T, testCase tcpCase) (result tcpResult, err error) {
	serverAddress, serverChannel := startServer(state, testCase.Server)
	flow := testFlow
	flow.OriginalDestination = serverAddress

	if testCase.Tgid != 0 {
		flow.Tgid = testCase.Tgid
	}

	useFlows(state, fixedFlow(flow))

	if testCase.Lookup != nil {
		useSecrets(state, testCase.Lookup.lookup)
	}

	var scope *filter.Filter

	if testCase.Scope != "" {
		parsed, parseErr := filter.Parse(testCase.Scope)

		if parseErr != nil {
			state.Fatalf("Test of the tcp proxy failed, cannot parse filter, error: %s", parseErr.Error())
		}

		scope = &parsed
	}

	if testCase.IsRecorded {
		result.recorder = history.New(history.DefaultLimits(), nil)
	}

	secretsMaps := map[bpf.BpfMapName]*ebpf.Map(nil)

	if testCase.HasSecrets {
		secretsMaps = testSecretsMaps
	}

	logger, logs := bufferLogger()
	result.logs = logs
	result.output = captureStdout(state, func() {
		address, stop := startTCPProxy(state, secretsMaps, testCase.Pipeline, testCase.HTTP, scope, result.recorder, logger)
		connection, dialErr := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(address))

		if err = dialErr; err != nil {
			stop()
			return
		}

		result.client, err = testCase.Client(connection)
		err = errors.Join(err, connection.Close())

		serverResult := <-serverChannel
		result.server = serverResult.received
		err = errors.Join(err, serverResult.err)

		// the proxy may still decrypt what it relayed, a flow in the history is done once it is closed
		if (result.recorder != nil) && !waitFor(func() bool {
			flows, _ := result.recorder.Flows(nil, 0, 10)
			return !slices.ContainsFunc(flows, func(flow api.Flow) bool { return flow.State != api.ClosedFlowState })
		}) {
			err = errors.Join(err, errors.New("the flow in the history was not closed"))
		}

		stop()
	})
	return
}

// Test if proxy.ListenTCP returns with the expected output: a dual-stack socket on loopback.
func TestListenTCPPositive(state *testing.T) {
	listener, err := ListenTCP(state.Context(), 0)

	if err != nil {
		state.Fatalf("Test of proxy.ListenTCP function failed, error: %s", err.Error())
	}

	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			state.Errorf("Test of proxy.ListenTCP failed, cannot close listener, error: %s", closeErr.Error())
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port

	for _, address := range []string{"127.0.0.1", "::1"} {
		connection, dialErr := net.Dial("tcp", net.JoinHostPort(address, strings.TrimPrefix(listener.Addr().String(), "[::]:")))

		if dialErr != nil {
			state.Errorf("Test of proxy.ListenTCP function failed, %s should reach port %d, error: %s", address, port, dialErr.Error())
			return
		}

		if closeErr := connection.Close(); closeErr != nil {
			state.Errorf("Test of proxy.ListenTCP failed, cannot close connection, error: %s", closeErr.Error())
			return
		}
	}
}

// Test if proxy.ListenTCP returns with the expected errors: a port in use is ErrListen.
func TestListenTCPNegative(state *testing.T) {
	listener, err := ListenTCP(state.Context(), 0)

	if err != nil {
		state.Fatalf("Test of proxy.ListenTCP failed, cannot listen, error: %s", err.Error())
	}

	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			state.Errorf("Test of proxy.ListenTCP failed, cannot close listener, error: %s", closeErr.Error())
		}
	}()

	second, err := ListenTCP(state.Context(), uint16(listener.Addr().(*net.TCPAddr).Port))

	if !errors.Is(err, ErrListen) || !errors.Is(err, syscall.EADDRINUSE) || (second != nil) {
		state.Errorf("Test of proxy.ListenTCP function failed, error should be %v, error: %v", ErrListen, err)
		return
	}
}

// Test if proxy.ServeTCP returns with the expected output: plain flows in and out of scope, a server that speaks first, a TLS flow observed with its HTTP exchange,
// an intercepted flow and a process that is gone; every flow in scope prints its flow line and goes into the history.
func TestServeTCPPositive(state *testing.T) {
	keyLog := newLockedBuffer()
	serverConfig, clientConfig := tlsConfigs(state, tls.VersionTLS13, []string{"http/1.1"}, keyLog)
	request := []byte("GET /tcp HTTP/1.1\r\nHost: decerter.test\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	pipeline := intercept.New([]intercept.Rule{replaceRule{old: []byte("GET /tcp "), new: []byte("GET /test ")}}, nil, nil)
	// a handshake record with a ClientHello whose body is no ClientHello
	badHello := []byte{0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef}
	positiveCases := []struct {
		Case      tcpCase
		Client    []byte
		Server    []byte
		Line      string
		Exchanges int
	}{
		{
			Case:   tcpCase{Name: "plain", Scope: "", IsRecorded: false, HasSecrets: false, Pipeline: nil, HTTP: nil, Tgid: 0, Lookup: nil, Client: plainClient([]byte("ping")), Server: plainServer([]byte("pong!"))},
			Client: []byte("pong!"), Server: []byte("ping"), Line: " up=4B down=5B ", Exchanges: 0,
		},
		{
			Case:   tcpCase{Name: "out of scope", Scope: "tcp.dstport == 1", IsRecorded: true, HasSecrets: true, Pipeline: pipeline, HTTP: nil, Tgid: 0, Lookup: nil, Client: plainClient(request), Server: plainServer(response)},
			Client: response, Server: request, Line: "", Exchanges: 0,
		},
		{
			Case:   tcpCase{Name: "out of scope after the opening", Scope: `tls.sni == "decerter.test"`, IsRecorded: false, HasSecrets: false, Pipeline: nil, HTTP: nil, Tgid: 0, Lookup: nil, Client: plainClient(request), Server: plainServer(response)},
			Client: response, Server: request, Line: "", Exchanges: 0,
		},
		{
			Case:   tcpCase{Name: "server first", Scope: "", IsRecorded: true, HasSecrets: false, Pipeline: nil, HTTP: nil, Tgid: 0, Lookup: nil, Client: bannerClient(10, []byte("QUIT\r\n")), Server: bannerServer([]byte("220 smtp\r\n"))},
			Client: []byte("220 smtp\r\n"), Server: []byte("QUIT\r\n"), Line: " up=6B down=10B ", Exchanges: 0,
		},
		{
			Case:   tcpCase{Name: "observed tls with http", Scope: `tls.sni == "decerter.test"`, IsRecorded: true, HasSecrets: true, Pipeline: nil, HTTP: &HTTPLayer{Pipeline: nil, Timeout: time.Second}, Tgid: 0, Lookup: newKeyLogLookup(keyLog, tls.VersionTLS13, true), Client: tlsClient(clientConfig, request), Server: tlsServer(serverConfig, response)},
			Client: response, Server: request, Line: "tcp pid=", Exchanges: 1,
		},
		{
			Case:   tcpCase{Name: "intercepted plain", Scope: "", IsRecorded: true, HasSecrets: false, Pipeline: pipeline, HTTP: &HTTPLayer{Pipeline: nil, Timeout: time.Second}, Tgid: 0, Lookup: nil, Client: plainClient(request), Server: plainServer(response)},
			Client: response, Server: []byte("GET /test HTTP/1.1\r\nHost: decerter.test\r\n\r\n"), Line: " up=43B down=40B ", Exchanges: 1,
		},
		{
			Case:   tcpCase{Name: "a ClientHello that can't be read", Scope: "", IsRecorded: true, HasSecrets: false, Pipeline: nil, HTTP: nil, Tgid: 0, Lookup: nil, Client: plainClient(badHello), Server: plainServer([]byte("no"))},
			Client: []byte("no"), Server: badHello, Line: " up=13B down=2B ", Exchanges: 0,
		},
		{
			Case:   tcpCase{Name: "process gone", Scope: "", IsRecorded: false, HasSecrets: false, Pipeline: nil, HTTP: nil, Tgid: 0x3fffffff, Lookup: nil, Client: plainClient([]byte("ping")), Server: plainServer([]byte("pong"))},
			Client: []byte("pong"), Server: []byte("ping"), Line: "cmdline=\"?\"", Exchanges: 0,
		},
	}

	for _, positive := range positiveCases {
		result, err := runTCPCase(state, positive.Case)

		if (err != nil) || !bytes.Equal(result.client, positive.Client) || !bytes.Equal(result.server, positive.Server) {
			state.Errorf("Test of proxy.ServeTCP function failed, case %q, the client should get %q and the server %q, they got %q and %q, error: %v, logs: %s", positive.Case.Name, positive.Client, positive.Server, result.client, result.server, err, result.logs.String())
			return
		}

		if ((positive.Line == "") && (result.output != "")) || !strings.Contains(result.output, positive.Line) {
			state.Errorf("Test of proxy.ServeTCP function failed, case %q, the output should have %q, output: %q", positive.Case.Name, positive.Line, result.output)
			return
		}

		if result.recorder == nil {
			continue
		}

		flows, _ := result.recorder.Flows(nil, 0, 10)
		exchanges, _, _ := result.recorder.Exchanges(1, 0, 10)

		if ((positive.Line == "") != (len(flows) == 0)) || (len(exchanges) != positive.Exchanges) {
			state.Errorf("Test of proxy.ServeTCP function failed, case %q, the history should have the flow in scope with %d exchanges, flows: %+v, exchanges: %+v, output: %q, logs: %s", positive.Case.Name, positive.Exchanges, flows, exchanges, result.output, result.logs.String())
			return
		}

		if positive.Case.HasSecrets && (positive.Line != "") {
			payloads, _ := historyPayloads(result.recorder, 1)

			if !bytes.Equal(payloads[tlsrecord.ClientDirection], request) || !bytes.Equal(payloads[tlsrecord.ServerDirection], response) || !strings.Contains(result.output, "sni=\"decerter.test\" alpn=\"http/1.1\"") {
				state.Errorf("Test of proxy.ServeTCP function failed, case %q, the decrypted records should be in the history and the output, up: %q, down: %q, output: %q", positive.Case.Name, payloads[0], payloads[1], result.output)
				return
			}
		}
	}
}

// Test if proxy.ServeTCP returns with the expected errors: a client without a flow, a flow to the proxy itself and a destination that refuses are reset,
// a flow whose ends say nothing ends with the proxy.
func TestServeTCPNegative(state *testing.T) {
	refused, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})

	if err != nil {
		state.Fatalf("Test of proxy.ServeTCP failed, cannot listen, error: %s", err.Error())
	}

	refusedAddress := refused.Addr().(*net.TCPAddr).AddrPort()
	err = refused.Close()

	if err != nil {
		state.Fatalf("Test of proxy.ServeTCP failed, cannot close listener, error: %s", err.Error())
	}

	// the client reads until the proxy resets the connection
	resetClient := func(connection *net.TCPConn) (received []byte, err error) {
		received, err = io.ReadAll(connection)
		return
	}
	negativeCases := []struct {
		Name    string
		Lookup  bool
		Loop    bool
		Address netip.AddrPort
		Warning string
	}{
		{Name: "no flow", Lookup: true, Loop: false, Address: netip.AddrPort{}, Warning: "Could not find flow of client"},
		{Name: "loop", Lookup: false, Loop: true, Address: netip.AddrPort{}, Warning: ErrLoop.Error()},
		{Name: "refused", Lookup: false, Loop: false, Address: refusedAddress, Warning: "Could not dial original destination"},
	}

	for _, negative := range negativeCases {
		logger, logs := bufferLogger()
		var received []byte
		var clientErr error
		// the destination is set once the proxy has its address, the lookup runs in the proxy's goroutine
		destination := &atomic.Pointer[netip.AddrPort]{}
		useFlows(state, func(client netip.AddrPort, ipProtocol uint8, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (cookie uint64, found redirect.Flow, err error) {
			if negative.Lookup {
				err = errTestLookup
				return
			}

			cookie = 1
			found = testFlow
			found.OriginalDestination = *destination.Load()
			return
		})
		output := captureStdout(state, func() {
			address, stop := startTCPProxy(state, nil, nil, nil, nil, nil, logger)
			destination.Store(&negative.Address)

			if negative.Loop {
				destination.Store(&address)
			}

			connection, dialErr := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(address))

			if dialErr != nil {
				clientErr = dialErr
				stop()
				return
			}

			received, clientErr = resetClient(connection)
			clientErr = errors.Join(clientErr, connection.Close())
			stop()
		})

		if !errors.Is(clientErr, syscall.ECONNRESET) || (len(received) != 0) || (output != "") || !strings.Contains(logs.String(), negative.Warning) {
			state.Errorf("Test of proxy.ServeTCP function failed, case %q, the client should be reset with the warning %q, error: %v, output: %q, logs: %s", negative.Name, negative.Warning, clientErr, output, logs.String())
			return
		}
	}

	// both ends wait for the other, the proxy shutdown ends the flow in its opening read
	acceptedChannel := make(chan struct{})
	serverAddress, serverChannel := startServer(state, func(connection *net.TCPConn) (received []byte, err error) {
		close(acceptedChannel)
		received, err = io.ReadAll(connection)
		return
	})
	flow := testFlow
	flow.OriginalDestination = serverAddress
	useFlows(state, fixedFlow(flow))
	logger, _ := bufferLogger()
	var received []byte
	output := captureStdout(state, func() {
		address, stop := startTCPProxy(state, nil, nil, nil, nil, history.New(history.DefaultLimits(), nil), logger)
		connection, dialErr := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(address))

		if dialErr != nil {
			err = dialErr
			stop()
			return
		}

		<-acceptedChannel
		stop()
		received, err = io.ReadAll(connection)
		err = errors.Join(err, connection.Close())
	})
	serverResult := <-serverChannel

	if (err != nil) || (len(received) != 0) || (serverResult.err != nil) || (len(serverResult.received) != 0) || !strings.Contains(output, " up=0B down=0B ") {
		state.Errorf("Test of proxy.ServeTCP function failed, a silent flow should end with the proxy, received: %q, error: %v, server: %v, output: %q", received, err, serverResult.err, output)
		return
	}
}

// Test if proxy.pipeTCP returns with the expected errors: an opening that can't be written, an observed write to a server that is gone
// and an observed read from a client that reset end both directions.
func TestPipeTCPNegative(state *testing.T) {
	chunks, _, _ := recordTLS(state, tls.VersionTLS13, nil, []byte("request"), []byte("response"))
	hello := chunks[0].data
	negativeCases := []struct {
		Name        string
		Opening     []TLSChunk
		ResetServer bool
		ResetClient bool
	}{
		{Name: "opening to a reset server", Opening: []TLSChunk{{direction: tlsrecord.ClientDirection, data: hello}}, ResetServer: true, ResetClient: false},
		{Name: "observed write to a reset server", Opening: nil, ResetServer: true, ResetClient: false},
		{Name: "observed read from a reset client", Opening: nil, ResetServer: false, ResetClient: true},
	}

	for _, negative := range negativeCases {
		app, proxyClient, err := tcpPair()

		if err != nil {
			state.Fatalf("Test of proxy.pipeTCP failed, cannot connect, error: %s", err.Error())
		}

		proxyUpstream, server, err := tcpPair()

		if err != nil {
			state.Fatalf("Test of proxy.pipeTCP failed, cannot connect, error: %s", err.Error())
		}

		logger, logs := bufferLogger()
		observer := NewTLSObserver(testFlow, testClient, intercept.Flow{}, nil, testSecretsMaps)

		// a reset end is closed with linger 0, its peer sees ECONNRESET
		if negative.ResetServer {
			err = errors.Join(server.SetLinger(0), server.Close())
			_, readErr := proxyUpstream.Read(make([]byte, 1))

			if !errors.Is(readErr, syscall.ECONNRESET) {
				err = errors.Join(err, readErr)
			}
		}

		if err != nil {
			state.Fatalf("Test of proxy.pipeTCP failed, cannot reset the server, error: %v", err)
		}

		doneChannel := make(chan [2]int64, 1)

		// the relay
		go func() {
			upBytes, downBytes := pipeTCP(state.Context(), proxyClient, proxyUpstream, negative.Opening, observer, logger)
			doneChannel <- [2]int64{upBytes, downBytes}
		}()

		if negative.Opening == nil {
			_, err = app.Write(hello)
		}

		if negative.ResetClient {
			// the hello is through before the client goes
			received := make([]byte, len(hello))
			_, readErr := io.ReadFull(server, received)
			err = errors.Join(err, readErr, app.SetLinger(0))
		}

		err = errors.Join(err, app.Close())
		written := <-doneChannel
		err = errors.Join(err, proxyClient.Close(), proxyUpstream.Close())

		if !negative.ResetServer {
			err = errors.Join(err, server.Close())
		}

		if (err != nil) || (written[1] != 0) || (negative.ResetClient && (written[0] != int64(len(hello)))) || !strings.Contains(logs.String(), "Could not") {
			state.Errorf("Test of proxy.pipeTCP function failed, case %q, the relay should end, written: %v, error: %v, logs: %s", negative.Name, written, err, logs.String())
			return
		}
	}
}

// Test if proxy.dialUpstream returns with the expected errors: a mark the process may not set fails the dial before it connects.
func TestDialUpstreamMarkNegative(state *testing.T) {
	if os.Geteuid() == 0 {
		state.Skip("root may set SO_MARK")
	}

	flow := testFlow
	flow.OriginalDestination = netip.MustParseAddrPort("127.0.0.1:9")
	flow.Mark = 0x10064
	connection, upstreamCookie, err := dialUpstream(state.Context(), "tcp", flow, 1, time.Second, nil, discardLogger())

	if !errors.Is(err, ErrMark) || (connection != nil) || (upstreamCookie != 0) {
		state.Errorf("Test of proxy.dialUpstream function failed, error should be %v, error: %v", ErrMark, err)
		return
	}
}
