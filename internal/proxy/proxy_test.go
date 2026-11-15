// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
	"golang.org/x/sys/unix"
)

var (
	testFlow = redirect.Flow{
		OriginalDestination: netip.MustParseAddrPort("93.184.216.34:443"),
		IPProtocol:          syscall.IPPROTO_TCP,
		Redirected:          true,
		Tgid:                uint32(os.Getpid()),
		UID:                 1001,
		GID:                 1002,
		CgroupID:            5,
		Comm:                "curl",
		Mark:                0,
		Client:              netip.AddrPort{},
	}
	testClient = netip.MustParseAddrPort("127.0.0.1:40000")
)

// Test if proxy.scopeValues and proxy.isInScope return with the expected output.
func TestScopeValuesPositive(state *testing.T) {
	values := scopeValues(testFlow, "curl -s https://example.com/", testClient, nil)
	expected := filter.Values{PID: testFlow.Tgid, UID: 1001, GID: 1002, Comm: "curl", Cmdline: "curl -s https://example.com/", Exe: "", IPProtocol: syscall.IPPROTO_TCP, Source: testClient, Destination: testFlow.OriginalDestination, TLS: filter.UnknownTLSState, TLSVersion: 0, ServerName: "", Protocols: nil}

	if !reflect.DeepEqual(values, expected) {
		state.Errorf("Test of proxy.scopeValues function failed, values should be %+v, values: %+v", expected, values)
		return
	}

	// proc.exe is only read when the filter has it, here the process is this test
	scope, err := filter.Parse(`proc.exe contains "proxy" && proc.uid == 1001`)

	if err != nil {
		state.Fatalf("Test of proxy.scopeValues failed, cannot parse filter, error: %s", err.Error())
	}

	executable, err := os.Executable()

	if err != nil {
		state.Fatalf("Test of proxy.scopeValues failed, cannot find test binary, error: %s", err.Error())
	}

	values = scopeValues(testFlow, "", testClient, &scope)

	if values.Exe != executable {
		state.Errorf("Test of proxy.scopeValues function failed, exe should be %s, exe: %s", executable, values.Exe)
		return
	}

	// a scope without proc.exe does not read it, the history reads it for a flow in scope only
	uidScope, err := filter.Parse(`proc.uid == 1001`)

	if err != nil {
		state.Fatalf("Test of proxy.scopeValues failed, cannot parse filter, error: %s", err.Error())
	}

	unread := scopeValues(testFlow, "", testClient, &uidScope)
	recorder := history.New(history.DefaultLimits(), nil)
	recorded := recordedValues(unread, recorder)
	unrecorded := recordedValues(unread, nil)
	kept := recordedValues(filter.Values{PID: testFlow.Tgid, Exe: "/usr/bin/curl"}, recorder)

	if (unread.Exe != "") || (recorded.Exe != executable) || (unrecorded.Exe != "") || (kept.Exe != "/usr/bin/curl") {
		state.Errorf("Test of proxy.recordedValues function failed, exe should be read for the history only, exe: %q %q %q %q", unread.Exe, recorded.Exe, unrecorded.Exe, kept.Exe)
		return
	}

	// no filter is everything, a ClientHello field is undecided before the ClientHello
	tlsScope, err := filter.Parse(`tls.sni == "example.com"`)

	if err != nil {
		state.Fatalf("Test of proxy.isInScope failed, cannot parse filter, error: %s", err.Error())
	}

	if (isInScope(nil, values) != filter.TrueResult) || (isInScope(&scope, values) != filter.TrueResult) || (isInScope(&tlsScope, values) != filter.UnknownResult) {
		state.Errorf("Test of proxy.isInScope function failed, results: %v %v %v", isInScope(nil, values), isInScope(&scope, values), isInScope(&tlsScope, values))
		return
	}
}

// Test if proxy.isLoop returns with the expected output.
func TestIsLoopPositive(state *testing.T) {
	local := netip.MustParseAddrPort("[::ffff:127.0.0.1]:15001")
	positiveCases := []struct {
		Destination netip.AddrPort
		IsLoop      bool
	}{
		{Destination: netip.MustParseAddrPort("127.0.0.1:15001"), IsLoop: true},
		{Destination: netip.MustParseAddrPort("127.0.0.53:15001"), IsLoop: true},
		{Destination: netip.MustParseAddrPort("[::1]:15001"), IsLoop: true},
		{Destination: netip.MustParseAddrPort("127.0.0.1:15002"), IsLoop: false},
		{Destination: netip.MustParseAddrPort("10.0.0.1:15001"), IsLoop: false},
	}

	for _, positive := range positiveCases {
		if isLoop(positive.Destination, local) != positive.IsLoop {
			state.Errorf("Test of proxy.isLoop function failed, destination %s, loop should be %v", positive.Destination, positive.IsLoop)
			return
		}
	}
}

// Test if proxy.datagramDestination returns with the expected output.
func TestDatagramDestinationPositive(state *testing.T) {
	positiveCases := []struct {
		Address netip.Addr
		Message []byte
	}{
		{Address: netip.MustParseAddr("::ffff:127.0.0.1"), Message: pktInfo6(netip.MustParseAddr("::ffff:127.0.0.1"))},
		// another control message in front of it
		{Address: netip.MustParseAddr("::1"), Message: append(unix.UnixRights(0), pktInfo6(netip.MustParseAddr("::1"))...)},
	}

	for _, positive := range positiveCases {
		local, err := datagramDestination(positive.Message)

		if (err != nil) || (local != positive.Address) {
			state.Errorf("Test of proxy.datagramDestination function failed, address should be %s, address: %s, error: %v", positive.Address, local, err)
			return
		}
	}
}

// Test if proxy.datagramDestination returns with the expected errors.
func TestDatagramDestinationNegative(state *testing.T) {
	negativeCases := [][]byte{
		nil,
		unix.UnixRights(0),
		// a header that claims more than there is
		pktInfo6(netip.IPv6Loopback())[:20],
	}

	for _, negative := range negativeCases {
		_, err := datagramDestination(negative)

		if !errors.Is(err, ErrPacketInfo) {
			state.Errorf("Test of proxy.datagramDestination function failed, message %x, error should be %v, error: %v", negative, ErrPacketInfo, err)
			return
		}
	}
}

// Test if proxy.markControl returns with the expected output: nothing for an unmarked socket, SO_MARK otherwise.
func TestMarkControlPositive(state *testing.T) {
	if markControl(0) != nil {
		state.Errorf("Test of proxy.markControl function failed, a socket without a mark should get no control function")
		return
	}

	fileDescriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)

	if err != nil {
		state.Fatalf("Test of proxy.markControl failed, cannot create socket, error: %s", err.Error())
	}

	sockets := []*os.File{os.NewFile(uintptr(fileDescriptors[0]), "a"), os.NewFile(uintptr(fileDescriptors[1]), "b")}

	defer func() {
		for _, socket := range sockets {
			if closeErr := socket.Close(); closeErr != nil {
				state.Errorf("Test of proxy.markControl failed, cannot close socket, error: %s", closeErr.Error())
			}
		}
	}()

	rawConnection, err := sockets[0].SyscallConn()

	if err != nil {
		state.Fatalf("Test of proxy.markControl failed, cannot get raw connection, error: %s", err.Error())
	}

	// SO_MARK needs CAP_NET_ADMIN, without it the error names the mark
	err = markControl(0x10064)("unix", "", rawConnection)

	if (os.Geteuid() != 0) && (!errors.Is(err, ErrMark) || !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), "0x10064")) {
		state.Errorf("Test of proxy.markControl function failed, error should be %v, error: %v", ErrMark, err)
		return
	}

	if (os.Geteuid() == 0) && (err != nil) {
		state.Errorf("Test of proxy.markControl function failed, error: %s", err.Error())
		return
	}
}

// Test if proxy.dialUpstream returns with the expected output without the capture: a connection to the original destination and no upstream cookie.
func TestDialUpstreamPositive(state *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		state.Fatalf("Test of proxy.dialUpstream failed, cannot listen, error: %s", err.Error())
	}

	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			state.Errorf("Test of proxy.dialUpstream failed, cannot close listener, error: %s", closeErr.Error())
		}
	}()

	flow := testFlow
	flow.OriginalDestination = listener.Addr().(*net.TCPAddr).AddrPort()
	connection, upstreamCookie, err := dialUpstream(state.Context(), "tcp", flow, 7, time.Second, nil, slog.New(slog.DiscardHandler))

	if err != nil {
		state.Fatalf("Test of proxy.dialUpstream function failed, error: %s", err.Error())
	}

	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			state.Errorf("Test of proxy.dialUpstream failed, cannot close connection, error: %s", closeErr.Error())
		}
	}()

	if (upstreamCookie != 0) || (connection.RemoteAddr().String() != flow.OriginalDestination.String()) {
		state.Errorf("Test of proxy.dialUpstream function failed, the connection should go to %s without a cookie, remote: %s, cookie: %d", flow.OriginalDestination, connection.RemoteAddr(), upstreamCookie)
		return
	}

	// a socket that is not captured has nothing to release
	releaseUpstream(upstreamCookie, nil, slog.New(slog.DiscardHandler))
}

// Test if proxy.dialUpstream returns with the expected errors: a refused dial has no connection and no upstream cookie.
func TestDialUpstreamNegative(state *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		state.Fatalf("Test of proxy.dialUpstream failed, cannot listen, error: %s", err.Error())
	}

	flow := testFlow
	flow.OriginalDestination = listener.Addr().(*net.TCPAddr).AddrPort()
	err = listener.Close()

	if err != nil {
		state.Fatalf("Test of proxy.dialUpstream failed, cannot close listener, error: %s", err.Error())
	}

	connection, upstreamCookie, err := dialUpstream(state.Context(), "tcp", flow, 7, time.Second, nil, slog.New(slog.DiscardHandler))

	if !errors.Is(err, syscall.ECONNREFUSED) || (connection != nil) || (upstreamCookie != 0) {
		state.Errorf("Test of proxy.dialUpstream function failed, error should be %v without a connection or cookie, connection: %v, cookie: %d, error: %v", syscall.ECONNREFUSED, connection, upstreamCookie, err)
		return
	}
}

// Test if proxy.UDPSessions returns with the expected output: an idle session expires, a replaced one does not take its successor along.
func TestUDPSessionsPositive(state *testing.T) {
	sessions := NewUDPSessions()
	key := UDPSessionKey{client: testClient, cookie: 7, destination: netip.MustParseAddrPort("9.9.9.9:53")}
	first := &UDPSession{key: key}
	sessions.Add(first)

	if sessions.Get(key) != first {
		state.Errorf("Test of proxy.UDPSessions.Get function failed, the added session should be found")
		return
	}

	// Get marked it active, it is not idle for a minute
	if sessions.Expire(first, time.Minute) || (sessions.Get(key) != first) {
		state.Errorf("Test of proxy.UDPSessions.Expire function failed, an active session should stay")
		return
	}

	// a new socket on the client port took the key, the old session goes without removing it
	second := &UDPSession{key: key}
	sessions.Add(second)

	if !sessions.Expire(first, 0) || (sessions.Get(key) != second) {
		state.Errorf("Test of proxy.UDPSessions.Expire function failed, the idle first session should expire and the second stay")
		return
	}

	sessions.Remove(first)

	if sessions.Get(key) != second {
		state.Errorf("Test of proxy.UDPSessions.Remove function failed, removing the first session should keep the second")
		return
	}

	sessions.Remove(second)

	if sessions.Get(key) != nil || (sessions.Get(UDPSessionKey{}) != nil) {
		state.Errorf("Test of proxy.UDPSessions.Remove function failed, no session should be left")
		return
	}
}

// Test if proxy.TLSObserver returns with the expected output: it takes copies until it falls behind, then it stops for good and logs it once.
func TestTLSObserverPositive(state *testing.T) {
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	observer := NewTLSObserver(intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{}), nil, nil)

	for range observerQueueLength {
		observer.Observe(tlsrecord.ClientDirection, []byte("x"), logger)
	}

	if !observer.Active() || (len(observer.chunks) != observerQueueLength) {
		state.Errorf("Test of proxy.TLSObserver.Observe function failed, a full queue should be active, queued: %d", len(observer.chunks))
		return
	}

	observer.Observe(tlsrecord.ServerDirection, []byte("y"), logger)
	observer.Observe(tlsrecord.ServerDirection, []byte("z"), logger)

	if observer.Active() || (strings.Count(logs.String(), ErrObserverBehind.Error()) != 1) {
		state.Errorf("Test of proxy.TLSObserver.Observe function failed, an observer behind should stop once, logs: %q", logs.String())
		return
	}

	// more bytes than the backlog may hold stop it at once, a flow that is not TLS stops it without a warning
	big := NewTLSObserver(intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{}), nil, nil)
	big.Observe(tlsrecord.ClientDirection, make([]byte, maxObserverBytes+1), logger)
	plain := NewTLSObserver(intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{}), nil, nil)
	plain.Stop(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if big.Active() || (len(big.chunks) != 0) || plain.Active() {
		state.Errorf("Test of proxy.TLSObserver function failed, both observers should have stopped")
		return
	}
}

// Test if proxy.statsText and proxy.printSession return with the expected output.
func TestLinesPositive(state *testing.T) {
	text := statsText(sendStats{sealed: 1, written: 2, identical: 3, changed: 4, dropped: 5, split: 6, forwarded: 7, passed: 8})

	if text != "sealed:1,written:2,identical:3,changed:4,dropped:5,split:6,forwarded:7,passed:8" {
		state.Errorf("Test of proxy.statsText function failed, text: %s", text)
		return
	}

	prefixCases := []struct {
		Layer   intercept.Layer
		Session tlsrecord.Session
		Prefix  string
	}{
		{Layer: intercept.TLSLayer, Session: tlsrecord.Session{Version: tlsrecord.VersionTLS13, CipherSuite: 0x1302}, Prefix: "tls pid=" + strconv.FormatUint(uint64(testFlow.Tgid), 10) + " uid=1001 comm=curl 93.184.216.34:443 client=127.0.0.1:40000 version=TLS1.3 suite=TLS_AES_256_GCM_SHA384 sni=\"\" alpn=\"\"\n"},
		{Layer: intercept.DTLSLayer, Session: tlsrecord.Session{Version: tlsrecord.VersionDTLS12, CipherSuite: 0xc02b}, Prefix: "dtls pid=" + strconv.FormatUint(uint64(testFlow.Tgid), 10) + " uid=1001 comm=curl 93.184.216.34:443 client=127.0.0.1:40000 version=DTLS1.2 suite=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 sni=\"\" alpn=\"\"\n"},
	}

	for _, positive := range prefixCases {
		flow := intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{})
		flow.Session = positive.Session
		line := captureStdout(state, func() {
			printSession(flow, positive.Layer)
		})

		if line != positive.Prefix {
			state.Errorf("Test of proxy.printSession function failed, line should be %q, line: %q", positive.Prefix, line)
			return
		}
	}
}

// replaces old with new in every message that contains old
type replaceRule struct {
	old []byte
	new []byte
}

func (rule replaceRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = bytes.Contains(message.Plain, rule.old)
	return
}

func (rule replaceRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	plain = bytes.ReplaceAll(message.Plain, rule.old, rule.new)
	verdict = intercept.ForwardVerdict
	return
}

// Test if proxy.interceptTCP returns with the expected output over loopback sockets: a plain TCP flow goes through the rules both ways,
// a TLS flow without the secrets uprobe is relayed raw and the rules never see it
func TestInterceptTCPPositive(state *testing.T) {
	// the start of a ClientHello, enough to tell a TLS flow
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x00, 0x00, 0x1c}
	positiveCases := []struct {
		Name     string
		Request  []byte
		Response []byte
		Upstream []byte
		Client   []byte
	}{
		{Name: "plain", Request: []byte("GET / HTTP/1.1\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\nX: GET / \r\n\r\n"), Upstream: []byte("GET /test HTTP/1.1\r\n\r\n"), Client: []byte("HTTP/1.1 200 OK\r\nX: GET /test \r\n\r\n")},
		{Name: "tls without secrets", Request: append(bytes.Clone(clientHello), "GET / "...), Response: []byte("GET / "), Upstream: append(bytes.Clone(clientHello), "GET / "...), Client: []byte("GET / ")},
	}

	for _, positive := range positiveCases {
		upstream, client, err := relay(state, positive.Request, positive.Response)

		if err != nil {
			state.Errorf("Test of proxy.interceptTCP failed, case %q, error: %s", positive.Name, err.Error())
			return
		}

		if !bytes.Equal(upstream, positive.Upstream) || !bytes.Equal(client, positive.Client) {
			state.Errorf("Test of proxy.interceptTCP function failed, case %q, upstream should get %q and the client %q, they got: %q and %q", positive.Name, positive.Upstream, positive.Client, upstream, client)
			return
		}
	}
}

// the app sends request and closes its side, the server reads all of it, answers with response and closes; what each end read
func relay(state *testing.T, request []byte, response []byte) (upstream []byte, client []byte, err error) {
	pipeline := intercept.New([]intercept.Rule{replaceRule{old: []byte("GET / "), new: []byte("GET /test ")}}, nil, nil)
	upstream, client, err = relayWith(state, request, response, pipeline, nil)
	return
}

// relay through pipeline and the HTTP layer of flow 1 of recorder, nil for none
func relayWith(state *testing.T, request []byte, response []byte, pipeline *intercept.Pipeline, flowHTTP *httpFlow) (upstream []byte, client []byte, err error) {
	app, proxyClient, err := tcpPair()

	if err != nil {
		return
	}

	proxyUpstream, server, err := tcpPair()

	if err != nil {
		err = errors.Join(err, app.Close(), proxyClient.Close())
		return
	}

	defer func() {
		err = errors.Join(err, app.Close(), proxyClient.Close(), proxyUpstream.Close(), server.Close())
	}()

	flow := intercept.FlowOf(1, 1, testFlow, testClient, filter.Values{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	doneChannel := make(chan [2]int64, 1)
	serverErrChannel := make(chan error, 1)

	// the proxy in the middle
	go func() {
		upBytes, downBytes := interceptTCP(state.Context(), proxyClient, proxyUpstream, nil, flow, pipeline, nil, flowHTTP, logger)
		doneChannel <- [2]int64{upBytes, downBytes}
	}()

	// test server
	go func() {
		received, readErr := io.ReadAll(server)
		upstream = received
		_, writeErr := server.Write(response)
		serverErrChannel <- errors.Join(readErr, writeErr, server.CloseWrite())
	}()

	_, err = app.Write(request)

	if err != nil {
		return
	}

	err = app.CloseWrite()

	if err != nil {
		return
	}

	client, err = io.ReadAll(app)
	err = errors.Join(err, <-serverErrChannel)
	written := <-doneChannel

	if (err == nil) && ((written[0] != int64(len(upstream))) || (written[1] != int64(len(client)))) {
		err = errors.New("the bytes interceptTCP wrote were not what the ends read")
	}

	return
}

// both ends of one loopback TCP connection
func tcpPair() (dialed *net.TCPConn, accepted *net.TCPConn, err error) {
	listener, listenErr := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})

	if err = listenErr; err != nil {
		return
	}

	acceptChannel := make(chan *net.TCPConn, 1)
	acceptErrChannel := make(chan error, 1)

	// accept the one connection
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		acceptChannel <- connection
		acceptErrChannel <- acceptErr
	}()

	dialed, err = net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	accepted = <-acceptChannel
	err = errors.Join(err, <-acceptErrChannel, listener.Close())
	return
}

// struct cmsghdr with IPV6_PKTINFO and struct in6_pktinfo, as the kernel gives it with IPV6_RECVPKTINFO
func pktInfo6(address netip.Addr) (message []byte) {
	info := unix.Inet6Pktinfo{Addr: address.As16(), Ifindex: 1}
	message = unix.PktInfo6(&info)
	return
}
