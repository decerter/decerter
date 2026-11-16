// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/app"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/platform"
)

const (
	// what the peer client sends the http server, getRule makes it GET /test in the proxy
	peerRequest string = "GET / HTTP/1.1\r\nHost: decerter-e2e\r\nConnection: close\r\n\r\n"
	// how long the peer client waits for an answer
	peerReadTimeout time.Duration = 5 * time.Second
	// the packets of the snaplen case are cut to this many bytes, less than its request and its response
	smallSnaplen uint32 = 128
	// the path of the snaplen case, with it the request and the response are longer than smallSnaplen
	longPathLength int = 600
	// an administratively scoped group for the multicast case, routed to lo for the test
	multicastGroup string = "239.255.77.77"
)

// Test if a redirected app sees the destination it asked for, not the proxy: getpeername of a tcp and of a connected udp socket and the source of the answer
// to a sendto, over IPv4, native IPv6 and an IPv4-mapped destination on an IPv6 socket; and one unconnected udp socket reaches two destinations as two flows.
func TestRedirectAddressPositive(state *testing.T) {
	clientPath := copyClient(state)
	positiveCases := []struct {
		Name   string
		Host   string
		Client string
		Prefix netip.Prefix
	}{
		{Name: "ipv4", Host: "127.0.0.1", Client: "127.0.0.1", Prefix: netip.MustParsePrefix("127.0.0.1/32")},
		{Name: "ipv6", Host: "::1", Client: "::1", Prefix: netip.MustParsePrefix("::1/128")},
		// the app's socket is AF_INET6, the server and the flow are IPv4
		{Name: "ipv4-mapped", Host: "127.0.0.1", Client: "::ffff:127.0.0.1", Prefix: netip.MustParsePrefix("127.0.0.1/32")},
	}

	for _, positive := range positiveCases {
		state.Run(positive.Name, func(state *testing.T) {
			server := startServer(state, serverConfig{Host: positive.Host})
			tcpPort := serverPort(state, server)
			firstPort, firstReceived := startUDPEchoServerAt(state, net.JoinHostPort(positive.Host, "0"))
			secondPort, secondReceived := startUDPEchoServerAt(state, net.JoinHostPort(positive.Host, "0"))
			flags := testFlags()
			flags.DestinationCIDRs = []netip.Prefix{positive.Prefix}
			client := startFlagsAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{getRule{}}, flags, false)
			targets := []string{net.JoinHostPort(positive.Client, tcpPort), net.JoinHostPort(positive.Client, firstPort), net.JoinHostPort(positive.Client, secondPort)}
			output, err := runClientAs(state.Context(), testUser, clientPath, "peer", strings.Join(targets, ","))
			expected := fmt.Sprintf("tcp %s /test\nudp %s connect\nsendto %s sendto\nsendto %s sendto\n", targets[0], targets[1], targets[1], targets[2])

			if (err != nil) || (output != expected) {
				state.Fatalf("Test of the address restore failed, the client should see the destinations it asked for and the proxy's GET /test, expected:\n%soutput:\n%serror: %v", expected, output, err)
			}

			request, err := server.received()

			if (err != nil) || (request.Path != "/test") {
				state.Errorf("Test of the address restore failed, the server should get the rewritten request, request: %+v, error: %v", request, err)
				return
			}

			if got := []string{<-firstReceived, <-firstReceived, <-secondReceived}; strings.Join(got, " ") != "connect sendto sendto" {
				state.Errorf("Test of the address restore failed, the udp servers should get the three datagrams, got: %q", got)
				return
			}

			// one tcp flow, one udp flow of the connected socket, and one per destination of the unconnected socket
			flows := v1.FlowList{}
			status, err := client.call(state.Context(), http.MethodGet, "/flows", nil, &flows)
			counts := map[string]int{}

			for _, flow := range flows.Flows {
				_, port, splitErr := net.SplitHostPort(flow.Destination)

				if splitErr != nil {
					state.Fatalf("Test of the address restore failed, cannot read the destination %q, error: %s", flow.Destination, splitErr.Error())
				}

				counts[flow.Protocol+" "+port]++
			}

			if (err != nil) || (status != http.StatusOK) || (len(flows.Flows) != 4) || (counts["tcp "+tcpPort] != 1) || (counts["udp "+firstPort] != 2) || (counts["udp "+secondPort] != 1) {
				state.Errorf("Test of the address restore failed, the flows should be one tcp, two udp to port %s and one udp to port %s, flows: %+v, status: %d, error: %v", firstPort, secondPort, flows.Flows, status, err)
				return
			}
		})
	}
}

// Test if a process is selected by its tgid whatever its user is, while the same call of a user that is not selected stays as it is, and if decerter never
// redirects its own connections although its tgid is selected too.
func TestRedirectPIDPositive(state *testing.T) {
	server := startServer(state, serverConfig{})
	testCase := legacyCases(false, "/test")[0]
	// a shell of the other user that waits for a line and then becomes curl: the pid is known before the call is made
	commandCtx, cancel := context.WithTimeout(state.Context(), commandTimeout)
	defer cancel()
	arguments := append([]string{"-c", `read line && exec "$@"`, "sh", curlPath, "-q", "--silent", "--show-error", "--max-time", curlMaxTime}, curlArguments(testCase, server.URL)...)
	command := exec.CommandContext(commandCtx, "/bin/sh", arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: otherUser.UID, Gid: otherUser.GID, Groups: []uint32{}, NoSetGroups: false}}
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	stdin, err := command.StdinPipe()

	if err != nil {
		state.Fatalf("Could not make the stdin of the waiting curl, error: %s", err.Error())
	}

	err = command.Start()

	if err != nil {
		state.Fatalf("Could not start the waiting curl, error: %s", err.Error())
	}

	isWaited := false

	state.Cleanup(func() {
		if isWaited {
			return
		}

		cancel()

		if waitErr := command.Wait(); waitErr == nil {
			state.Errorf("The waiting curl should have been killed")
		}
	})

	flags := redirect.Filter{
		UIDs:             nil,
		Tgids:            []uint32{uint32(command.Process.Pid), uint32(os.Getpid())},
		DestinationCIDRs: []netip.Prefix{destinationPrefix},
		DestinationPorts: nil,
		Comms:            nil,
	}
	startFilteredDecerter(state, InterceptDecerterMode, "", []intercept.Rule{getRule{}}, flags, "")
	_, err = io.WriteString(stdin, "go\n")
	err = errors.Join(err, stdin.Close(), command.Wait())
	isWaited = true

	if (err != nil) || (stdout.String() != "/test") {
		state.Fatalf("Test of the pid selection failed, the call of the selected pid should be rewritten, output: %q, error: %v, stderr: %s", stdout.String(), err, stderr.String())
	}

	request, err := server.received()

	if (err != nil) || (request.Path != "/test") {
		state.Errorf("Test of the pid selection failed, the server should get the rewritten request, request: %+v, error: %v", request, err)
		return
	}

	// neither user is selected by its uid
	for _, runAs := range []account{otherUser, testUser} {
		output, curlErr := runCurl(state.Context(), runAs, curlArguments(testCase, server.URL))
		request, err = server.received()

		if (curlErr != nil) || (err != nil) || (output != "/") || (request.Path != "/") {
			state.Errorf("Test of the pid selection failed, the call of %s should stay as it is, output: %q, request: %+v, error: %v", runAs.Name, output, request, errors.Join(curlErr, err))
			return
		}
	}

	// decerter runs in this process: its tgid is selected, and still its own connection goes straight to the server
	httpClient := &http.Client{Timeout: commandTimeout}
	response, err := httpClient.Get(server.URL)

	if err != nil {
		state.Fatalf("Test of the pid selection failed, decerter's own process should reach the server, error: %s", err.Error())
	}

	body, err := io.ReadAll(response.Body)
	err = errors.Join(err, response.Body.Close())
	request, receivedErr := server.received()

	if (err != nil) || (receivedErr != nil) || (string(body) != "/") || (request.Path != "/") {
		state.Errorf("Test of the pid selection failed, decerter's own connection should not be redirected, body: %q, request: %+v, error: %v", body, request, errors.Join(err, receivedErr))
		return
	}
}

// Test if a selected process is left alone outside the selection: a destination outside --dst-cidr, a tcp port that is not in --dst-port while the
// udp port in it is redirected; and if --block-quic leaves udp 443 of a user that is not selected alone.
func TestRedirectSelectionNegative(state *testing.T) {
	clientPath := copyClient(state)
	server := startServer(state, serverConfig{})
	outside := startServer(state, serverConfig{Host: secondLoopback})
	selectedPort, selectedReceived := startUDPEchoServer(state)
	otherPort, otherReceived := startUDPEchoServer(state)
	_, quicReceived := startUDPEchoServerAt(state, net.JoinHostPort(destinationPrefix.Addr().String(), quicPort))
	selected, selectedErr := strconv.ParseUint(selectedPort, 10, 16)
	outsidePort, outsideErr := strconv.ParseUint(serverPort(state, outside), 10, 16)

	if err := errors.Join(selectedErr, outsideErr); err != nil {
		state.Fatalf("Could not read the ports of the servers, error: %s", err.Error())
	}

	flags := testFlags()
	flags.DestinationPorts = []redirect.DestinationPort{
		{Port: uint16(selected), IPProtocol: syscall.IPPROTO_UDP},
		// the port of the server outside 127.0.0.1/32: its port is in the selection, its address is not
		{Port: uint16(outsidePort), IPProtocol: syscall.IPPROTO_TCP},
	}
	client := startFlagsAPIDecerter(state, InterceptDecerterMode, []intercept.Rule{getRule{}}, flags, true)
	address := destinationPrefix.Addr().String()
	targets := []string{net.JoinHostPort(address, serverPort(state, server)), net.JoinHostPort(address, selectedPort), net.JoinHostPort(address, otherPort)}
	output, err := runClientAs(state.Context(), testUser, clientPath, "peer", strings.Join(targets, ","))
	expected := fmt.Sprintf("tcp %s /\nudp %s connect\nsendto %s sendto\nsendto %s sendto\n", targets[0], targets[1], targets[1], targets[2])

	if (err != nil) || (output != expected) {
		state.Fatalf("Test of the selection failed, the tcp call outside --dst-port should stay as it is, expected:\n%soutput:\n%serror: %v", expected, output, err)
	}

	if got := []string{<-selectedReceived, <-selectedReceived, <-otherReceived}; strings.Join(got, " ") != "connect sendto sendto" {
		state.Errorf("Test of the selection failed, the udp servers should get the three datagrams, got: %q", got)
		return
	}

	// the port matches, the address does not
	testCase := legacyCases(false, "/")[0]
	curlOutput, err := runCurl(state.Context(), testUser, curlArguments(testCase, outside.URL))
	request, receivedErr := outside.received()

	if (err != nil) || (receivedErr != nil) || (curlOutput != "/") || (request.Path != "/") {
		state.Errorf("Test of the selection failed, a call outside --dst-cidr should stay as it is, output: %q, request: %+v, error: %v", curlOutput, request, errors.Join(err, receivedErr))
		return
	}

	// udp 443 of the user that is not selected is not blocked
	quicOutput, err := runClientAs(state.Context(), otherUser, clientPath, "udp", net.JoinHostPort(address, quicPort))

	if (err != nil) || (quicOutput != "connect=ok:connect sendto=ok:sendto") {
		state.Errorf("Test of the selection failed, --block-quic should leave udp 443 of %s alone, output: %q, error: %v", otherUser.Name, quicOutput, err)
		return
	}

	if got := []string{<-quicReceived, <-quicReceived}; strings.Join(got, " ") != "connect sendto" {
		state.Errorf("Test of the selection failed, the udp 443 server should get both datagrams, got: %q", got)
		return
	}

	// only the two sockets to the udp port in --dst-port went through the proxy
	flows := v1.FlowList{}
	status, err := client.call(state.Context(), http.MethodGet, "/flows", nil, &flows)

	if (err != nil) || (status != http.StatusOK) || (len(flows.Flows) != 2) {
		state.Fatalf("Test of the selection failed, the proxy should have two flows, flows: %+v, status: %d, error: %v", flows.Flows, status, err)
	}

	for _, flow := range flows.Flows {
		if (flow.Protocol != "udp") || (flow.Destination != targets[1]) {
			state.Errorf("Test of the selection failed, the flows should be udp to %s, flow: %+v", targets[1], flow)
			return
		}
	}
}

// Test if --snaplen cuts the packets of a capture: no packet in the file has more than the snaplen, and the ones cut short keep their length on the wire.
func TestCaptureSnaplenPositive(state *testing.T) {
	tsharkPath, lookErr := exec.LookPath("tshark")

	if lookErr != nil {
		state.Skipf("tshark is not installed, error: %s", lookErr.Error())
	}

	capturePath := filepath.Join(state.TempDir(), "snaplen.pcapng")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	decerter := app.New(context.Background(), testFlags(), nil, proxyPort, udpIdleTimeout, false, false, false, false, nil, "", apiHoldTimeout, apiAssemblyTimeout, "", true, capturePath, false, smallSnaplen, platform.Detect("/"), logger)
	stop := startApp(state, &decerter, CaptureDecerterMode)
	server := startServer(state, serverConfig{})
	path := "/" + strings.Repeat("a", longPathLength)
	output, err := runCurl(state.Context(), testUser, []string{"--http1.1", strings.TrimSuffix(server.URL, "/") + path})

	if (err != nil) || (output != path) {
		state.Fatalf("Test of the snaplen failed, capture mode should change nothing, output: %q, error: %v", output, err)
	}

	err = stop()

	if err != nil {
		state.Fatalf("Could not stop decerter, error: %s", err.Error())
	}

	lengths, err := runCommandTimeout(state.Context(), tsharkTimeout, tsharkPath, "-n", "-r", capturePath, "-Y", "tcp.port == "+serverPort(state, server), "-T", "fields", "-E", "separator=,", "-e", "frame.len", "-e", "frame.cap_len")

	if err != nil {
		state.Fatalf("Test of the snaplen failed, cannot read the capture, error: %s", err.Error())
	}

	packets, cut := 0, 0

	for line := range strings.Lines(lengths) {
		wireText, capturedText, _ := strings.Cut(strings.TrimSpace(line), ",")
		wire, wireErr := strconv.Atoi(wireText)
		captured, capturedErr := strconv.Atoi(capturedText)

		if (wireErr != nil) || (capturedErr != nil) || (captured > int(smallSnaplen)) || (captured > wire) {
			state.Errorf("Test of the snaplen failed, a packet should have at most %d bytes in the file, line: %q", smallSnaplen, line)
			return
		}

		packets++

		if wire > captured {
			cut++
		}
	}

	// the request and the response each have a packet longer than the snaplen
	if (packets == 0) || (cut < 2) {
		state.Errorf("Test of the snaplen failed, the long packets should be cut short and keep their length, packets: %d, cut: %d, lengths:\n%s", packets, cut, lengths)
		return
	}
}

// Test if a capture counts the packets it lost: decerter capture is stopped with SIGSTOP while the test user downloads more than packet_map holds, and
// reports the dropped packets once it runs again; the file is still a capture tshark reads.
func TestCaptureDropPositive(state *testing.T) {
	tsharkPath, lookErr := exec.LookPath("tshark")

	if lookErr != nil {
		state.Skipf("tshark is not installed, error: %s", lookErr.Error())
	}

	capturePath := filepath.Join(state.TempDir(), "drop.pcapng")
	bulk := startBulkServer(state)
	command, _, logs, stop := startDecerterProcess(state, []string{"Recording flows"}, "capture", "--uid", strconv.FormatUint(uint64(testUser.UID), 10), "--dst-cidr", destinationPrefix.String(), "--write", capturePath)
	err := command.Process.Signal(syscall.SIGSTOP)

	if err != nil {
		state.Fatalf("Could not stop decerter capture with SIGSTOP, error: %s", err.Error())
	}

	// the programs go on without their reader: the body is twice the ring
	_, curlErr := runCurl(state.Context(), testUser, []string{"--output", "/dev/null", bulk})
	err = command.Process.Signal(syscall.SIGCONT)

	if (err != nil) || (curlErr != nil) {
		state.Fatalf("Test of the dropped packets failed, the download should finish while decerter is stopped and decerter should go on, error: %v", errors.Join(curlErr, err))
	}

	err = stop()

	if err != nil {
		state.Fatalf("Could not stop decerter, error: %s", err.Error())
	}

	if !strings.Contains(logs.String(), "Dropped packets, packet_map was full") {
		state.Errorf("Test of the dropped packets failed, decerter should report the packets packet_map had no room for, logs:\n%s", logs.String())
		return
	}

	ports, err := capturedPorts(state.Context(), tsharkPath, capturePath)

	if (err != nil) || !ports[serverPortOf(testServer{URL: bulk})] {
		state.Errorf("Test of the dropped packets failed, the file should have the packets that fit, ports: %v, error: %v", ports, err)
		return
	}
}

// Test if decerter run stops by itself when its stdout is a pipe whose reader is gone, as with decerter run | head after head exited: the flow line of a
// relayed flow fails with EPIPE instead of a SIGPIPE that kills decerter, and decerter then runs its normal shutdown and exits with 0, without an interrupt.
func TestRunClosedStdoutPositive(state *testing.T) {
	reader, writer, err := os.Pipe()

	if err != nil {
		state.Fatalf("Could not make a pipe, error: %s", err.Error())
	}

	err = reader.Close()

	if err != nil {
		state.Fatalf("Could not close the reader of the pipe, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if closeErr := writer.Close(); closeErr != nil {
			state.Errorf("Could not close the writer of the pipe, error: %s", closeErr.Error())
		}
	})

	server := startServer(state, serverConfig{})
	command, _, logs, stop := startDecerterProcessTo(state, writer, nil, []string{"Redirecting flows"}, "run", "--uid", strconv.FormatUint(uint64(testUser.UID), 10), "--dst-cidr", destinationPrefix.String())
	output, curlErr := runCurl(state.Context(), testUser, []string{server.URL + "pipe"})

	if (curlErr != nil) || (output != "/pipe") {
		state.Fatalf("Test of a closed stdout failed, the flow should be relayed, output: %q, error: %v, logs:\n%s", output, curlErr, logs.String())
	}

	// the flow line is written once the proxy saw both sides close, decerter exits after its shutdown
	if !hasExited(command.Process.Pid, 15*time.Second) {
		state.Fatalf("Test of a closed stdout failed, decerter should stop after its flow line failed, logs:\n%s", logs.String())
	}

	err = stop()

	if (err != nil) || !strings.Contains(logs.String(), "Stdout reader went away, stopping") || strings.Contains(logs.String(), "Got shutdown signal") || strings.Contains(logs.String(), `"level":"ERROR"`) {
		state.Errorf("Test of a closed stdout failed, decerter should stop cleanly by itself, error: %v, logs:\n%s", err, logs.String())
		return
	}
}

// true once the process is gone or a zombie that waits for its parent, false after timeout
func hasExited(pid int, timeout time.Duration) (isExited bool) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		stat, readErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))

		// the state follows the comm in parentheses
		if (readErr != nil) || strings.Contains(string(stat[bytes.LastIndexByte(stat, ')')+1:]), " Z ") {
			isExited = true
			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	return
}

// Test if a datagram to a multicast group is never redirected, one upstream socket of the proxy could not relay it: the group gets it straight from
// the app and the proxy has no flow, although the group is in --dst-cidr and has a route. The datagram is sent with sendto: a connected udp socket
// does not reach a group routed to lo, with or without decerter.
func TestRedirectMulticastNegative(state *testing.T) {
	group := netip.MustParseAddr(multicastGroup)
	addRoute(state, netip.PrefixFrom(group, 32).String(), "dev", "lo")
	loopback, err := net.InterfaceByName("lo")

	if err != nil {
		state.Fatalf("Could not find the loopback interface, error: %s", err.Error())
	}

	connection, err := net.ListenMulticastUDP("udp4", loopback, &net.UDPAddr{IP: group.AsSlice(), Port: 0})

	if err != nil {
		state.Fatalf("Could not join the multicast group, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if closeErr := connection.Close(); closeErr != nil {
			state.Errorf("Could not leave the multicast group, error: %s", closeErr.Error())
		}
	})

	flags := testFlags()
	flags.DestinationCIDRs = []netip.Prefix{netip.PrefixFrom(group, 32), destinationPrefix}
	client := startFlagsAPIDecerter(state, RelayDecerterMode, nil, flags, false)
	target := netip.AddrPortFrom(group, connection.LocalAddr().(*net.UDPAddr).AddrPort().Port()).String()
	output, err := runClientAs(state.Context(), testUser, copyClient(state), "send", target)

	if (err != nil) || (output != "sent") {
		state.Fatalf("Test of a multicast destination failed, the client should send its datagram, output: %q, error: %v", output, err)
	}

	buffer := make([]byte, 1500)
	err = connection.SetReadDeadline(time.Now().Add(commandTimeout))

	if err != nil {
		state.Fatalf("Test of a multicast destination failed, cannot set the read deadline, error: %s", err.Error())
	}

	count, _, err := connection.ReadFrom(buffer)

	if (err != nil) || (string(buffer[:count]) != "sendto") {
		state.Fatalf("Test of a multicast destination failed, the group should get the datagram, got: %q, error: %v", buffer[:count], err)
	}

	flows := v1.FlowList{}
	status, err := client.call(state.Context(), http.MethodGet, "/flows", nil, &flows)

	if (err != nil) || (status != http.StatusOK) || (len(flows.Flows) != 0) {
		state.Errorf("Test of a multicast destination failed, the proxy should have no flow, flows: %+v, status: %d, error: %v", flows.Flows, status, err)
		return
	}
}

// Test if a udp datagram to a destination under an unreachable route fails with EHOSTUNREACH as it does without decerter, at connect and at sendto, and
// nothing reaches the proxy, while a destination with a route under the same --dst-cidr is redirected.
func TestRouteUDPNegative(state *testing.T) {
	// the servers listen before the route makes 127.0.0.2 unreachable for them too
	unroutedPort, unroutedReceived := startUDPEchoServerAt(state, net.JoinHostPort(secondLoopback, "0"))
	routedPort, routedReceived := startUDPEchoServer(state)
	addRoute(state, "unreachable", routePrefix)
	flags := testFlags()
	flags.DestinationCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	client := startFlagsAPIDecerter(state, RelayDecerterMode, nil, flags, false)
	clientPath := copyClient(state)
	output, err := runGoClient(state.Context(), clientPath, "udp", net.JoinHostPort(secondLoopback, unroutedPort))

	if (err != nil) || (strings.Count(output, "no_route_to_host") != 2) {
		state.Errorf("Test of an unrouted udp destination failed, connect and sendto should fail with EHOSTUNREACH, output: %q, error: %v", output, err)
		return
	}

	routed := net.JoinHostPort(destinationPrefix.Addr().String(), routedPort)
	output, err = runGoClient(state.Context(), clientPath, "udp", routed)

	if (err != nil) || (output != "connect=ok:connect sendto=ok:sendto") {
		state.Errorf("Test of an unrouted udp destination failed, a destination with a route should be relayed, output: %q, error: %v", output, err)
		return
	}

	if got := []string{<-routedReceived, <-routedReceived}; strings.Join(got, " ") != "connect sendto" {
		state.Errorf("Test of an unrouted udp destination failed, the routed server should get both datagrams, got: %q", got)
		return
	}

	select {
	case datagram := <-unroutedReceived:
		state.Errorf("Test of an unrouted udp destination failed, the unrouted server got %q", datagram)
		return
	default:
	}

	flows := v1.FlowList{}
	status, err := client.call(state.Context(), http.MethodGet, "/flows", nil, &flows)

	if (err != nil) || (status != http.StatusOK) || (len(flows.Flows) != 2) {
		state.Fatalf("Test of an unrouted udp destination failed, the proxy should have the two flows of the routed destination, flows: %+v, status: %d, error: %v", flows.Flows, status, err)
	}

	for _, flow := range flows.Flows {
		if flow.Destination != routed {
			state.Errorf("Test of an unrouted udp destination failed, the flows should go to %s, flow: %+v", routed, flow)
			return
		}
	}
}

// ip route add with the arguments given, the route is deleted when the test ends
func addRoute(state *testing.T, arguments ...string) {
	_, err := runCommand(state.Context(), "ip", append([]string{"route", "add"}, arguments...)...)

	if err != nil {
		state.Fatalf("Could not add the route, error: %s", err.Error())
	}

	state.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()

		if _, deleteErr := runCommand(ctx, "ip", append([]string{"route", "del"}, arguments...)...); deleteErr != nil {
			state.Errorf("Could not delete the route, error: %s", deleteErr.Error())
		}
	})
}

// startBlockingAPIDecerter with the flags given
func startFlagsAPIDecerter(state *testing.T, mode decerterMode, rules []intercept.Rule, flags redirect.Filter, blockQuic bool) (client apiClient) {
	socket := filepath.Join(state.TempDir(), "api.sock")
	decerter := newBlockingDecerter(state, mode, "", rules, flags, "", socket, blockQuic)
	startApp(state, &decerter, mode)
	client = socketClient(socket)
	return
}

// a client of the API on the unix socket of a decerter
func socketClient(socket string) (client apiClient) {
	client = apiClient{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					dialer := net.Dialer{}
					return dialer.DialContext(ctx, "unix", socket)
				},
			},
		},
		socket: socket,
	}
	return
}

// runGoClient as the user given
func runClientAs(ctx context.Context, runAs account, path string, mode string, target string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, path, target)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: runAs.UID, Gid: runAs.GID, Groups: []uint32{}, NoSetGroups: false}}
	command.Dir = "/"
	command.Env = []string{clientCommandEnvironment + "=" + mode, "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()

	if err != nil {
		err = fmt.Errorf("go client %s %s as %s: %w: %s", mode, target, runAs.Name, err, strings.TrimSpace(stderr.String()))
		return
	}

	output = stdout.String()
	return
}

// the test user's client of the redirect cases, targets are the address of an http server and of one or more udp echo servers, comma separated
// it prints what an app sees of its peers, one line each: the peer of a tcp connection and the body the server answered, the peer of a connected udp
// socket and its echo, and for every udp server the source of the answer to a sendto on one unconnected socket and its echo
// the sockets are made with the family of the address as it is written, so an IPv4-mapped address goes out of an IPv6 socket, which the net package never does
func reportPeers(targets string) (output string, err error) {
	addresses := []netip.AddrPort{}

	for target := range strings.SplitSeq(targets, ",") {
		address, parseErr := netip.ParseAddrPort(target)

		if err = parseErr; err != nil {
			return
		}

		addresses = append(addresses, address)
	}

	if len(addresses) < 2 {
		err = fmt.Errorf("usage: the address of the http server and of the udp servers, comma separated: %q", targets)
		return
	}

	builder := strings.Builder{}
	peer, body, err := exchangeTCP(addresses[0])

	if err != nil {
		err = fmt.Errorf("tcp %s: %w", addresses[0], err)
		return
	}

	fmt.Fprintf(&builder, "tcp %s %s\n", peer, body)
	peer, echo, err := exchangeConnected(addresses[1])

	if err != nil {
		err = fmt.Errorf("udp %s: %w", addresses[1], err)
		return
	}

	fmt.Fprintf(&builder, "udp %s %s\n", peer, echo)
	descriptor, _, err := peerSocket(addresses[1], syscall.SOCK_DGRAM)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, syscall.Close(descriptor))
	}()

	for _, address := range addresses[1:] {
		_, sockaddr := sockaddrOf(address)
		err = syscall.Sendto(descriptor, []byte("sendto"), 0, sockaddr)

		if err != nil {
			err = fmt.Errorf("sendto %s: %w", address, err)
			return
		}

		buffer := make([]byte, 1500)
		count, source, receiveErr := syscall.Recvfrom(descriptor, buffer, 0)

		if err = receiveErr; err != nil {
			err = fmt.Errorf("recvfrom %s: %w", address, err)
			return
		}

		fmt.Fprintf(&builder, "sendto %s %s\n", sockaddrText(source), buffer[:count])
	}

	output = builder.String()
	return
}

// one datagram with sendto on an unconnected socket, no answer is read; SO_BROADCAST lets it go to a broadcast address
func sendDatagram(target string) (output string, err error) {
	address, err := netip.ParseAddrPort(target)

	if err != nil {
		return
	}

	descriptor, sockaddr, err := peerSocket(address, syscall.SOCK_DGRAM)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, syscall.Close(descriptor))
	}()

	err = syscall.SetsockoptInt(descriptor, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)

	if err != nil {
		return
	}

	err = syscall.Sendto(descriptor, []byte("sendto"), 0, sockaddr)
	output = "sent"
	return
}

// connect to the http server, ask what getpeername says and send peerRequest; body is the body of the answer
func exchangeTCP(address netip.AddrPort) (peer string, body string, err error) {
	descriptor, sockaddr, err := peerSocket(address, syscall.SOCK_STREAM)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, syscall.Close(descriptor))
	}()

	err = syscall.Connect(descriptor, sockaddr)

	if err != nil {
		return
	}

	name, err := syscall.Getpeername(descriptor)

	if err != nil {
		return
	}

	peer = sockaddrText(name)
	_, err = syscall.Write(descriptor, []byte(peerRequest))

	if err != nil {
		return
	}

	response := []byte{}
	buffer := make([]byte, 4096)

	for {
		count, readErr := syscall.Read(descriptor, buffer)

		if err = readErr; err != nil {
			return
		}

		if count == 0 {
			break
		}

		response = append(response, buffer[:count]...)
	}

	_, body, _ = strings.Cut(string(response), "\r\n\r\n")
	return
}

// connect a udp socket to the echo server, ask what getpeername says and send one datagram; echo is the answer
func exchangeConnected(address netip.AddrPort) (peer string, echo string, err error) {
	descriptor, sockaddr, err := peerSocket(address, syscall.SOCK_DGRAM)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, syscall.Close(descriptor))
	}()

	err = syscall.Connect(descriptor, sockaddr)

	if err != nil {
		return
	}

	name, err := syscall.Getpeername(descriptor)

	if err != nil {
		return
	}

	peer = sockaddrText(name)
	_, err = syscall.Write(descriptor, []byte("connect"))

	if err != nil {
		return
	}

	buffer := make([]byte, 1500)
	count, err := syscall.Read(descriptor, buffer)

	if err != nil {
		return
	}

	echo = string(buffer[:count])
	return
}

// a socket of the family of the address with a receive timeout, kind is SOCK_STREAM or SOCK_DGRAM; sockaddr is the address for connect and sendto
func peerSocket(address netip.AddrPort, kind int) (descriptor int, sockaddr syscall.Sockaddr, err error) {
	family, sockaddr := sockaddrOf(address)
	descriptor, err = syscall.Socket(family, kind|syscall.SOCK_CLOEXEC, 0)

	if err != nil {
		return
	}

	timeout := syscall.NsecToTimeval(int64(peerReadTimeout))
	err = syscall.SetsockoptTimeval(descriptor, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)

	if err != nil {
		err = errors.Join(err, syscall.Close(descriptor))
	}

	return
}

// an IPv4 address is AF_INET, anything else AF_INET6, an IPv4-mapped address too
func sockaddrOf(address netip.AddrPort) (family int, sockaddr syscall.Sockaddr) {
	if address.Addr().Is4() {
		family = syscall.AF_INET
		sockaddr = &syscall.SockaddrInet4{Port: int(address.Port()), Addr: address.Addr().As4()}
		return
	}

	family = syscall.AF_INET6
	sockaddr = &syscall.SockaddrInet6{Port: int(address.Port()), ZoneId: 0, Addr: address.Addr().As16()}
	return
}

// an address of the kernel as the tests write it
func sockaddrText(sockaddr syscall.Sockaddr) (text string) {
	switch typed := sockaddr.(type) {
	case *syscall.SockaddrInet4:
		text = netip.AddrPortFrom(netip.AddrFrom4(typed.Addr), uint16(typed.Port)).String()
	case *syscall.SockaddrInet6:
		text = netip.AddrPortFrom(netip.AddrFrom16(typed.Addr), uint16(typed.Port)).String()
	default:
		text = fmt.Sprintf("%v", sockaddr)
	}

	return
}
