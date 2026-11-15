// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/intercept"
)

const (
	// the fwmark the mark client sets on its socket, as netd sets the mark of the app's network on Android
	testMark int = 0x2a
	// a released redirected UDP flow lives releaseDelay + releaseSweep after the close, app.go, this is that with room for a slow runner
	releaseTimeout time.Duration = 10 * time.Second
)

// Test if a datagram to a broadcast address is never redirected, one upstream socket of the proxy could not relay it: the limited broadcast with a
// route to lo and the directed broadcast of lo reach a server on the wildcard address straight from the app, and the proxy has no flow, although
// both are in --dst-cidr.
func TestRedirectBroadcastNegative(state *testing.T) {
	addRoute(state, "255.255.255.255/32", "dev", "lo")
	flags := testFlags()
	flags.DestinationCIDRs = []netip.Prefix{netip.MustParsePrefix("255.255.255.255/32"), netip.MustParsePrefix("127.0.0.0/8")}
	client := startFlagsAPIDecerter(state, RelayDecerterMode, nil, flags, false)
	clientPath := copyClient(state)
	negativeCases := []struct {
		Name    string
		Address string
	}{
		{Name: "limited", Address: "255.255.255.255"},
		{Name: "directed", Address: "127.255.255.255"},
	}

	for _, negative := range negativeCases {
		state.Run(negative.Name, func(state *testing.T) {
			port, received := startUDPEchoServerAt(state, "0.0.0.0:0")
			output, err := runClientAs(state.Context(), testUser, clientPath, "send", net.JoinHostPort(negative.Address, port))

			if (err != nil) || (output != "sent") {
				state.Fatalf("Test of a broadcast destination failed, the client should send its datagram, output: %q, error: %v", output, err)
			}

			select {
			case datagram := <-received:
				if datagram != "sendto" {
					state.Fatalf("Test of a broadcast destination failed, the server should get the datagram, got: %q", datagram)
				}
			case <-time.After(commandTimeout):
				state.Fatalf("Test of a broadcast destination failed, the server got no datagram in %s", commandTimeout)
			}

			flows := v1.FlowList{}
			status, err := client.call(state.Context(), http.MethodGet, "/flows", nil, &flows)

			if (err != nil) || (status != http.StatusOK) || (len(flows.Flows) != 0) {
				state.Errorf("Test of a broadcast destination failed, the proxy should have no flow, flows: %+v, status: %d, error: %v", flows.Flows, status, err)
				return
			}
		})
	}
}

// Test if a ping socket of a selected process is left as it is, the proxy relays only TCP and UDP: the connected and the unconnected socket get the
// echo reply from the address they pinged, over IPv4 and IPv6, and the proxy has no flow.
func TestRedirectPingNegative(state *testing.T) {
	flags := testFlags()
	flags.DestinationCIDRs = []netip.Prefix{destinationPrefix, netip.MustParsePrefix("::1/128")}
	client := startFlagsAPIDecerter(state, RelayDecerterMode, nil, flags, false)
	clientPath := copyClient(state)

	for _, address := range []string{"127.0.0.1", "::1"} {
		output, err := runClientAs(state.Context(), testUser, clientPath, "ping", address)
		peer := netip.AddrPortFrom(netip.MustParseAddr(address), 0).String()
		expected := fmt.Sprintf("connect %s reply\nsendto %s reply\n", peer, peer)

		if (err != nil) || (output != expected) {
			state.Fatalf("Test of a ping socket failed, both sockets should get the echo reply of %s, expected:\n%soutput:\n%serror: %v", address, expected, output, err)
		}
	}

	flows := v1.FlowList{}
	status, err := client.call(state.Context(), http.MethodGet, "/flows", nil, &flows)

	if (err != nil) || (status != http.StatusOK) || (len(flows.Flows) != 0) {
		state.Errorf("Test of a ping socket failed, the proxy should have no flow, flows: %+v, status: %d, error: %v", flows.Flows, status, err)
		return
	}
}

// Test if the fwmark of a redirected socket is set on the proxy's upstream socket, as netd sets the mark of the app's network on Android before
// connect: the mark client sets it with SO_MARK, which needs CAP_NET_ADMIN, and ss shows it on the upstream connection to the server.
func TestRedirectMarkPositive(state *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		state.Fatalf("Could not listen for the mark server, error: %s", err.Error())
	}

	connectionChannel := make(chan net.Conn, 1)

	// mark server, keeps the connection open until the test has looked at it
	go func() {
		connection, acceptErr := listener.Accept()

		if acceptErr != nil {
			close(connectionChannel)
			return
		}

		connectionChannel <- connection
	}()

	state.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil {
			state.Errorf("Could not close the mark server, error: %s", closeErr.Error())
		}
	})

	_, port, err := net.SplitHostPort(listener.Addr().String())

	if err != nil {
		state.Fatalf("Could not read the port of the mark server, error: %s", err.Error())
	}

	startFlagsAPIDecerter(state, RelayDecerterMode, nil, testFlags(), false)
	commandCtx, cancel := context.WithTimeout(state.Context(), commandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, copyClient(state), listener.Addr().String())
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: testUser.UID, Gid: testUser.GID, Groups: []uint32{}, NoSetGroups: false}, AmbientCaps: []uintptr{unix.CAP_NET_ADMIN}}
	command.Dir = "/"
	command.Env = []string{clientCommandEnvironment + "=mark", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Start()

	if err != nil {
		state.Fatalf("Could not start the mark client, error: %s", err.Error())
	}

	connection, isOpen := <-connectionChannel

	if !isOpen {
		state.Fatalf("Test of the socket mark failed, the server got no connection, client: %s", stderr.String())
	}

	line, err := bufio.NewReader(connection).ReadString('\n')

	if (err != nil) || (line != "marked\n") {
		state.Fatalf("Test of the socket mark failed, the server should get the client's line, line: %q, error: %v", line, err)
	}

	// the only established socket with the server's port as its destination is the proxy's upstream socket, the client's goes to the proxy
	sockets, ssErr := runCommand(state.Context(), "ss", "-Htne", "state", "established", "dst", "127.0.0.1", "dport", "=", ":"+port)
	closeErr := connection.Close()
	waitErr := command.Wait()

	if (ssErr != nil) || (strings.Count(sockets, "\n") != 1) || !strings.Contains(sockets, fmt.Sprintf("fwmark:%#x", testMark)) {
		state.Errorf("Test of the socket mark failed, the upstream socket should have fwmark %#x, sockets: %q, error: %v", testMark, sockets, ssErr)
		return
	}

	if (closeErr != nil) || (waitErr != nil) || (stdout.String() != "closed") {
		state.Errorf("Test of the socket mark failed, the client should see the server close, output: %q, close error: %v, error: %v: %s", stdout.String(), closeErr, waitErr, stderr.String())
		return
	}
}

// Test if flow_map and client_map are empty again once the sockets of a selected process are closed: a TCP connection, a connected and an
// unconnected UDP socket and a ping socket, the released UDP flows stay until the release sweep removes them.
func TestRedirectReleasePositive(state *testing.T) {
	before := map[string][]ebpf.MapID{}

	for _, name := range []string{"flow_map", "client_map"} {
		before[name] = mapIDs(state, name)
	}

	server := startServer(state, serverConfig{})
	tcpPort := serverPort(state, server)
	udpPort, received := startUDPEchoServer(state)
	startFlagsAPIDecerter(state, RelayDecerterMode, []intercept.Rule{}, testFlags(), false)
	decerterMaps := map[string]*ebpf.Map{}

	// the maps of this decerter are the ones that were not there before it started
	for _, name := range []string{"flow_map", "client_map"} {
		for _, id := range mapIDs(state, name) {
			if !slices.Contains(before[name], id) {
				decerterMaps[name] = openMap(state, id)
			}
		}

		if decerterMaps[name] == nil {
			state.Fatalf("Test of the released flows failed, no %s of this decerter, before: %v", name, before[name])
		}
	}

	clientPath := copyClient(state)
	target := net.JoinHostPort("127.0.0.1", udpPort)
	_, err := runClientAs(state.Context(), testUser, clientPath, "peer", net.JoinHostPort("127.0.0.1", tcpPort)+","+target)

	if err != nil {
		state.Fatalf("Test of the released flows failed, the peer client should reach the servers, error: %s", err.Error())
	}

	_, err = runClientAs(state.Context(), testUser, clientPath, "ping", "127.0.0.1")

	if err != nil {
		state.Fatalf("Test of the released flows failed, the ping client should get its replies, error: %s", err.Error())
	}

	if got := []string{<-received, <-received}; strings.Join(got, " ") != "connect sendto" {
		state.Fatalf("Test of the released flows failed, the udp server should get both datagrams, got: %q", got)
	}

	// the released udp flows wait for the sweep, so the map is not empty yet: this checks that the test looks at the right map
	count, err := countEntries(decerterMaps["flow_map"])

	if (err != nil) || (count == 0) {
		state.Fatalf("Test of the released flows failed, flow_map should still have the released udp flows, entries: %d, error: %v", count, err)
	}

	deadline := time.Now().Add(releaseTimeout)
	counts := map[string]int{}

	for time.Now().Before(deadline) {
		for name, decerterMap := range decerterMaps {
			counts[name], err = countEntries(decerterMap)

			if err != nil {
				state.Fatalf("Test of the released flows failed, cannot read %s, error: %s", name, err.Error())
			}
		}

		if (counts["flow_map"] == 0) && (counts["client_map"] == 0) {
			return
		}

		time.Sleep(100 * time.Millisecond)
	}

	state.Errorf("Test of the released flows failed, flow_map and client_map should be empty %s after the close, entries: %v", releaseTimeout, counts)
}

// the ids of the maps with the name given the kernel has now
func mapIDs(state *testing.T, name string) (ids []ebpf.MapID) {
	id := ebpf.MapID(0)

	for {
		next, err := ebpf.MapGetNextID(id)

		if errors.Is(err, os.ErrNotExist) {
			return
		}

		if err != nil {
			state.Fatalf("Could not list the bpf maps, error: %s", err.Error())
		}

		id = next
		bpfMap, err := ebpf.NewMapFromID(id)

		// a map can go away between the two calls
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			state.Fatalf("Could not open the bpf map %d, error: %s", id, err.Error())
		}

		info, infoErr := bpfMap.Info()
		closeErr := bpfMap.Close()

		if err = errors.Join(infoErr, closeErr); err != nil {
			state.Fatalf("Could not read the bpf map %d, error: %s", id, err.Error())
		}

		if info.Name == name {
			ids = append(ids, id)
		}
	}
}

// a bpf map by its id, closed when the test ends
func openMap(state *testing.T, id ebpf.MapID) (bpfMap *ebpf.Map) {
	bpfMap, err := ebpf.NewMapFromID(id)

	if err != nil {
		state.Fatalf("Could not open the bpf map %d, error: %s", id, err.Error())
	}

	state.Cleanup(func() {
		if closeErr := bpfMap.Close(); closeErr != nil {
			state.Errorf("Could not close the bpf map %d, error: %s", id, closeErr.Error())
		}
	})

	return
}

// the number of entries of a hash map
func countEntries(bpfMap *ebpf.Map) (count int, err error) {
	key := make([]byte, bpfMap.KeySize())
	value := make([]byte, bpfMap.ValueSize())
	iterator := bpfMap.Iterate()

	for iterator.Next(key, value) {
		count++
	}

	err = iterator.Err()
	return
}

// the test user's ping client of one address: an unprivileged ICMP socket that is connected and one that sends with sendto, it prints the source
// of the echo reply each gets
func pingAddress(target string) (output string, err error) {
	address, err := netip.ParseAddr(target)

	if err != nil {
		return
	}

	family, protocol, request, reply := syscall.AF_INET, syscall.IPPROTO_ICMP, byte(8), byte(0)

	if address.Is6() {
		family, protocol, request, reply = syscall.AF_INET6, syscall.IPPROTO_ICMPV6, byte(128), byte(129)
	}

	builder := strings.Builder{}

	for _, isConnected := range []bool{true, false} {
		line, pingErr := pingOnce(family, protocol, netip.AddrPortFrom(address, 0), isConnected, []byte{request, 0, 0, 0, 0, 0, 0, 1, 'b', 'i', 't', 'm'}, reply)

		if err = pingErr; err != nil {
			return
		}

		builder.WriteString(line)
	}

	output = builder.String()
	return
}

// one echo request on a new ping socket, the kernel fills the identifier and the checksum
func pingOnce(family int, protocol int, address netip.AddrPort, isConnected bool, message []byte, reply byte) (line string, err error) {
	descriptor, err := syscall.Socket(family, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, protocol)

	if err != nil {
		err = fmt.Errorf("ping socket: %w", err)
		return
	}

	defer func() {
		err = errors.Join(err, syscall.Close(descriptor))
	}()

	timeout := syscall.NsecToTimeval(int64(peerReadTimeout))
	err = syscall.SetsockoptTimeval(descriptor, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)

	if err != nil {
		return
	}

	_, sockaddr := sockaddrOf(address)
	line = "sendto "

	// getpeername of a ping socket is ENOTCONN, it has no destination port, so both sockets report the source of the reply
	if isConnected {
		err = syscall.Connect(descriptor, sockaddr)

		if err != nil {
			return
		}

		_, err = syscall.Write(descriptor, message)
		line = "connect "
	} else {
		err = syscall.Sendto(descriptor, message, 0, sockaddr)
	}

	if err != nil {
		return
	}

	buffer := make([]byte, 1500)
	count, source, err := syscall.Recvfrom(descriptor, buffer, 0)

	if err != nil {
		return
	}

	line += sockaddrText(source)

	if (count < len(message)) || (buffer[0] != reply) || !bytes.Equal(buffer[8:count], message[8:]) {
		err = fmt.Errorf("not an echo reply: %x", buffer[:count])
		return
	}

	line += " reply\n"
	return
}

// the test user's mark client: connect to the server with SO_MARK, send one line and wait until the server closes
func connectMarked(target string) (output string, err error) {
	address, err := netip.ParseAddrPort(target)

	if err != nil {
		return
	}

	descriptor, sockaddr, err := peerSocket(address, syscall.SOCK_STREAM)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, syscall.Close(descriptor))
	}()

	err = syscall.SetsockoptInt(descriptor, syscall.SOL_SOCKET, syscall.SO_MARK, testMark)

	if err != nil {
		err = fmt.Errorf("SO_MARK: %w", err)
		return
	}

	err = syscall.Connect(descriptor, sockaddr)

	if err != nil {
		return
	}

	_, err = syscall.Write(descriptor, []byte("marked\n"))

	if err != nil {
		return
	}

	buffer := make([]byte, 64)

	for {
		count, readErr := syscall.Read(descriptor, buffer)

		if err = readErr; err != nil {
			return
		}

		if count == 0 {
			break
		}
	}

	output = "closed"
	return
}
