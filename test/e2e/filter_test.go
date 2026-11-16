// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/app"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/intercept"
)

const (
	// the server name the curl calls of the tls.sni cases send, and one that is not in the filter
	filterServerName string = "curl.decerter.test"
	otherServerName  string = "other.decerter.test"
)

// the servers of a filter case: two plain HTTP and two TLS 1.3 servers, so every call can have a port of its own
type filterServers struct {
	PlainA testServer
	PlainB testServer
	TLSA   testServer
	TLSB   testServer
}

// one client call of a filter case: Tool is curl or wget, ServerName the name curl sends in its ClientHello (empty sends none), Arguments go before the URL
// Expected is the path the server must see, /test when decerter intercepted the call
type filterCall struct {
	Name       string
	Tool       string
	RunAs      account
	Server     testServer
	ServerName string
	Arguments  []string
	Expected   string
}

// one decerter run with a --filter: Filter can use the ports of the servers, Flags are the selection flags next to it
type filterCase struct {
	Name   string
	Flags  redirect.Filter
	Filter string
	Calls  []filterCall
}

// Test if a flow in scope of the --filter is intercepted and a flow out of scope reaches its server unchanged, for filters decided in the kernel and in Go.
func TestFilterPositive(state *testing.T) {
	wgetPath, lookErr := exec.LookPath("wget")

	if lookErr != nil {
		state.Skipf("wget is not installed, error: %s", lookErr.Error())
	}

	servers := startFilterServers(state)
	onlyCIDR := testFlags()
	onlyCIDR.UIDs = nil

	for _, positive := range filterCases(servers, onlyCIDR) {
		state.Run(positive.Name, func(state *testing.T) {
			startFilteredDecerter(state, InterceptDecerterMode, "", []intercept.Rule{getRule{}}, positive.Flags, positive.Filter)

			for _, call := range positive.Calls {
				err := testFilterCall(state.Context(), wgetPath, call)

				if err != nil {
					state.Errorf("Test of the filter failed, case: %s, filter: %s, call: %s, error: %s", positive.Name, positive.Filter, call.Name, err.Error())
				}
			}
		})
	}
}

// Test if the --filter decides a DTLS session in Go when the session starts, with the ClientHello of its first datagram.
func TestFilterDTLSPositive(state *testing.T) {
	positiveCases := []struct {
		Filter   string
		Expected string
	}{
		{Filter: "udp && tls && !(proc.comm == \"curl\")", Expected: dtlsEditedLine},
		{Filter: "udp && !tls", Expected: dtlsLine},
	}

	for _, positive := range positiveCases {
		state.Run(positive.Filter, func(state *testing.T) {
			startFilteredDecerter(state, InterceptDecerterMode, "", []intercept.Rule{newDTLSRule()}, testFlags(), positive.Filter)
			server := startDTLSServer(state)
			output, err := runDTLSClient(state, testUser, server, "", dtlsLine, positive.Expected)

			if (err == nil) && (positive.Expected != dtlsLine) && strings.Contains(output, dtlsLine) {
				err = fmt.Errorf("dtls server printed the original line %q, output:\n%s", dtlsLine, output)
			}

			if err != nil {
				state.Errorf("Test of the DTLS filter failed, filter: %s, error: %s", positive.Filter, err.Error())
			}
		})
	}
}

// Test if a filter that selects no process is refused when no --uid or --pid is given.
func TestFilterNegative(state *testing.T) {
	negativeCases := []string{
		`proc.comm == "curl"`,
		`proc.uid == 1001 || proc.comm == "curl"`,
		`!(proc.uid == 1001)`,
	}
	onlyCIDR := testFlags()
	onlyCIDR.UIDs = nil

	for _, negative := range negativeCases {
		decerter := newDecerter(state, InterceptDecerterMode, "", nil, onlyCIDR, negative)
		err := decerter.LoadBpfObjects()

		if err == nil {
			err = decerter.UpdateBpfMaps()
		}

		shutdownErr := decerter.Shutdown()

		if !errors.Is(err, app.ErrNoProcess) || (shutdownErr != nil) {
			state.Errorf("Test of the filter failed, filter: %s, error should be %v, error: %v, shutdown error: %v", negative, app.ErrNoProcess, err, shutdownErr)
		}
	}
}

// Test if a capture with a --filter has only the flows in scope: proc.comm decided in the kernel, tls.sni in Go after the ClientHello, in both capture formats.
func TestCaptureFilterPositive(state *testing.T) {
	wgetPath, lookErr := exec.LookPath("wget")

	if lookErr != nil {
		state.Skipf("wget is not installed, error: %s", lookErr.Error())
	}

	tsharkPath, tsharkErr := exec.LookPath("tshark")

	if tsharkErr != nil {
		state.Skipf("tshark is not installed, error: %s", tsharkErr.Error())
	}

	positiveCases := []struct {
		Mode     decerterMode
		Filter   string
		InScope  []string
		OutScope []string
	}{
		{Mode: CaptureDecerterMode, Filter: `proc.comm == "curl"`, InScope: []string{"curl plain", "curl tls"}, OutScope: []string{"wget plain", "wget tls"}},
		{Mode: CaptureDecerterMode, Filter: `tls.sni == "` + filterServerName + `"`, InScope: []string{"curl tls"}, OutScope: []string{"curl plain", "wget plain", "wget tls"}},
		{Mode: PlaintextDecerterMode, Filter: `tls.sni == "` + filterServerName + `"`, InScope: []string{"curl tls"}, OutScope: []string{"curl plain", "wget plain", "wget tls"}},
	}

	for _, positive := range positiveCases {
		state.Run(string(positive.Mode)+" "+positive.Filter, func(state *testing.T) {
			servers := startFilterServers(state)
			calls := map[string]filterCall{
				"curl plain": {Name: "curl plain", Tool: "curl", RunAs: testUser, Server: servers.PlainA, ServerName: "", Arguments: nil, Expected: "/"},
				"wget plain": {Name: "wget plain", Tool: "wget", RunAs: testUser, Server: servers.PlainB, ServerName: "", Arguments: nil, Expected: "/"},
				"curl tls":   {Name: "curl tls", Tool: "curl", RunAs: testUser, Server: servers.TLSA, ServerName: filterServerName, Arguments: nil, Expected: "/"},
				"wget tls":   {Name: "wget tls", Tool: "wget", RunAs: testUser, Server: servers.TLSB, ServerName: "", Arguments: nil, Expected: "/"},
			}
			capturePath := filepath.Join(state.TempDir(), "filter.pcapng")
			stop := startFilteredDecerter(state, positive.Mode, capturePath, nil, testFlags(), positive.Filter)

			for _, name := range slices.Concat(positive.InScope, positive.OutScope) {
				err := testFilterCall(state.Context(), wgetPath, calls[name])

				if err != nil {
					state.Fatalf("Could not run the call during the capture, call: %s, error: %s", name, err.Error())
				}
			}

			stopErr := stop()

			if stopErr != nil {
				state.Fatalf("Could not stop decerter, error: %s", stopErr.Error())
			}

			ports, err := capturedPorts(state.Context(), tsharkPath, capturePath)

			if err != nil {
				state.Fatalf("Could not read the capture, error: %s", err.Error())
			}

			var captured []capturedCall

			for _, name := range slices.Concat(positive.InScope, positive.OutScope) {
				port := serverPort(state, calls[name].Server)
				isInScope := slices.Contains(positive.InScope, name)

				if ports[port] != isInScope {
					state.Errorf("Test of the capture filter failed, filter: %s, call: %s, port %s should be in the file: %v, ports: %v", positive.Filter, name, port, isInScope, ports)
				}

				if isInScope {
					captured = append(captured, capturedCall{Name: name, Port: port, IsTLS: strings.HasPrefix(calls[name].Server.URL, "https://"), IsHTTP2: false})
				}
			}

			// a flow that waited for its ClientHello is whole in the file: tshark decrypts it with the DSB, or reads the synthesized plaintext
			err = testTshark(state.Context(), tsharkPath, capturePath, captured, positive.Mode == PlaintextDecerterMode)

			if err != nil {
				state.Errorf("Test of the capture filter failed, filter: %s, error: %s", positive.Filter, err.Error())
			}
		})
	}
}

// the cases of TestFilterPositive, every filter keeps to the test user: through the flags, or through proc.uid when onlyCIDR has no uid
func filterCases(servers filterServers, onlyCIDR redirect.Filter) (cases []filterCase) {
	curlPlain := filterCall{Name: "curl plain", Tool: "curl", RunAs: testUser, Server: servers.PlainA, ServerName: "", Arguments: nil, Expected: "/test"}
	curlPlainB := filterCall{Name: "curl plain b", Tool: "curl", RunAs: testUser, Server: servers.PlainB, ServerName: "", Arguments: nil, Expected: "/test"}
	curlTLS := filterCall{Name: "curl tls", Tool: "curl", RunAs: testUser, Server: servers.TLSA, ServerName: "", Arguments: nil, Expected: "/test"}
	wgetPlain := filterCall{Name: "wget plain", Tool: "wget", RunAs: testUser, Server: servers.PlainA, ServerName: "", Arguments: nil, Expected: "/test"}
	wgetTLS := filterCall{Name: "wget tls", Tool: "wget", RunAs: testUser, Server: servers.TLSA, ServerName: "", Arguments: nil, Expected: "/test"}
	portA := serverPortOf(servers.PlainA)
	cases = []filterCase{
		{
			Name:   "proc.comm in the kernel",
			Flags:  testFlags(),
			Filter: `proc.comm == "curl"`,
			Calls:  []filterCall{curlPlain, curlTLS, unchanged(wgetPlain), unchanged(wgetTLS)},
		},
		{
			Name:   "not",
			Flags:  testFlags(),
			Filter: `!(proc.comm == "wget")`,
			Calls:  []filterCall{curlPlain, curlTLS, unchanged(wgetPlain), unchanged(wgetTLS)},
		},
		{
			Name:   "or",
			Flags:  testFlags(),
			Filter: `proc.comm == "wget" || tcp.dstport == ` + serverPortOf(servers.PlainB),
			Calls:  []filterCall{unchanged(curlPlain), curlPlainB, wgetPlain},
		},
		{
			Name:   "matches",
			Flags:  testFlags(),
			Filter: `proc.cmdline matches "x-decerter: *decerter-marker"`,
			Calls:  []filterCall{withArguments(curlPlain, "-H", "X-Decerter: DECERTER-MARKER"), unchanged(curlPlainB), unchanged(wgetPlain)},
		},
		{
			Name:   "tls.sni",
			Flags:  testFlags(),
			Filter: `tls.sni == "` + filterServerName + `"`,
			Calls:  []filterCall{withServerName(curlTLS, filterServerName), unchanged(withServerName(curlTLS, otherServerName)), unchanged(curlTLS), unchanged(curlPlain), unchanged(wgetTLS)},
		},
		{
			Name:   "ip.dst and tcp.dstport in the kernel",
			Flags:  testFlags(),
			Filter: `ip.dst == 127.0.0.0/8 && tcp.dstport in {` + portA + `, 1}`,
			Calls:  []filterCall{curlPlain, wgetPlain, unchanged(curlPlainB)},
		},
		{
			Name:   "process from the filter",
			Flags:  onlyCIDR,
			Filter: fmt.Sprintf(`proc.uid == %d && proc.comm == "curl"`, testUser.UID),
			Calls:  []filterCall{curlPlain, unchanged(asUser(curlPlain, otherUser)), unchanged(wgetPlain)},
		},
	}
	return
}

func unchanged(call filterCall) (result filterCall) {
	result = call
	result.Name += " unchanged"
	result.Expected = "/"
	return
}

func withArguments(call filterCall, arguments ...string) (result filterCall) {
	result = call
	result.Name += " " + strings.Join(arguments, " ")
	result.Arguments = arguments
	return
}

func withServerName(call filterCall, serverName string) (result filterCall) {
	result = call
	result.Name += " sni " + serverName
	result.ServerName = serverName
	return
}

func asUser(call filterCall, runAs account) (result filterCall) {
	result = call
	result.Name += " as " + runAs.Name
	result.RunAs = runAs
	return
}

func startFilterServers(state *testing.T) (servers filterServers) {
	plain := serverConfig{Certificate: nil, Version: 0, CipherSuite: 0, HTTP2: false}
	tls13 := serverConfig{Certificate: &rsaCertificate, Version: tls.VersionTLS13, CipherSuite: 0, HTTP2: false}
	servers = filterServers{
		PlainA: startServer(state, plain),
		PlainB: startServer(state, plain),
		TLSA:   startServer(state, tls13),
		TLSB:   startServer(state, tls13),
	}
	return
}

func serverPortOf(server testServer) (port string) {
	address, err := url.Parse(server.URL)

	if err != nil {
		return
	}

	port = address.Port()
	return
}

func serverPort(state *testing.T, server testServer) (port string) {
	port = serverPortOf(server)

	if port == "" {
		state.Fatalf("Could not read the port of %s", server.URL)
	}

	return
}

// run the call and check what the tool printed and the server saw, both are the path the server got
func testFilterCall(ctx context.Context, wgetPath string, call filterCall) (err error) {
	var output string

	switch call.Tool {
	case "wget":
		output, err = runWget(ctx, wgetPath, call)
	default:
		output, err = runCurl(ctx, call.RunAs, curlFilterArguments(call))
	}

	if err != nil {
		return
	}

	request, receivedErr := call.Server.received()

	if err = receivedErr; err != nil {
		return
	}

	if (request.Path != call.Expected) || (output != call.Expected) {
		err = fmt.Errorf("server path return value was not %v instead: %v, output: %q", call.Expected, request.Path, output)
		return
	}

	return
}

// HTTP/1.1, the server key pinned for TLS; a server name is sent by asking for that host and connecting to the server's address
func curlFilterArguments(call filterCall) (arguments []string) {
	arguments = append([]string{"--http1.1"}, call.Arguments...)
	target := call.Server.URL

	if !strings.HasPrefix(target, "https://") {
		arguments = append(arguments, target)
		return
	}

	arguments = append(arguments, "--insecure", "--pinnedpubkey", rsaCertificate.Pin)

	if call.ServerName != "" {
		address := netip.MustParseAddrPort(strings.TrimSuffix(strings.TrimPrefix(target, "https://"), "/"))
		arguments = append(arguments, "--connect-to", fmt.Sprintf("%s:%d:%s:%d", call.ServerName, address.Port(), address.Addr(), address.Port()))
		target = fmt.Sprintf("https://%s:%d/", call.ServerName, address.Port())
	}

	arguments = append(arguments, target)
	return
}

// run wget as a user without root's groups, environment or wgetrc, the body is the output
func runWget(ctx context.Context, wgetPath string, call filterCall) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	arguments := []string{"--quiet", "--no-hsts", "--no-config", "--tries=1", "--timeout=" + curlMaxTime, "--output-document=-"}

	if strings.HasPrefix(call.Server.URL, "https://") {
		arguments = append(arguments, "--no-check-certificate")
	}

	arguments = append(arguments, call.Server.URL)
	command := exec.CommandContext(commandCtx, wgetPath, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: call.RunAs.UID, Gid: call.RunAs.GID, Groups: []uint32{}, NoSetGroups: false}}
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()

	if err != nil {
		err = fmt.Errorf("wget %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()))
		return
	}

	output = stdout.String()
	return
}

// the TCP ports of every packet in the capture
func capturedPorts(ctx context.Context, tsharkPath string, capturePath string) (ports map[string]bool, err error) {
	output, runErr := runCommand(ctx, tsharkPath, "-n", "-r", capturePath, "-Y", "tcp", "-T", "fields", "-E", "separator=,", "-e", "tcp.srcport", "-e", "tcp.dstport")

	if err = runErr; err != nil {
		return
	}

	ports = map[string]bool{}

	for line := range strings.Lines(output) {
		for port := range strings.SplitSeq(strings.TrimSpace(line), ",") {
			ports[port] = true
		}
	}

	return
}
