// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/app"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/platform"
	decertercmd "github.com/decerter/decerter/pkg/cmd"
)

const (
	// the local user whose flows decerter selects, curl runs as this user
	testUserName string = "test"
	// a user decerter does not select, its flows reach the servers unchanged
	otherUserName string = "nobody"
	// every external command is killed after this long, curl gives up a little earlier on its own
	commandTimeout time.Duration = 20 * time.Second
	// tshark reading a whole capture file gets longer, a file with a bulk download takes a slow CI runner more than commandTimeout
	tsharkTimeout  time.Duration = 60 * time.Second
	curlMaxTime    string        = "10"
	proxyPort      uint16        = 15001
	udpIdleTimeout time.Duration = 30 * time.Second
	// a message held over the API that nobody decides goes on after this
	apiHoldTimeout time.Duration = 3 * time.Second
	// a message kept back for a rule or hold of layer http goes on as it came when it is not whole after this
	apiAssemblyTimeout time.Duration = time.Second
	// the test binary runs as decerter with its arguments when this is 1
	decerterCommandEnvironment string = "DECERTER_E2E_COMMAND"
)

// how decerter runs in a test
type decerterMode string

const (
	// redirect to the proxy, which runs the rules on every message
	InterceptDecerterMode decerterMode = "intercept"
	// record the flows into a pcapng file with the TLS secrets in a DSB
	CaptureDecerterMode decerterMode = "capture"
	// record the flows into a pcapng file with the decrypted payload
	PlaintextDecerterMode decerterMode = "plaintext"
	// redirect to the proxy, which decrypts and prints the TLS flows (--decrypt)
	DecryptDecerterMode decerterMode = "decrypt"
	// redirect to the proxy, which only relays
	RelayDecerterMode decerterMode = "relay"
)

type account struct {
	Name string
	UID  uint32
	GID  uint32
}

// a server certificate of eproxy and the curl --pinnedpubkey of its key
type certificate struct {
	Pair tls.Certificate
	Pin  string
}

var (
	testUser          account
	otherUser         account
	curlPath          string
	rsaCertificate    certificate
	ecdsaCertificate  certificate
	destinationPrefix = netip.MustParsePrefix("127.0.0.1/32")
)

func TestMain(main *testing.M) {
	// the test binary is decerter for the mcp stdio and the distro OpenSSL cases, its arguments are decerter's
	if os.Getenv(decerterCommandEnvironment) == "1" {
		decertercmd.Execute()
		os.Exit(0)
	}

	// the test binary is the Go HTTP/2 client of the test user in the http/2 cases
	if mode := os.Getenv(clientCommandEnvironment); mode != "" {
		os.Exit(runClient(mode, os.Args[1:]))
	}

	// the test binary is the root's Go h2c server of the http/2 editing case
	if os.Getenv(serverCommandEnvironment) == "1" {
		os.Exit(runServer())
	}

	err := prepare()

	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e tests need root, the %q and %q users, curl and the certificates in assets: %s\n", testUserName, otherUserName, err.Error())
		os.Exit(1)
	}

	os.Exit(main.Run())
}

func prepare() (err error) {
	if os.Geteuid() != 0 {
		err = errors.New("not running as root, decerter loads bpf programs")
		return
	}

	testUser, err = lookupAccount(testUserName)

	if err != nil {
		return
	}

	otherUser, err = lookupAccount(otherUserName)

	if err != nil {
		return
	}

	curlPath, err = exec.LookPath("curl")

	if err != nil {
		return
	}

	rsaCertificate, err = loadCertificate("server_rsa")

	if err != nil {
		return
	}

	ecdsaCertificate, err = loadCertificate("server_ecdsa")
	return
}

func lookupAccount(name string) (found account, err error) {
	entry, lookupErr := user.Lookup(name)

	if err = lookupErr; err != nil {
		return
	}

	uid, uidErr := strconv.ParseUint(entry.Uid, 10, 32)

	if err = uidErr; err != nil {
		return
	}

	gid, gidErr := strconv.ParseUint(entry.Gid, 10, 32)

	if err = gidErr; err != nil {
		return
	}

	// decerter must never select the owner's own traffic
	if (uid == 0) || (uid == 1000) {
		err = fmt.Errorf("user %q has uid %d, the e2e tests need a separate user", name, uid)
		return
	}

	found = account{Name: name, UID: uint32(uid), GID: uint32(gid)}
	return
}

// the certificates have no subjectAltName, so curl skips the name check with -k and checks the server key with --pinnedpubkey
func loadCertificate(name string) (loaded certificate, err error) {
	pair, loadErr := tls.LoadX509KeyPair(filepath.Join("assets", name+".crt"), filepath.Join("assets", name+".key"))

	if err = loadErr; err != nil {
		return
	}

	digest := sha256.Sum256(pair.Leaf.RawSubjectPublicKeyInfo)
	loaded = certificate{Pair: pair, Pin: "sha256//" + base64.StdEncoding.EncodeToString(digest[:])}
	return
}

// start decerter in the test process in the order of the decerter commands, selecting only the test user's flows to 127.0.0.1
// stop shuts it down once and is a cleanup of the test too, so a failed test leaves nothing attached
func startDecerter(state *testing.T, mode decerterMode, capturePath string, rules []intercept.Rule) (stop func() error) {
	stop = startFilteredDecerter(state, mode, capturePath, rules, testFlags(), "")
	return
}

// the flags of every case: the test user's flows to 127.0.0.1
func testFlags() (flags redirect.Filter) {
	flags = redirect.Filter{
		UIDs:             []uint32{testUser.UID},
		Tgids:            nil,
		DestinationCIDRs: []netip.Prefix{destinationPrefix},
		DestinationPorts: nil,
		Comms:            nil,
	}
	return
}

// startDecerter with the flags given and a --filter, empty is none
func startFilteredDecerter(state *testing.T, mode decerterMode, capturePath string, rules []intercept.Rule, flags redirect.Filter, scopeText string) (stop func() error) {
	decerter := newDecerter(state, mode, capturePath, rules, flags, scopeText)
	stop = startApp(state, &decerter, mode)
	return
}

// start a decerter made by newDecerter or newAPIDecerter, stop shuts it down once and is a cleanup of the test too
func startApp(state *testing.T, decerter *app.App, mode decerterMode) (stop func() error) {
	stop = sync.OnceValue(decerter.Shutdown)

	state.Cleanup(func() {
		if stopErr := stop(); stopErr != nil {
			state.Errorf("Could not stop decerter, error: %s", stopErr.Error())
		}
	})

	// the same start order as the run and capture commands
	err := decerter.Start()

	if err != nil {
		state.Fatalf("Could not start decerter in %s mode, error: %s", mode, err.Error())
	}

	return
}

// a decerter that is not started yet, the filter must parse
func newDecerter(state *testing.T, mode decerterMode, capturePath string, rules []intercept.Rule, flags redirect.Filter, scopeText string) (decerter app.App) {
	decerter = newAPIDecerter(state, mode, capturePath, rules, flags, scopeText, "")
	return
}

// newDecerter that serves the control API on apiSocket, empty is none; the decrypt mode runs --decrypt
func newAPIDecerter(state *testing.T, mode decerterMode, capturePath string, rules []intercept.Rule, flags redirect.Filter, scopeText string, apiSocket string) (decerter app.App) {
	decerter = newBlockingDecerter(state, mode, capturePath, rules, flags, scopeText, apiSocket, false)
	return
}

// newAPIDecerter with --block-quic when blockQuic is true
func newBlockingDecerter(state *testing.T, mode decerterMode, capturePath string, rules []intercept.Rule, flags redirect.Filter, scopeText string, apiSocket string, blockQuic bool) (decerter app.App) {
	var scopeFilter *filter.Filter

	if scopeText != "" {
		parsed, parseErr := filter.Parse(scopeText)

		if parseErr != nil {
			state.Fatalf("Could not parse filter %q, error: %s", scopeText, parseErr.Error())
		}

		scopeFilter = &parsed
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	decerter = app.New(context.Background(), flags, scopeFilter, proxyPort, udpIdleTimeout, blockQuic, false, false, mode == DecryptDecerterMode, rules, apiSocket, apiHoldTimeout, apiAssemblyTimeout, "", (mode == CaptureDecerterMode) || (mode == PlaintextDecerterMode), capturePath, mode == PlaintextDecerterMode, capturebpf.MaxSnaplen, platform.Detect("/"), logger)
	return
}

// run the system curl as a user without root's groups, environment or curlrc, the body is the output
func runCurl(ctx context.Context, runAs account, arguments []string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, curlPath, append([]string{"-q", "--silent", "--show-error", "--max-time", curlMaxTime}, arguments...)...)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: runAs.UID, Gid: runAs.GID, Groups: []uint32{}, NoSetGroups: false}}
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()

	if err != nil {
		err = fmt.Errorf("curl %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()))
		return
	}

	output = stdout.String()
	return
}

// run a tool of the host as root, killed after commandTimeout, stdout is the output
func runCommand(ctx context.Context, name string, arguments ...string) (output string, err error) {
	output, err = runCommandTimeout(ctx, commandTimeout, name, arguments...)
	return
}

// run a tool of the host as root, killed after timeout, stdout is the output
func runCommandTimeout(ctx context.Context, timeout time.Duration, name string, arguments ...string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, name, arguments...)
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()

	if err != nil {
		err = fmt.Errorf("%s %s: %w: %s", name, strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()))
		return
	}

	output = stdout.String()
	return
}

// run openssl s_client -dtls1_2 as runAs against the server on port, suite empty takes OpenSSL's default
// line goes to the client's stdin, which stays open until the server printed expected or commandTimeout passed: s_client sends close_notify and leaves at the end of its input
// output is what the server printed
func runDTLSClient(ctx context.Context, runAs account, server dtlsServer, suite string, line string, expected string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	arguments := []string{"s_client", "-dtls1_2", "-connect", net.JoinHostPort(destinationPrefix.Addr().String(), server.Port), "-nocommands"}

	if suite != "" {
		arguments = append(arguments, "-cipher", suite)
	}

	command := exec.CommandContext(commandCtx, "openssl", arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: runAs.UID, Gid: runAs.GID, Groups: []uint32{}, NoSetGroups: false}}
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	stderr := &bytes.Buffer{}
	command.Stdout = io.Discard
	command.Stderr = stderr
	stdin, stdinErr := command.StdinPipe()

	if err = stdinErr; err != nil {
		return
	}

	err = command.Start()

	if err != nil {
		return
	}

	_, writeErr := io.WriteString(stdin, line+"\n")
	output, found := server.waitFor(expected, commandTimeout)
	closeErr := stdin.Close()
	waitErr := command.Wait()

	if err = errors.Join(writeErr, closeErr, waitErr); err != nil {
		err = fmt.Errorf("openssl %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()))
		return
	}

	if !found {
		err = fmt.Errorf("dtls server did not print %q, output:\n%s", expected, output)
	}

	return
}
