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
	"log/slog"
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
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/platform"
)

const (
	// the local user whose flows decerter selects, curl runs as this user
	testUserName string = "test"
	// a user decerter does not select, its flows reach the servers unchanged
	otherUserName string = "nobody"
	// every external command is killed after this long, curl gives up a little earlier on its own
	commandTimeout time.Duration = 20 * time.Second
	curlMaxTime    string        = "10"
	proxyPort      uint16        = 15001
	udpIdleTimeout time.Duration = 30 * time.Second
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

// start decerter in the test process in the order main.go uses, selecting only the test user's flows to 127.0.0.1
// stop shuts it down once and is a cleanup of the test too, so a failed test leaves nothing attached
func startDecerter(state *testing.T, mode decerterMode, capturePath string, rules []intercept.Rule) (stop func() error) {
	filter := redirect.Filter{
		UIDs:             []uint32{testUser.UID},
		Tgids:            nil,
		DestinationCIDRs: []netip.Prefix{destinationPrefix},
		DestinationPorts: nil,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	decerter := app.New(context.Background(), filter, proxyPort, udpIdleTimeout, false, false, false, rules, "", capturePath, mode == PlaintextDecerterMode, capturebpf.MaxSnaplen, platform.Detect("/"), logger)
	stop = sync.OnceValue(decerter.Shutdown)

	state.Cleanup(func() {
		if stopErr := stop(); stopErr != nil {
			state.Errorf("Could not stop decerter, error: %s", stopErr.Error())
		}
	})

	err := startSequence(&decerter, mode)

	if err != nil {
		state.Fatalf("Could not start decerter in %s mode, error: %s", mode, err.Error())
	}

	return
}

func startSequence(decerter *app.App, mode decerterMode) (err error) {
	err = decerter.PreparePlatform()

	if err != nil {
		return
	}

	err = decerter.LoadBpfObjects()

	if err != nil {
		return
	}

	err = decerter.UpdateBpfMaps()

	if err != nil {
		return
	}

	err = decerter.LoadSecretsBpfObjects()

	if err != nil {
		return
	}

	// capture mode records the flows and copies their packets, no proxy listener and no route sync
	if mode != InterceptDecerterMode {
		err = decerter.LoadCaptureObjects()

		if err != nil {
			return
		}

		err = decerter.StartCapture()

		if err != nil {
			return
		}

		err = decerter.AttachSecrets()

		if err != nil {
			return
		}

		err = decerter.ShareNetdHooks()

		if err != nil {
			return
		}

		err = decerter.AttachCapture()

		if err != nil {
			return
		}

		decerter.StartReleaseSweep()
		err = decerter.AttachRedirect()
		return
	}

	err = decerter.StartRouteSync()

	if err != nil {
		return
	}

	err = decerter.StartProxy()

	if err != nil {
		return
	}

	err = decerter.AttachSecrets()

	if err != nil {
		return
	}

	err = decerter.ShareNetdHooks()

	if err != nil {
		return
	}

	decerter.StartReleaseSweep()
	err = decerter.AttachRedirect()
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

// run a tool of the host as root with a timeout, stdout is the output
func runCommand(ctx context.Context, name string, arguments ...string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
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
