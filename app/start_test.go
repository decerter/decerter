// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/api"
	"github.com/decerter/decerter/internal/attach"
	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/proxy"
	"github.com/decerter/decerter/internal/tls/boringssl"
	"github.com/decerter/decerter/internal/tls/openssl"
)

// the options of app.New the tests change, the rest is the default of run mode
type appOptions struct {
	Flags       redirect.Filter
	ProxyPort   uint16
	FlowTable   bool
	Keylog      bool
	Decrypt     bool
	Rules       []intercept.Rule
	APISocket   string
	Libssl      string
	IsCapture   bool
	CapturePath string
	Platform    platform.Platform
}

var (
	errClose = errors.New("close failed")
)

// an app with options, its logs go to output
func newOptionsApp(ctx context.Context, options appOptions, output *bytes.Buffer) (app App) {
	logger := slog.New(slog.NewTextHandler(output, nil))
	app = New(ctx, options.Flags, nil, options.ProxyPort, 30*time.Second, false, options.FlowTable, options.Keylog, options.Decrypt, options.Rules, options.APISocket, time.Minute, 5*time.Second, options.Libssl, options.IsCapture, options.CapturePath, false, 0, options.Platform, logger)
	return
}

// Android with its data directory in a temporary directory
func androidPlatform(directory string) (currentPlatform platform.Platform) {
	currentPlatform = platform.Platform{Type: platform.AndroidType, SDK: 35, Release: "15", DataDirectory: directory, APISocket: platform.AndroidAPISocket}
	return
}

// an abstract socket name no other test uses
func abstractSocket(name string) (socket string) {
	socket = "@decerter-app-test-" + name + "-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	return
}

// a netd hook state without hooks whose cgroup is directory, RestoreHooks then needs no bpf syscall
func writeEmptyNetdState(directory string, cgroup string) (err error) {
	err = attach.WriteNetdState(filepath.Join(directory, platform.NetdStateName), attach.NetdState{Pid: 1, Cgroup: cgroup, Hooks: nil})
	return
}

// Test if app.Start returns with the expected errors before anything is loaded: an unknown --libssl in keylog mode, an api socket under a file in
// run and capture mode (Listen makes a missing directory, a file in the way fails as root and without a group decerter too), a data directory that
// can't be made, locked or read on Android; Shutdown undoes what ran.
func TestStartNegative(state *testing.T) {
	directory := state.TempDir()
	notDirectory := filepath.Join(directory, "file")
	corrupt := filepath.Join(directory, "corrupt")
	locked := filepath.Join(directory, "locked")
	err := errors.Join(os.WriteFile(notDirectory, []byte("x"), 0o600), os.MkdirAll(corrupt, 0o700), os.MkdirAll(locked, 0o700))

	if err == nil {
		err = os.WriteFile(filepath.Join(corrupt, platform.NetdStateName), []byte("{"), 0o600)
	}

	if err != nil {
		state.Fatalf("Test of app.Start failed, cannot create the directories, error: %s", err.Error())
	}

	unlock, err := attach.LockNetdState(filepath.Join(locked, lockName))

	if err != nil {
		state.Fatalf("Test of app.Start failed, cannot lock, error: %s", err.Error())
	}

	defer func() {
		if unlockErr := unlock(); unlockErr != nil {
			state.Errorf("Test of app.Start failed, cannot unlock, error: %s", unlockErr.Error())
		}
	}()

	linux := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: directory, APISocket: ""}
	negativeCases := []struct {
		Name     string
		Options  appOptions
		Expected error
	}{
		{Name: "keylog with a --libssl that does not exist", Options: appOptions{Keylog: true, Libssl: filepath.Join(directory, "missing", "libssl.so.3"), Platform: linux}, Expected: openssl.ErrLibraryNotFound},
		{Name: "run mode with an api socket under a file", Options: appOptions{APISocket: filepath.Join(notDirectory, "api.sock"), Platform: linux}, Expected: api.ErrSocket},
		{Name: "capture mode with an api socket under a file", Options: appOptions{IsCapture: true, APISocket: filepath.Join(notDirectory, "api.sock"), Platform: linux}, Expected: api.ErrSocket},
		{Name: "a data directory that is a file", Options: appOptions{Keylog: true, Platform: androidPlatform(notDirectory)}, Expected: platform.ErrDataDirectory},
		{Name: "a data directory another decerter holds", Options: appOptions{Keylog: true, Platform: androidPlatform(locked)}, Expected: attach.ErrLocked},
		{Name: "a netd hook state that can't be read", Options: appOptions{Keylog: true, Platform: androidPlatform(corrupt)}, Expected: attach.ErrNetdState},
	}

	for _, negative := range negativeCases {
		logs := &bytes.Buffer{}
		app := newOptionsApp(state.Context(), negative.Options, logs)
		err = app.Start()
		shutdownErr := app.Shutdown()

		if !errors.Is(err, negative.Expected) || (shutdownErr != nil) || !strings.Contains(logs.String(), "level=ERROR") {
			state.Errorf("Test of app.Start function failed, case %q, error should be %v, error: %v, shutdown error: %v, logs: %q", negative.Name, negative.Expected, err, shutdownErr, logs.String())
		}
	}
}

// Test if app.PreparePlatform returns with the expected output: nothing to do on Linux; on Android the data directory is created and locked, the
// state a killed decerter left is restored and removed, and the lock is released by Shutdown.
func TestPreparePlatformPositive(state *testing.T) {
	logs := &bytes.Buffer{}
	app := newOptionsApp(state.Context(), appOptions{Platform: platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: filepath.Join(state.TempDir(), "unused"), APISocket: ""}}, logs)
	err := app.PreparePlatform()

	if (err != nil) || (len(app.closeFunctions) != 0) {
		state.Errorf("Test of app.PreparePlatform function failed, Linux should do nothing, close functions: %d, error: %v", len(app.closeFunctions), err)
		return
	}

	directory := filepath.Join(state.TempDir(), "decerter.d")
	err = errors.Join(os.MkdirAll(directory, 0o700), writeEmptyNetdState(directory, state.TempDir()))

	if err != nil {
		state.Fatalf("Test of app.PreparePlatform failed, cannot write the state, error: %s", err.Error())
	}

	app = newOptionsApp(state.Context(), appOptions{Platform: androidPlatform(directory)}, logs)
	err = app.PreparePlatform()
	_, statErr := os.Stat(filepath.Join(directory, platform.NetdStateName))
	_, lockErr := attach.LockNetdState(filepath.Join(directory, lockName))

	if (err != nil) || !errors.Is(statErr, fs.ErrNotExist) || !errors.Is(lockErr, attach.ErrLocked) || !strings.Contains(logs.String(), "did not exit cleanly") || !strings.Contains(logs.String(), "Netd hooks are exclusive again") {
		state.Errorf("Test of app.PreparePlatform function failed, the state should be restored and removed under the lock, stat error: %v, lock error: %v, error: %v, logs: %q", statErr, lockErr, err, logs.String())
		return
	}

	err = app.Shutdown()
	unlock, lockErr := attach.LockNetdState(filepath.Join(directory, lockName))

	if (err != nil) || (lockErr != nil) {
		state.Errorf("Test of app.Shutdown function failed, the lock should be released, error: %v, lock error: %v", err, lockErr)
		return
	}

	if err = unlock(); err != nil {
		state.Errorf("Test of app.PreparePlatform failed, cannot unlock, error: %s", err.Error())
		return
	}
}

// Test if app.RestoreNetdHooks returns with the expected output: nothing to restore on Linux or without a state file, a state file without hooks is removed.
func TestRestoreNetdHooksPositive(state *testing.T) {
	directory := filepath.Join(state.TempDir(), "decerter.d")
	positiveCases := []struct {
		Name     string
		Platform platform.Platform
		HasState bool
		Expected string
	}{
		{Name: "Linux", Platform: platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: directory, APISocket: ""}, HasState: false, Expected: "Not on Android, nothing to restore"},
		{Name: "no state", Platform: androidPlatform(directory), HasState: false, Expected: "No netd hook state, nothing to restore"},
		{Name: "a state without hooks", Platform: androidPlatform(directory), HasState: true, Expected: "Netd hooks are exclusive again"},
	}

	for _, positive := range positiveCases {
		if positive.HasState {
			err := writeEmptyNetdState(directory, state.TempDir())

			if err != nil {
				state.Fatalf("Test of app.RestoreNetdHooks failed, cannot write the state, error: %s", err.Error())
			}
		}

		logs := &bytes.Buffer{}
		app := newOptionsApp(state.Context(), appOptions{Platform: positive.Platform}, logs)
		err := app.RestoreNetdHooks()
		shutdownErr := app.Shutdown()
		_, statErr := os.Stat(filepath.Join(directory, platform.NetdStateName))

		if (err != nil) || (shutdownErr != nil) || !errors.Is(statErr, fs.ErrNotExist) || !strings.Contains(logs.String(), positive.Expected) {
			state.Errorf("Test of app.RestoreNetdHooks function failed, case %q, logs should contain %q, error: %v, shutdown error: %v, stat error: %v, logs: %q", positive.Name, positive.Expected, err, shutdownErr, statErr, logs.String())
		}
	}
}

// Test if app.RestoreNetdHooks returns with the expected errors: a data directory that can't be created, a state that can't be read, a cgroup that
// can't be opened (the state is kept), a state file that can't be removed.
func TestRestoreNetdHooksNegative(state *testing.T) {
	directory := state.TempDir()
	notDirectory := filepath.Join(directory, "file")
	unreadable := filepath.Join(directory, "unreadable")
	missingCgroup := filepath.Join(directory, "missing-cgroup")
	readOnly := filepath.Join(directory, "read-only")
	err := errors.Join(os.WriteFile(notDirectory, []byte("x"), 0o600), os.MkdirAll(filepath.Join(unreadable, platform.NetdStateName), 0o700), os.MkdirAll(missingCgroup, 0o700), os.MkdirAll(readOnly, 0o700))

	if err == nil {
		err = errors.Join(writeEmptyNetdState(missingCgroup, filepath.Join(directory, "missing")), writeEmptyNetdState(readOnly, directory), os.WriteFile(filepath.Join(readOnly, lockName), nil, 0o600))
	}

	if err == nil {
		err = os.Chmod(readOnly, 0o500)
	}

	if err != nil {
		state.Fatalf("Test of app.RestoreNetdHooks failed, cannot create the directories, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if chmodErr := os.Chmod(readOnly, 0o700); chmodErr != nil {
			state.Errorf("Test of app.RestoreNetdHooks failed, cannot make the directory writable, error: %s", chmodErr.Error())
		}
	})

	negativeCases := []struct {
		Name      string
		Directory string
		Expected  error
		Logs      string
	}{
		{Name: "a data directory that is a file", Directory: notDirectory, Expected: platform.ErrDataDirectory, Logs: "Could not create data directory"},
		{Name: "a state that is a directory", Directory: unreadable, Expected: nil, Logs: "Could not read netd hook state"},
		{Name: "a cgroup that does not exist", Directory: missingCgroup, Expected: attach.ErrRestore, Logs: "the state file is kept"},
		{Name: "a state that can't be removed", Directory: readOnly, Expected: attach.ErrNetdState, Logs: "Could not remove netd hook state"},
	}

	for _, negative := range negativeCases {
		// root may remove a file of a read-only directory
		if (negative.Directory == readOnly) && (os.Geteuid() == 0) {
			continue
		}

		logs := &bytes.Buffer{}
		app := newOptionsApp(state.Context(), appOptions{Platform: androidPlatform(negative.Directory)}, logs)
		err = app.RestoreNetdHooks()
		shutdownErr := app.Shutdown()

		if (err == nil) || ((negative.Expected != nil) && !errors.Is(err, negative.Expected)) || (shutdownErr != nil) || !strings.Contains(logs.String(), negative.Logs) {
			state.Errorf("Test of app.RestoreNetdHooks function failed, case %q, error should be %v, logs should contain %q, error: %v, shutdown error: %v, logs: %q", negative.Name, negative.Expected, negative.Logs, err, shutdownErr, logs.String())
		}
	}

	_, statErr := os.Stat(filepath.Join(missingCgroup, platform.NetdStateName))

	if statErr != nil {
		state.Errorf("Test of app.RestoreNetdHooks function failed, a state that can't be restored should be kept, error: %s", statErr.Error())
		return
	}
}

// Test if app.Shutdown returns with the expected output: the close functions run in reverse order once, the capture error and the close errors are
// joined, and Done is closed.
func TestShutdownPositive(state *testing.T) {
	logs := &bytes.Buffer{}
	app := newOptionsApp(state.Context(), appOptions{Platform: platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "", APISocket: ""}}, logs)
	err := app.Shutdown()

	if err != nil {
		state.Errorf("Test of app.Shutdown function failed, an app that loaded nothing should shut down cleanly, error: %s", err.Error())
		return
	}

	select {
	case <-app.Done():
	default:
		state.Errorf("Test of app.Done function failed, Done should be closed after Shutdown")
		return
	}

	order := []int{}
	app = newOptionsApp(state.Context(), appOptions{Platform: platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "", APISocket: ""}}, logs)
	app.closeFunctions = append(app.closeFunctions,
		func() (closeErr error) {
			order = append(order, 1)
			return
		},
		func() (closeErr error) {
			order = append(order, 2)
			closeErr = errClose
			return
		},
	)
	captureErr := errors.New("capture failed")
	app.setStopErr(captureErr)
	err = app.Shutdown()

	if !errors.Is(err, errClose) || !errors.Is(err, captureErr) || (len(order) != 2) || (order[0] != 2) || !strings.Contains(logs.String(), "Could not close bpf resource") {
		state.Errorf("Test of app.Shutdown function failed, errors should be joined after closing in reverse order, order: %v, error: %v, logs: %q", order, err, logs.String())
		return
	}

	// nothing is closed twice
	err = app.Shutdown()

	if !errors.Is(err, captureErr) || (len(order) != 2) {
		state.Errorf("Test of app.Shutdown function failed, a second Shutdown should close nothing, order: %v, error: %v", order, err)
		return
	}
}

// Test if the steps of app.Start that have nothing to do in a mode return with the expected output: no secrets selection, key log, secrets, capture,
// flow table or api without their mode or option, and the attachments of each mode.
func TestModeStepsPositive(state *testing.T) {
	linux := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "", APISocket: ""}
	logs := &bytes.Buffer{}
	app := newOptionsApp(state.Context(), appOptions{Platform: linux}, logs)
	err := errors.Join(app.UpdateSecretsSelection(), app.AttachSecrets(), app.AttachCapture())
	app.StartKeylog()
	app.StartFlowTable()
	app.ServeAPI()
	shutdownErr := app.Shutdown()

	if (err != nil) || (shutdownErr != nil) || (logs.Len() != 0) {
		state.Errorf("Test of app steps failed, run mode without options should do nothing, error: %v, shutdown error: %v, logs: %q", err, shutdownErr, logs.String())
		return
	}

	positiveCases := []struct {
		Name     string
		Options  appOptions
		Capture  bool
		Redirect int
	}{
		{Name: "run mode", Options: appOptions{Platform: linux}, Capture: false, Redirect: 11},
		{Name: "run mode with the api", Options: appOptions{APISocket: "@decerter-api", Platform: linux}, Capture: true, Redirect: 11},
		{Name: "keylog mode with the api", Options: appOptions{Keylog: true, APISocket: "@decerter-api", Platform: linux}, Capture: false, Redirect: 11},
		{Name: "capture mode", Options: appOptions{IsCapture: true, Platform: linux}, Capture: true, Redirect: 6},
	}

	for _, positive := range positiveCases {
		app = newOptionsApp(state.Context(), positive.Options, logs)
		hasCapture := app.hasCapture()
		captureCount := len(app.captureAttachments())
		redirectCount := len(app.redirectAttachments())
		shutdownErr = app.Shutdown()

		if (hasCapture != positive.Capture) || ((captureCount == 2) != positive.Capture) || (redirectCount != positive.Redirect) || (shutdownErr != nil) {
			state.Errorf("Test of app.hasCapture function failed, case %q, capture should be %v with %d redirect programs, capture: %v (%d programs), redirect programs: %d, shutdown error: %v", positive.Name, positive.Capture, positive.Redirect, hasCapture, captureCount, redirectCount, shutdownErr)
		}
	}
}

// Test if app.withoutSecrets returns with the expected output: run mode warns and goes on, capture mode goes on and warns later, keylog mode fails.
func TestWithoutSecretsPositive(state *testing.T) {
	reason := errors.New("no libssl")
	positiveCases := []struct {
		Name      string
		Options   appOptions
		IsError   bool
		IsWarning bool
	}{
		{Name: "run mode", Options: appOptions{}, IsError: false, IsWarning: true},
		{Name: "capture mode", Options: appOptions{IsCapture: true}, IsError: false, IsWarning: false},
		{Name: "keylog mode", Options: appOptions{Keylog: true}, IsError: true, IsWarning: false},
	}

	for _, positive := range positiveCases {
		logs := &bytes.Buffer{}
		app := newOptionsApp(state.Context(), positive.Options, logs)
		err := app.withoutSecrets(reason)
		isWarning := strings.Contains(logs.String(), "running without TLS secrets")

		if (errors.Is(err, reason) != positive.IsError) || (isWarning != positive.IsWarning) || (!positive.IsError && !errors.Is(app.secretsErr, reason)) {
			state.Errorf("Test of app.withoutSecrets function failed, case %q, error %v and warning %v expected, error: %v, secrets error: %v, logs: %q", positive.Name, positive.IsError, positive.IsWarning, err, app.secretsErr, logs.String())
		}
	}
}

// Test if app.LoadSecretsBpfObjects returns with the expected output before it loads anything: on Android a Conscrypt that can't be hooked and no
// app library leaves run and capture mode without secrets.
func TestLoadSecretsBpfObjectsPositive(state *testing.T) {
	notELF := filepath.Join(state.TempDir(), "libssl.so")
	err := os.WriteFile(notELF, []byte("no ELF file"), 0o600)

	if err != nil {
		state.Fatalf("Test of app.LoadSecretsBpfObjects failed, cannot write the library, error: %s", err.Error())
	}

	positiveCases := []struct {
		Name     string
		Options  appOptions
		Expected error
	}{
		{Name: "run mode with a --libssl that is no ELF file", Options: appOptions{Libssl: notELF, Platform: androidPlatform(state.TempDir())}, Expected: boringssl.ErrOpenLibrary},
		// the selected process is this test, Conscrypt is not on this host and there is no packages.list
		{Name: "capture mode without Conscrypt", Options: appOptions{Flags: redirect.Filter{Tgids: []uint32{uint32(os.Getpid())}}, IsCapture: true, Platform: androidPlatform(state.TempDir())}, Expected: boringssl.ErrLibraryNotFound},
	}

	for _, positive := range positiveCases {
		logs := &bytes.Buffer{}
		app := newOptionsApp(state.Context(), positive.Options, logs)
		app.selection = app.filter
		err = app.LoadSecretsBpfObjects()
		shutdownErr := app.Shutdown()

		if (err != nil) || (shutdownErr != nil) || !errors.Is(app.secretsErr, positive.Expected) || (app.secretsBpfMaps != nil) {
			state.Errorf("Test of app.LoadSecretsBpfObjects function failed, case %q, secrets error should be %v, error: %v, secrets error: %v, shutdown error: %v, logs: %q", positive.Name, positive.Expected, err, app.secretsErr, shutdownErr, logs.String())
		}
	}
}

// Test if app.LoadSecretsBpfObjects returns with the expected errors before it loads anything: keylog mode without secrets, a --libssl on Android
// without ssl_log_secret is an OpenSSL whose version is unknown, a --libssl on Linux that does not exist or is no OpenSSL.
func TestLoadSecretsBpfObjectsNegative(state *testing.T) {
	directory := state.TempDir()
	notELF := filepath.Join(directory, "libssl.so")
	noSymbols := filepath.Join(directory, "lib", "libssl.so.3")
	err := errors.Join(os.WriteFile(notELF, []byte("no ELF file"), 0o600), os.MkdirAll(filepath.Dir(noSymbols), 0o700))

	if err == nil {
		err = writeStaticELF(noSymbols)
	}

	if err != nil {
		state.Fatalf("Test of app.LoadSecretsBpfObjects failed, cannot write the libraries, error: %s", err.Error())
	}

	linux := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: directory, APISocket: ""}
	negativeCases := []struct {
		Name     string
		Options  appOptions
		Expected error
		Logs     string
	}{
		{Name: "keylog mode with a --libssl that is no ELF file", Options: appOptions{Keylog: true, Libssl: notELF, Platform: androidPlatform(directory)}, Expected: boringssl.ErrOpenLibrary, Logs: "Could not load secrets uprobe"},
		{Name: "an OpenSSL on Android without its libcrypto", Options: appOptions{Libssl: noSymbols, Platform: androidPlatform(directory)}, Expected: openssl.ErrOpenLibrary, Logs: "Could not get OpenSSL offsets"},
		{Name: "a --libssl that does not exist", Options: appOptions{Libssl: filepath.Join(directory, "missing.so"), Platform: linux}, Expected: openssl.ErrLibraryNotFound, Logs: "Could not find libssl"},
	}

	for _, negative := range negativeCases {
		logs := &bytes.Buffer{}
		app := newOptionsApp(state.Context(), negative.Options, logs)
		err = app.LoadSecretsBpfObjects()
		shutdownErr := app.Shutdown()

		if !errors.Is(err, negative.Expected) || (shutdownErr != nil) || !strings.Contains(logs.String(), negative.Logs) {
			state.Errorf("Test of app.LoadSecretsBpfObjects function failed, case %q, error should be %v, logs should contain %q, error: %v, shutdown error: %v, logs: %q", negative.Name, negative.Expected, negative.Logs, err, shutdownErr, logs.String())
		}
	}
}

// Test if app.LoadSecretsBpfObjects returns with the expected output on a Linux host without libssl.so.3 or .4 and no --libssl: run and capture mode go
// on without TLS secrets, run mode with a warning, and keylog mode fails.
func TestLoadSecretsWithoutLibsslPositive(state *testing.T) {
	missing := fmt.Errorf("%w: libssl.so.3 or libssl.so.4, give its path with --libssl", openssl.ErrLibraryNotFound)
	previous := findLibssl
	findLibssl = func(override string) (libraries []openssl.Library, err error) {
		err = missing
		return
	}
	state.Cleanup(func() {
		findLibssl = previous
	})

	linux := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: state.TempDir(), APISocket: ""}
	positiveCases := []struct {
		Name     string
		Options  appOptions
		Expected error
		Logs     string
	}{
		{Name: "run mode", Options: appOptions{Platform: linux}, Expected: nil, Logs: "running without TLS secrets"},
		{Name: "capture mode", Options: appOptions{IsCapture: true, Platform: linux}, Expected: nil, Logs: ""},
		{Name: "keylog mode", Options: appOptions{Keylog: true, Platform: linux}, Expected: openssl.ErrLibraryNotFound, Logs: "Could not load secrets uprobe"},
	}

	for _, positive := range positiveCases {
		logs := &bytes.Buffer{}
		app := newOptionsApp(state.Context(), positive.Options, logs)
		err := app.LoadSecretsBpfObjects()
		shutdownErr := app.Shutdown()
		isWithout := (app.secretsBpfMaps == nil) && ((positive.Expected != nil) || errors.Is(app.secretsErr, openssl.ErrLibraryNotFound))

		if !errors.Is(err, positive.Expected) || ((positive.Expected == nil) != (err == nil)) || !isWithout || (shutdownErr != nil) || !strings.Contains(logs.String(), positive.Logs) {
			state.Errorf("Test of app.LoadSecretsBpfObjects function failed, case %q, error should be %v, logs should contain %q, error: %v, secrets error: %v, shutdown error: %v, logs: %q", positive.Name, positive.Expected, positive.Logs, err, app.secretsErr, shutdownErr, logs.String())
		}
	}
}

// Test if app.ListenAPI and app.ServeAPI return with the expected output: the api socket is created, served until Shutdown and closed by it.
func TestListenAPIPositive(state *testing.T) {
	logs := &bytes.Buffer{}
	socket := abstractSocket("api")
	app := newOptionsApp(state.Context(), appOptions{APISocket: socket, Platform: platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "", APISocket: ""}}, logs)
	err := app.ListenAPI()

	if err != nil {
		state.Fatalf("Test of app.ListenAPI function failed, error: %s", err.Error())
	}

	app.backend = app.newBackend(v1.RunMode, v1.RelayProcessing)
	app.ServeAPI()
	connection, dialErr := net.Dial("unix", socket)

	if dialErr == nil {
		dialErr = connection.Close()
	}

	err = app.Shutdown()
	_, afterErr := net.Dial("unix", socket)

	if (dialErr != nil) || (err != nil) || (afterErr == nil) {
		state.Errorf("Test of app.ListenAPI function failed, the socket should take connections until Shutdown, dial error: %v, shutdown error: %v, dial after shutdown error: %v", dialErr, err, afterErr)
		return
	}
}

// Test if app.newBackend returns with the expected output: the scope of the filter, the processing and whether the key log can be read.
func TestNewBackendPositive(state *testing.T) {
	app, err := newTestApp(state.Context(), redirect.Filter{UIDs: []uint32{1001}}, `tls.sni == "example.com"`, &bytes.Buffer{})

	if err != nil {
		state.Fatalf("Test of app.newBackend failed, cannot parse filter, error: %s", err.Error())
	}

	backend := app.newBackend(v1.CaptureMode, v1.RecordProcessing)
	info := backend.Info

	if (info.Scope != `tls.sni == "example.com"`) || (info.Mode != v1.CaptureMode) || (info.Processing != v1.RecordProcessing) || info.HasTLSSecrets || info.IsInterceptCapable {
		state.Errorf("Test of app.newBackend function failed, info: %+v", info)
		return
	}

	// a non-nil map set is enough for the key log reader, it is only read when the API asks for a key
	app.secretsBpfMaps = map[bpf.BpfMapName]*ebpf.Map{}
	backend = app.newBackend(v1.RunMode, v1.InterceptProcessing)

	if !backend.Info.HasTLSSecrets || !backend.Info.IsInterceptCapable {
		state.Errorf("Test of app.newBackend function failed, with secrets and intercept, info: %+v", backend.Info)
		return
	}

	if err = app.Shutdown(); err != nil {
		state.Errorf("Test of app.Shutdown function failed, error: %s", err.Error())
		return
	}
}

// Test if app.StartProxy returns with the expected output: the tcp and udp proxy listen on loopback until Shutdown, relaying, decrypting or
// intercepting with the rules of the code and the api.
func TestStartProxyPositive(state *testing.T) {
	linux := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "", APISocket: ""}
	positiveCases := []struct {
		Name     string
		Options  appOptions
		Secrets  bool
		Expected string
	}{
		{Name: "relay", Options: appOptions{Platform: linux}, Secrets: false, Expected: "Udp proxy listening"},
		{Name: "decrypt", Options: appOptions{Decrypt: true, Platform: linux}, Secrets: true, Expected: "Decrypting tls flows"},
		{Name: "intercept with the api", Options: appOptions{Rules: []intercept.Rule{intercept.NewRuleSet()}, APISocket: abstractSocket("proxy"), Platform: linux}, Secrets: false, Expected: "Intercepting the flows of the proxy"},
	}

	for _, positive := range positiveCases {
		logs := &bytes.Buffer{}
		app := newOptionsApp(state.Context(), positive.Options, logs)

		if positive.Secrets {
			app.secretsBpfMaps = map[bpf.BpfMapName]*ebpf.Map{}
		}

		err := app.StartProxy()

		if err != nil {
			state.Errorf("Test of app.StartProxy function failed, case %q, error: %v, logs: %q", positive.Name, errors.Join(err, app.Shutdown()), logs.String())
			continue
		}

		isListening := (app.tcpListener != nil) && (app.udpConnection != nil)
		err = app.Shutdown()

		if !isListening || (err != nil) || !strings.Contains(logs.String(), positive.Expected) || ((positive.Options.APISocket != "") != (app.backend != nil)) {
			state.Errorf("Test of app.StartProxy function failed, case %q, logs should contain %q, listening: %v, error: %v, logs: %q", positive.Name, positive.Expected, isListening, err, logs.String())
		}
	}
}

// Test if app.StartProxy returns with the expected errors: the tcp or the udp port is taken.
func TestStartProxyNegative(state *testing.T) {
	linux := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "", APISocket: ""}
	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: nil, Port: 0})

	if err != nil {
		state.Fatalf("Test of app.StartProxy failed, cannot listen, error: %s", err.Error())
	}

	defer func() {
		if closeErr := tcpListener.Close(); closeErr != nil {
			state.Errorf("Test of app.StartProxy failed, cannot close the listener, error: %s", closeErr.Error())
		}
	}()

	udpConnection, err := net.ListenUDP("udp", &net.UDPAddr{IP: nil, Port: 0})

	if err != nil {
		state.Fatalf("Test of app.StartProxy failed, cannot listen, error: %s", err.Error())
	}

	defer func() {
		if closeErr := udpConnection.Close(); closeErr != nil {
			state.Errorf("Test of app.StartProxy failed, cannot close the socket, error: %s", closeErr.Error())
		}
	}()

	negativeCases := []struct {
		Name string
		Port int
		Logs string
	}{
		{Name: "tcp port taken", Port: tcpListener.Addr().(*net.TCPAddr).Port, Logs: "Could not start tcp proxy"},
		{Name: "udp port taken", Port: udpConnection.LocalAddr().(*net.UDPAddr).Port, Logs: "Could not start udp proxy"},
	}

	for _, negative := range negativeCases {
		logs := &bytes.Buffer{}
		app := newOptionsApp(state.Context(), appOptions{ProxyPort: uint16(negative.Port), Platform: linux}, logs)
		err = app.StartProxy()
		shutdownErr := app.Shutdown()

		if !errors.Is(err, proxy.ErrListen) || (shutdownErr != nil) || !strings.Contains(logs.String(), negative.Logs) {
			state.Errorf("Test of app.StartProxy function failed, case %q, error should be %v, logs should contain %q, error: %v, shutdown error: %v, logs: %q", negative.Name, proxy.ErrListen, negative.Logs, err, shutdownErr, logs.String())
		}
	}
}

// Test if app.StartCapture returns with the expected errors: a capture file that can't be created fails before the hub starts.
func TestStartCaptureNegative(state *testing.T) {
	logs := &bytes.Buffer{}
	path := filepath.Join(state.TempDir(), "missing", "capture.pcapng")
	app := newOptionsApp(state.Context(), appOptions{IsCapture: true, CapturePath: path, Platform: platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "", APISocket: ""}}, logs)
	err := app.StartCapture()
	shutdownErr := app.Shutdown()

	if !errors.Is(err, fs.ErrNotExist) || (shutdownErr != nil) || !strings.Contains(logs.String(), "Could not open capture file") {
		state.Errorf("Test of app.StartCapture function failed, error should be %v, error: %v, shutdown error: %v, logs: %q", fs.ErrNotExist, err, shutdownErr, logs.String())
		return
	}
}

// Test if app.closeCaptureFile returns with the expected output: no file and stdout are not closed, a file is.
func TestCloseCaptureFilePositive(state *testing.T) {
	file, err := os.Create(filepath.Join(state.TempDir(), "capture.pcapng"))

	if err != nil {
		state.Fatalf("Test of app.closeCaptureFile failed, cannot create the file, error: %s", err.Error())
	}

	err = errors.Join(closeCaptureFile(nil), closeCaptureFile(os.Stdout), closeCaptureFile(file))
	_, statErr := os.Stdout.Stat()

	if (err != nil) || (statErr != nil) || !errors.Is(file.Close(), os.ErrClosed) {
		state.Errorf("Test of app.closeCaptureFile function failed, only the file should be closed, error: %v, stdout error: %v", err, statErr)
		return
	}
}
