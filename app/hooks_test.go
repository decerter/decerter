// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package app

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/tls/boringssl"
)

// an ELF header of the architecture the test runs on, without sections: no symbols, no .rodata
func writeStaticELF(path string) (err error) {
	machines := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}
	header := elf.Header64{
		Ident:     [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(machines[runtime.GOARCH]),
		Version:   uint32(elf.EV_CURRENT),
		Ehsize:    64,
		Phentsize: 56,
		Shentsize: 64,
	}
	file, err := os.Create(path)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	err = binary.Write(file, binary.LittleEndian, header)
	return
}

// Test if app.flutterReleases, app.shortRevision and app.libraryName return with the expected output.
func TestHookNamesPositive(state *testing.T) {
	releases := map[string][]string{"unknown": nil, "3.24.0": {"3.24.0"}, "3.24.0 to 3.24.5": {"3.24.0", "3.24.3", "3.24.5"}}

	for expected, flutter := range releases {
		if text := flutterReleases(flutter); text != expected {
			state.Errorf("Test of app.flutterReleases function failed, releases %q should be %q, text: %q", flutter, expected, text)
			return
		}
	}

	revisions := map[string]string{"": "", "abc": "abc", "0123456789abcdef0123": "0123456789ab"}

	for revision, expected := range revisions {
		if short := shortRevision(revision); short != expected {
			state.Errorf("Test of app.shortRevision function failed, revision %q should be %q, short: %q", revision, expected, short)
			return
		}
	}

	names := map[string]boringssl.LibraryFile{
		"/data/app/x/lib/x86_64/libflutter.so":     {Path: "/data/app/x/lib/x86_64/libflutter.so", Entry: "", Offset: 0, Size: 1},
		"/data/app/x/base.apk!/lib/x86_64/libc.so": {Path: "/data/app/x/base.apk", Entry: "lib/x86_64/libc.so", Offset: 4096, Size: 1},
	}

	for expected, file := range names {
		if name := libraryName(file); name != expected {
			state.Errorf("Test of app.libraryName function failed, name should be %q, name: %q", expected, name)
			return
		}
	}
}

// Test if app.processUID, app.processName and app.libraryKey return with the expected output for this test's own process and files.
func TestProcessInfoPositive(state *testing.T) {
	uid, found := processUID(os.Getpid())

	if !found || (uid != uint32(os.Getuid())) {
		state.Errorf("Test of app.processUID function failed, uid should be %d, uid: %d, found: %v", os.Getuid(), uid, found)
		return
	}

	executable, err := os.Executable()

	if err != nil {
		state.Fatalf("Test of app.processName failed, cannot get the executable, error: %s", err.Error())
	}

	if name := processName(os.Getpid()); !strings.HasSuffix(name, filepath.Base(executable)) {
		state.Errorf("Test of app.processName function failed, name should end in %s, name: %q", filepath.Base(executable), name)
		return
	}

	first := libraryKey(executable)
	second := libraryKey(executable)

	if (first == "") || (first != second) || !strings.Contains(first, ":") {
		state.Errorf("Test of app.libraryKey function failed, the key should be device:inode, keys: %q %q", first, second)
		return
	}
}

// Test if app.processUID, app.processName and app.libraryKey return with the expected output for a process and a file that don't exist.
func TestProcessInfoNegative(state *testing.T) {
	uid, found := processUID(-1)
	name := processName(-1)
	key := libraryKey(filepath.Join(state.TempDir(), "missing"))

	if found || (uid != 0) || (name != "") || (key != "") {
		state.Errorf("Test of app.processUID function failed, nothing should be found, uid: %d, found: %v, name: %q, key: %q", uid, found, name, key)
		return
	}
}

// Test if app.findBoringsslHooks and app.findMappedOpenssl return with the expected output: no BoringSSL on Linux, no mapped libssl without a
// selected process or in this test's process.
func TestFindHooksPositive(state *testing.T) {
	logs := &bytes.Buffer{}
	app := newOptionsApp(state.Context(), appOptions{Platform: platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "", APISocket: ""}}, logs)
	hooks, useBoringssl, seen, err := app.findBoringsslHooks()

	if (err != nil) || useBoringssl || (len(hooks) != 0) || (seen == nil) {
		state.Errorf("Test of app.findBoringsslHooks function failed, Linux has no BoringSSL hook, hooks: %+v, useBoringssl: %v, error: %v", hooks, useBoringssl, err)
		return
	}

	seen = map[string]bool{}

	if mapped := app.findMappedOpenssl(seen); (len(mapped) != 0) || (len(seen) != 0) {
		state.Errorf("Test of app.findMappedOpenssl function failed, no selected process should look at nothing, hooks: %+v, seen: %v", mapped, seen)
		return
	}

	// the go test binary maps no libssl
	app.selection = redirect.Filter{Tgids: []uint32{uint32(os.Getpid())}}

	if mapped := app.findMappedOpenssl(seen); len(mapped) != 0 {
		state.Errorf("Test of app.findMappedOpenssl function failed, this process maps no libssl, hooks: %+v", mapped)
		return
	}

	if err = app.Shutdown(); err != nil {
		state.Errorf("Test of app.Shutdown function failed, error: %s", err.Error())
		return
	}
}

// Test if app.selectedPackages returns with the expected output: no selection reads nothing, a selected pid on a host without packages.list is a warning.
func TestSelectedPackagesPositive(state *testing.T) {
	usePaths(state, state.TempDir())
	// the selected pid is this test's process
	procDirectory = "/proc"
	logs := &bytes.Buffer{}
	app := newOptionsApp(state.Context(), appOptions{Platform: androidPlatform(state.TempDir())}, logs)
	selected, packages := app.selectedPackages()

	if (len(selected) != 0) || (len(packages) != 0) || (logs.Len() != 0) {
		state.Errorf("Test of app.selectedPackages function failed, no selection should read nothing, selected: %+v, logs: %q", selected, logs.String())
		return
	}

	app.keylog = true
	app.filter = redirect.Filter{Tgids: []uint32{uint32(os.Getpid())}}
	selected, packages = app.selectedPackages()

	if (len(selected) != 0) || (len(packages) != 0) || !strings.Contains(logs.String(), "Could not read the installed packages") {
		state.Errorf("Test of app.selectedPackages function failed, a missing packages.list should be a warning, selected: %+v, logs: %q", selected, logs.String())
		return
	}

	if err := app.Shutdown(); err != nil {
		state.Errorf("Test of app.Shutdown function failed, error: %s", err.Error())
		return
	}
}

// Test if app.unknownOpensslError returns with the expected output: the first library's error, nil without one.
func TestUnknownOpensslErrorPositive(state *testing.T) {
	first := errors.New("first")
	err := unknownOpensslError([]unknownOpenssl{{Err: first}, {Err: errors.New("second")}})

	if !errors.Is(err, first) || (unknownOpensslError(nil) != nil) {
		state.Errorf("Test of app.unknownOpensslError function failed, error should be %v, error: %v", first, err)
		return
	}
}
