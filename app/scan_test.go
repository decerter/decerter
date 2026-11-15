// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package app

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/android"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/tls/boringssl"
)

// procDirectory, appDirectory and packagesList point into directory until the test ends
func usePaths(state *testing.T, directory string) {
	previousProc, previousApps, previousPackages := procDirectory, appDirectory, packagesList
	procDirectory = filepath.Join(directory, "proc")
	appDirectory = filepath.Join(directory, "data", "app")
	packagesList = filepath.Join(directory, "data", "system", "packages.list")
	state.Cleanup(func() {
		procDirectory, appDirectory, packagesList = previousProc, previousApps, previousPackages
	})
}

// a file with content, its directories made first
func writeFile(path string, content string) (err error) {
	err = os.MkdirAll(filepath.Dir(path), 0o755)

	if err != nil {
		return
	}

	err = os.WriteFile(path, []byte(content), 0o644)
	return
}

// Test if app.selectedMaps, app.findMappedOpenssl and app.findMappedChromiumHooks return with the expected output: nothing selected reads no process,
// the selected processes' libssl (through /proc/<pid>/root) and Chromium mappings are looked at once, a library that can't be hooked is logged.
func TestFindMappedHooksPositive(state *testing.T) {
	directory := state.TempDir()
	usePaths(state, directory)
	cronet := filepath.Join(directory, "lib", "libcronet.126.0.6452.4.so")
	missing := filepath.Join(directory, "lib", "libmonochrome_64.so")
	maps := "1000-2000 r-xp 00000000 fe:05 1 /usr/lib/libssl.so.3\n" +
		"2000-3000 r-xp 00002000 fe:05 2 " + cronet + "\n" +
		"3000-4000 r-xp 00000000 fe:05 3 " + missing + "\n" +
		"4000-5000 r-xp 00000000 fe:05 4 /usr/lib/libc.so.6\n" +
		"5000-6000 rw-p 00000000 fe:05 4 /usr/lib/libc.so.6\n"
	files := map[string]string{
		filepath.Join(procDirectory, "4242", "maps"):                        maps,
		filepath.Join(procDirectory, "4242", "cmdline"):                     "com.example.app:service\x00--flag\x00",
		filepath.Join(procDirectory, "4242", "root", "usr/lib/libssl.so.3"): "not an ELF file",
		filepath.Join(procDirectory, "4343", "cmdline"):                     "gone\x00",
		filepath.Join(procDirectory, "self", "maps"):                        maps,
		cronet: "not an ELF file",
	}

	for path, content := range files {
		if err := writeFile(path, content); err != nil {
			state.Fatalf("Test of app.findMappedOpenssl failed, cannot write %s, error: %s", path, err.Error())
		}
	}

	logs := &bytes.Buffer{}
	app := newOptionsApp(state.Context(), appOptions{Platform: androidPlatform(state.TempDir())}, logs)
	state.Cleanup(func() {
		if err := app.Shutdown(); err != nil {
			state.Errorf("Test of app.Shutdown function failed, error: %s", err.Error())
		}
	})

	// nothing selected: /proc is not read, even when it can't be
	procDirectory = filepath.Join(directory, "missing")
	seen := map[string]bool{}
	openssl := app.findMappedOpenssl(seen)
	chromium := app.findMappedChromiumHooks(seen)

	if (len(openssl) != 0) || (len(chromium) != 0) || (len(seen) != 0) || (logs.Len() != 0) {
		state.Errorf("Test of app.findMappedChromiumHooks function failed, no selection should read nothing, hooks: %+v %+v, seen: %v, logs: %q", openssl, chromium, seen, logs.String())
		return
	}

	// a selected uid and a /proc that can't be listed is a warning of each
	app.selection = redirect.Filter{UIDs: []uint32{uint32(os.Getuid())}}
	openssl = app.findMappedOpenssl(seen)
	chromium = app.findMappedChromiumHooks(seen)

	if (len(openssl) != 0) || (len(chromium) != 0) || (strings.Count(logs.String(), "Could not list the processes") != 2) {
		state.Errorf("Test of app.findMappedChromiumHooks function failed, an unreadable /proc should be a warning, hooks: %+v %+v, logs: %q", openssl, chromium, logs.String())
		return
	}

	procDirectory = filepath.Join(directory, "proc")
	logs.Reset()
	processes, err := app.selectedMaps()

	if (err != nil) || (len(processes) != 1) || (processes[0].Pid != 4242) || (processes[0].Maps != maps) {
		state.Errorf("Test of app.selectedMaps function failed, only 4242 has maps, processes: %+v, error: %v", processes, err)
		return
	}

	libssl := libraryKey(filepath.Join(procDirectory, "4242", "root", "usr/lib/libssl.so.3"))
	expectedLogs := []string{
		"Could not hook the OpenSSL a selected process maps",
		"Could not hook Chromium's BoringSSL of the app",
		"Could not read a library the process maps",
		"process=com.example.app",
	}

	for range 2 {
		openssl = app.findMappedOpenssl(seen)
		chromium = app.findMappedChromiumHooks(seen)
	}

	for _, expected := range expectedLogs {
		if strings.Count(logs.String(), expected) == 0 {
			state.Errorf("Test of app.findMappedChromiumHooks function failed, the logs should contain %q, logs: %q", expected, logs.String())
			return
		}
	}

	isSeen := seen[libssl] && seen["mapped:"+cronet+"@8192"] && seen[cronet+"@0"] && seen["mapped:"+missing+"@0"] && seen["mapped:/usr/lib/libc.so.6@0"]

	if (len(openssl) != 0) || (len(chromium) != 0) || (libssl == "") || !isSeen || (strings.Count(logs.String(), "level=") != 3) {
		state.Errorf("Test of app.findMappedChromiumHooks function failed, each library should be looked at once, hooks: %+v %+v, seen: %v, logs: %q", openssl, chromium, seen, logs.String())
		return
	}
}

// Test if app.findFlutterHooks returns with the expected output: an install directory is read once, a library that appears in it later is not read
// on the rescan, the directory an update installs into is read, a library that can't be hooked is logged.
func TestFindFlutterHooksPositive(state *testing.T) {
	directory := state.TempDir()
	usePaths(state, directory)
	installed := filepath.Join(appDirectory, "~~a==", "io.decerter.flutter-b==")
	updated := filepath.Join(appDirectory, "~~c==", "io.decerter.flutter-d==")
	isa := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[runtime.GOARCH]

	if err := os.MkdirAll(installed, 0o755); err != nil {
		state.Fatalf("Test of app.findFlutterHooks failed, cannot make %s, error: %s", installed, err.Error())
	}

	logs := &bytes.Buffer{}
	app := newOptionsApp(state.Context(), appOptions{Platform: androidPlatform(state.TempDir())}, logs)
	state.Cleanup(func() {
		if err := app.Shutdown(); err != nil {
			state.Errorf("Test of app.Shutdown function failed, error: %s", err.Error())
		}
	})

	selected := []android.Package{{Name: "io.decerter.flutter", UID: 10123, VersionCode: 1}}
	seen := map[string]bool{}
	hooks := app.findFlutterHooks(selected, seen)

	if (len(hooks) != 0) || !seen["flutter:"+installed] || (logs.Len() != 0) {
		state.Errorf("Test of app.findFlutterHooks function failed, a directory without libflutter.so should be seen, hooks: %+v, seen: %v, logs: %q", hooks, seen, logs.String())
		return
	}

	// the rescan reads only the new directory, not a library that appeared in a directory it read
	if err := writeFile(filepath.Join(installed, "lib", isa, boringssl.FlutterLibraryName), "not an ELF file"); err != nil {
		state.Fatalf("Test of app.findFlutterHooks failed, cannot write the library, error: %s", err.Error())
	}

	if err := os.MkdirAll(updated, 0o755); err != nil {
		state.Fatalf("Test of app.findFlutterHooks failed, cannot make %s, error: %s", updated, err.Error())
	}

	hooks = app.findFlutterHooks(selected, seen)

	if (len(hooks) != 0) || !seen["flutter:"+updated] || (logs.Len() != 0) {
		state.Errorf("Test of app.findFlutterHooks function failed, the rescan should read only the new directory, hooks: %+v, seen: %v, logs: %q", hooks, seen, logs.String())
		return
	}

	// an update into a new directory with a library that can't be hooked
	update := filepath.Join(appDirectory, "~~e==", "io.decerter.flutter-f==")

	if err := writeFile(filepath.Join(update, "lib", isa, boringssl.FlutterLibraryName), "not an ELF file"); err != nil {
		state.Fatalf("Test of app.findFlutterHooks failed, cannot write the library, error: %s", err.Error())
	}

	hooks = app.findFlutterHooks(selected, seen)
	hooks = append(hooks, app.findFlutterHooks(selected, seen)...)

	if (len(hooks) != 0) || !seen["flutter:"+update] || (strings.Count(logs.String(), "Could not hook the Flutter app") != 1) {
		state.Errorf("Test of app.findFlutterHooks function failed, the new directory should be read once, hooks: %+v, seen: %v, logs: %q", hooks, seen, logs.String())
		return
	}
}

// Test if app.selectedPackages returns with the expected output from packages.list: the packages of the selected uids and every package.
func TestSelectedPackagesListPositive(state *testing.T) {
	directory := state.TempDir()
	usePaths(state, directory)
	list := "com.example.app 10123 0 /data/user/0/com.example.app default:targetSdkVersion=35 3003 0 42 1 com.android.vending\n" +
		"com.example.other 10124 0 /data/user/0/com.example.other default:targetSdkVersion=35 3003 0 7 1 com.android.vending\n"

	if err := writeFile(packagesList, list); err != nil {
		state.Fatalf("Test of app.selectedPackages failed, cannot write packages.list, error: %s", err.Error())
	}

	logs := &bytes.Buffer{}
	app := newOptionsApp(state.Context(), appOptions{Platform: androidPlatform(state.TempDir())}, logs)
	state.Cleanup(func() {
		if err := app.Shutdown(); err != nil {
			state.Errorf("Test of app.Shutdown function failed, error: %s", err.Error())
		}
	})

	app.selection = redirect.Filter{UIDs: []uint32{10123}}
	selected, packages := app.selectedPackages()
	expected := []android.Package{{Name: "com.example.app", UID: 10123, VersionCode: 42}}

	if !slices.Equal(selected, expected) || (len(packages) != 2) || (logs.Len() != 0) {
		state.Errorf("Test of app.selectedPackages function failed, selected should be %+v, selected: %+v, packages: %+v, logs: %q", expected, selected, packages, logs.String())
		return
	}
}
