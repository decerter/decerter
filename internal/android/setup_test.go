// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package android

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// one answer of the fake adb: the first rule whose Match is part of <arguments> (without -s serial) prints Output and exits with Status;
// <root> matches only adb root, <push only the start of a push
type adbRule struct {
	Match  string
	Output string
	Status int
}

// a fake Android SDK in a temporary directory: platform-tools/adb answers by its rules and logs its arguments, emulator/emulator is written by the test
type fakeSDK struct {
	Directory string
	ADB       string
	Emulator  string
	Log       string
	Binary    string
	ARMBinary string
}

var (
	errWrite = errors.New("write failed")
	// the adb calls of a setup and a remove on the emulator emulator-5580 with adbd as shell, every step works
	workingRules = []adbRule{
		{Match: "<devices>", Output: "List of devices attached\nemulator-5580\tdevice\n", Status: 0},
		{Match: "echo abi=", Output: deviceInfoOutput, Status: 0},
		{Match: "<root>", Output: "restarting adbd as root\n", Status: 0},
		{Match: "<shell id -u>", Output: "0\n", Status: 0},
		{Match: "<shell pidof decerter || true>", Output: "", Status: 0},
		{Match: "cat /data/system/packages.list", Output: packagesList, Status: 0},
		{Match: "if [ -d /data/local/tmp/decerter ]", Output: "no\n", Status: 0},
		{Match: "<push ", Output: "1 file pushed\n", Status: 0},
		{Match: "<shell chmod 755 /data/local/tmp/decerter>", Output: "", Status: 0},
		{Match: "/data/local/tmp/decerter --version", Output: "decerter 1.2.3\n", Status: 0},
		{Match: "android tls --package", Output: "io.decerter.java: no libflutter.so and no Chromium library, not a Flutter or Chromium app; Java TLS goes through Conscrypt\n", Status: 0},
		{Match: "echo wrote", Output: "wrote\n", Status: 0},
		{Match: "echo removed", Output: "removed\n", Status: 0},
		{Match: "<forward --list>", Output: forwardsOutput, Status: 0},
		{Match: "<forward --remove ", Output: "", Status: 0},
		{Match: "<forward tcp:0 ", Output: "41461\n", Status: 0},
		{Match: "<forward tcp:", Output: "", Status: 0},
		{Match: "[ -e /data/local/tmp/decerter ]", Output: "yes\n", Status: 0},
		{Match: "[ -e /data/local/tmp/decerter.d/netd-hooks.json ]", Output: "yes\n", Status: 0},
		{Match: "android restore", Output: "restored\n", Status: 0},
		{Match: "rm -rf /data/local/tmp/decerter", Output: "", Status: 0},
		{Match: "getprop sys.boot_completed", Output: "1\n", Status: 0},
		{Match: "<emu avd name>", Output: "decerter-a15\nOK\n", Status: 0},
	}
	// what a rooted phone answers: no qemu property, adbd can't be root, su can
	phoneRules = []adbRule{
		{Match: "echo abi=", Output: "abi=arm64-v8a\nrelease=VanillaIceCream\nsdk=35\nkernel=6.6.50-android15-8-g1\nmodel=Pixel 9\ntype=user\nqemu=\nuid=2000\n", Status: 0},
		{Match: "<root>", Output: "adbd cannot run as root in production builds\n", Status: 1},
		{Match: "<shell su -c 'id -u'>", Output: "0\n", Status: 0},
	}
)

// an output that fails every write
type failingWriter struct{}

func (writer failingWriter) Write(data []byte) (count int, err error) {
	err = errWrite
	return
}

// the rules in front of base, the first match wins
func withRules(base []adbRule, rules ...adbRule) (combined []adbRule) {
	combined = append(slices.Clone(rules), base...)
	return
}

func writeScript(path string, body string) (err error) {
	err = os.MkdirAll(filepath.Dir(path), 0o700)

	if err != nil {
		return
	}

	err = os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700)
	return
}

// the fake adb: log the arguments, drop -s serial, answer by the first rule that matches
func writeFakeADB(path string, log string, rules []adbRule) (err error) {
	var body strings.Builder
	body.WriteString("printf '%s\\n' \"$*\" >> " + shellQuote(log) + "\nif [ \"$1\" = -s ]; then shift 2; fi\ncase \"<$*>\" in\n")

	for _, rule := range rules {
		body.WriteString("*" + shellQuote(rule.Match) + "*) printf '%s' " + shellQuote(rule.Output) + "; exit " + strconv.Itoa(rule.Status) + " ;;\n")
	}

	body.WriteString("esac\necho \"fake adb: unexpected $*\" >&2\nexit 1\n")
	err = writeScript(path, body.String())
	return
}

// a fake SDK with adb in its platform-tools; ADB points to it, the SDK variables are empty, HOME, PATH and TMPDIR are empty directories of the test
// so neither the host's SDK nor its adb or emulator is found
func newFakeSDK(state *testing.T, rules []adbRule) (sdk fakeSDK) {
	directory := state.TempDir()
	sdk = fakeSDK{
		Directory: directory,
		ADB:       filepath.Join(directory, "sdk", "platform-tools", "adb"),
		Emulator:  filepath.Join(directory, "sdk", "emulator", "emulator"),
		Log:       filepath.Join(directory, "adb.log"),
		Binary:    filepath.Join(directory, "decerter-amd64"),
		ARMBinary: filepath.Join(directory, "decerter-arm64"),
	}
	err := errors.Join(os.MkdirAll(filepath.Join(directory, "home"), 0o700), os.MkdirAll(filepath.Join(directory, "bin"), 0o700), os.MkdirAll(filepath.Join(directory, "tmp"), 0o700))

	if err == nil {
		err = errors.Join(writeFakeADB(sdk.ADB, sdk.Log, rules), writeELF(sdk.Binary, elf.ELFCLASS64, elf.EM_X86_64, false), writeELF(sdk.ARMBinary, elf.ELFCLASS64, elf.EM_AARCH64, false))
	}

	if err != nil {
		state.Fatalf("Test of android failed, cannot create the fake SDK, error: %s", err.Error())
	}

	state.Setenv("ADB", sdk.ADB)
	state.Setenv("ANDROID_HOME", "")
	state.Setenv("ANDROID_SDK_ROOT", "")
	state.Setenv("HOME", filepath.Join(directory, "home"))
	state.Setenv("PATH", filepath.Join(directory, "bin"))
	state.Setenv("TMPDIR", filepath.Join(directory, "tmp"))
	return
}

// the arguments of every adb call so far, one a line
func (sdk fakeSDK) calls() (calls string, err error) {
	data, err := os.ReadFile(sdk.Log)

	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}

	calls = string(data)
	return
}

// Test if android.Setup returns with the expected output: an emulator with adb root, a rooted phone through su, a running AVD, Chrome with its flags file,
// the forwards of the api socket kept, replaced or picked by adb.
func TestSetupPositive(state *testing.T) {
	positiveCases := []struct {
		Name     string
		Rules    []adbRule
		Options  Options
		IsPath   bool
		Phone    bool
		Expected []string
		Calls    []string
	}{
		{
			Name: "chrome on the emulator",
			Rules: withRules(workingRules,
				adbRule{Match: "android tls --package", Output: "com.android.chrome: Chrome 140.0.7339.0 of com.google.android.trichromelibrary_636771938, BoringSSL offsets known\ncom.android.chrome: " + ChromiumQUICLine + "\n", Status: 0},
			),
			Options:  Options{Serial: "", AVD: "", Binary: "", Port: 0, Package: "com.android.chrome", Executable: "", Command: "decerter"},
			IsPath:   false,
			Phone:    false,
			Expected: []string{"adb      ", "device   emulator-5580, sdk_gphone64_x86_64 (emulator)", "root     adbd runs as root (adb root)", "package  com.android.chrome, uid 10120", "binary   /data/local/tmp/decerter, decerter 1.2.3, pushed from ", "tls      Conscrypt offsets for Android 15 on x86_64", "app      com.android.chrome: Chrome 140", "quic     com.android.chrome is a Chromium app", "chrome   wrote /data/local/tmp/chrome-command-line", "api      adb forward tcp:41459 localabstract:decerter-api", " -s emulator-5580 shell -tt /data/local/tmp/decerter run --intercept --api-socket @decerter-api --package com.android.chrome --block-quic\n", "decerter ui --api-socket 127.0.0.1:41459\n", "Undo the setup with: decerter android setup --remove --serial emulator-5580\n"},
			Calls:    []string{"-s emulator-5580 push "},
		},
		{
			Name:     "no package, adb on PATH, another port",
			Rules:    workingRules,
			Options:  Options{Serial: "emulator-5580", AVD: "", Binary: "", Port: 8080, Package: "", Executable: "", Command: "/opt/my tools/decerter"},
			IsPath:   true,
			Phone:    false,
			Expected: []string{"api      adb forward tcp:8080 localabstract:decerter-api", "\n  adb -s emulator-5580 shell -tt /data/local/tmp/decerter run --intercept --api-socket @decerter-api --package PACKAGE\n", "PACKAGE is the app's package name", "'/opt/my tools/decerter' ui --api-socket 127.0.0.1:8080\n"},
			Calls:    []string{"-s emulator-5580 forward --remove tcp:41459\n", "-s emulator-5580 forward tcp:8080 localabstract:decerter-api\n"},
		},
		{
			Name:     "adbd already root, a running AVD",
			Rules:    withRules(workingRules, adbRule{Match: "echo abi=", Output: strings.Replace(deviceInfoOutput, "uid=2000", "uid=0", 1), Status: 0}),
			Options:  Options{Serial: "", AVD: "decerter-a15", Binary: "", Port: 0, Package: "com.google.android.youtube", Executable: "", Command: "decerter"},
			IsPath:   false,
			Phone:    false,
			Expected: []string{"root     adbd runs as root\n", "device   emulator-5580"},
			Calls:    []string{"-s emulator-5580 emu avd name\n"},
		},
		{
			Name: "a rooted phone with su, a shared uid, a tls check that fails",
			Rules: withRules(workingRules, append(slices.Clone(phoneRules),
				adbRule{Match: "android tls --package", Output: "com.android.settings: unknown\n", Status: 1},
				adbRule{Match: "<forward --list>", Output: "", Status: 0},
			)...),
			Options:  Options{Serial: "", AVD: "", Binary: "", Port: 0, Package: "com.android.settings", Executable: "", Command: "decerter"},
			IsPath:   false,
			Phone:    true,
			Expected: []string{"device   emulator-5580, Pixel 9 (real device, experimental)", "root     su, adbd cannot run as root on this user build", "tls      no Conscrypt offsets for Android VanillaIceCream", "app      com.android.settings: unknown", "api      adb forward tcp:41461 localabstract:decerter-api", `shell -tt "su -c '/data/local/tmp/decerter run --intercept --api-socket @decerter-api --package com.android.settings'"`, "127.0.0.1:41461\n"},
			Calls:    []string{"shell su -c 'cat /data/system/packages.list'\n", "push " + "ARM"},
		},
		{
			Name: "chrome with a flags file of the user",
			Rules: withRules(workingRules,
				adbRule{Match: "android tls --package", Output: "com.android.chrome: " + ChromiumQUICLine + "\n", Status: 0},
				adbRule{Match: "echo wrote", Output: "kept\n", Status: 0},
			),
			Options:  Options{Serial: "", AVD: "", Binary: "", Port: 0, Package: "com.android.chrome", Executable: "", Command: "decerter"},
			IsPath:   false,
			Phone:    false,
			Expected: []string{"chrome   kept /data/local/tmp/chrome-command-line, it is not the one setup writes"},
			Calls:    []string{},
		},
	}

	for _, positive := range positiveCases {
		sdk := newFakeSDK(state, positive.Rules)
		options := positive.Options
		options.Binary = sdk.Binary

		if positive.Phone {
			options.Binary = sdk.ARMBinary
		}

		if positive.IsPath {
			state.Setenv("PATH", filepath.Dir(sdk.ADB))
		}

		output := &bytes.Buffer{}
		err := Setup(context.Background(), options, output, slog.New(slog.DiscardHandler))
		calls, callsErr := sdk.calls()

		if (err != nil) || (callsErr != nil) {
			state.Errorf("Test of android.Setup function failed, case %q, error: %v, calls error: %v, output: %s, calls: %s", positive.Name, err, callsErr, output.String(), calls)
			continue
		}

		for _, expected := range positive.Expected {
			if !strings.Contains(output.String(), expected) {
				state.Errorf("Test of android.Setup function failed, case %q, output should contain %q, output: %s", positive.Name, expected, output.String())
			}
		}

		for _, expected := range positive.Calls {
			expected = strings.ReplaceAll(expected, "ARM", sdk.ARMBinary)

			if !strings.Contains(calls, expected) {
				state.Errorf("Test of android.Setup function failed, case %q, calls should contain %q, calls: %s", positive.Name, expected, calls)
			}
		}
	}
}

// Test if android.Setup returns with the expected errors: every adb call that fails, a device decerter can't run on, no root, a running decerter, a package,
// binary, flags file or forward that doesn't work; the binary is not pushed when the device is refused.
func TestSetupNegative(state *testing.T) {
	negativeCases := []struct {
		Name     string
		Rules    []adbRule
		Package  string
		Port     uint16
		AVD      string
		Phone    bool
		ARM      bool
		Timeout  time.Duration
		Expected error
		Text     string
	}{
		{Name: "adb devices fails", Rules: withRules(workingRules, adbRule{Match: "<devices>", Output: "", Status: 1}), Expected: ErrADB, Text: "adb devices"},
		{Name: "no device", Rules: withRules(workingRules, adbRule{Match: "<devices>", Output: "List of devices attached\n\n", Status: 0}), Expected: ErrNoDevice, Text: "adb sees no device"},
		{Name: "the name of a running emulator", Rules: withRules(workingRules, adbRule{Match: "<emu avd name>", Output: "", Status: 1}), AVD: "decerter-a15", Expected: ErrADB, Text: "emu avd name"},
		{Name: "getprop fails", Rules: withRules(workingRules, adbRule{Match: "echo abi=", Output: "", Status: 1}), Expected: ErrADB, Text: "adb -s emulator-5580 shell"},
		{Name: "no properties", Rules: withRules(workingRules, adbRule{Match: "echo abi=", Output: "error: closed\n", Status: 0}), Expected: ErrDeviceInfo, Text: "no abi"},
		{Name: "Android 14", Rules: withRules(workingRules, adbRule{Match: "echo abi=", Output: strings.Replace(deviceInfoOutput, "sdk=35", "sdk=34", 1), Status: 0}), Expected: ErrOldAndroid, Text: "API level 34"},
		{Name: "a binary of another architecture", Rules: workingRules, ARM: true, Expected: ErrBinary, Text: "the device needs amd64"},
		{Name: "adbd can't be root on the emulator", Rules: withRules(workingRules, adbRule{Match: "<root>", Output: "adbd cannot run as root in production builds\n", Status: 1}), Expected: ErrNoRoot, Text: "use a Google APIs image"},
		{Name: "su refused on a phone", Rules: withRules(workingRules, append([]adbRule{{Match: "<shell su -c 'id -u'>", Output: "Permission denied\n", Status: 1}}, phoneRules...)...), Phone: true, Expected: ErrNoRoot, Text: "on this user build"},
		{Name: "adbd stays shell after adb root", Rules: withRules(workingRules, adbRule{Match: "<shell id -u>", Output: "2000\n", Status: 0}), Timeout: 600 * time.Millisecond, Expected: ErrNoRoot, Text: `adb root: "restarting adbd as root"`},
		{Name: "decerter runs", Rules: withRules(workingRules, adbRule{Match: "<shell pidof decerter || true>", Output: "1234\n", Status: 0}), Expected: ErrDecerterRunning, Text: "pid 1234"},
		{Name: "pidof fails", Rules: withRules(workingRules, adbRule{Match: "<shell pidof decerter || true>", Output: "", Status: 255}), Expected: ErrADB, Text: "pidof decerter"},
		{Name: "no packages.list", Rules: withRules(workingRules, adbRule{Match: "cat /data/system/packages.list", Output: "", Status: 1}), Package: "com.android.chrome", Expected: ErrADB, Text: "packages.list"},
		{Name: "a broken packages.list", Rules: withRules(workingRules, adbRule{Match: "cat /data/system/packages.list", Output: "broken\n", Status: 0}), Package: "com.android.chrome", Expected: ErrPackagesList, Text: "has no uid"},
		{Name: "an unknown package", Rules: workingRules, Package: "com.android.chrom", Expected: ErrUnknownPackage, Text: "com.android.chrome"},
		{Name: "a directory at the binary path", Rules: withRules(workingRules, adbRule{Match: "if [ -d /data/local/tmp/decerter ]", Output: "yes\n", Status: 0}), Expected: ErrBinaryPath, Text: "is a directory"},
		{Name: "the directory check fails", Rules: withRules(workingRules, adbRule{Match: "if [ -d /data/local/tmp/decerter ]", Output: "", Status: 1}), Expected: ErrADB, Text: "if [ -d"},
		{Name: "push fails", Rules: withRules(workingRules, adbRule{Match: "<push ", Output: "", Status: 1}), Expected: ErrADB, Text: "adb -s emulator-5580 push"},
		{Name: "chmod fails", Rules: withRules(workingRules, adbRule{Match: "<shell chmod 755 /data/local/tmp/decerter>", Output: "", Status: 1}), Expected: ErrADB, Text: "chmod 755"},
		{Name: "the binary does not run", Rules: withRules(workingRules, adbRule{Match: "/data/local/tmp/decerter --version", Output: "", Status: 126}), Expected: ErrBinaryNotWorking, Text: "--version"},
		{Name: "the binary is no decerter", Rules: withRules(workingRules, adbRule{Match: "/data/local/tmp/decerter --version", Output: "hello\n", Status: 0}), Expected: ErrBinaryNotWorking, Text: `printed "hello"`},
		{Name: "the flags file can't be written", Rules: withRules(workingRules, adbRule{Match: "android tls --package", Output: ChromiumQUICLine + "\n", Status: 0}, adbRule{Match: "echo wrote", Output: "", Status: 1}), Package: "com.android.chrome", Expected: ErrADB, Text: "chrome-command-line"},
		{Name: "the flags file check answers nonsense", Rules: withRules(workingRules, adbRule{Match: "android tls --package", Output: ChromiumQUICLine + "\n", Status: 0}, adbRule{Match: "echo wrote", Output: "cmp: not found\n", Status: 0}), Package: "com.android.chrome", Expected: ErrChromeFlags, Text: `"cmp: not found\n"`},
		{Name: "forward --list fails", Rules: withRules(workingRules, adbRule{Match: "<forward --list>", Output: "", Status: 1}), Expected: ErrADB, Text: "forward --list"},
		{Name: "an old forward can't be removed", Rules: withRules(workingRules, adbRule{Match: "<forward --remove ", Output: "", Status: 1}), Port: 8080, Expected: ErrADB, Text: "forward --remove tcp:41459"},
		{Name: "forward fails", Rules: withRules(workingRules, adbRule{Match: "<forward tcp:", Output: "", Status: 1}), Expected: ErrForward, Text: "localabstract:decerter-api"},
		{Name: "adb picks no port", Rules: withRules(workingRules, adbRule{Match: "<forward --list>", Output: "", Status: 0}, adbRule{Match: "<forward tcp:0 ", Output: "error\n", Status: 0}), Expected: ErrForward, Text: `"tcp:error"`},
	}

	for _, negative := range negativeCases {
		sdk := newFakeSDK(state, negative.Rules)
		options := Options{Serial: "", AVD: negative.AVD, Binary: sdk.Binary, Port: negative.Port, Package: negative.Package, Executable: "", Command: "decerter"}

		if negative.Phone || negative.ARM {
			options.Binary = sdk.ARMBinary
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)

		if negative.Timeout != 0 {
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), negative.Timeout)
		}

		output := &bytes.Buffer{}
		err := Setup(ctx, options, output, slog.New(slog.DiscardHandler))
		cancel()

		if !errors.Is(err, negative.Expected) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of android.Setup function failed, case %q, error should be %v with %q, error: %v, output: %s", negative.Name, negative.Expected, negative.Text, err, output.String())
		}
	}

	// a device that is refused gets nothing pushed
	sdk := newFakeSDK(state, withRules(workingRules, adbRule{Match: "echo abi=", Output: strings.Replace(deviceInfoOutput, "abi=x86_64", "abi=armeabi-v7a", 1), Status: 0}))
	err := Setup(context.Background(), Options{Serial: "", AVD: "", Binary: sdk.Binary, Port: 0, Package: "", Executable: "", Command: "decerter"}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))
	calls, callsErr := sdk.calls()

	if !errors.Is(err, ErrUnsupportedABI) || (callsErr != nil) || strings.Contains(calls, "push") || strings.Contains(calls, "root") {
		state.Errorf("Test of android.Setup function failed, an armeabi-v7a device should be refused before root and push, error: %v, calls error: %v, calls: %s", err, callsErr, calls)
		return
	}

	// without adb
	state.Setenv("ADB", "")
	err = Setup(context.Background(), Options{Serial: "", AVD: "", Binary: sdk.Binary, Port: 0, Package: "", Executable: "", Command: "decerter"}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))

	if !errors.Is(err, ErrNoADB) {
		state.Errorf("Test of android.Setup function failed, error should be %v, error: %v", ErrNoADB, err)
		return
	}
}

// Test if android.Setup returns with the expected errors when its output fails: the setup still runs and the write error is returned.
func TestSetupOutputNegative(state *testing.T) {
	sdk := newFakeSDK(state, workingRules)
	err := Setup(context.Background(), Options{Serial: "", AVD: "", Binary: sdk.Binary, Port: 0, Package: "", Executable: "", Command: "decerter"}, failingWriter{}, slog.New(slog.DiscardHandler))
	calls, callsErr := sdk.calls()

	if !errors.Is(err, errWrite) || (callsErr != nil) || !strings.Contains(calls, "forward tcp:41459 localabstract:decerter-api") {
		state.Errorf("Test of android.Setup function failed, error should be %v after the forward, error: %v, calls error: %v, calls: %s", errWrite, err, callsErr, calls)
		return
	}
}

// Test if android.Remove returns with the expected output: netd's hooks put back by the binary, Chrome's flags file removed or kept, the binary,
// the data directory and the forwards removed; without the binary the state file stays.
func TestRemovePositive(state *testing.T) {
	positiveCases := []struct {
		Name     string
		Rules    []adbRule
		Phone    bool
		Expected []string
		Missing  []string
		Calls    []string
	}{
		{
			Name:     "state and binary",
			Rules:    workingRules,
			Phone:    false,
			Expected: []string{"restore  netd's hooks a killed decerter left shared are exclusive again", "chrome   removed /data/local/tmp/chrome-command-line, setup wrote it", "binary   removed /data/local/tmp/decerter /data/local/tmp/decerter.d\n", "api      removed adb forward tcp:41459 localabstract:decerter-api"},
			Missing:  []string{"tcp:41460"},
			Calls:    []string{"-s emulator-5580 shell /data/local/tmp/decerter android restore 2>&1\n", "-s emulator-5580 shell rm -rf /data/local/tmp/decerter /data/local/tmp/decerter.d\n", "-s emulator-5580 forward --remove tcp:41459\n"},
		},
		{
			Name:     "state without the binary",
			Rules:    withRules(workingRules, adbRule{Match: "[ -e /data/local/tmp/decerter ]", Output: "no\n", Status: 0}, adbRule{Match: "echo removed", Output: "kept\n", Status: 0}),
			Phone:    false,
			Expected: []string{"chrome   kept /data/local/tmp/chrome-command-line, it changed since setup wrote it", "binary   no binary at /data/local/tmp/decerter, removed /data/local/tmp/decerter\n"},
			Missing:  []string{"restore", "decerter.d\n"},
			Calls:    []string{"-s emulator-5580 shell rm -rf /data/local/tmp/decerter\n"},
		},
		{
			Name:     "nothing on a phone with su",
			Rules:    withRules(workingRules, append(slices.Clone(phoneRules), adbRule{Match: "<shell if [ -e /data/local/tmp/decerter", Output: "no\n", Status: 0}, adbRule{Match: "echo removed", Output: "none\n", Status: 0}, adbRule{Match: "<forward --list>", Output: "", Status: 0})...),
			Phone:    true,
			Expected: []string{"root     su", "binary   no binary at /data/local/tmp/decerter, removed /data/local/tmp/decerter /data/local/tmp/decerter.d\n"},
			Missing:  []string{"chrome   ", "api      "},
			Calls:    []string{"-s emulator-5580 shell su -c 'rm -rf /data/local/tmp/decerter /data/local/tmp/decerter.d'\n"},
		},
	}

	for _, positive := range positiveCases {
		sdk := newFakeSDK(state, positive.Rules)
		output := &bytes.Buffer{}
		err := Remove(context.Background(), Options{Serial: "emulator-5580", AVD: "", Binary: "", Port: 0, Package: "", Executable: "", Command: "decerter"}, output, slog.New(slog.DiscardHandler))
		calls, callsErr := sdk.calls()

		if (err != nil) || (callsErr != nil) {
			state.Errorf("Test of android.Remove function failed, case %q, error: %v, calls error: %v, output: %s, calls: %s", positive.Name, err, callsErr, output.String(), calls)
			continue
		}

		for _, expected := range positive.Expected {
			if !strings.Contains(output.String(), expected) {
				state.Errorf("Test of android.Remove function failed, case %q, output should contain %q, output: %s", positive.Name, expected, output.String())
			}
		}

		for _, missing := range positive.Missing {
			if strings.Contains(output.String(), missing) {
				state.Errorf("Test of android.Remove function failed, case %q, output should not contain %q, output: %s", positive.Name, missing, output.String())
			}
		}

		for _, expected := range positive.Calls {
			if !strings.Contains(calls, expected) {
				state.Errorf("Test of android.Remove function failed, case %q, calls should contain %q, calls: %s", positive.Name, expected, calls)
			}
		}
	}
}

// Test if android.Remove returns with the expected errors: no device, no root, a running decerter and every adb call that fails.
func TestRemoveNegative(state *testing.T) {
	negativeCases := []struct {
		Name     string
		Rules    []adbRule
		Expected error
		Text     string
	}{
		{Name: "no such device", Rules: withRules(workingRules, adbRule{Match: "<devices>", Output: "List of devices attached\nemulator-5582\tdevice\n", Status: 0}), Expected: ErrNoDevice, Text: "emulator-5580"},
		{Name: "no root", Rules: withRules(workingRules, adbRule{Match: "<root>", Output: "adbd cannot run as root in production builds\n", Status: 1}), Expected: ErrNoRoot, Text: "emulator-5580"},
		{Name: "decerter runs", Rules: withRules(workingRules, adbRule{Match: "<shell pidof decerter || true>", Output: "77 78\n", Status: 0}), Expected: ErrDecerterRunning, Text: "adb shell kill 77 78"},
		{Name: "the binary check fails", Rules: withRules(workingRules, adbRule{Match: "[ -e /data/local/tmp/decerter ]", Output: "", Status: 1}), Expected: ErrADB, Text: "[ -e /data/local/tmp/decerter ]"},
		{Name: "restore fails", Rules: withRules(workingRules, adbRule{Match: "android restore", Output: "could not restore\n", Status: 1}), Expected: ErrADB, Text: "decerter android restore: could not restore"},
		{Name: "the flags file check fails", Rules: withRules(workingRules, adbRule{Match: "echo removed", Output: "", Status: 1}), Expected: ErrADB, Text: "chrome-command-line"},
		{Name: "the flags file check answers nonsense", Rules: withRules(workingRules, adbRule{Match: "echo removed", Output: "huh\n", Status: 0}), Expected: ErrChromeFlags, Text: `"huh\n"`},
		{Name: "rm fails", Rules: withRules(workingRules, adbRule{Match: "rm -rf /data/local/tmp/decerter", Output: "", Status: 1}), Expected: ErrADB, Text: "rm -rf"},
		{Name: "forward --list fails", Rules: withRules(workingRules, adbRule{Match: "<forward --list>", Output: "", Status: 1}), Expected: ErrADB, Text: "forward --list"},
		{Name: "forward --remove fails", Rules: withRules(workingRules, adbRule{Match: "<forward --remove ", Output: "", Status: 1}), Expected: ErrADB, Text: "forward --remove tcp:41459"},
	}

	for _, negative := range negativeCases {
		newFakeSDK(state, negative.Rules)
		output := &bytes.Buffer{}
		err := Remove(context.Background(), Options{Serial: "emulator-5580", AVD: "", Binary: "", Port: 0, Package: "", Executable: "", Command: "decerter"}, output, slog.New(slog.DiscardHandler))

		if !errors.Is(err, negative.Expected) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of android.Remove function failed, case %q, error should be %v with %q, error: %v, output: %s", negative.Name, negative.Expected, negative.Text, err, output.String())
		}
	}
}
