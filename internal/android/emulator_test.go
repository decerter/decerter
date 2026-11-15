// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package android

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	// what emulator -list-avds prints
	avdsOutput string = "INFO    | Storing crashdata in: /tmp/android-user/emu-crash-36.1.9.db\ndecerter-a15\nPixel_9_API_35\n"
	// a boot that keeps running like the emulator does, its pid in emulator.pid
	runningBoot string = "echo $$ > \"$0.pid.tmp\" && /bin/mv \"$0.pid.tmp\" \"$0.pid\"\nexec /bin/sleep 60\n"
)

// the fake emulator: -list-avds runs listBody, a boot runs bootBody
func writeFakeEmulator(path string, listBody string, bootBody string) (err error) {
	err = writeScript(path, "if [ \"$1\" = -list-avds ]; then\n"+listBody+"\nfi\n"+bootBody)
	return
}

// the pid of the fake emulator a boot started, polled until its pid file is there
func emulatorPid(path string) (pid int, err error) {
	deadline := time.Now().Add(10 * time.Second)

	for {
		data, readErr := os.ReadFile(path + ".pid")

		if readErr == nil {
			pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
			return
		}

		if time.Now().After(deadline) {
			err = readErr
			return
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// Test if android.findEmulator returns with the expected output: the emulator of adb's SDK, then of ANDROID_HOME, ANDROID_SDK_ROOT and ~/Android/Sdk, then PATH.
func TestFindEmulatorPositive(state *testing.T) {
	directory := state.TempDir()
	adbSDK := filepath.Join(directory, "adb-sdk")
	androidHome := filepath.Join(directory, "android-home")
	sdkRoot := filepath.Join(directory, "sdk-root")
	home := filepath.Join(directory, "home")
	pathDirectory := filepath.Join(directory, "bin")

	for _, emulator := range []string{filepath.Join(adbSDK, "emulator", "emulator"), filepath.Join(androidHome, "emulator", "emulator"), filepath.Join(sdkRoot, "emulator", "emulator"), filepath.Join(home, "Android", "Sdk", "emulator", "emulator"), filepath.Join(pathDirectory, "emulator")} {
		err := writeScript(emulator, "exit 0\n")

		if err != nil {
			state.Fatalf("Test of android.findEmulator failed, cannot create %s, error: %s", emulator, err.Error())
		}
	}

	positiveCases := []struct {
		Name        string
		ADB         string
		AndroidHome string
		SDKRoot     string
		Home        string
		Expected    string
	}{
		{Name: "the SDK of adb", ADB: filepath.Join(adbSDK, "platform-tools", "adb"), AndroidHome: androidHome, SDKRoot: sdkRoot, Home: home, Expected: filepath.Join(adbSDK, "emulator", "emulator")},
		{Name: "ANDROID_HOME", ADB: "/usr/bin/adb", AndroidHome: androidHome, SDKRoot: sdkRoot, Home: home, Expected: filepath.Join(androidHome, "emulator", "emulator")},
		{Name: "ANDROID_SDK_ROOT", ADB: "/usr/bin/adb", AndroidHome: "", SDKRoot: sdkRoot, Home: home, Expected: filepath.Join(sdkRoot, "emulator", "emulator")},
		{Name: "~/Android/Sdk", ADB: "/usr/bin/adb", AndroidHome: "", SDKRoot: "", Home: home, Expected: filepath.Join(home, "Android", "Sdk", "emulator", "emulator")},
		{Name: "PATH", ADB: "/usr/bin/adb", AndroidHome: "", SDKRoot: "", Home: directory, Expected: filepath.Join(pathDirectory, "emulator")},
	}

	for _, positive := range positiveCases {
		state.Setenv("ANDROID_HOME", positive.AndroidHome)
		state.Setenv("ANDROID_SDK_ROOT", positive.SDKRoot)
		state.Setenv("HOME", positive.Home)
		state.Setenv("PATH", pathDirectory)
		emulator, err := findEmulator(positive.ADB)

		if (err != nil) || (emulator != positive.Expected) {
			state.Errorf("Test of android.findEmulator function failed, case %q, emulator should be %s, emulator: %s, error: %v", positive.Name, positive.Expected, emulator, err)
		}
	}
}

// Test if android.findEmulator returns with the expected errors: no SDK and nothing on PATH.
func TestFindEmulatorNegative(state *testing.T) {
	directory := state.TempDir()
	state.Setenv("ANDROID_HOME", filepath.Join(directory, "missing"))
	state.Setenv("ANDROID_SDK_ROOT", "")
	state.Setenv("HOME", directory)
	state.Setenv("PATH", directory)
	emulator, err := findEmulator(filepath.Join(directory, "platform-tools", "adb"))

	if !errors.Is(err, ErrNoEmulator) {
		state.Errorf("Test of android.findEmulator function failed, error should be %v, emulator: %s, error: %v", ErrNoEmulator, emulator, err)
		return
	}
}

// Test if android.Setup returns with the expected output for an AVD that does not run: it boots it without a window on a free console port and waits
// for sys.boot_completed, the emulator keeps running.
func TestBootAVDPositive(state *testing.T) {
	sdk := newFakeSDK(state, withRules(workingRules, adbRule{Match: "<devices>", Output: "List of devices attached\nemulator-5554\toffline\n", Status: 0}))
	err := writeFakeEmulator(sdk.Emulator, "printf '%s' "+shellQuote(avdsOutput)+"; exit 0", runningBoot)

	if err != nil {
		state.Fatalf("Test of android.Setup failed, cannot write the emulator, error: %s", err.Error())
	}

	output := &bytes.Buffer{}
	err = Setup(context.Background(), Options{Serial: "", AVD: "decerter-a15", Binary: sdk.Binary, Port: 0, Package: "", Executable: "", Command: "decerter"}, output, slog.New(slog.DiscardHandler))
	pid, pidErr := emulatorPid(sdk.Emulator)

	if pidErr == nil {
		state.Cleanup(func() {
			killErr := syscall.Kill(pid, syscall.SIGKILL)

			if (killErr != nil) && !errors.Is(killErr, syscall.ESRCH) {
				state.Errorf("Test of android.Setup failed, cannot kill the fake emulator %d, error: %s", pid, killErr.Error())
			}
		})
	}

	calls, callsErr := sdk.calls()

	if (err != nil) || (pidErr != nil) || (callsErr != nil) {
		state.Errorf("Test of android.Setup function failed, error: %v, pid error: %v, calls error: %v, output: %s", err, pidErr, callsErr, output.String())
		return
	}

	// the emulator-5554 adb lists is skipped, offline or not
	if !strings.Contains(output.String(), "boot     decerter-a15 as emulator-") || strings.Contains(output.String(), "as emulator-5554 ") || !strings.Contains(output.String(), "its log is "+filepath.Join(sdk.Directory, "tmp", "decerter-emulator-")) || !strings.Contains(calls, " shell getprop sys.boot_completed\n") {
		state.Errorf("Test of android.Setup function failed, the AVD should boot on a free port with its log in TMPDIR, output: %s, calls: %s", output.String(), calls)
		return
	}
}

// Test if android.bootAVD returns with the expected errors: no emulator, -list-avds that fails, an unknown AVD, no free port, no log file, an output
// that fails, an emulator that can't start, exits or does not boot in time.
func TestBootAVDNegative(state *testing.T) {
	allPorts := []Device{}

	for port := firstEmulatorPort; port <= lastEmulatorPort; port += 2 {
		allPorts = append(allPorts, Device{Serial: "emulator-" + strconv.Itoa(port), State: "offline"})
	}

	negativeCases := []struct {
		Name       string
		NoEmulator bool
		List       string
		Boot       string
		Rules      []adbRule
		Devices    []Device
		TMPDIR     string
		Output     io.Writer
		Timeout    time.Duration
		Expected   error
		Text       string
	}{
		{Name: "no emulator", NoEmulator: true, Expected: ErrNoEmulator, Text: "could not find the emulator"},
		{Name: "-list-avds fails", List: "exit 1", Expected: ErrNoEmulator, Text: "-list-avds: exit status 1"},
		{Name: "an unknown AVD", List: "printf '%s' 'Pixel_9_API_35\n'; exit 0", Expected: ErrUnknownAVD, Text: "unknown AVD decerter-a15, the AVDs of this user: Pixel_9_API_35"},
		{Name: "no free port", Devices: allPorts, Expected: ErrBoot, Text: "no free console port between 5554 and 5584"},
		{Name: "no log file", TMPDIR: "missing", Expected: os.ErrNotExist, Text: "decerter-emulator-"},
		{Name: "the output fails", Output: failingWriter{}, Expected: errWrite, Text: "write failed"},
		{Name: "the emulator can't start", List: "/bin/chmod 600 \"$0\"; printf '%s' 'decerter-a15\n'; exit 0", Expected: ErrBoot, Text: "permission denied"},
		{Name: "the emulator exits", Boot: "exit 3\n", Rules: withRules(workingRules, adbRule{Match: "getprop sys.boot_completed", Output: "", Status: 1}), Expected: ErrBoot, Text: "the emulator exited after"},
		{Name: "the boot takes too long", Boot: runningBoot, Rules: withRules(workingRules, adbRule{Match: "getprop sys.boot_completed", Output: "0\n", Status: 0}), Timeout: 700 * time.Millisecond, Expected: ErrBoot, Text: "did not boot in 5m0s"},
	}

	for _, negative := range negativeCases {
		rules := negative.Rules

		if rules == nil {
			rules = workingRules
		}

		sdk := newFakeSDK(state, rules)
		list := negative.List
		boot := negative.Boot
		output := negative.Output

		if list == "" {
			list = "printf '%s' " + shellQuote(avdsOutput) + "; exit 0"
		}

		if boot == "" {
			boot = "exit 0\n"
		}

		if output == nil {
			output = &bytes.Buffer{}
		}

		if negative.TMPDIR != "" {
			state.Setenv("TMPDIR", filepath.Join(sdk.Directory, negative.TMPDIR))
		}

		adbPath := sdk.ADB

		if negative.NoEmulator {
			adbPath = filepath.Join(sdk.Directory, "bin", "adb")
		} else if err := writeFakeEmulator(sdk.Emulator, list, boot); err != nil {
			state.Fatalf("Test of android.bootAVD failed, cannot write the emulator, error: %s", err.Error())
		}

		timeout := negative.Timeout

		if timeout == 0 {
			timeout = time.Minute
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		serial, err := bootAVD(ctx, ADB{Path: adbPath, Serial: "", Root: ""}, "decerter-a15", negative.Devices, output)
		cancel()

		if !errors.Is(err, negative.Expected) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of android.bootAVD function failed, case %q, error should be %v with %q, serial: %s, error: %v", negative.Name, negative.Expected, negative.Text, serial, err)
		}
	}
}

// Test if android.Setup returns with the expected errors for an AVD that can't boot.
func TestSetupAVDNegative(state *testing.T) {
	sdk := newFakeSDK(state, withRules(workingRules, adbRule{Match: "<devices>", Output: "List of devices attached\n", Status: 0}))
	err := writeFakeEmulator(sdk.Emulator, "exit 0", "exit 0\n")

	if err != nil {
		state.Fatalf("Test of android.Setup failed, cannot write the emulator, error: %s", err.Error())
	}

	err = Setup(context.Background(), Options{Serial: "", AVD: "decerter-a15", Binary: sdk.Binary, Port: 0, Package: "", Executable: "", Command: "decerter"}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))

	if !errors.Is(err, ErrUnknownAVD) {
		state.Errorf("Test of android.Setup function failed, error should be %v, error: %v", ErrUnknownAVD, err)
		return
	}
}

// Test if android.freeEmulatorPort returns with the expected output: a console port that is taken on loopback or listed by adb is skipped.
func TestFreeEmulatorPortPositive(state *testing.T) {
	listener, listenErr := net.Listen("tcp", "127.0.0.1:5554")

	if listenErr == nil {
		defer func() {
			if closeErr := listener.Close(); closeErr != nil {
				state.Errorf("Test of android.freeEmulatorPort failed, cannot close the listener, error: %s", closeErr.Error())
			}
		}()
	}

	port, err := freeEmulatorPort([]Device{{Serial: "emulator-5556", State: "device"}})

	if (err != nil) || (port == 5554) || (port == 5556) || (port%2 != 0) || (port > lastEmulatorPort) {
		state.Errorf("Test of android.freeEmulatorPort function failed, the port should be a free even port above 5556, port: %d, error: %v", port, err)
		return
	}
}
