// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package android

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	// adb devices with a header, an emulator, a phone that waits for the prompt and one udev doesn't let adb open
	devicesOutput string = "List of devices attached\nemulator-5580\tdevice\r\n0A1B2C3D\tunauthorized\n0B2C3D4E\tno permissions (missing udev rules? user is in the plugdev group); see [http://developer.android.com/tools/device.html]\n\n"
	// adb forward --list lists the forwards of every device
	forwardsOutput string = "emulator-5580 tcp:41459 localabstract:decerter-api\nemulator-5580 tcp:5000 tcp:5000\nemulator-5582 tcp:41460 localabstract:decerter-api\n\n"
	// deviceInfoCommand on the emulator, adb shell ends the lines with \r\n on old adbd
	deviceInfoOutput string = "abi=x86_64\r\nrelease=15\r\nsdk=35\r\nkernel=6.6.50-android15-8-g8adecb593e9b-ab12525588\r\nmodel=sdk_gphone64_x86_64\r\ntype=userdebug\r\nqemu=11\r\nuid=2000\r\n"
)

var (
	emulatorInfo = DeviceInfo{ABI: "x86_64", Release: "15", SDK: 35, Kernel: "6.6.50-android15-8-g8adecb593e9b-ab12525588", Model: "sdk_gphone64_x86_64", BuildType: "userdebug", IsEmulator: true, UID: "2000"}
)

// Test if android.ParseDevices returns with the expected output.
func TestParseDevicesPositive(state *testing.T) {
	expected := []Device{
		{Serial: "emulator-5580", State: "device"},
		{Serial: "0A1B2C3D", State: "unauthorized"},
		{Serial: "0B2C3D4E", State: "no permissions (missing udev rules? user is in the plugdev group); see [http://developer.android.com/tools/device.html]"},
	}
	devices := ParseDevices(devicesOutput)

	if !reflect.DeepEqual(devices, expected) {
		state.Errorf("Test of android.ParseDevices function failed, devices should be %+v, devices: %+v", expected, devices)
		return
	}
}

// Test if android.ParseDevices returns with the expected output for adb devices without a device.
func TestParseDevicesNegative(state *testing.T) {
	for _, output := range []string{"", "List of devices attached\n\n", "* daemon not running; starting now at tcp:5037\n* daemon started successfully\nList of devices attached\n"} {
		devices := ParseDevices(output)

		if len(devices) != 0 {
			state.Errorf("Test of android.ParseDevices function failed, output %q should have no device, devices: %+v", output, devices)
			return
		}
	}
}

// Test if android.SelectDevice returns with the expected output: the serial asked for, or the one device adb can use.
func TestSelectDevicePositive(state *testing.T) {
	devices := ParseDevices(devicesOutput)
	positiveCases := []struct {
		Serial   string
		Expected string
	}{
		{Serial: "", Expected: "emulator-5580"},
		{Serial: "emulator-5580", Expected: "emulator-5580"},
	}

	for _, positive := range positiveCases {
		device, err := SelectDevice(devices, positive.Serial)

		if (err != nil) || (device.Serial != positive.Expected) {
			state.Errorf("Test of android.SelectDevice function failed, serial %q, device should be %s, device: %+v, error: %v", positive.Serial, positive.Expected, device, err)
			return
		}
	}
}

// Test if android.SelectDevice returns with the expected errors: a missing serial, a device adb can't use, several devices and none.
func TestSelectDeviceNegative(state *testing.T) {
	devices := ParseDevices(devicesOutput)
	negativeCases := []struct {
		Devices  []Device
		Serial   string
		Expected error
		Text     string
	}{
		{Devices: devices, Serial: "emulator-5999", Expected: ErrNoDevice, Text: "no such device emulator-5999, adb sees emulator-5580 (device), 0A1B2C3D (unauthorized), 0B2C3D4E (no permissions"},
		{Devices: nil, Serial: "emulator-5999", Expected: ErrNoDevice, Text: "adb sees no device"},
		{Devices: devices, Serial: "0A1B2C3D", Expected: ErrDeviceState, Text: "0A1B2C3D is unauthorized, allow USB debugging"},
		{Devices: devices, Serial: "0B2C3D4E", Expected: ErrDeviceState, Text: "0B2C3D4E: no permissions (missing udev rules?"},
		{Devices: []Device{{Serial: "emulator-5554", State: "offline"}}, Serial: "", Expected: ErrDeviceState, Text: "emulator-5554 is offline"},
		{Devices: nil, Serial: "", Expected: ErrNoDevice, Text: "boot an AVD with --avd"},
		{Devices: append(devices, Device{Serial: "emulator-5582", State: "device"}), Serial: "", Expected: ErrSeveralDevices, Text: "pick one with --serial: emulator-5580 (device), emulator-5582 (device)"},
	}

	for _, negative := range negativeCases {
		device, err := SelectDevice(negative.Devices, negative.Serial)

		if !errors.Is(err, negative.Expected) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of android.SelectDevice function failed, serial %q, error should be %v with %q, device: %+v, error: %v", negative.Serial, negative.Expected, negative.Text, device, err)
			return
		}
	}
}

// Test if android.ParseForwards and android.apiForwards return with the expected output: the forwards of one device to the api socket.
func TestParseForwardsPositive(state *testing.T) {
	forwards := apiForwards(ParseForwards(forwardsOutput), "emulator-5580")
	expected := []Forward{{Serial: "emulator-5580", Local: "tcp:41459", Remote: "localabstract:decerter-api"}}

	if !reflect.DeepEqual(forwards, expected) {
		state.Errorf("Test of android.ParseForwards function failed, forwards should be %+v, forwards: %+v", expected, forwards)
		return
	}
}

// Test if android.ParseForwards and android.apiForwards return with the expected output when no forward fits.
func TestParseForwardsNegative(state *testing.T) {
	positives := [][]Forward{
		apiForwards(ParseForwards(""), "emulator-5580"),
		apiForwards(ParseForwards(forwardsOutput), "emulator-5584"),
		apiForwards(ParseForwards("emulator-5580 tcp:41459\nemulator-5580 tcp:1 localabstract:other-socket\n"), "emulator-5580"),
	}

	for _, forwards := range positives {
		if len(forwards) != 0 {
			state.Errorf("Test of android.ParseForwards function failed, there should be no forward, forwards: %+v", forwards)
			return
		}
	}
}

// Test if android.ParseDeviceInfo returns with the expected output.
func TestParseDeviceInfoPositive(state *testing.T) {
	info, err := ParseDeviceInfo(deviceInfoOutput)

	if (err != nil) || !reflect.DeepEqual(info, emulatorInfo) {
		state.Errorf("Test of android.ParseDeviceInfo function failed, info should be %+v, info: %+v, error: %v", emulatorInfo, info, err)
		return
	}

	// a phone: no qemu property, adbd as root
	info, err = ParseDeviceInfo("abi=arm64-v8a\nrelease=16\nsdk=36\nkernel=6.12.23-android16-5-g1\nmodel=Pixel 10\ntype=user\nqemu=\nuid=0\n")
	expected := DeviceInfo{ABI: "arm64-v8a", Release: "16", SDK: 36, Kernel: "6.12.23-android16-5-g1", Model: "Pixel 10", BuildType: "user", IsEmulator: false, UID: "0"}

	if (err != nil) || !reflect.DeepEqual(info, expected) {
		state.Errorf("Test of android.ParseDeviceInfo function failed, info should be %+v, info: %+v, error: %v", expected, info, err)
		return
	}
}

// Test if android.ParseDeviceInfo returns with the expected errors: a missing value, an API level that is no number.
func TestParseDeviceInfoNegative(state *testing.T) {
	negativeCases := []string{
		"",
		"error: closed\n",
		strings.Replace(deviceInfoOutput, "kernel=6.6.50-android15-8-g8adecb593e9b-ab12525588", "kernel=", 1),
		strings.Replace(deviceInfoOutput, "abi=x86_64\r\n", "", 1),
		strings.Replace(deviceInfoOutput, "sdk=35", "sdk=VanillaIceCream", 1),
	}

	for _, negative := range negativeCases {
		info, err := ParseDeviceInfo(negative)

		if !errors.Is(err, ErrDeviceInfo) {
			state.Errorf("Test of android.ParseDeviceInfo function failed, output %q, error should be %v, info: %+v, error: %v", negative, ErrDeviceInfo, info, err)
			return
		}
	}
}

// Test if android.ParseKernel returns with the expected output.
func TestParseKernelPositive(state *testing.T) {
	positiveCases := map[string]Kernel{
		"6.6.50-android15-8-g8adecb593e9b-ab12525588":  {Major: 6, Minor: 6, Android: 15},
		"6.12.23-android16-5-g1":                       {Major: 6, Minor: 12, Android: 16},
		"6.1.75-android14-11-g48b922851ac5-ab11568788": {Major: 6, Minor: 1, Android: 14},
		// a kernel that is not a GKI one
		"7.0.3+deb14-amd64": {Major: 7, Minor: 0, Android: 0},
	}

	for release, expected := range positiveCases {
		kernel, err := ParseKernel(release)

		if (err != nil) || (kernel != expected) {
			state.Errorf("Test of android.ParseKernel function failed, release %q, kernel should be %+v, kernel: %+v, error: %v", release, expected, kernel, err)
			return
		}
	}
}

// Test if android.ParseKernel returns with the expected errors.
func TestParseKernelNegative(state *testing.T) {
	for _, release := range []string{"", "android15-6.6", "six.six", "6", "99999999999999999999.6.1"} {
		kernel, err := ParseKernel(release)

		if !errors.Is(err, ErrKernelVersion) {
			state.Errorf("Test of android.ParseKernel function failed, release %q, error should be %v, kernel: %+v, error: %v", release, ErrKernelVersion, kernel, err)
			return
		}
	}
}

// Test if android.CheckDevice returns with the expected output: Android 15 or newer with android15-6.6 or newer, x86_64 or arm64.
func TestCheckDevicePositive(state *testing.T) {
	phone := emulatorInfo
	phone.ABI, phone.Release, phone.SDK, phone.Kernel = "arm64-v8a", "16", 36, "6.12.23-android16-5-g1"
	mainline := emulatorInfo
	mainline.Kernel = "6.18.1"

	for _, info := range []DeviceInfo{emulatorInfo, phone, mainline} {
		err := CheckDevice(info)

		if err != nil {
			state.Errorf("Test of android.CheckDevice function failed, info: %+v, error: %s", info, err.Error())
			return
		}
	}
}

// Test if android.CheckDevice returns with the expected errors and names the reason.
func TestCheckDeviceNegative(state *testing.T) {
	negativeCases := []struct {
		Change   func(info *DeviceInfo)
		Expected error
		Text     string
	}{
		{Change: func(info *DeviceInfo) { info.ABI = "armeabi-v7a" }, Expected: ErrUnsupportedABI, Text: "unsupported ABI armeabi-v7a"},
		{Change: func(info *DeviceInfo) { info.ABI = "x86" }, Expected: ErrUnsupportedABI, Text: "x86_64 emulators"},
		{Change: func(info *DeviceInfo) { info.Release, info.SDK = "14", 34 }, Expected: ErrOldAndroid, Text: "Android 14 (API level 34) is older than Android 15"},
		{Change: func(info *DeviceInfo) { info.Kernel = "6.1.75-android14-11-g48b922851ac5" }, Expected: ErrOldKernel, Text: "6.1.75-android14-11-g48b922851ac5 is older than android15-6.6"},
		// Android 15 on an upgraded device keeps its old kernel
		{Change: func(info *DeviceInfo) { info.Kernel = "5.15.148-android13-8-g1" }, Expected: ErrOldKernel, Text: "need Linux 6.6 or newer"},
		{Change: func(info *DeviceInfo) { info.Kernel = "6.6.0-android14-1" }, Expected: ErrOldKernel, Text: "is older than android15-6.6"},
		{Change: func(info *DeviceInfo) { info.Kernel = "unknown" }, Expected: ErrKernelVersion, Text: `"unknown"`},
	}

	for _, negative := range negativeCases {
		info := emulatorInfo
		negative.Change(&info)
		err := CheckDevice(info)

		if !errors.Is(err, negative.Expected) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of android.CheckDevice function failed, info %+v, error should be %v with %q, error: %v", info, negative.Expected, negative.Text, err)
			return
		}
	}
}

// Test if android.ArchitectureOf and android.ChooseBinary return with the expected output.
func TestChooseBinaryPositive(state *testing.T) {
	positiveCases := []struct {
		ABI      string
		OS       string
		Host     string
		Override string
		Expected string
	}{
		{ABI: "x86_64", OS: "linux", Host: "amd64", Override: "", Expected: "/opt/decerter/decerter"},
		{ABI: "arm64-v8a", OS: "linux", Host: "amd64", Override: "", Expected: "/opt/decerter/decerter-arm64"},
		{ABI: "arm64-v8a", OS: "linux", Host: "arm64", Override: "", Expected: "/opt/decerter/decerter"},
		{ABI: "x86_64", OS: "linux", Host: "arm64", Override: "", Expected: "/opt/decerter/decerter-amd64"},
		{ABI: "arm64-v8a", OS: "linux", Host: "amd64", Override: "./out/decerter-arm64", Expected: "./out/decerter-arm64"},
		// a Mac runs a macOS decerter, the device gets the Linux binary next to it even for the same architecture
		{ABI: "arm64-v8a", OS: "darwin", Host: "arm64", Override: "", Expected: "/opt/decerter/decerter-arm64"},
		{ABI: "x86_64", OS: "darwin", Host: "amd64", Override: "", Expected: "/opt/decerter/decerter-amd64"},
		{ABI: "arm64-v8a", OS: "darwin", Host: "arm64", Override: "./out/decerter-arm64", Expected: "./out/decerter-arm64"},
	}

	for _, positive := range positiveCases {
		architecture, err := ArchitectureOf(positive.ABI)

		if err != nil {
			state.Errorf("Test of android.ArchitectureOf function failed, abi %s, error: %s", positive.ABI, err.Error())
			return
		}

		binary := ChooseBinary(architecture, positive.OS, positive.Host, "/opt/decerter/decerter", positive.Override)

		if binary != positive.Expected {
			state.Errorf("Test of android.ChooseBinary function failed, abi %s on %s/%s, binary should be %s, binary: %s", positive.ABI, positive.OS, positive.Host, positive.Expected, binary)
			return
		}
	}
}

// Test if android.ArchitectureOf returns with the expected errors.
func TestChooseBinaryNegative(state *testing.T) {
	for _, abi := range []string{"", "armeabi-v7a", "x86", "riscv64"} {
		architecture, err := ArchitectureOf(abi)

		if !errors.Is(err, ErrUnsupportedABI) {
			state.Errorf("Test of android.ArchitectureOf function failed, abi %q, error should be %v, architecture: %s, error: %v", abi, ErrUnsupportedABI, architecture, err)
			return
		}
	}
}

// write a 64-bit little-endian ELF header for machine, with one PT_INTERP program header when interpreter is set
func writeELF(path string, class elf.Class, machine elf.Machine, interpreter bool) (err error) {
	header := elf.Header64{
		Ident:     [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(class), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(machine),
		Version:   uint32(elf.EV_CURRENT),
		Ehsize:    64,
		Phentsize: 56,
	}
	program := elf.Prog64{Type: uint32(elf.PT_INTERP), Off: 120, Filesz: 0}

	if interpreter {
		header.Phoff = 64
		header.Phnum = 1
	}

	file, err := os.Create(path)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	err = binary.Write(file, binary.LittleEndian, header)

	if (err != nil) || !interpreter {
		return
	}

	err = binary.Write(file, binary.LittleEndian, program)
	return
}

// Test if android.CheckBinary returns with the expected output for static binaries of both architectures.
func TestCheckBinaryPositive(state *testing.T) {
	for architecture, machine := range map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64} {
		path := filepath.Join(state.TempDir(), "decerter-"+architecture)
		err := writeELF(path, elf.ELFCLASS64, machine, false)

		if err != nil {
			state.Fatalf("Test of android.CheckBinary failed, cannot write the binary, error: %s", err.Error())
		}

		err = CheckBinary(path, architecture)

		if err != nil {
			state.Errorf("Test of android.CheckBinary function failed, architecture %s, error: %s", architecture, err.Error())
			return
		}
	}
}

// Test if android.CheckBinary returns with the expected errors: another architecture, a 32-bit or dynamic binary, no ELF, no file.
func TestCheckBinaryNegative(state *testing.T) {
	directory := state.TempDir()
	negativeCases := []struct {
		Name        string
		Class       elf.Class
		Machine     elf.Machine
		Interpreter bool
		Text        string
	}{
		{Name: "arm64", Class: elf.ELFCLASS64, Machine: elf.EM_AARCH64, Interpreter: false, Text: "is ELFCLASS64 EM_AARCH64, the device needs amd64"},
		{Name: "dynamic", Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Interpreter: true, Text: "is dynamically linked"},
		{Name: "32bit", Class: elf.ELFCLASS32, Machine: elf.EM_386, Interpreter: false, Text: ""},
	}

	for _, negative := range negativeCases {
		path := filepath.Join(directory, negative.Name)
		err := writeELF(path, negative.Class, negative.Machine, negative.Interpreter)

		if err != nil {
			state.Fatalf("Test of android.CheckBinary failed, cannot write the binary, error: %s", err.Error())
		}

		err = CheckBinary(path, "amd64")

		if !errors.Is(err, ErrBinary) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of android.CheckBinary function failed, %s, error should be %v with %q, error: %v", negative.Name, ErrBinary, negative.Text, err)
			return
		}
	}

	text := filepath.Join(directory, "script")
	err := os.WriteFile(text, []byte("#!/bin/sh\n"), 0o755)

	if err != nil {
		state.Fatalf("Test of android.CheckBinary failed, cannot write the script, error: %s", err.Error())
	}

	for _, path := range []string{text, filepath.Join(directory, "missing")} {
		err = CheckBinary(path, "amd64")

		if !errors.Is(err, ErrBinary) || !strings.Contains(err.Error(), "make build-arm64") {
			state.Errorf("Test of android.CheckBinary function failed, %s, error should be %v, error: %v", path, ErrBinary, err)
			return
		}
	}
}

// Test if android.NextCommands returns with the expected output: copy-pasteable commands with the socket, the binary path and the forward of the platform.
func TestNextCommandsPositive(state *testing.T) {
	positiveCases := []struct {
		ADB       string
		Root      RootType
		Package   string
		BlockQuic bool
		Decerter  string
		Device    string
		UI        string
	}{
		{ADB: "adb", Root: ADBRootType, Package: "com.example.app", BlockQuic: false, Decerter: "decerter", Device: "adb -s emulator-5580 shell -tt /data/local/tmp/decerter run --intercept --api-socket @decerter-api --package com.example.app", UI: "decerter ui --api-socket 127.0.0.1:8080"},
		{ADB: "'/opt/android sdk/platform-tools/adb'", Root: ADBRootType, Package: "", BlockQuic: false, Decerter: "/home/user/my tools/decerter", Device: "'/opt/android sdk/platform-tools/adb' -s emulator-5580 shell -tt /data/local/tmp/decerter run --intercept --api-socket @decerter-api --package PACKAGE", UI: "'/home/user/my tools/decerter' ui --api-socket 127.0.0.1:8080"},
		{ADB: "adb", Root: SuRootType, Package: "com.example.app", BlockQuic: false, Decerter: "./decerter", Device: `adb -s emulator-5580 shell -tt "su -c '/data/local/tmp/decerter run --intercept --api-socket @decerter-api --package com.example.app'"`, UI: "./decerter ui --api-socket 127.0.0.1:8080"},
		// a Chromium app
		{ADB: "adb", Root: ADBRootType, Package: "com.android.chrome", BlockQuic: true, Decerter: "decerter", Device: "adb -s emulator-5580 shell -tt /data/local/tmp/decerter run --intercept --api-socket @decerter-api --package com.android.chrome --block-quic", UI: "decerter ui --api-socket 127.0.0.1:8080"},
		{ADB: "adb", Root: SuRootType, Package: "com.google.android.youtube", BlockQuic: true, Decerter: "decerter", Device: `adb -s emulator-5580 shell -tt "su -c '/data/local/tmp/decerter run --intercept --api-socket @decerter-api --package com.google.android.youtube --block-quic'"`, UI: "decerter ui --api-socket 127.0.0.1:8080"},
	}

	for _, positive := range positiveCases {
		device, ui := NextCommands(positive.ADB, "emulator-5580", positive.Root, positive.Package, positive.BlockQuic, 8080, positive.Decerter)

		if (device != positive.Device) || (ui != positive.UI) {
			state.Errorf("Test of android.NextCommands function failed, commands should be %q and %q, commands: %q and %q", positive.Device, positive.UI, device, ui)
			return
		}
	}
}

// Test if android.FindADB returns with the expected output: ADB first, then the platform-tools of ANDROID_HOME, ANDROID_SDK_ROOT and ~/Android/Sdk,
// and the adb on PATH only without an SDK, so the adb the emulator starts and setup's are the same; an adb that can't run is skipped.
func TestFindADBPositive(state *testing.T) {
	directory := state.TempDir()
	home := filepath.Join(directory, "home")
	studio := filepath.Join(home, "Android", "Sdk", "platform-tools", "adb")
	androidHome := filepath.Join(directory, "android-home", "platform-tools", "adb")
	sdkRoot := filepath.Join(directory, "sdk-root", "platform-tools", "adb")
	pathADB := filepath.Join(directory, "bin", "adb")
	notExecutable := filepath.Join(directory, "broken", "platform-tools", "adb")

	for _, adb := range []string{studio, androidHome, sdkRoot, pathADB, notExecutable} {
		err := os.MkdirAll(filepath.Dir(adb), 0o700)

		if err == nil {
			err = os.WriteFile(adb, []byte("#!/bin/sh\n"), 0o700)
		}

		if err != nil {
			state.Fatalf("Test of android.FindADB failed, cannot create %s, error: %s", adb, err.Error())
		}
	}

	if err := os.Chmod(notExecutable, 0o600); err != nil {
		state.Fatalf("Test of android.FindADB failed, error: %s", err.Error())
	}

	positiveCases := []struct {
		Name        string
		ADB         string
		AndroidHome string
		SDKRoot     string
		Home        string
		Expected    string
	}{
		{Name: "ADB wins", ADB: "/opt/adb", AndroidHome: filepath.Dir(filepath.Dir(androidHome)), SDKRoot: "", Home: home, Expected: "/opt/adb"},
		{Name: "ANDROID_HOME before PATH", ADB: "", AndroidHome: filepath.Dir(filepath.Dir(androidHome)), SDKRoot: filepath.Dir(filepath.Dir(sdkRoot)), Home: home, Expected: androidHome},
		{Name: "ANDROID_SDK_ROOT before PATH", ADB: "", AndroidHome: "", SDKRoot: filepath.Dir(filepath.Dir(sdkRoot)), Home: home, Expected: sdkRoot},
		{Name: "~/Android/Sdk before PATH", ADB: "", AndroidHome: "", SDKRoot: "", Home: home, Expected: studio},
		{Name: "an adb that can't run is skipped", ADB: "", AndroidHome: filepath.Dir(filepath.Dir(notExecutable)), SDKRoot: "", Home: home, Expected: studio},
		{Name: "PATH without an SDK", ADB: "", AndroidHome: "", SDKRoot: "", Home: directory, Expected: pathADB},
	}

	for _, positive := range positiveCases {
		state.Setenv("ADB", positive.ADB)
		state.Setenv("ANDROID_HOME", positive.AndroidHome)
		state.Setenv("ANDROID_SDK_ROOT", positive.SDKRoot)
		state.Setenv("HOME", positive.Home)
		state.Setenv("PATH", filepath.Dir(pathADB))
		adb, err := FindADB()

		if (err != nil) || (adb != positive.Expected) {
			state.Errorf("Test of android.FindADB function failed, case %q, adb should be %s, adb: %s, error: %v", positive.Name, positive.Expected, adb, err)
		}
	}
}

// Test if android.FindADB returns with the expected errors: no SDK and nothing on PATH, or only an adb that can't run.
func TestFindADBNegative(state *testing.T) {
	directory := state.TempDir()
	notExecutable := filepath.Join(directory, "sdk", "platform-tools", "adb")
	err := os.MkdirAll(filepath.Dir(notExecutable), 0o700)

	if err == nil {
		err = os.WriteFile(notExecutable, []byte("#!/bin/sh\n"), 0o600)
	}

	if err != nil {
		state.Fatalf("Test of android.FindADB failed, error: %s", err.Error())
	}

	for _, sdk := range []string{"", filepath.Join(directory, "sdk")} {
		state.Setenv("ADB", "")
		state.Setenv("ANDROID_HOME", sdk)
		state.Setenv("ANDROID_SDK_ROOT", "")
		state.Setenv("HOME", directory)
		state.Setenv("PATH", directory)
		adb, err := FindADB()

		if !errors.Is(err, ErrNoADB) {
			state.Errorf("Test of android.FindADB function failed, ANDROID_HOME %q, error should be %v, adb: %s, error: %v", sdk, ErrNoADB, adb, err)
		}
	}
}

// Test if android.shellQuote returns with the expected output for words the shell would split or expand.
func TestShellQuotePositive(state *testing.T) {
	positiveCases := map[string]string{
		"com.example.app":   "com.example.app",
		"@decerter-api":     "@decerter-api",
		"":                  "''",
		"my tools/decerter": "'my tools/decerter'",
		"it's":              `'it'\''s'`,
		"$(reboot)":         "'$(reboot)'",
		"a;b":               "'a;b'",
		"<package>":         "'<package>'",
	}

	for word, expected := range positiveCases {
		quoted := shellQuote(word)

		if quoted != expected {
			state.Errorf("Test of android.shellQuote function failed, word %q should be %s, quoted: %s", word, expected, quoted)
			return
		}
	}
}

// Test if android.parseAVDs returns with the expected output, without the emulator's INFO lines.
func TestParseAVDsPositive(state *testing.T) {
	avds := parseAVDs("INFO    | Storing crashdata in: /tmp/android-user/emu-crash-36.1.9.db\ndecerter-a15\nPixel_9_API_35\n\n")

	if !reflect.DeepEqual(avds, []string{"decerter-a15", "Pixel_9_API_35"}) {
		state.Errorf("Test of android.parseAVDs function failed, avds: %q", avds)
		return
	}

	if avds = parseAVDs(""); len(avds) != 0 {
		state.Errorf("Test of android.parseAVDs function failed, no output should have no AVD, avds: %q", avds)
		return
	}
}
