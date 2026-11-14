// SPDX-License-Identifier: AGPL-3.0-only

package android

import (
	"debug/elf"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	// one shell call reads every property setup needs, a key=value line each
	deviceInfoCommand string = "echo abi=$(getprop ro.product.cpu.abi); echo release=$(getprop ro.build.version.release); echo sdk=$(getprop ro.build.version.sdk); echo kernel=$(uname -r); echo model=$(getprop ro.product.model); echo type=$(getprop ro.build.type); echo qemu=$(getprop ro.kernel.qemu)$(getprop ro.boot.qemu); echo uid=$(id -u)"
)

var (
	// 6.6.50-android15-8-g8adecb593e9b-ab12525588: the version, then the GKI branch android15
	kernelVersionPattern = regexp.MustCompile(`^(\d+)\.(\d+)`)
	kernelBranchPattern  = regexp.MustCompile(`-android(\d+)-`)
)

// adb devices: a header line, then serial<TAB>state; the state of a device adb can't use may have spaces in it
func ParseDevices(output string) (devices []Device) {
	for line := range strings.Lines(output) {
		serial, state, isFound := strings.Cut(strings.TrimRight(line, "\r\n"), "\t")

		if !isFound || (serial == "") {
			continue
		}

		devices = append(devices, Device{Serial: serial, State: strings.TrimSpace(state)})
	}

	return
}

// the device of serial, or the one device adb can use when serial is empty
func SelectDevice(devices []Device, serial string) (device Device, err error) {
	if serial != "" {
		index := slices.IndexFunc(devices, func(listed Device) (isMatch bool) {
			isMatch = (listed.Serial == serial)
			return
		})

		if index < 0 {
			err = fmt.Errorf("%w %s, adb sees %s", ErrNoDevice, serial, describeDevices(devices))
			return
		}

		device = devices[index]
		err = checkDeviceState(device)
		return
	}

	ready := slices.DeleteFunc(slices.Clone(devices), func(listed Device) (isNotReady bool) {
		isNotReady = (listed.State != "device")
		return
	})

	switch len(ready) {
	case 1:
		device = ready[0]
	case 0:
		if len(devices) > 0 {
			err = checkDeviceState(devices[0])
			return
		}

		err = fmt.Errorf("%w: adb sees no device, start an emulator, connect a device or boot an AVD with --avd", ErrNoDevice)
	default:
		err = fmt.Errorf("%w: %s", ErrSeveralDevices, describeDevices(ready))
	}

	return
}

// what is wrong with a device adb lists but can't use
func checkDeviceState(device Device) (err error) {
	switch {
	case device.State == "device":
	case device.State == "unauthorized":
		err = fmt.Errorf("%w: %s is unauthorized, allow USB debugging in the prompt on the device", ErrDeviceState, device.Serial)
	case strings.HasPrefix(device.State, "no permissions"):
		err = fmt.Errorf("%w: %s: %s", ErrDeviceState, device.Serial, device.State)
	default:
		err = fmt.Errorf("%w: %s is %s, wait for it or reconnect it", ErrDeviceState, device.Serial, device.State)
	}

	return
}

func describeDevices(devices []Device) (description string) {
	if len(devices) == 0 {
		description = "no device"
		return
	}

	described := []string{}

	for _, device := range devices {
		described = append(described, device.Serial+" ("+device.State+")")
	}

	description = strings.Join(described, ", ")
	return
}

// adb forward --list lists the forwards of every device: serial local remote
func ParseForwards(output string) (forwards []Forward) {
	for line := range strings.Lines(output) {
		fields := strings.Fields(line)

		if len(fields) != 3 {
			continue
		}

		forwards = append(forwards, Forward{Serial: fields[0], Local: fields[1], Remote: fields[2]})
	}

	return
}

// the forwards of serial to the api socket
func apiForwards(forwards []Forward, serial string) (selected []Forward) {
	for _, forward := range forwards {
		if (forward.Serial == serial) && (forward.Remote == "localabstract:"+apiSocketName) {
			selected = append(selected, forward)
		}
	}

	return
}

// the key=value lines of deviceInfoCommand; adb shell may end lines with \r
func ParseDeviceInfo(output string) (info DeviceInfo, err error) {
	values := map[string]string{}

	for line := range strings.Lines(output) {
		key, value, isFound := strings.Cut(strings.TrimSpace(line), "=")

		if isFound {
			values[key] = strings.TrimSpace(value)
		}
	}

	for _, key := range []string{"abi", "release", "sdk", "kernel", "uid"} {
		if values[key] == "" {
			err = fmt.Errorf("%w: no %s in %q", ErrDeviceInfo, key, output)
			return
		}
	}

	sdk, parseErr := strconv.Atoi(values["sdk"])

	if err = parseErr; err != nil {
		err = fmt.Errorf("%w: invalid API level %q: %w", ErrDeviceInfo, values["sdk"], err)
		return
	}

	info = DeviceInfo{
		ABI:        values["abi"],
		Release:    values["release"],
		SDK:        sdk,
		Kernel:     values["kernel"],
		Model:      values["model"],
		BuildType:  values["type"],
		IsEmulator: strings.Contains(values["qemu"], "1"),
		UID:        values["uid"],
	}
	return
}

func ParseKernel(release string) (kernel Kernel, err error) {
	version := kernelVersionPattern.FindStringSubmatch(release)

	if version == nil {
		err = fmt.Errorf("%w: %q", ErrKernelVersion, release)
		return
	}

	// the patterns only match digits, a number too long for an int is the only error left
	major, majorErr := strconv.Atoi(version[1])
	minor, minorErr := strconv.Atoi(version[2])

	if (majorErr != nil) || (minorErr != nil) {
		err = fmt.Errorf("%w: %q", ErrKernelVersion, release)
		return
	}

	kernel = Kernel{Major: major, Minor: minor, Android: 0}
	branch := kernelBranchPattern.FindStringSubmatch(release)

	if branch != nil {
		kernel.Android, _ = strconv.Atoi(branch[1])
	}

	return
}

// the GOARCH of a binary for the device's primary ABI
func ArchitectureOf(abi string) (architecture string, err error) {
	switch abi {
	case "x86_64":
		architecture = "amd64"
	case "arm64-v8a":
		architecture = "arm64"
	default:
		err = fmt.Errorf("%w %s: decerter runs on arm64-v8a devices and x86_64 emulators", ErrUnsupportedABI, abi)
	}

	return
}

// refuse a device decerter can't run on: an ABI without a binary, Android before 15 or a kernel before android15-6.6
func CheckDevice(info DeviceInfo) (err error) {
	_, err = ArchitectureOf(info.ABI)

	if err != nil {
		return
	}

	if info.SDK < minimumSDK {
		err = fmt.Errorf("%w: Android %s (API level %d) is older than Android 15 (API level %d), decerter shares netd's cgroup hooks the way Android 15 attaches them", ErrOldAndroid, info.Release, info.SDK, minimumSDK)
		return
	}

	kernel, err := ParseKernel(info.Kernel)

	if err != nil {
		return
	}

	isOldVersion := (kernel.Major < minimumKernelMajor) || ((kernel.Major == minimumKernelMajor) && (kernel.Minor < minimumKernelMinor))
	isOldBranch := (kernel.Android != 0) && (kernel.Android < minimumAndroidKernel)

	if isOldVersion || isOldBranch {
		err = fmt.Errorf("%w: %s is older than android15-6.6, decerter's eBPF programs need Linux 6.6 or newer (GKI android15-6.6, android16-6.12, …)", ErrOldKernel, info.Kernel)
		return
	}

	return
}

// the binary for a device: override when given, this decerter when it is a Linux binary of the device's architecture, otherwise decerter-<arch> next to it
// (make build-arm64); on a Mac this decerter is a macOS binary, so the device always gets decerter-<arch>
func ChooseBinary(deviceArchitecture string, hostOS string, hostArchitecture string, executable string, override string) (binary string) {
	switch {
	case override != "":
		binary = override
	case (hostOS == "linux") && (deviceArchitecture == hostArchitecture):
		binary = executable
	default:
		binary = filepath.Join(filepath.Dir(executable), "decerter-"+deviceArchitecture)
	}

	return
}

// a static 64-bit ELF file for architecture: Android has no glibc, so a binary with an interpreter can't run there
func CheckBinary(binary string, architecture string) (err error) {
	machines := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}
	file, openErr := elf.Open(binary)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %s: %w (make build-arm64 builds decerter-arm64, --binary takes another one)", ErrBinary, binary, err)
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	if (file.Class != elf.ELFCLASS64) || (file.Machine != machines[architecture]) {
		err = fmt.Errorf("%w: %s is %s %s, the device needs %s", ErrBinary, binary, file.Class, file.Machine, architecture)
		return
	}

	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			err = fmt.Errorf("%w: %s is dynamically linked, build it static with make build or make build-arm64", ErrBinary, binary)
			return
		}
	}

	return
}

// quote one shell word for sh on the device or the host, a plain word stays as it is
func shellQuote(word string) (quoted string) {
	isPlain := (word != "") && !strings.ContainsFunc(word, func(character rune) (isSpecial bool) {
		isWordCharacter := ((character >= 'a') && (character <= 'z')) || ((character >= 'A') && (character <= 'Z')) || ((character >= '0') && (character <= '9')) || strings.ContainsRune("@%+=:,./-_", character)
		isSpecial = !isWordCharacter
		return
	})

	if isPlain {
		quoted = word
		return
	}

	quoted = "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
	return
}
