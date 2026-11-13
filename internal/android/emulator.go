// SPDX-License-Identifier: AGPL-3.0-only

package android

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// the names emulator -list-avds prints, one a line; its INFO lines have a | in them
func parseAVDs(output string) (avds []string) {
	for line := range strings.Lines(output) {
		name := strings.TrimSpace(line)

		if (name != "") && !strings.ContainsAny(name, " |") {
			avds = append(avds, name)
		}
	}

	return
}

func listAVDs(ctx context.Context, emulator string) (avds []string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, adbTimeout)
	defer cancel()
	output, err := exec.CommandContext(commandCtx, emulator, "-list-avds").Output()

	if err != nil {
		err = fmt.Errorf("%w: %s -list-avds: %w", ErrNoEmulator, emulator, err)
		return
	}

	avds = parseAVDs(string(output))
	return
}

// the serial of a running emulator of avd, empty when none runs; adb emu avd name answers with the name and OK
func findRunningAVD(ctx context.Context, adb ADB, devices []Device, avd string) (serial string, err error) {
	for _, device := range devices {
		if !strings.HasPrefix(device.Serial, "emulator-") || (device.State != "device") {
			continue
		}

		output, nameErr := ADB{Path: adb.Path, Serial: device.Serial, Root: ""}.run(ctx, adbTimeout, "emu", "avd", "name")

		if err = nameErr; err != nil {
			return
		}

		name, _, _ := strings.Cut(output, "\n")

		if strings.TrimSpace(name) == avd {
			serial = device.Serial
			return
		}
	}

	return
}

// boot avd without a window, audio or snapshot on a free console port and wait until it booted; it keeps running in its own session after decerter exits
func bootAVD(ctx context.Context, adb ADB, avd string, devices []Device, output io.Writer) (serial string, err error) {
	emulator, err := findEmulator(adb.Path)

	if err != nil {
		return
	}

	avds, err := listAVDs(ctx, emulator)

	if err != nil {
		return
	}

	if !slices.Contains(avds, avd) {
		err = fmt.Errorf("%w %s, the AVDs of this user: %s (Android Studio's Device Manager or avdmanager create avd makes one)", ErrUnknownAVD, avd, strings.Join(avds, ", "))
		return
	}

	port, err := freeEmulatorPort(devices)

	if err != nil {
		return
	}

	logFile, err := os.CreateTemp("", "decerter-emulator-*.log")

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, logFile.Close())
	}()

	serial = "emulator-" + strconv.Itoa(port)
	_, err = fmt.Fprintf(output, "boot     %s as %s without a window, its log is %s\n", avd, serial, logFile.Name())

	if err != nil {
		return
	}

	command := exec.Command(emulator, "-avd", avd, "-port", strconv.Itoa(port), "-no-window", "-no-audio", "-no-boot-anim", "-gpu", "swiftshader_indirect", "-no-snapshot", "-no-metrics")
	command.Stdout = logFile
	command.Stderr = logFile
	// its own session: a ^C of decerter android setup does not stop it
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = command.Start()

	if err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrBoot, emulator, err)
		return
	}

	waitChannel := make(chan error, 1)

	// emulator process, it outlives decerter when the boot works
	go func() {
		waitChannel <- command.Wait()
	}()

	err = waitForBoot(ctx, ADB{Path: adb.Path, Serial: serial, Root: ""}, waitChannel, logFile.Name())

	if err != nil {
		err = errors.Join(err, command.Process.Kill())
		return
	}

	return
}

// sys.boot_completed is the last property a boot sets; adb sees the emulator only after a few seconds
func waitForBoot(ctx context.Context, adb ADB, waitChannel <-chan error, logPath string) (err error) {
	bootCtx, cancel := context.WithTimeout(ctx, bootTimeout)
	defer cancel()
	start := time.Now()
	err = poll(bootCtx, func() (isDone bool, pollErr error) {
		select {
		case waitErr := <-waitChannel:
			pollErr = fmt.Errorf("%w: the emulator exited after %s, see %s: %w", ErrBoot, time.Since(start).Round(time.Second), logPath, waitErr)
			return
		default:
		}

		booted, shellErr := adb.run(bootCtx, adbTimeout, "shell", "getprop sys.boot_completed")
		isDone = (shellErr == nil) && (strings.TrimSpace(booted) == "1")
		return
	})

	if errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("%w in %s, see %s: %w", ErrBoot, bootTimeout, logPath, err)
	}

	return
}

// the first even console port no listed emulator has whose console and adb port are free on loopback
func freeEmulatorPort(devices []Device) (port int, err error) {
	for candidate := firstEmulatorPort; candidate <= lastEmulatorPort; candidate += 2 {
		isListed := slices.ContainsFunc(devices, func(device Device) (isMatch bool) {
			isMatch = (device.Serial == "emulator-"+strconv.Itoa(candidate))
			return
		})

		if !isListed && isPortFree(candidate) && isPortFree(candidate+1) {
			port = candidate
			return
		}
	}

	err = fmt.Errorf("%w: no free console port between %d and %d", ErrBoot, firstEmulatorPort, lastEmulatorPort)
	return
}

func isPortFree(port int) (isFree bool) {
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	if err != nil {
		return
	}

	isFree = (listener.Close() == nil)
	return
}
