// SPDX-License-Identifier: AGPL-3.0-only

package android

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// the SDK directories of ANDROID_HOME and ANDROID_SDK_ROOT, then Android Studio's default ~/Android/Sdk
func sdkDirectories() (environment []string, studio string) {
	for _, directory := range []string{os.Getenv("ANDROID_HOME"), os.Getenv("ANDROID_SDK_ROOT")} {
		if directory != "" {
			environment = append(environment, directory)
		}
	}

	home, homeErr := os.UserHomeDir()

	if homeErr == nil {
		studio = filepath.Join(home, "Android", "Sdk")
	}

	return
}

// ADB when set, then the platform-tools of ANDROID_HOME, ANDROID_SDK_ROOT and ~/Android/Sdk, then PATH
// the emulator starts the adb of its SDK's platform-tools, and an adb of another version (a distribution's on PATH) restarts the server of the other one,
// so the SDK's adb comes before PATH
func FindADB() (adb string, err error) {
	adb = os.Getenv("ADB")

	if adb != "" {
		return
	}

	environment, studio := sdkDirectories()
	candidates := []string{}

	for _, directory := range append(environment, studio) {
		if directory != "" {
			candidates = append(candidates, filepath.Join(directory, "platform-tools", "adb"))
		}
	}

	pathADB, lookErr := exec.LookPath("adb")

	if lookErr == nil {
		candidates = append(candidates, pathADB)
	}

	for _, candidate := range candidates {
		info, statErr := os.Stat(candidate)

		if (statErr == nil) && info.Mode().IsRegular() && (info.Mode().Perm()&0o111 != 0) {
			adb = candidate
			return
		}
	}

	err = ErrNoADB
	return
}

// the emulator of the SDK adb comes from, then of the SDK directories, then PATH
func findEmulator(adb string) (emulator string, err error) {
	candidates := []string{}

	if filepath.Base(filepath.Dir(adb)) == "platform-tools" {
		candidates = append(candidates, filepath.Join(filepath.Dir(filepath.Dir(adb)), "emulator", "emulator"))
	}

	environment, studio := sdkDirectories()

	for _, directory := range append(environment, studio) {
		if directory != "" {
			candidates = append(candidates, filepath.Join(directory, "emulator", "emulator"))
		}
	}

	pathEmulator, lookErr := exec.LookPath("emulator")

	if lookErr == nil {
		candidates = append(candidates, pathEmulator)
	}

	for _, candidate := range candidates {
		_, statErr := os.Stat(candidate)

		if statErr == nil {
			emulator = candidate
			return
		}
	}

	err = ErrNoEmulator
	return
}

// adb with the serial of the device, output is stdout; the call is killed after timeout
func (adb ADB) run(ctx context.Context, timeout time.Duration, arguments ...string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if adb.Serial != "" {
		arguments = append([]string{"-s", adb.Serial}, arguments...)
	}

	command := exec.CommandContext(commandCtx, adb.Path, arguments...)
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	output = stdout.String()

	if err != nil {
		err = fmt.Errorf("%w: adb %s: %w: %s", ErrADB, strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()+" "+output))
	}

	return
}

// one shell command on the device as adb's shell user, adb returns its exit status
func (adb ADB) shell(ctx context.Context, command string) (output string, err error) {
	output, err = adb.run(ctx, adbTimeout, "shell", command)
	return
}

// one shell command on the device as root: adbd is root after adb root, otherwise through su -c
func (adb ADB) rootShell(ctx context.Context, command string) (output string, err error) {
	if adb.Root == SuRootType {
		command = "su -c " + shellQuote(command)
	}

	output, err = adb.shell(ctx, command)
	return
}

func (adb ADB) devices(ctx context.Context) (devices []Device, err error) {
	output, err := adb.run(ctx, adbTimeout, "devices")

	if err != nil {
		return
	}

	devices = ParseDevices(output)
	return
}

func (adb ADB) fileExists(ctx context.Context, path string) (isExisting bool, err error) {
	output, err := adb.shell(ctx, "if [ -e "+shellQuote(path)+" ]; then echo yes; else echo no; fi")
	isExisting = (strings.TrimSpace(output) == "yes")
	return
}

// the pids of the processes named decerter, empty when none runs
func (adb ADB) decerterPids(ctx context.Context) (pids string, err error) {
	output, err := adb.shell(ctx, "pidof decerter || true")
	pids = strings.TrimSpace(output)
	return
}

// call check every pollInterval until it is done, fails or ctx ends
func poll(ctx context.Context, check func() (isDone bool, err error)) (err error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		isDone, checkErr := check()

		if err = checkErr; (err != nil) || isDone {
			return
		}

		select {
		case <-ctx.Done():
			err = ctx.Err()
			return
		case <-ticker.C:
		}
	}
}
