// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package cmd

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/android"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/pkg/internal/logging"
)

const (
	// adb devices without a device
	fakeADBScript string = "#!/bin/sh\necho 'List of devices attached'\necho\n"
)

// a fake adb that sees no device, ADB points at it for the test
func fakeADB(state *testing.T) (adb string) {
	adb = filepath.Join(state.TempDir(), "adb")
	err := os.WriteFile(adb, []byte(fakeADBScript), 0o700)

	if err != nil {
		state.Fatalf("Test of cmd failed, cannot write the fake adb, error: %s", err.Error())
	}

	state.Setenv("ADB", adb)
	return
}

// the tests of the device commands need a host that is not Android
func skipOnAndroid(state *testing.T) {
	if platform.Detect("/").Type == platform.AndroidType {
		state.Skip("the host is Android")
	}
}

// Test if cmd.SetupAndroid returns with the expected errors: setup and --remove find the adb of ADB, print it and stop when adb sees no device.
func TestSetupAndroidNegative(state *testing.T) {
	if os.Geteuid() == 0 {
		state.Skip("setup refuses root before it looks for adb")
	}

	adb := fakeADB(state)
	negativeCases := []struct {
		Remove bool
		Text   string
	}{
		{Remove: false, Text: `"msg":"Could not set up the Android device"`},
		{Remove: true, Text: `"msg":"Could not remove decerter from the Android device"`},
	}

	for _, negative := range negativeCases {
		stdout := redirectStdout(state)
		logs := &bytes.Buffer{}
		logger := logging.New(logs, slog.LevelInfo)
		err := SetupAndroid(android.Options{Serial: "", AVD: "", Binary: "", Port: 0, Package: "", Executable: "", Command: ""}, negative.Remove, &logger)
		printed := stdout.read(state)

		if !errors.Is(err, android.ErrNoDevice) || !strings.Contains(logs.String(), negative.Text) || !strings.Contains(printed, adb) {
			state.Errorf("Test of cmd.SetupAndroid function failed, remove %v, error should be %v with the log %q and adb on stdout, error: %v, logs: %s, stdout: %q", negative.Remove, android.ErrNoDevice, negative.Text, err, logs.String(), printed)
			return
		}
	}
}

// Test if cmd.RestoreAndroid returns with the expected errors: it is refused outside of Android.
func TestRestoreAndroidNegative(state *testing.T) {
	skipOnAndroid(state)
	logs := &bytes.Buffer{}
	logger := logging.New(logs, slog.LevelInfo)
	err := RestoreAndroid(&logger)

	if !errors.Is(err, ErrNotAndroid) || !strings.Contains(err.Error(), "there are no netd hooks to restore") || !strings.Contains(logs.String(), `"msg":"Could not restore netd hooks"`) {
		state.Errorf("Test of cmd.RestoreAndroid function failed, error should be %v, error: %v, logs: %s", ErrNotAndroid, err, logs.String())
		return
	}
}

// Test if cmd.AndroidTLS returns with the expected errors: it is refused outside of Android.
func TestAndroidTLSNegative(state *testing.T) {
	skipOnAndroid(state)
	logs := &bytes.Buffer{}
	logger := logging.New(logs, slog.LevelInfo)
	err := AndroidTLS([]string{"com.example.app"}, &logger)

	// the message is its own, not the one of android restore
	if !errors.Is(err, ErrNotAndroid) || !strings.Contains(err.Error(), "checks the apps installed on the device") || strings.Contains(err.Error(), "netd") || !strings.Contains(logs.String(), `"msg":"Could not check the apps"`) {
		state.Errorf("Test of cmd.AndroidTLS function failed, error should be %v, error: %v, logs: %s", ErrNotAndroid, err, logs.String())
		return
	}
}
