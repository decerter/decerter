// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/decerter/decerter/app"
	"github.com/decerter/decerter/internal/android"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/pkg/internal/logging"
)

// put netd's cgroup hooks back to exclusive mode from the state file a killed decerter left, refused while another decerter runs and outside of Android
func RestoreAndroid(logger *logging.Logger) (err error) {
	currentPlatform := platform.Detect("/")

	if currentPlatform.Type != platform.AndroidType {
		err = ErrNotAndroid
		logger.Error("Could not restore netd hooks", "error", err)
		return
	}

	decerter := app.New(context.Background(), redirect.Filter{}, nil, 0, time.Duration(0), false, false, false, nil, "", time.Duration(0), "", false, "", false, capturebpf.MaxSnaplen, currentPlatform, logger.Slog())

	defer func() {
		err = errors.Join(err, decerter.Shutdown())
	}()

	err = decerter.RestoreNetdHooks()
	return
}

// on the device as root: for each package, whether decerter hooks its TLS: a Flutter app with known offsets, one it can't hook, or no Flutter app
// the lines go to stdout, a Flutter app that can't be hooked fails with ErrFlutterUnknown after all lines are printed
func AndroidTLS(packageNames []string, logger *logging.Logger) (err error) {
	currentPlatform := platform.Detect("/")

	if currentPlatform.Type != platform.AndroidType {
		err = ErrNotAndroid
		logger.Error("Could not check the apps", "error", err)
		return
	}

	packages, err := android.ReadPackages(platform.AndroidPackagesList)

	if err != nil {
		logger.Error("Could not read the installed packages", "error", err, "fileName", platform.AndroidPackagesList)
		return
	}

	resolved, err := android.ResolvePackages(packageNames, packages)

	if err != nil {
		logger.Error("Could not check the apps", "error", err)
		return
	}

	for _, selected := range resolved {
		lines, isKnown, describeErr := android.DescribeTLS(selected.Name, platform.AndroidAppDirectory, runtime.GOARCH)

		if describeErr != nil {
			err = errors.Join(err, describeErr)
			logger.Error("Could not check the app", "error", describeErr, "package", selected.Name)
			continue
		}

		for _, line := range lines {
			_, writeErr := fmt.Fprintln(os.Stdout, line)
			err = errors.Join(err, writeErr)
		}

		if !isKnown {
			err = errors.Join(err, fmt.Errorf("%w: %s", ErrFlutterUnknown, selected.Name))
		}
	}

	return
}

// on the Linux host as the user: push decerter to the device adb picks or the AVD it boots, forward the api socket and print the commands to run next; remove undoes the push and the forward
// the steps go to stdout, a failure is logged with its reason
func SetupAndroid(options android.Options, remove bool, logger *logging.Logger) (err error) {
	ctx, cancel := shutdownContext()
	defer cancel()

	if os.Geteuid() == 0 {
		err = ErrSetupAsRoot
		logger.Error("Could not set up the Android device", "error", err)
		return
	}

	executable, err := os.Executable()

	if err != nil {
		logger.Error("Could not find the decerter binary", "error", err)
		return
	}

	// the printed commands call decerter the way the user did, by its path or from PATH
	options.Executable = executable
	options.Command = "decerter"

	if strings.Contains(os.Args[0], "/") {
		options.Command = os.Args[0]
	}

	if remove {
		err = android.Remove(ctx, options, os.Stdout, logger.Slog())

		if err != nil {
			logger.Error("Could not remove decerter from the Android device", "error", err)
		}

		return
	}

	err = android.Setup(ctx, options, os.Stdout, logger.Slog())

	if err != nil {
		logger.Error("Could not set up the Android device", "error", err)
	}

	return
}
