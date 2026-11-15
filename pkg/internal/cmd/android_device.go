// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
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
		err = fmt.Errorf("%w, there are no netd hooks to restore", ErrNotAndroid)
		logger.Error("Could not restore netd hooks", "error", err)
		return
	}

	decerter := app.New(context.Background(), redirect.Filter{}, nil, 0, time.Duration(0), false, false, false, false, nil, "", time.Duration(0), time.Duration(0), "", false, "", false, capturebpf.MaxSnaplen, currentPlatform, logger.Slog())

	defer func() {
		err = errors.Join(err, decerter.Shutdown())
	}()

	err = decerter.RestoreNetdHooks()
	return
}

// on the device as root: for each package, whether decerter hooks its TLS: a Flutter or Chromium app with known offsets, one it can't hook, or neither
// the lines go to stdout, an app library that can't be hooked fails with ErrLibraryUnknown after all lines are printed
func AndroidTLS(packageNames []string, logger *logging.Logger) (err error) {
	currentPlatform := platform.Detect("/")

	if currentPlatform.Type != platform.AndroidType {
		err = fmt.Errorf("%w, android tls checks the apps installed on the device: run it there as root", ErrNotAndroid)
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
		lines, isKnown, describeErr := android.DescribeTLS(selected, packages, platform.AndroidAppDirectory, runtime.GOARCH)

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
			err = errors.Join(err, fmt.Errorf("%w: %s", ErrLibraryUnknown, selected.Name))
		}
	}

	return
}
