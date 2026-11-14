// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package cmd

import (
	"slices"

	"github.com/decerter/decerter/internal/android"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/pkg/internal/logging"
)

// add the uid of each --package to the uids of the selection, so a package selects exactly what --uid with its uid selects, also with --filter
// the uids come from packagesList, which only Android has; on Linux a package name is refused
func selectPackages(selection redirect.Filter, packageNames []string, currentPlatform platform.Platform, packagesList string, logger *logging.Logger) (packageSelection redirect.Filter, err error) {
	packageSelection = selection

	if len(packageNames) == 0 {
		return
	}

	if currentPlatform.Type != platform.AndroidType {
		err = ErrPackageNotAndroid
		logger.Error("Could not select packages", "error", err, "packages", packageNames)
		return
	}

	packages, err := android.ReadPackages(packagesList)

	if err != nil {
		logger.Error("Could not read the installed packages", "error", err, "fileName", packagesList)
		return
	}

	resolved, err := android.ResolvePackages(packageNames, packages)

	if err != nil {
		logger.Error("Could not select packages", "error", err)
		return
	}

	packageSelection.UIDs = slices.Clone(selection.UIDs)

	for _, selected := range resolved {
		if !slices.Contains(packageSelection.UIDs, selected.UID) {
			packageSelection.UIDs = append(packageSelection.UIDs, selected.UID)
		}

		logger.Info("Selected package", "package", selected.Name, "uid", selected.UID)
		sharing := android.SharingPackages(selected, packages)

		// a system uid such as 1000 is system_server and more, not one app
		if (len(sharing) > 0) || android.IsSystemUID(selected.UID) {
			logger.Warn("The package shares its uid, every process of the uid is selected", "package", selected.Name, "uid", selected.UID, "sharing", sharing)
		}
	}

	return
}
