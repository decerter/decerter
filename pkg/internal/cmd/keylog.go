// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package cmd

import (
	"time"

	"github.com/decerter/decerter/app"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/pkg/internal/logging"
)

// print the TLS secrets of the processes selected by uid, pid and Android package as NSS key log lines on stdout until stopped; only the secrets uprobe is attached, there is no redirect object and no proxy port
func Keylog(selection redirect.Filter, packageNames []string, libssl string, logger *logging.Logger) (err error) {
	currentPlatform := platform.Detect("/")
	selection, err = selectPackages(selection, packageNames, currentPlatform, platform.AndroidPackagesList, logger)

	if err != nil {
		return
	}

	ctx, cancel := shutdownContext()
	defer cancel()
	decerter := app.New(ctx, selection, nil, 0, time.Duration(0), false, false, true, false, nil, "", time.Duration(0), time.Duration(0), libssl, false, "", false, capturebpf.MaxSnaplen, currentPlatform, logger.Slog())
	err = serve(ctx, &decerter, logger)
	return
}
