// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"time"

	"github.com/decerter/decerter/app"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/pkg/internal/logging"
)

// print the TLS secrets of the processes selected by uid and pid as NSS key log lines on stdout until stopped; only the secrets uprobe is attached, there is no redirect object and no proxy port
func Keylog(selection redirect.Filter, libssl string, logger *logging.Logger) (err error) {
	ctx, cancel := shutdownContext()
	defer cancel()
	decerter := app.New(ctx, selection, nil, 0, time.Duration(0), false, true, false, nil, libssl, "", false, capturebpf.MaxSnaplen, platform.Detect("/"), logger.Slog())
	err = serve(ctx, &decerter, logger)
	return
}
