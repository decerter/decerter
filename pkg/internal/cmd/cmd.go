// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package cmd

import (
	"context"
	"errors"

	"github.com/decerter/decerter/app"
	"github.com/decerter/decerter/pkg/internal/logging"
)

// start decerter and keep it running until a shutdown signal, or until the capture writer stops it; every link is closed and netd's hooks are put back on the way out, also after a failed start
// a failed step was logged where it failed, the error only sets the exit code
func serve(ctx context.Context, decerter *app.App, logger *logging.Logger) (err error) {
	defer func() {
		err = errors.Join(err, decerter.Shutdown())
		logger.Debug("Stopped")
	}()

	err = decerter.Start()

	if err != nil {
		return
	}

	// the capture writer cancels it too: the file can't be written any more or the stream reader went away
	<-decerter.Done()

	if ctx.Err() != nil {
		logger.Info("Got shutdown signal", "cause", context.Cause(ctx))
	}

	return
}
