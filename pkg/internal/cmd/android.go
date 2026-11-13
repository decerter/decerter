// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"time"

	"github.com/decerter/decerter/app"
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

	decerter := app.New(context.Background(), redirect.Filter{}, nil, 0, time.Duration(0), false, false, false, nil, "", time.Duration(0), "", "", false, capturebpf.MaxSnaplen, currentPlatform, logger.Slog())

	defer func() {
		err = errors.Join(err, decerter.Shutdown())
	}()

	err = decerter.RestoreNetdHooks()
	return
}
