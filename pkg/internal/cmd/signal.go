// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// SIGINT and SIGTERM stop decerter; SIGHUP too, so a closed adb shell on Android still lets decerter put netd's hooks back
func shutdownContext() (ctx context.Context, cancel context.CancelFunc) {
	ctx, cancel = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	return
}
