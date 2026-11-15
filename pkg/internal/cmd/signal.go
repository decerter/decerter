// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// SIGINT and SIGTERM stop decerter; SIGHUP too, so a closed adb shell on Android still lets decerter put netd's hooks back
// SIGPIPE is ignored: a write to stdout or stderr after their reader went away (decerter run | head, Ctrl-C with | grep) fails with EPIPE, the Go runtime
// would kill decerter with SIGPIPE otherwise, in the middle of relaying or of its shutdown; the commands that serve long all start here
func shutdownContext() (ctx context.Context, cancel context.CancelFunc) {
	signal.Ignore(syscall.SIGPIPE)
	ctx, cancel = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	return
}
