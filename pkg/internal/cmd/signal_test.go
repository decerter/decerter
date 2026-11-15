// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package cmd

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

// Test if cmd.shutdownContext returns with the expected output: SIGINT, SIGTERM and SIGHUP each cancel the context, and the context is not done before.
func TestShutdownContextPositive(state *testing.T) {
	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		ctx, cancel := shutdownContext()

		if ctx.Err() != nil {
			cancel()
			state.Errorf("Test of cmd.shutdownContext function failed, the context should not be done before %s, error: %v", signal, ctx.Err())
			return
		}

		signalSelf(state, signal)

		select {
		case <-ctx.Done():
		case <-time.After(waitTimeout):
		}

		err := ctx.Err()
		cancel()

		if !errors.Is(err, context.Canceled) {
			state.Errorf("Test of cmd.shutdownContext function failed, %s should cancel the context, error: %v", signal, err)
			return
		}
	}
}
