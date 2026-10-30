// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/decerter/decerter/internal/attach"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/cilium/ebpf"
)

func main() {
	err := run()

	if err != nil {
		os.Exit(1)
	}
}

func run() (err error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	bpfMaps, bpfPrograms, closeObjects, loadErr := redirect.LoadBpfObjects()

	if err = loadErr; err != nil {
		slog.Error("Could not load bpf objects", "error", err)
		return
	}

	// links are closed before the objects, defers run in reverse order
	defer func() {
		closeErr := closeObjects()

		if closeErr != nil {
			slog.Error("Could not close bpf objects", "error", closeErr)
		}

		err = errors.Join(err, closeErr)
	}()

	closeLink, attachErr := attach.AddCgroup(attach.CgroupRoot, bpfPrograms[redirect.CountConnect4], ebpf.AttachCGroupInet4Connect)

	if err = attachErr; err != nil {
		slog.Error("Could not attach bpf program", "error", err)
		return
	}

	defer func() {
		closeErr := closeLink()

		if closeErr != nil {
			slog.Error("Could not close cgroup link", "error", closeErr)
		}

		err = errors.Join(err, closeErr)
	}()

	slog.Info("Counting connects per uid", "cgroup", attach.CgroupRoot)
	waitGroup := sync.WaitGroup{}

	// counter_map printer
	waitGroup.Go(func() {
		redirect.Read(ctx, bpfMaps[redirect.CounterMap])
	})

	<-ctx.Done()
	slog.Info("Got shutdown signal", "cause", context.Cause(ctx))
	waitGroup.Wait()
	return
}
