// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/decerter/decerter/internal/attach"
	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/cilium/ebpf"
)

var (
	uids []uint32
)

func main() {
	flag.Func("uid", "uid of an inspected user, repeatable or comma separated (default is none, an empty set matches no process)", parseUIDs)
	flag.Parse()
	err := run()

	if err != nil {
		os.Exit(1)
	}
}

func parseUIDs(value string) (err error) {
	for part := range strings.SplitSeq(value, ",") {
		uid, parseErr := strconv.ParseUint(strings.TrimSpace(part), 10, 32)

		if err = parseErr; err != nil {
			err = fmt.Errorf("invalid uid %q: %w", part, err)
			return
		}

		uids = append(uids, uint32(uid))
	}

	return
}

func run() (err error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	closeFunctions := []func() error{}

	// links are closed before the objects, in reverse order of creation
	defer func() {
		for _, closeFunction := range slices.Backward(closeFunctions) {
			closeErr := closeFunction()

			if closeErr != nil {
				slog.Error("Could not close bpf resource", "error", closeErr)
			}

			err = errors.Join(err, closeErr)
		}
	}()

	bpfMaps, bpfPrograms, closeObjects, loadErr := redirect.LoadBpfObjects(uint32(os.Getpid()))

	if err = loadErr; err != nil {
		slog.Error("Could not load bpf objects", "error", err)
		return
	}

	closeFunctions = append(closeFunctions, closeObjects)
	err = redirect.UpdateBpfMaps(uids, bpfMaps)

	if err != nil {
		slog.Error("Could not update bpf maps", "error", err)
		return
	}

	if len(uids) == 0 {
		slog.Warn("No uid given, no flow will be recorded")
	}

	attachments := []struct {
		program    bpf.BpfProgramName
		attachType ebpf.AttachType
	}{
		{program: redirect.RedirectConnect4, attachType: ebpf.AttachCGroupInet4Connect},
		{program: redirect.RedirectConnect6, attachType: ebpf.AttachCGroupInet6Connect},
		{program: redirect.RedirectSendmsg4, attachType: ebpf.AttachCGroupUDP4Sendmsg},
		{program: redirect.RedirectSendmsg6, attachType: ebpf.AttachCGroupUDP6Sendmsg},
	}

	for _, attachment := range attachments {
		closeLink, attachErr := attach.AddCgroup(attach.CgroupRoot, bpfPrograms[attachment.program], attachment.attachType)

		if err = attachErr; err != nil {
			slog.Error("Could not attach bpf program", "error", err, "attachType", attachment.attachType)
			return
		}

		closeFunctions = append(closeFunctions, closeLink)
	}

	slog.Info("Recording flows", "cgroup", attach.CgroupRoot, "uids", uids)
	waitGroup := sync.WaitGroup{}

	// flow_map printer
	waitGroup.Go(func() {
		redirect.Read(ctx, bpfMaps[redirect.FlowMap])
	})

	<-ctx.Done()
	slog.Info("Got shutdown signal", "cause", context.Cause(ctx))
	waitGroup.Wait()
	return
}
