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
	"strconv"
	"strings"
	"syscall"

	"github.com/decerter/decerter/app"
)

var (
	uids         []uint32
	tcpProxyPort uint16 = 15001
	flowTable    bool
)

func main() {
	flag.Func("uid", "uid of an inspected user, repeatable or comma separated (default is none, an empty set matches no process)", parseUIDs)
	flag.Func("port", "port of the tcp proxy listener on lo (default is 15001)", parsePort)
	flag.BoolVar(&flowTable, "flow-table", false, "print the flow_map table every 5 seconds, for debugging")
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

func parsePort(value string) (err error) {
	port, parseErr := strconv.ParseUint(value, 10, 16)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid port %q: %w", value, err)
		return
	}

	// the port is a load-time constant in the bpf programs, so it can't be picked by the kernel
	if port == 0 {
		err = fmt.Errorf("invalid port %q: must be between 1 and 65535", value)
		return
	}

	tcpProxyPort = uint16(port)
	return
}

func run() (err error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	logger := slog.Default()
	decerter := app.New(ctx, uids, tcpProxyPort, flowTable, logger)

	defer func() {
		err = errors.Join(err, decerter.Shutdown())
	}()

	err = decerter.LoadBpfObjects()

	if err != nil {
		return
	}

	err = decerter.UpdateBpfMaps()

	if err != nil {
		return
	}

	err = decerter.StartRouteSync()

	if err != nil {
		return
	}

	err = decerter.StartProxy()

	if err != nil {
		return
	}

	err = decerter.AttachRedirect()

	if err != nil {
		return
	}

	decerter.StartFlowTable()
	<-ctx.Done()
	logger.Info("Got shutdown signal", "cause", context.Cause(ctx))
	return
}
