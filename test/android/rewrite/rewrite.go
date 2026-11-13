// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e_android

// a decerter for the Android e2e tests with eproxy's legacy rule built in: every GET / a selected app sends becomes GET /test
// the command line has only the identity rule, rules come from code, so the test builds this next to decerter and runs it on the device
// usage: rewrite -uid <uid> -dst-cidr <prefix>, it stops on SIGINT, SIGTERM and SIGHUP and puts netd's hooks back like decerter run
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/decerter/decerter/app"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	proxyPort      uint16        = 15001
	udpIdleTimeout time.Duration = 30 * time.Second
)

var (
	http1OldGet = []byte("GET / ")
	http1NewGet = []byte("GET /test ")
)

// eproxy's HTTP/1.1 rewrite, the same rule as in test/e2e
type getRule struct{}

func (rule getRule) Match(message intercept.Message) (isMatch bool) {
	isMatch = (message.Direction == tlsrecord.ClientDirection) && ((message.Layer == intercept.TLSLayer) || (message.Layer == intercept.TCPLayer))
	return
}

func (rule getRule) Apply(ctx context.Context, message intercept.Message) (plain []byte, verdict intercept.Verdict, err error) {
	plain = bytes.ReplaceAll(message.Plain, http1OldGet, http1NewGet)
	verdict = intercept.ForwardVerdict
	return
}

func main() {
	err := run()

	if err != nil {
		os.Exit(1)
	}
}

func run() (err error) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{AddSource: true, Level: slog.LevelInfo}))
	uid := flag.Uint("uid", 0, "select the processes of the user with this uid (required)")
	cidr := flag.String("dst-cidr", "", "only flows to this destination prefix (required)")
	flag.Parse()
	prefix, parseErr := netip.ParsePrefix(*cidr)

	if err = parseErr; err != nil {
		logger.Error("Could not parse destination cidr", "error", err, "cidr", *cidr)
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	selection := redirect.Filter{
		UIDs:             []uint32{uint32(*uid)},
		Tgids:            nil,
		DestinationCIDRs: []netip.Prefix{prefix.Masked()},
		DestinationPorts: nil,
		Comms:            nil,
	}
	decerter := app.New(ctx, selection, nil, proxyPort, udpIdleTimeout, false, false, false, []intercept.Rule{getRule{}}, "", "", false, capturebpf.MaxSnaplen, platform.Detect("/"), logger)

	// every link is closed and netd's hooks are put back, also after a failed start
	defer func() {
		err = errors.Join(err, decerter.Shutdown())
	}()

	err = decerter.Start()

	if err != nil {
		return
	}

	<-decerter.Done()
	logger.Info("Got shutdown signal", "cause", context.Cause(ctx))
	return
}
