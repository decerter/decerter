// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package route

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Test if route.List and route.Subscribe return with the expected output: the routing tables of this host can be dumped and their changes
// subscribed to without privileges.
func TestSubscribePositive(state *testing.T) {
	routes, err := List()

	if (err != nil) || (routes == nil) {
		state.Errorf("Test of route.List function failed, routes: %v, error: %v", routes, err)
		return
	}

	subscription, err := Subscribe()

	if err != nil {
		state.Errorf("Test of route.Subscribe function failed, error: %s", err.Error())
		return
	}

	if err = subscription.Close(); err != nil {
		state.Errorf("Test of route.Subscribe function failed, cannot close the subscription, error: %s", err.Error())
		return
	}
}

// Test if route.Watch returns with the expected output for a subscription that fails: a read error is a lost event after a backoff, a subscription
// closed by someone else ends Watch, which logs that it can't close it again, and a cancel ends a Watch that waits to send its event.
func TestWatchNegative(state *testing.T) {
	// a file that can't be read
	broken, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)

	if err != nil {
		state.Fatalf("Test of route.Watch failed, cannot open %s, error: %s", os.DevNull, err.Error())
	}

	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	eventChannel := make(chan EventType)
	doneChannel := make(chan struct{})
	ctx, cancel := context.WithCancel(state.Context())

	// route watcher of the broken file
	go func() {
		Watch(ctx, broken, eventChannel, logger)
		close(doneChannel)
	}()

	select {
	case event := <-eventChannel:
		if event != LostEventType {
			state.Errorf("Test of route.Watch function failed, a read error should be %s, event: %s", LostEventType, event)
		}
	case <-time.After(10 * time.Second):
		state.Errorf("Test of route.Watch function failed, no event after a read error")
	}

	cancel()
	<-doneChannel

	if !strings.Contains(logs.String(), "Could not read route events") {
		state.Errorf("Test of route.Watch function failed, the read error should be logged, logs: %q", logs.String())
		return
	}

	// closed by someone else
	subscription, sender, err := datagramPair()

	if err != nil {
		state.Fatalf("Test of route.Watch failed, cannot create socket pair, error: %s", err.Error())
	}

	defer func() {
		if closeErr := sender.Close(); closeErr != nil {
			state.Errorf("Test of route.Watch failed, cannot close socket, error: %s", closeErr.Error())
		}
	}()

	logs.Reset()
	doneChannel = make(chan struct{})

	// route watcher of a subscription closed under it
	go func() {
		Watch(state.Context(), subscription, eventChannel, logger)
		close(doneChannel)
	}()

	if err = subscription.Close(); err != nil {
		state.Fatalf("Test of route.Watch failed, cannot close the subscription, error: %s", err.Error())
	}

	<-doneChannel

	if !strings.Contains(logs.String(), "Could not close route subscription") {
		state.Errorf("Test of route.Watch function failed, the second close should be logged, logs: %q", logs.String())
		return
	}

	// nobody takes the events
	subscription, otherSender, err := datagramPair()

	if err != nil {
		state.Fatalf("Test of route.Watch failed, cannot create socket pair, error: %s", err.Error())
	}

	defer func() {
		if closeErr := otherSender.Close(); closeErr != nil {
			state.Errorf("Test of route.Watch failed, cannot close socket, error: %s", closeErr.Error())
		}
	}()

	doneChannel = make(chan struct{})
	ctx, cancel = context.WithCancel(state.Context())

	// route watcher nobody reads
	go func() {
		Watch(ctx, subscription, eventChannel, logger)
		close(doneChannel)
	}()

	for range 2 {
		if _, err = otherSender.Write(netlinkMessage(syscall.RTM_NEWROUTE, rtmsg(dumpMessages[1]))); err != nil {
			cancel()
			state.Fatalf("Test of route.Watch failed, cannot send, error: %s", err.Error())
		}
	}

	// the first event is taken, Watch then waits with the second one
	<-eventChannel
	cancel()

	select {
	case <-doneChannel:
	case <-time.After(10 * time.Second):
		state.Errorf("Test of route.Watch function failed, it should end with the context while it waits to send")
		return
	}
}
