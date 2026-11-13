// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package intercept_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// what Apply of a held message returned
type holdResult struct {
	plain   []byte
	verdict intercept.Verdict
	err     error
}

// the events of a hold queue in order
type holdEvents struct {
	mutex  *sync.Mutex
	events []intercept.HoldEvent
}

func (recorded *holdEvents) add(event intercept.HoldEvent) {
	recorded.mutex.Lock()
	defer recorded.mutex.Unlock()
	recorded.events = append(recorded.events, event)
}

// the release reasons in order
func (recorded *holdEvents) reasons() (reasons []intercept.ReleaseReason) {
	recorded.mutex.Lock()
	defer recorded.mutex.Unlock()

	for _, event := range recorded.events {
		if event.Type == intercept.ReleasedHoldEventType {
			reasons = append(reasons, event.Reason)
		}
	}

	return
}

// Test if intercept.HoldQueue returns with the expected output: forward after an edit, drop, the timeout, intercept off and the end of the flow.
func TestHoldQueuePositive(state *testing.T) {
	synctest.Test(state, func(state *testing.T) {
		recorded := &holdEvents{mutex: &sync.Mutex{}, events: nil}
		queue := intercept.NewHoldQueue(time.Minute, recorded.add)
		queue.Set(true, nil, intercept.UpDirections)
		flow := tlsTestFlow()
		message := func(id uint64) (current intercept.Message) {
			current = intercept.Message{Flow: flow, ID: id, Direction: tlsrecord.ClientDirection, Layer: intercept.TLSLayer, Plain: []byte("GET / HTTP/1.1\r\n\r\n")}
			return
		}
		ctx, cancel := context.WithCancel(state.Context())
		defer cancel()
		results := map[uint64]chan holdResult{}

		for id := range uint64(3) {
			results[id+1] = hold(ctx, queue, message(id+1))
		}

		synctest.Wait()

		if held := queue.List(); (len(held) != 3) || (queue.State().HeldCount != 3) {
			state.Fatalf("Test of intercept.HoldQueue failed, 3 messages should be held, held: %d", len(held))
		}

		// 1 edited and forwarded, 2 dropped
		edited, err := queue.Edit(1, []byte("GET /test HTTP/1.1\r\n\r\n"))

		if (err != nil) || !edited.IsEdited || (string(edited.Plain) != "GET /test HTTP/1.1\r\n\r\n") {
			state.Fatalf("Test of intercept.HoldQueue.Edit failed, held: %+v, error: %v", edited, err)
		}

		err = errors.Join(queue.Forward(1), queue.Drop(2))

		if err != nil {
			state.Fatalf("Test of intercept.HoldQueue failed, cannot decide, error: %s", err.Error())
		}

		first, second := <-results[1], <-results[2]
		synctest.Wait()

		if (string(first.plain) != "GET /test HTTP/1.1\r\n\r\n") || (first.verdict != intercept.ForwardVerdict) || (second.plain != nil) || (second.verdict != intercept.DropVerdict) {
			state.Errorf("Test of intercept.HoldQueue failed, first should be forwarded edited, second dropped, first: %+v, second: %+v", first, second)
			return
		}

		// 3 times out after the minute and goes on as it is
		time.Sleep(time.Minute)
		third := <-results[3]

		if (string(third.plain) != "GET / HTTP/1.1\r\n\r\n") || (third.verdict != intercept.ForwardVerdict) {
			state.Errorf("Test of intercept.HoldQueue failed, the timeout should forward, result: %+v", third)
			return
		}

		// intercept off forwards 4, then a flow that ends drops what it had held
		results[4] = hold(ctx, queue, message(4))
		synctest.Wait()
		queue.Set(false, nil, intercept.UpDirections)
		fourth := <-results[4]
		queue.Set(true, nil, intercept.UpDirections)
		fifth := hold(ctx, queue, message(5))
		synctest.Wait()
		cancel()
		closed := <-fifth

		if (fourth.verdict != intercept.ForwardVerdict) || (closed.verdict != intercept.DropVerdict) {
			state.Errorf("Test of intercept.HoldQueue failed, intercept off should forward and the end of the flow drop, fourth: %+v, fifth: %+v", fourth, closed)
			return
		}

		// forward and drop were decided together, their goroutines tell in any order
		expected := []intercept.ReleaseReason{intercept.ClosedReleaseReason, intercept.DropReleaseReason, intercept.ForwardReleaseReason, intercept.InterceptOffReleaseReason, intercept.TimeoutReleaseReason}
		reasons := recorded.reasons()
		slices.Sort(reasons)

		if !slices.Equal(reasons, expected) {
			state.Errorf("Test of intercept.HoldQueue failed, release reasons should be %v, reasons: %v", expected, reasons)
			return
		}
	})
}

// Test if intercept.HoldQueue returns with the expected errors: decisions on messages that are not held, and messages it does not match.
func TestHoldQueueNegative(state *testing.T) {
	queue := intercept.NewHoldQueue(time.Minute, nil)
	flow := tlsTestFlow()
	up := intercept.Message{Flow: flow, ID: 1, Direction: tlsrecord.ClientDirection, Layer: intercept.TLSLayer, Plain: []byte("x")}
	down := intercept.Message{Flow: flow, ID: 2, Direction: tlsrecord.ServerDirection, Layer: intercept.TLSLayer, Plain: []byte("x")}

	// off by default
	if queue.Match(up) {
		state.Errorf("Test of intercept.HoldQueue.Match function failed, a queue that is off should hold nothing")
		return
	}

	scope, err := filter.Parse(`tls.sni == "other.example"`)

	if err != nil {
		state.Fatalf("Test of intercept.HoldQueue failed, cannot parse filter, error: %s", err.Error())
	}

	queue.Set(true, &scope, intercept.UpDirections)

	if queue.Match(up) || queue.Match(down) || (queue.State().Filter != `tls.sni == "other.example"`) {
		state.Errorf("Test of intercept.HoldQueue.Match function failed, the filter and the direction should keep both messages out")
		return
	}

	queue.Set(true, nil, intercept.BothDirections)

	if !queue.Match(up) || !queue.Match(down) {
		state.Errorf("Test of intercept.HoldQueue.Match function failed, both directions should be held")
		return
	}

	_, editErr := queue.Edit(9, []byte("x"))
	_, getErr := queue.Get(9)

	for _, err := range []error{queue.Forward(9), queue.Drop(9), editErr, getErr} {
		if !errors.Is(err, intercept.ErrNotHeld) {
			state.Errorf("Test of intercept.HoldQueue function failed, error should be %v, error: %v", intercept.ErrNotHeld, err)
			return
		}
	}

	// turned off between Match and Apply the message goes on at once
	queue.Set(false, nil, intercept.UpDirections)
	plain, verdict, err := queue.Apply(state.Context(), up)

	if (err != nil) || (verdict != intercept.ForwardVerdict) || (string(plain) != "x") {
		state.Errorf("Test of intercept.HoldQueue.Apply function failed, a queue that is off should forward at once, verdict: %s, error: %v", verdict, err)
		return
	}
}

// Apply in a goroutine of its own, as the sender of a direction
func hold(ctx context.Context, queue *intercept.HoldQueue, message intercept.Message) (result chan holdResult) {
	result = make(chan holdResult, 1)

	// the sender of the message's direction
	go func() {
		plain, verdict, err := queue.Apply(ctx, message)
		result <- holdResult{plain: plain, verdict: verdict, err: err}
	}()

	return
}
