// SPDX-License-Identifier: AGPL-3.0-only

package intercept

import (
	"bytes"
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/decerter/decerter/internal/filter"
)

// what happened in the hold queue
type HoldEventType string

const (
	HeldHoldEventType     HoldEventType = "held"
	EditedHoldEventType   HoldEventType = "edited"
	ReleasedHoldEventType HoldEventType = "released"
)

// why a held message went on, or did not
type ReleaseReason string

const (
	// forwarded over the API
	ForwardReleaseReason ReleaseReason = "forward"
	// dropped over the API
	DropReleaseReason ReleaseReason = "drop"
	// nobody decided before the hold timeout, the message went on as it was then
	TimeoutReleaseReason ReleaseReason = "timeout"
	// intercept was turned off, every held message went on as it was then
	InterceptOffReleaseReason ReleaseReason = "intercept_off"
	// the flow was aborted or decerter stops, the message is not sent
	ClosedReleaseReason ReleaseReason = "closed"
)

// a held message: Message as it came to the hold queue, after the rules before it; Plain is what goes on when it is forwarded
type Held struct {
	Message  Message
	Plain    []byte
	IsEdited bool
	HeldAt   time.Time
	Deadline time.Time
}

// Reason is set for a released message only
type HoldEvent struct {
	Type   HoldEventType
	Held   Held
	Reason ReleaseReason
}

// whether messages are held, which ones, for how long at most, and how many wait now
type InterceptState struct {
	IsEnabled  bool
	Filter     string
	Directions Directions
	Layer      Layer
	Timeout    time.Duration
	HeldCount  int
}

type holdDecision struct {
	verdict Verdict
	reason  ReleaseReason
}

// decision gets exactly one value, from whoever removed the entry from the queue
type heldEntry struct {
	held     Held
	decision chan holdDecision
}

// the last rule of the pipeline while the API runs: with intercept on, each message of its directions and filter waits for forward, drop or the timeout
// Apply blocks in the sending goroutine of the message's direction, so only that direction of that flow waits (4 MiB backpressure on tcp, datagrams are dropped past it on udp)
// notify gets every change, it must not block; it is called without the mutex
// layer empty holds the messages of every record layer, http whole HTTP messages instead
type HoldQueue struct {
	mutex      *sync.Mutex
	isEnabled  bool
	filter     *filter.Filter
	directions Directions
	layer      Layer
	timeout    time.Duration
	held       map[uint64]*heldEntry
	notify     func(event HoldEvent)
}

// intercept starts off, holding the client's messages once it is turned on without directions
func NewHoldQueue(timeout time.Duration, notify func(event HoldEvent)) (queue *HoldQueue) {
	queue = &HoldQueue{
		mutex:      &sync.Mutex{},
		isEnabled:  false,
		filter:     nil,
		directions: UpDirections,
		layer:      "",
		timeout:    timeout,
		held:       map[uint64]*heldEntry{},
		notify:     notify,
	}
	return
}

func (queue *HoldQueue) Match(message Message) (isMatch bool) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()
	isMatch = queue.isEnabled && queue.directions.has(message.Direction) && takesLayer(queue.layer, message.Layer) && matchesFilter(queue.filter, message)
	return
}

// a message the queue takes waits in Apply
func (queue *HoldQueue) Blocks(message Message) (isBlocking bool) {
	isBlocking = queue.Match(message)
	return
}

func (queue *HoldQueue) Takes(layer Layer) (isTaken bool) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()
	isTaken = queue.isEnabled && takesLayer(queue.layer, layer)
	return
}

// wait for the decision on the message; the timeout forwards it as it is then, the end of ctx (flow aborted, decerter stops) drops it
func (queue *HoldQueue) Apply(ctx context.Context, message Message) (plain []byte, verdict Verdict, err error) {
	now := time.Now()
	entry := &heldEntry{
		held: Held{
			Message:  message,
			Plain:    message.Plain,
			IsEdited: false,
			HeldAt:   now,
			Deadline: now,
		},
		decision: make(chan holdDecision, 1),
	}
	held, isHeld := queue.add(entry)

	// turned off between Match and Apply
	if !isHeld {
		plain = message.Plain
		verdict = ForwardVerdict
		return
	}

	queue.publish(HoldEvent{Type: HeldHoldEventType, Held: held, Reason: ""})
	timer := time.NewTimer(time.Until(held.Deadline))
	defer timer.Stop()
	var decision holdDecision

	select {
	case decision = <-entry.decision:
	case <-timer.C:
		queue.decide(message.ID, holdDecision{verdict: ForwardVerdict, reason: TimeoutReleaseReason})
		decision = <-entry.decision
	case <-ctx.Done():
		queue.decide(message.ID, holdDecision{verdict: DropVerdict, reason: ClosedReleaseReason})
		decision = <-entry.decision
	}

	// the entry is out of the queue, nothing changes it any more
	held = entry.held
	queue.publish(HoldEvent{Type: ReleasedHoldEventType, Held: held, Reason: decision.reason})
	verdict = decision.verdict

	if verdict == ForwardVerdict {
		plain = held.Plain
	}

	return
}

func (queue *HoldQueue) add(entry *heldEntry) (held Held, isHeld bool) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()

	if !queue.isEnabled {
		return
	}

	entry.held.Deadline = entry.held.HeldAt.Add(queue.timeout)
	queue.held[entry.held.Message.ID] = entry
	held = entry.held
	isHeld = true
	return
}

// the first decision on a message wins, found is false when it is not held (any more)
func (queue *HoldQueue) decide(id uint64, decision holdDecision) (found bool) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()
	entry, found := queue.held[id]

	if !found {
		return
	}

	delete(queue.held, id)
	entry.decision <- decision
	return
}

func (queue *HoldQueue) publish(event HoldEvent) {
	if queue.notify != nil {
		queue.notify(event)
	}
}

// the held message goes on with what it has now
func (queue *HoldQueue) Forward(id uint64) (err error) {
	if !queue.decide(id, holdDecision{verdict: ForwardVerdict, reason: ForwardReleaseReason}) {
		err = ErrNotHeld
	}

	return
}

// the held message does not go on: a TLS record is left out, tcp bytes are not sent, a datagram is lost
func (queue *HoldQueue) Drop(id uint64) (err error) {
	if !queue.decide(id, holdDecision{verdict: DropVerdict, reason: DropReleaseReason}) {
		err = ErrNotHeld
	}

	return
}

// the payload of a held message is replaced, it goes on with it when forwarded or at the timeout
func (queue *HoldQueue) Edit(id uint64, plain []byte) (held Held, err error) {
	held, err = queue.edit(id, plain)

	if err != nil {
		return
	}

	queue.publish(HoldEvent{Type: EditedHoldEventType, Held: held, Reason: ""})
	return
}

func (queue *HoldQueue) edit(id uint64, plain []byte) (held Held, err error) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()
	entry, found := queue.held[id]

	if !found {
		err = ErrNotHeld
		return
	}

	entry.held.Plain = bytes.Clone(plain)
	entry.held.IsEdited = true
	held = entry.held
	return
}

// the held message of an id
func (queue *HoldQueue) Get(id uint64) (held Held, err error) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()
	entry, found := queue.held[id]

	if !found {
		err = ErrNotHeld
		return
	}

	held = entry.held
	return
}

// the held messages, oldest first
func (queue *HoldQueue) List() (helds []Held) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()

	for _, entry := range queue.held {
		helds = append(helds, entry.held)
	}

	slices.SortFunc(helds, func(first Held, second Held) int {
		return cmp.Compare(first.Message.ID, second.Message.ID)
	})
	return
}

// turn holding on or off; off forwards every held message as it is, a new filter, direction or layer only decides the messages that come after it
// scope nil holds every message of the directions, layer empty every message of a record layer
func (queue *HoldQueue) Set(isEnabled bool, scope *filter.Filter, directions Directions, layer Layer) (state InterceptState) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()
	queue.isEnabled = isEnabled
	queue.filter = scope
	queue.directions = directions
	queue.layer = layer

	if !isEnabled {
		for id, entry := range queue.held {
			delete(queue.held, id)
			entry.decision <- holdDecision{verdict: ForwardVerdict, reason: InterceptOffReleaseReason}
		}
	}

	state = queue.state()
	return
}

func (queue *HoldQueue) State() (state InterceptState) {
	queue.mutex.Lock()
	defer queue.mutex.Unlock()
	state = queue.state()
	return
}

func (queue *HoldQueue) state() (state InterceptState) {
	state = InterceptState{
		IsEnabled:  queue.isEnabled,
		Filter:     "",
		Directions: queue.directions,
		Layer:      queue.layer,
		Timeout:    queue.timeout,
		HeldCount:  len(queue.held),
	}

	if queue.filter != nil {
		state.Filter = queue.filter.String()
	}

	return
}
