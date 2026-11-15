// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"log/slog"
	"sync"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
)

// the record layer of a TLS or a DTLS interception as the wait for its secrets sees it
type secretsConn interface {
	Waiting() (waiting bool)
	Holding() (holding bool)
	Session() (session tlsrecord.Session)
	SetSecrets(secrets tlsrecord.Secrets) (records []tlsrecord.Record, err error)
	Release() (records []tlsrecord.Record)
}

// what a TLS or a DTLS interception does for the wait: isDecrypting while its records go through the record layer, isOver once it ended,
// records that can go on now, giveUp when the record layer can't go on
type secretsHooks struct {
	isDecrypting func() (isDecrypting bool)
	isOver       func() (isOver bool)
	goOn         func(records []tlsrecord.Record)
	giveUp       func(reason error)
}

// the mutex of a TLS or a DTLS interception and its wait for the secrets, every method runs under mutex; wake is signalled on every change
// holdDeadline ends the wait for the secrets, graceDeadline lets held records go on raw before it, the poll runs on pollTimer while a record waits
type secretsWait struct {
	mutex          *sync.Mutex
	wake           *sync.Cond
	recordLayer    secretsConn
	secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map
	hooks          secretsHooks
	isHolding      bool
	holdDeadline   time.Time
	graceDeadline  time.Time
	pollPause      time.Duration
	pollTimer      *time.Timer
	isPollPending  bool
	waitLogger     *slog.Logger
}

func newSecretsWait(recordLayer secretsConn, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, hooks secretsHooks, logger *slog.Logger) (wait *secretsWait) {
	mutex := &sync.Mutex{}
	wait = &secretsWait{
		mutex:          mutex,
		wake:           sync.NewCond(mutex),
		recordLayer:    recordLayer,
		secretsBpfMaps: secretsBpfMaps,
		hooks:          hooks,
		pollPause:      interceptPollStart,
		waitLogger:     logger,
	}
	wait.pollTimer = time.AfterFunc(time.Hour, wait.poll)
	wait.pollTimer.Stop()
	return
}

// keep the deadlines and the poll in step with the record layer
func (wait *secretsWait) watch() {
	if !wait.hooks.isDecrypting() || !wait.recordLayer.Waiting() {
		wait.isHolding = false
		return
	}

	now := time.Now()

	if wait.holdDeadline.IsZero() {
		wait.holdDeadline = now.Add(holdTimeout)
	}

	holding := wait.recordLayer.Holding()

	if holding && !wait.isHolding {
		wait.graceDeadline = now.Add(interceptGrace)
		wait.pollPause = interceptPollStart
		wait.isPollPending = false
	}

	wait.isHolding = holding

	if !wait.isPollPending {
		wait.isPollPending = true
		wait.pollTimer.Reset(wait.pollPause)
	}
}

// secrets poll, runs on its own timer while a record waits for them
func (wait *secretsWait) poll() {
	wait.mutex.Lock()
	defer wait.mutex.Unlock()
	wait.isPollPending = false

	if wait.hooks.isOver() || !wait.hooks.isDecrypting() {
		return
	}

	now := time.Now()
	wait.lookup(now.After(wait.holdDeadline))

	// nothing was changed without the secrets, so the held records can go on as they came
	if wait.hooks.isDecrypting() && wait.recordLayer.Holding() && now.After(wait.graceDeadline) {
		wait.waitLogger.Debug("Secrets are late, held records go on raw")
		wait.hooks.goOn(wait.recordLayer.Release())
	}

	wait.pollPause = min(2*wait.pollPause, interceptPollMax)
	wait.watch()
	wait.wake.Broadcast()
}

// ask secrets_map for the session and let the held records go on if they are there, isLast makes missing secrets the end of the interception
func (wait *secretsWait) lookup(isLast bool) {
	sessionSecrets, found, lookupErr := secretsByRandom(wait.recordLayer.Session().ClientRandom, wait.secretsBpfMaps)

	if lookupErr != nil {
		wait.hooks.giveUp(lookupErr)
		return
	}

	if !found {
		if isLast {
			wait.hooks.giveUp(ErrNoSecrets)
		}

		return
	}

	records, secretsErr := wait.recordLayer.SetSecrets(sessionSecrets)
	wait.hooks.goOn(records)

	if secretsErr != nil {
		wait.hooks.giveUp(secretsErr)
	}
}
