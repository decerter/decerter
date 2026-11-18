// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package proxy

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// a record layer that holds one record until its secrets are set or it is released
type fakeSecretsConn struct {
	isWaiting bool
	isHolding bool
	held      tlsrecord.Record
	secrets   tlsrecord.Secrets
}

func (conn *fakeSecretsConn) Waiting() (waiting bool) {
	waiting = conn.isWaiting
	return
}

func (conn *fakeSecretsConn) Holding() (holding bool) {
	holding = conn.isHolding
	return
}

func (conn *fakeSecretsConn) Session() (session tlsrecord.Session) {
	return
}

func (conn *fakeSecretsConn) SetSecrets(secrets tlsrecord.Secrets) (records []tlsrecord.Record, err error) {
	conn.secrets = secrets
	conn.isWaiting = false
	conn.isHolding = false
	records = []tlsrecord.Record{conn.held}
	return
}

func (conn *fakeSecretsConn) Release() (records []tlsrecord.Record) {
	conn.isHolding = false
	records = []tlsrecord.Record{conn.held}
	return
}

// what the hooks of a secretsWait saw
type secretsHookCalls struct {
	isRaw  bool
	isOver bool
	goOn   []tlsrecord.Record
	reason error
}

func newFakeSecretsWait(conn *fakeSecretsConn, calls *secretsHookCalls) (wait *secretsWait) {
	hooks := secretsHooks{
		isDecrypting: func() (isDecrypting bool) {
			isDecrypting = !calls.isRaw
			return
		},
		isOver: func() (isOver bool) {
			isOver = calls.isOver
			return
		},
		goOn: func(records []tlsrecord.Record) {
			calls.goOn = append(calls.goOn, records...)
		},
		giveUp: func(reason error) {
			calls.reason = reason
			calls.isRaw = true
		},
	}
	wait = newSecretsWait(conn, nil, hooks, discardLogger())
	// the test calls poll itself, the timer only counts as pending
	wait.pollTimer.Stop()
	wait.pollTimer = time.NewTimer(time.Hour)
	wait.pollTimer.Stop()
	return
}

// Test if proxy.secretsWait returns with the expected output: watch sets the deadlines and starts the poll, the poll lets held records go on raw after
// the grace time, secrets that come let the record go on decrypted; nothing happens once the interception is over or raw.
func TestSecretsWaitPositive(state *testing.T) {
	held := tlsrecord.Record{Direction: tlsrecord.ClientDirection, ContentType: tlsrecord.ApplicationDataContentType, Payload: []byte("held")}
	secrets := tlsrecord.Secrets{Version: 0x0304, ClientTrafficSecret: []byte("client")}
	isFound := false
	useSecrets(state, func(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (found tlsrecord.Secrets, isThere bool, err error) {
		if isFound {
			found = secrets
			isThere = true
		}

		return
	})

	conn := &fakeSecretsConn{isWaiting: true, isHolding: true, held: held}
	calls := &secretsHookCalls{}
	wait := newFakeSecretsWait(conn, calls)
	wait.mutex.Lock()
	wait.watch()
	isStarted := !wait.holdDeadline.IsZero() && !wait.graceDeadline.IsZero() && wait.isHolding && wait.isPollPending
	// the grace time is over, the secrets are not there yet
	wait.graceDeadline = time.Now().Add(-time.Second)
	wait.mutex.Unlock()
	wait.poll()

	if !isStarted || !slices.EqualFunc(calls.goOn, []tlsrecord.Record{held}, recordsEqual) || conn.isHolding || (calls.reason != nil) || (wait.pollPause != 2*interceptPollStart) {
		state.Errorf("Test of proxy.secretsWait.poll function failed, the held record should go on raw after the grace time, started: %v, records: %+v, reason: %v, pause: %s", isStarted, calls.goOn, calls.reason, wait.pollPause)
		return
	}

	// the secrets come
	isFound = true
	wait.poll()

	if (len(calls.goOn) != 2) || !slices.Equal(conn.secrets.ClientTrafficSecret, secrets.ClientTrafficSecret) || (calls.reason != nil) || wait.isPollPending {
		state.Errorf("Test of proxy.secretsWait.lookup function failed, the secrets should be set, records: %+v, secrets: %+v, reason: %v", calls.goOn, conn.secrets, calls.reason)
		return
	}

	// an interception that is over or raw is not polled
	conn.isWaiting = true
	calls.isOver = true
	wait.poll()
	calls.isOver = false
	calls.isRaw = true
	wait.poll()
	wait.mutex.Lock()
	wait.watch()
	wait.mutex.Unlock()

	if (len(calls.goOn) != 2) || wait.isHolding || wait.isPollPending {
		state.Errorf("Test of proxy.secretsWait.poll function failed, an interception that is over should not be polled, records: %+v", calls.goOn)
		return
	}
}

// Test if proxy.secretsWait returns with the expected errors: a failed lookup gives up at once, missing secrets give up after the hold deadline.
func TestSecretsWaitNegative(state *testing.T) {
	errLookup := errors.New("lookup failed")
	lookupErr := error(nil)
	useSecrets(state, func(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (found tlsrecord.Secrets, isThere bool, err error) {
		err = lookupErr
		return
	})

	negativeCases := []struct {
		Name      string
		LookupErr error
		IsLate    bool
		Expected  error
	}{
		{Name: "lookup error", LookupErr: errLookup, IsLate: false, Expected: errLookup},
		{Name: "no secrets before the hold deadline", LookupErr: nil, IsLate: false, Expected: nil},
		{Name: "no secrets after the hold deadline", LookupErr: nil, IsLate: true, Expected: ErrNoSecrets},
	}

	for _, negative := range negativeCases {
		lookupErr = negative.LookupErr
		conn := &fakeSecretsConn{isWaiting: true, isHolding: false}
		calls := &secretsHookCalls{}
		wait := newFakeSecretsWait(conn, calls)
		wait.mutex.Lock()
		wait.watch()

		if negative.IsLate {
			wait.holdDeadline = time.Now().Add(-time.Second)
		}

		wait.mutex.Unlock()
		wait.poll()

		if !errors.Is(calls.reason, negative.Expected) || ((negative.Expected == nil) != (calls.reason == nil)) || (len(calls.goOn) != 0) {
			state.Errorf("Test of proxy.secretsWait.poll function failed, case %q, reason should be %v, reason: %v, records: %+v", negative.Name, negative.Expected, calls.reason, calls.goOn)
			return
		}
	}
}

func recordsEqual(first tlsrecord.Record, second tlsrecord.Record) (isEqual bool) {
	isEqual = (first.Direction == second.Direction) && (first.ContentType == second.ContentType) && slices.Equal(first.Payload, second.Payload)
	return
}
