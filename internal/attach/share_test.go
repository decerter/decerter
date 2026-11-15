// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package attach_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/decerter/decerter/internal/attach"
)

// Test if attach.ExclusiveHooks, attach.ShareHooks and attach.RestoreHooks return with the expected output without hooks: nothing is queried or
// changed, ShareHooks still writes the state file with this process' pid.
func TestShareHooksPositive(state *testing.T) {
	directory := state.TempDir()
	statePath := filepath.Join(directory, "netd-hooks.json")
	hooks, err := attach.ExclusiveHooks(directory, nil)

	if (err != nil) || (len(hooks) != 0) {
		state.Errorf("Test of attach.ExclusiveHooks function failed, no attach type should have no hook, hooks: %+v, error: %v", hooks, err)
		return
	}

	shared, err := attach.ShareHooks(directory, nil, statePath)
	written, readErr := attach.ReadNetdState(statePath)

	if (err != nil) || (len(shared) != 0) || (readErr != nil) || (written.Pid != os.Getpid()) || (written.Cgroup != directory) {
		state.Errorf("Test of attach.ShareHooks function failed, the state should be written, shared: %+v, state: %+v, error: %v, read error: %v", shared, written, err, readErr)
		return
	}

	restored, err := attach.RestoreHooks(directory, nil)

	if (err != nil) || (len(restored) != 0) {
		state.Errorf("Test of attach.RestoreHooks function failed, nothing should be restored, restored: %+v, error: %v", restored, err)
		return
	}
}

// Test if attach.ExclusiveHooks, attach.ShareHooks and attach.RestoreHooks return with the expected errors: a cgroup that can't be opened, a state
// file that can't be written.
func TestShareHooksNegative(state *testing.T) {
	directory := state.TempDir()
	missing := filepath.Join(directory, "missing")
	_, err := attach.ExclusiveHooks(missing, nil)

	if !errors.Is(err, attach.ErrQuery) || !errors.Is(err, fs.ErrNotExist) {
		state.Errorf("Test of attach.ExclusiveHooks function failed, error should be %v, error: %v", attach.ErrQuery, err)
		return
	}

	_, err = attach.ShareHooks(directory, netdState.Hooks, filepath.Join(missing, "netd-hooks.json"))

	if !errors.Is(err, attach.ErrNetdState) {
		state.Errorf("Test of attach.ShareHooks function failed, error should be %v, error: %v", attach.ErrNetdState, err)
		return
	}

	// the state is written before the cgroup is opened
	statePath := filepath.Join(directory, "netd-hooks.json")
	_, err = attach.ShareHooks(missing, netdState.Hooks, statePath)
	_, readErr := attach.ReadNetdState(statePath)

	if !errors.Is(err, attach.ErrShare) || (readErr != nil) {
		state.Errorf("Test of attach.ShareHooks function failed, error should be %v with the state written, error: %v, read error: %v", attach.ErrShare, err, readErr)
		return
	}

	_, err = attach.RestoreHooks(missing, netdState.Hooks)

	if !errors.Is(err, attach.ErrRestore) {
		state.Errorf("Test of attach.RestoreHooks function failed, error should be %v, error: %v", attach.ErrRestore, err)
		return
	}
}

// Test if attach.WriteNetdState, attach.RemoveNetdState and attach.LockNetdState return with the expected errors: a directory in the way of the
// rename, a directory that can't be read for the sync or written for the remove, a lock in a missing directory.
func TestNetdStateFilesNegative(state *testing.T) {
	directory := state.TempDir()
	inTheWay := filepath.Join(directory, "in-the-way")
	err := os.MkdirAll(filepath.Join(inTheWay, "child"), 0o700)

	if err != nil {
		state.Fatalf("Test of attach.WriteNetdState failed, cannot create the directory, error: %s", err.Error())
	}

	err = attach.WriteNetdState(inTheWay, netdState)

	if !errors.Is(err, attach.ErrNetdState) {
		state.Errorf("Test of attach.WriteNetdState function failed, a directory in the way should be %v, error: %v", attach.ErrNetdState, err)
		return
	}

	_, err = attach.LockNetdState(filepath.Join(directory, "missing", "decerter.lock"))

	if !errors.Is(err, attach.ErrNetdState) || !errors.Is(err, fs.ErrNotExist) {
		state.Errorf("Test of attach.LockNetdState function failed, error should be %v, error: %v", attach.ErrNetdState, err)
		return
	}

	// root reads and writes every directory
	if os.Geteuid() == 0 {
		return
	}

	negativeCases := []struct {
		Name  string
		Mode  fs.FileMode
		Write bool
	}{
		// the file can be written and renamed, the directory can't be opened for its sync
		{Name: "no read permission", Mode: 0o300, Write: true},
		{Name: "no write permission", Mode: 0o500, Write: false},
	}

	for _, negative := range negativeCases {
		stateDirectory := filepath.Join(directory, negative.Name)
		statePath := filepath.Join(stateDirectory, "netd-hooks.json")
		err = os.MkdirAll(stateDirectory, 0o700)

		if err == nil {
			err = attach.WriteNetdState(statePath, netdState)
		}

		if err == nil {
			err = os.Chmod(stateDirectory, negative.Mode)
		}

		if err != nil {
			state.Fatalf("Test of attach.WriteNetdState failed, cannot prepare %s, error: %s", negative.Name, err.Error())
		}

		writeErr := attach.WriteNetdState(statePath, netdState)
		removeErr := attach.RemoveNetdState(statePath)
		err = os.Chmod(stateDirectory, 0o700)

		if err != nil {
			state.Fatalf("Test of attach.WriteNetdState failed, cannot make %s writable again, error: %s", negative.Name, err.Error())
		}

		if !errors.Is(writeErr, attach.ErrNetdState) || (removeErr == nil) || (negative.Write == errors.Is(removeErr, attach.ErrNetdState)) {
			state.Errorf("Test of attach.WriteNetdState function failed, %s, write and remove should fail, write error: %v, remove error: %v", negative.Name, writeErr, removeErr)
		}
	}
}
