// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package attach_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/decerter/decerter/internal/attach"
	"github.com/cilium/ebpf"
)

// the hooks netd held on the Android 15 emulator that run mode shares
var netdState = attach.NetdState{
	Pid:    4242,
	Cgroup: "/sys/fs/cgroup",
	Hooks: []attach.SharedHook{
		{AttachType: ebpf.AttachCGroupInetEgress, AttachTypeName: "CGroupInetEgress", Flags: 0, ProgramID: 15, ProgramName: "cgroupskb_egres", ProgramTag: "5c67b2494b78ba1a", PinPath: "/sys/fs/bpf/netd_shared/prog_netd_cgroupskb_egress_stats", Gap: 0},
		{AttachType: ebpf.AttachCGroupInet4Connect, AttachTypeName: "CGroupInet4Connect", Flags: 0, ProgramID: 23, ProgramName: "connect4_inet4_", ProgramTag: "57cd311f2e27366b", PinPath: "", Gap: 0},
	},
}

func testNetdStateRoundTrip(statePath string) (err error) {
	err = attach.WriteNetdState(statePath, netdState)

	if err != nil {
		return
	}

	info, statErr := os.Stat(statePath)

	if err = statErr; err != nil {
		return
	}

	if info.Mode().Perm() != 0o600 {
		err = fmt.Errorf("state file mode was not %v instead: %v", fs.FileMode(0o600), info.Mode().Perm())
		return
	}

	// the temporary file is renamed over the state file
	if _, tmpErr := os.Stat(statePath + ".tmp"); !errors.Is(tmpErr, fs.ErrNotExist) {
		err = fmt.Errorf("temporary state file is still there: %v", tmpErr)
		return
	}

	state, readErr := attach.ReadNetdState(statePath)

	if err = readErr; err != nil {
		return
	}

	if !reflect.DeepEqual(state, netdState) {
		err = fmt.Errorf("attach.ReadNetdState return value was not %+v instead: %+v", netdState, state)
		return
	}

	err = attach.RemoveNetdState(statePath)

	if err != nil {
		return
	}

	_, err = attach.ReadNetdState(statePath)

	if !errors.Is(err, fs.ErrNotExist) {
		err = fmt.Errorf("attach.ReadNetdState after remove return value was not %v instead: %v", fs.ErrNotExist, err)
		return
	}

	// removing a state that isn't there is fine
	err = attach.RemoveNetdState(statePath)
	return
}

// Test if attach.WriteNetdState, attach.ReadNetdState and attach.RemoveNetdState return with the expected output.
func TestNetdStatePositive(state *testing.T) {
	err := testNetdStateRoundTrip(filepath.Join(state.TempDir(), "netd-hooks.json"))

	if err != nil {
		state.Errorf("Test of attach.WriteNetdState failed, error: %s", err.Error())
		return
	}
}

// Test if attach.ReadNetdState and attach.WriteNetdState return with the expected errors.
func TestNetdStateNegative(state *testing.T) {
	directory := state.TempDir()
	brokenPath := filepath.Join(directory, "broken.json")
	err := os.WriteFile(brokenPath, []byte("{\"hooks\": ["), 0o600)

	if err != nil {
		state.Fatalf("Test of attach.ReadNetdState failed, cannot write file, error: %s", err.Error())
	}

	_, err = attach.ReadNetdState(brokenPath)

	if !errors.Is(err, attach.ErrNetdState) {
		state.Errorf("Test of attach.ReadNetdState function failed, error should be %v, error: %v", attach.ErrNetdState, err)
		return
	}

	err = attach.WriteNetdState(filepath.Join(directory, "missing", "netd-hooks.json"), netdState)

	if !errors.Is(err, attach.ErrNetdState) {
		state.Errorf("Test of attach.WriteNetdState function failed, error should be %v, error: %v", attach.ErrNetdState, err)
		return
	}
}

// Test if attach.LockNetdState returns with the expected output.
func TestLockNetdStatePositive(state *testing.T) {
	lockPath := filepath.Join(state.TempDir(), "decerter.lock")

	// the lock can be taken again after it was released
	for range 2 {
		unlock, err := attach.LockNetdState(lockPath)

		if err != nil {
			state.Errorf("Test of attach.LockNetdState failed, error: %s", err.Error())
			return
		}

		err = unlock()

		if err != nil {
			state.Errorf("Test of attach.LockNetdState failed, cannot unlock, error: %s", err.Error())
			return
		}
	}
}

// Test if attach.LockNetdState returns with the expected errors.
func TestLockNetdStateNegative(state *testing.T) {
	lockPath := filepath.Join(state.TempDir(), "decerter.lock")
	unlock, err := attach.LockNetdState(lockPath)

	if err != nil {
		state.Fatalf("Test of attach.LockNetdState failed, cannot take the first lock, error: %s", err.Error())
	}

	defer func() {
		if unlockErr := unlock(); unlockErr != nil {
			state.Errorf("Test of attach.LockNetdState failed, cannot unlock, error: %s", unlockErr.Error())
		}
	}()

	_, err = attach.LockNetdState(lockPath)

	if !errors.Is(err, attach.ErrLocked) {
		state.Errorf("Test of attach.LockNetdState function failed, error should be %v, error: %v", attach.ErrLocked, err)
		return
	}
}
