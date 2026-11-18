// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package attach_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/decerter/decerter/internal/attach"
)

// Test if attach.OpenExecutable returns with the expected output for this test's binary.
func TestOpenExecutablePositive(state *testing.T) {
	path, err := os.Executable()

	if err != nil {
		state.Fatalf("Test of attach.OpenExecutable failed, cannot get the executable, error: %s", err.Error())
	}

	executable, err := attach.OpenExecutable(path)

	if (err != nil) || (executable == nil) {
		state.Errorf("Test of attach.OpenExecutable function failed, path %s, error: %v", path, err)
		return
	}
}

// Test if attach.OpenExecutable, attach.AddCgroup, attach.AddUprobe and attach.AddUprobeAddress return with the expected errors before any bpf
// syscall: a missing file, a missing cgroup, no program.
func TestAttachNegative(state *testing.T) {
	directory := state.TempDir()
	_, err := attach.OpenExecutable(filepath.Join(directory, "missing"))

	if !errors.Is(err, attach.ErrOpenExecutable) || !errors.Is(err, fs.ErrNotExist) {
		state.Errorf("Test of attach.OpenExecutable function failed, error should be %v, error: %v", attach.ErrOpenExecutable, err)
		return
	}

	closeFunction, err := attach.AddCgroup(filepath.Join(directory, "missing-cgroup"), nil, ebpf.AttachCGroupInet4Connect)

	if !errors.Is(err, attach.ErrAttach) || (closeFunction != nil) {
		state.Errorf("Test of attach.AddCgroup function failed, error should be %v, error: %v", attach.ErrAttach, err)
		return
	}

	path, err := os.Executable()

	if err != nil {
		state.Fatalf("Test of attach.AddUprobe failed, cannot get the executable, error: %s", err.Error())
	}

	executable, err := attach.OpenExecutable(path)

	if err != nil {
		state.Fatalf("Test of attach.AddUprobe failed, cannot open the executable, error: %s", err.Error())
	}

	for _, isReturn := range []bool{false, true} {
		closeFunction, err = attach.AddUprobe(executable, "main.main", nil, isReturn, 1)

		if !errors.Is(err, attach.ErrAttach) || (closeFunction != nil) {
			state.Errorf("Test of attach.AddUprobe function failed, return %v, error should be %v, error: %v", isReturn, attach.ErrAttach, err)
			return
		}
	}

	closeFunction, err = attach.AddUprobeAddress(executable, 0x1000, nil, 1)

	if !errors.Is(err, attach.ErrAttach) || (closeFunction != nil) {
		state.Errorf("Test of attach.AddUprobeAddress function failed, error should be %v, error: %v", attach.ErrAttach, err)
		return
	}
}
