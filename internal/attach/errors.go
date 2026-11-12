// SPDX-License-Identifier: AGPL-3.0-only

package attach

import (
	"errors"
)

var (
	ErrAttach         = errors.New("could not attach bpf program")
	ErrOpenExecutable = errors.New("could not open executable")
	ErrQuery          = errors.New("could not query cgroup programs")
	// a program attached without BPF_F_ALLOW_MULTI refuses every bpf_link of the same attach type
	ErrExclusiveHook = errors.New("cgroup hook is held exclusively by another program")
	ErrShare         = errors.New("could not share cgroup hook")
	ErrRestore       = errors.New("could not restore cgroup hook")
	// a hook to restore still has more than the one program, decerter's links are not closed yet or another program joined
	ErrHookInUse = errors.New("cgroup hook has more than one program")
	// the program on the hook is not the one in the state file
	ErrHookChanged = errors.New("cgroup hook holds another program than the state file")
	ErrNetdState   = errors.New("could not write netd hook state")
	ErrLocked      = errors.New("another decerter is running")
)
