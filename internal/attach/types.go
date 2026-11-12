// SPDX-License-Identifier: AGPL-3.0-only

package attach

import (
	"time"

	"github.com/cilium/ebpf"
)

// an attach type of a cgroup that held exactly one program attached without BPF_F_ALLOW_MULTI, as netd attaches on Android
// Flags are the attach flags it had (0 or BPF_F_ALLOW_OVERRIDE), it is put back with them
// ProgramName and ProgramTag tell the program apart from another one that got its id after a reboot, PinPath is for people reading the state file
// Gap is how long the hook had no program while it was detached and attached again, it is not stored
type SharedHook struct {
	AttachType     ebpf.AttachType `json:"attachType"`
	AttachTypeName string          `json:"attachTypeName"`
	Flags          uint32          `json:"flags"`
	ProgramID      ebpf.ProgramID  `json:"programId"`
	ProgramName    string          `json:"programName"`
	ProgramTag     string          `json:"programTag"`
	PinPath        string          `json:"pinPath,omitzero"`
	Gap            time.Duration   `json:"-"`
}

// written before the first hook is detached and removed after the last one is put back, so a decerter killed in between can be undone
type NetdState struct {
	Pid    int          `json:"pid"`
	Cgroup string       `json:"cgroup"`
	Hooks  []SharedHook `json:"hooks"`
}
