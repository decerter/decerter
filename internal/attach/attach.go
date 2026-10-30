// SPDX-License-Identifier: AGPL-3.0-only

package attach

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	CgroupRoot string = "/sys/fs/cgroup"
)

func AddCgroup(cgroupPath string, program *ebpf.Program, attachType ebpf.AttachType) (closeFunction func() error, err error) {
	cgroupLink, attachErr := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  attachType,
		Program: program,
	})

	if err = attachErr; err != nil {
		err = fmt.Errorf("%w: %s %s: %w", ErrAttach, cgroupPath, attachType, err)
		return
	}

	closeFunction = cgroupLink.Close
	return
}
