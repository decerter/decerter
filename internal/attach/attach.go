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

// open the executable or shared library the uprobes attach to, one handle serves many symbol attaches
func OpenExecutable(path string) (executable *link.Executable, err error) {
	executable, openErr := link.OpenExecutable(path)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrOpenExecutable, path, err)
		return
	}

	return
}

// attach program to the entry (isReturn false) or the return (isReturn true) of symbol in executable
func AddUprobe(executable *link.Executable, symbol string, program *ebpf.Program, isReturn bool) (closeFunction func() error, err error) {
	var (
		uprobeLink link.Link
		attachErr  error
	)

	if isReturn {
		uprobeLink, attachErr = executable.Uretprobe(symbol, program, nil)
	} else {
		uprobeLink, attachErr = executable.Uprobe(symbol, program, nil)
	}

	if err = attachErr; err != nil {
		err = fmt.Errorf("%w: %s return=%t: %w", ErrAttach, symbol, isReturn, attachErr)
		return
	}

	closeFunction = uprobeLink.Close
	return
}
