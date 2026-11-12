// SPDX-License-Identifier: AGPL-3.0-only

package attach

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Android's netd attaches its cgroup programs with BPF_PROG_ATTACH and flags 0, which makes the kernel refuse decerter's links of the same attach types
// sharing a hook: get netd's program by id, detach it, attach it again with BPF_F_ALLOW_MULTI, then decerter's links go after it, so netd's program runs first and sees the original destination
// restoring a hook: after decerter's links are closed, detach and attach again with the old flags
// the kernel only changes the flags of a hook while nothing else is attached, so each change leaves the hook without a program for a few dozen microseconds

const (
	// attach flags of BPF_PROG_ATTACH on a cgroup (include/uapi/linux/bpf.h)
	flagAllowMulti uint32 = 2
	// BPF_CGROUP_MAX_PROGS, the most programs one cgroup hook can hold
	maxCgroupPrograms int = 64
	// Android's bpfloader pins every program under here with a prog_ prefix
	bpffsRoot        string = "/sys/fs/bpf"
	programPinPrefix string = "prog_"
)

// union bpf_attr of BPF_PROG_QUERY up to prog_cnt, the kernel reads the fields after it as zero
// cilium's link.QueryPrograms doesn't return attach_flags, which tell an exclusive hook from a shared one
type progQueryAttr struct {
	targetFd    uint32
	attachType  uint32
	queryFlags  uint32
	attachFlags uint32
	progIDs     uint64
	progCount   uint32
	padding     uint32
}

// AttachCGroupInetIngress is 0 like AttachNone, and the stringer prints None for it
func attachTypeName(attachType ebpf.AttachType) (name string) {
	if attachType == ebpf.AttachCGroupInetIngress {
		name = "CGroupInetIngress"
		return
	}

	name = attachType.String()
	return
}

// attach flags of the hook and the ids of its programs in the order they run
func queryCgroup(cgroupFd int, attachType ebpf.AttachType) (attachFlags uint32, programIDs []ebpf.ProgramID, err error) {
	ids := make([]uint32, maxCgroupPrograms)
	attr := progQueryAttr{
		targetFd:    uint32(cgroupFd),
		attachType:  uint32(attachType),
		queryFlags:  0,
		attachFlags: 0,
		progIDs:     uint64(uintptr(unsafe.Pointer(&ids[0]))),
		progCount:   uint32(len(ids)),
		padding:     0,
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_QUERY, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(ids)

	if errno != 0 {
		err = fmt.Errorf("%w: %s: %w", ErrQuery, attachTypeName(attachType), errno)
		return
	}

	attachFlags = attr.attachFlags

	for _, id := range ids[:attr.progCount] {
		programIDs = append(programIDs, ebpf.ProgramID(id))
	}

	return
}

// the hooks of attachTypes that hold one program attached without BPF_F_ALLOW_MULTI; a hook that is empty or already allows more programs takes decerter's links as it is
// on desktop Linux nothing is attached this way and the result is empty
func ExclusiveHooks(cgroupPath string, attachTypes []ebpf.AttachType) (hooks []SharedHook, err error) {
	cgroup, openErr := os.Open(cgroupPath)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrQuery, err)
		return
	}

	defer func() {
		err = errors.Join(err, cgroup.Close())
	}()

	sortedTypes := slices.Clone(attachTypes)
	slices.Sort(sortedTypes)

	for _, attachType := range slices.Compact(sortedTypes) {
		attachFlags, programIDs, queryErr := queryCgroup(int(cgroup.Fd()), attachType)

		if err = queryErr; err != nil {
			return
		}

		if (len(programIDs) != 1) || (attachFlags&flagAllowMulti != 0) {
			continue
		}

		program, programErr := ebpf.NewProgramFromID(programIDs[0])

		if err = programErr; err != nil {
			err = fmt.Errorf("%w: %s program %d: %w", ErrQuery, attachTypeName(attachType), programIDs[0], err)
			return
		}

		info, infoErr := program.Info()
		err = errors.Join(infoErr, program.Close())

		if err != nil {
			err = fmt.Errorf("%w: %s program %d: %w", ErrQuery, attachTypeName(attachType), programIDs[0], err)
			return
		}

		hooks = append(hooks, SharedHook{
			AttachType:     attachType,
			AttachTypeName: attachTypeName(attachType),
			Flags:          attachFlags,
			ProgramID:      programIDs[0],
			ProgramName:    info.Name,
			ProgramTag:     info.Tag,
			PinPath:        "",
			Gap:            0,
		})
	}

	if len(hooks) > 0 {
		addPinPaths(hooks)
	}

	return
}

// only for people reading the state file, a program that isn't found keeps an empty pin path
func addPinPaths(hooks []SharedHook) {
	missing := len(hooks)

	// the pin paths are only informative, a bpffs that can't be walked leaves them empty
	_ = filepath.WalkDir(bpffsRoot, func(path string, entry fs.DirEntry, walkErr error) (err error) {
		if (walkErr != nil) || entry.IsDir() || !strings.HasPrefix(entry.Name(), programPinPrefix) {
			return
		}

		program, loadErr := ebpf.LoadPinnedProgram(path, &ebpf.LoadPinOptions{ReadOnly: true})

		if loadErr != nil {
			return
		}

		info, infoErr := program.Info()
		closeErr := program.Close()

		if (infoErr != nil) || (closeErr != nil) {
			return
		}

		id, hasID := info.ID()

		if !hasID {
			return
		}

		for index := range hooks {
			if (hooks[index].ProgramID == id) && (hooks[index].PinPath == "") {
				hooks[index].PinPath = path
				missing--
			}
		}

		if missing == 0 {
			err = fs.SkipAll
		}

		return
	})
}

// the state file is written before the first hook changes, so a decerter killed with SIGKILL can be undone by RestoreHooks with the state from ReadNetdState
// a hook that fails is put back with its old flags, and every hook shared before it is restored; the state file is removed when that worked and kept when not
func ShareHooks(cgroupPath string, hooks []SharedHook, statePath string) (shared []SharedHook, err error) {
	err = WriteNetdState(statePath, NetdState{Pid: os.Getpid(), Cgroup: cgroupPath, Hooks: hooks})

	if err != nil {
		return
	}

	cgroup, openErr := os.Open(cgroupPath)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrShare, err)
		return
	}

	defer func() {
		err = errors.Join(err, cgroup.Close())
	}()

	for index, hook := range hooks {
		gap, shareErr := shareHook(int(cgroup.Fd()), hook)

		if err = shareErr; err != nil {
			_, restoreErr := RestoreHooks(cgroupPath, hooks[:index+1])

			if restoreErr == nil {
				restoreErr = RemoveNetdState(statePath)
			}

			err = errors.Join(err, restoreErr)
			shared = nil
			return
		}

		hook.Gap = gap
		shared = append(shared, hook)
	}

	return
}

// the program fd is held across detach and attach, the pin keeps netd's program alive anyway
func shareHook(cgroupFd int, hook SharedHook) (gap time.Duration, err error) {
	program, programErr := ebpf.NewProgramFromID(hook.ProgramID)

	if err = programErr; err != nil {
		err = fmt.Errorf("%w: %s program %d: %w", ErrShare, hook.AttachTypeName, hook.ProgramID, err)
		return
	}

	defer func() {
		err = errors.Join(err, program.Close())
	}()

	gap, err = changeFlags(cgroupFd, program, hook.AttachType, flagAllowMulti, hook.Flags)

	if err != nil {
		err = fmt.Errorf("%w: %s program %d: %w", ErrShare, hook.AttachTypeName, hook.ProgramID, err)
		return
	}

	return
}

// detach program and attach it again with flags; when that attach fails it goes back with fallbackFlags, so the hook isn't left empty
func changeFlags(cgroupFd int, program *ebpf.Program, attachType ebpf.AttachType, flags uint32, fallbackFlags uint32) (gap time.Duration, err error) {
	startTime := time.Now()
	err = link.RawDetachProgram(link.RawDetachProgramOptions{Target: cgroupFd, Program: program, Attach: attachType})

	if err != nil {
		err = fmt.Errorf("detach: %w", err)
		return
	}

	attachErr := link.RawAttachProgram(link.RawAttachProgramOptions{Target: cgroupFd, Program: program, Attach: attachType, Flags: flags})
	gap = time.Since(startTime)

	if attachErr == nil {
		return
	}

	err = fmt.Errorf("attach with flags %#x: %w", flags, attachErr)
	fallbackErr := link.RawAttachProgram(link.RawAttachProgramOptions{Target: cgroupFd, Program: program, Attach: attachType, Flags: fallbackFlags})

	if fallbackErr != nil {
		err = errors.Join(err, fmt.Errorf("hook left without its program, attach with flags %#x: %w", fallbackFlags, fallbackErr))
	}

	return
}

// put each hook back to its old flags, decerter's links have to be closed first; restored are the hooks that changed, with the gap
// a hook that is exclusive already (restored before, or the device rebooted) is left alone; one that lost its program, because decerter was killed between detach and attach, gets it back if the program is still loaded
// every hook is tried, the errors are joined
func RestoreHooks(cgroupPath string, hooks []SharedHook) (restored []SharedHook, err error) {
	cgroup, openErr := os.Open(cgroupPath)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrRestore, err)
		return
	}

	defer func() {
		err = errors.Join(err, cgroup.Close())
	}()

	for _, hook := range hooks {
		isRestored, gap, restoreErr := restoreHook(int(cgroup.Fd()), hook)

		if restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("%w: %s program %d: %w", ErrRestore, hook.AttachTypeName, hook.ProgramID, restoreErr))
			continue
		}

		if isRestored {
			hook.Gap = gap
			restored = append(restored, hook)
		}
	}

	return
}

func restoreHook(cgroupFd int, hook SharedHook) (isRestored bool, gap time.Duration, err error) {
	attachFlags, programIDs, queryErr := queryCgroup(cgroupFd, hook.AttachType)

	if err = queryErr; err != nil {
		return
	}

	switch {
	case len(programIDs) == 0:
		// the program is attached again below, no detach
	case attachFlags&flagAllowMulti == 0:
		return
	case len(programIDs) > 1:
		err = fmt.Errorf("%w: %d programs", ErrHookInUse, len(programIDs))
		return
	default:
	}

	programID := hook.ProgramID

	if len(programIDs) == 1 {
		programID = programIDs[0]
	}

	program, programErr := ebpf.NewProgramFromID(programID)

	if err = programErr; err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, program.Close())
	}()

	// the id alone can belong to another program after a reboot
	info, infoErr := program.Info()

	if err = infoErr; err != nil {
		return
	}

	if (info.Name != hook.ProgramName) || (info.Tag != hook.ProgramTag) {
		err = fmt.Errorf("%w: program %d is %s %s", ErrHookChanged, programID, info.Name, info.Tag)
		return
	}

	if len(programIDs) == 0 {
		startTime := time.Now()
		err = link.RawAttachProgram(link.RawAttachProgramOptions{Target: cgroupFd, Program: program, Attach: hook.AttachType, Flags: hook.Flags})
		gap = time.Since(startTime)
		isRestored = (err == nil)
		return
	}

	gap, err = changeFlags(cgroupFd, program, hook.AttachType, hook.Flags, flagAllowMulti)
	isRestored = (err == nil)
	return
}

// written to a temporary file, synced, renamed over path and the directory synced, so a crash leaves the old state or the new one
func WriteNetdState(path string, state NetdState) (err error) {
	content, marshalErr := json.MarshalIndent(state, "", "\t")

	if err = marshalErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrNetdState, err)
		return
	}

	temporaryPath := path + ".tmp"
	err = writeSynced(temporaryPath, append(content, '\n'))

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrNetdState, errors.Join(err, os.Remove(temporaryPath)))
		return
	}

	err = os.Rename(temporaryPath, path)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrNetdState, err)
		return
	}

	err = syncDirectory(filepath.Dir(path))

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrNetdState, err)
		return
	}

	return
}

func writeSynced(path string, content []byte) (err error) {
	file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)

	if err = openErr; err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	_, err = file.Write(content)

	if err != nil {
		return
	}

	err = file.Sync()
	return
}

func syncDirectory(directory string) (err error) {
	file, openErr := os.Open(directory)

	if err = openErr; err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	err = file.Sync()
	return
}

// a missing file is an error that matches fs.ErrNotExist
func ReadNetdState(path string) (state NetdState, err error) {
	content, readErr := os.ReadFile(path)

	if err = readErr; err != nil {
		return
	}

	err = json.Unmarshal(content, &state)

	if err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrNetdState, path, err)
		return
	}

	return
}

// the removal is synced like the write, a missing file is not an error
func RemoveNetdState(path string) (err error) {
	err = os.Remove(path)

	if errors.Is(err, fs.ErrNotExist) {
		err = nil
		return
	}

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrNetdState, err)
		return
	}

	err = syncDirectory(filepath.Dir(path))
	return
}

// held while decerter runs, so a second decerter or a restore can't touch the hooks of a running one; closing the file releases it
func LockNetdState(path string) (unlock func() error, err error) {
	file, openErr := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrNetdState, err)
		return
	}

	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)

	if err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			err = fmt.Errorf("%w: %s is locked", ErrLocked, path)
		} else {
			err = fmt.Errorf("%w: lock %s: %w", ErrNetdState, path, err)
		}

		err = errors.Join(err, file.Close())
		return
	}

	unlock = file.Close
	return
}
