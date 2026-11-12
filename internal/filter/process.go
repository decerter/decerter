// SPDX-License-Identifier: AGPL-3.0-only

package filter

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
)

// the arguments of the process joined by spaces, as proc.cmdline; the process can be gone by the time its flow is decided
func ReadCmdline(tgid uint32) (cmdline string, err error) {
	cmdlineBytes, readErr := os.ReadFile("/proc/" + strconv.FormatUint(uint64(tgid), 10) + "/cmdline")

	if err = readErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrProcess, err)
		return
	}

	// arguments are NUL separated with a trailing NUL
	cmdline = string(bytes.ReplaceAll(bytes.TrimRight(cmdlineBytes, "\x00"), []byte{0}, []byte{' '}))
	return
}

// the path of the executable of the process, as proc.exe
func ReadExe(tgid uint32) (exe string, err error) {
	exe, err = os.Readlink("/proc/" + strconv.FormatUint(uint64(tgid), 10) + "/exe")

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrProcess, err)
		return
	}

	return
}
