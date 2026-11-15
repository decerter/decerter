// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package capture

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// a pseudo terminal, raw without output processing, echo and line editing as adb exec-out gives one; the test closes both ends at its end
func openTerminal(state *testing.T, isRaw bool) (terminal *os.File) {
	masterFd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)

	if err != nil {
		state.Skipf("no pseudo terminal here: %s", err.Error())
	}

	master := os.NewFile(uintptr(masterFd), "/dev/ptmx")
	err = unix.IoctlSetPointerInt(masterFd, unix.TIOCSPTLCK, 0)
	number := 0

	if err == nil {
		number, err = unix.IoctlGetInt(masterFd, unix.TIOCGPTN)
	}

	if err == nil {
		terminal, err = os.OpenFile("/dev/pts/"+strconv.Itoa(number), os.O_RDWR|syscall.O_NOCTTY, 0)
	}

	if err != nil {
		state.Fatalf("Test of capture.OpenFile failed, cannot open a pseudo terminal, error: %s", errors.Join(err, master.Close()).Error())
	}

	state.Cleanup(func() {
		closeErr := errors.Join(terminal.Close(), master.Close())

		if closeErr != nil {
			state.Errorf("Test of capture.OpenFile failed, cannot close the pseudo terminal, error: %s", closeErr.Error())
		}
	})

	if !isRaw {
		return
	}

	termios, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)

	if err == nil {
		termios.Oflag &^= unix.OPOST
		termios.Lflag &^= unix.ICANON | unix.ECHO
		err = unix.IoctlSetTermios(int(terminal.Fd()), unix.TCSETS, termios)
	}

	if err != nil {
		state.Fatalf("Test of capture.OpenFile failed, cannot make the terminal raw, error: %s", err.Error())
	}

	return
}

// stdout is output until the test ends, SIGPIPE is not ignored any more then
func useStdout(state *testing.T, output *os.File) {
	oldStdout := os.Stdout
	state.Cleanup(func() {
		os.Stdout = oldStdout
		signal.Reset(syscall.SIGPIPE)
	})
	os.Stdout = output
}

// Test if capture.OpenFile returns with the expected output: a new file and one that was there with the mode 0600, under sudo for the user who called it, and stdout when it is a pipe or a raw terminal.
func TestOpenFilePositive(state *testing.T) {
	directory := state.TempDir()
	existing := filepath.Join(directory, "existing.pcapng")
	err := os.WriteFile(existing, []byte("old"), 0o644)

	if err != nil {
		state.Fatalf("Test of capture.OpenFile failed, cannot write file, error: %s", err.Error())
	}

	positiveCases := []struct {
		Name    string
		Path    string
		IsSudo  bool
		Content string
	}{
		{Name: "new file", Path: filepath.Join(directory, "new.pcapng")},
		{Name: "existing file", Path: existing},
		{Name: "under sudo", Path: filepath.Join(directory, "sudo.pcapng"), IsSudo: true},
	}

	for _, positive := range positiveCases {
		if positive.IsSudo {
			state.Setenv(sudoUIDVariable, strconv.Itoa(os.Getuid()))
			state.Setenv(sudoGIDVariable, strconv.Itoa(os.Getgid()))
		}

		file, openErr := OpenFile(positive.Path)

		if openErr != nil {
			state.Fatalf("Test of capture.OpenFile failed, case %q, error: %s", positive.Name, openErr.Error())
		}

		info, statErr := file.Stat()
		err = errors.Join(statErr, file.Close())

		if (err != nil) || (info.Mode().Perm() != fileMode) || (info.Size() != 0) || (info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid())) {
			state.Errorf("Test of capture.OpenFile failed, case %q, the file should be empty with mode %v for the user, info: %v, error: %v", positive.Name, fileMode, info.Mode(), err)
			return
		}
	}

	reader, writer, err := os.Pipe()

	if err != nil {
		state.Fatalf("Test of capture.OpenFile failed, cannot make pipe, error: %s", err.Error())
	}

	defer func() {
		closeErr := errors.Join(reader.Close(), writer.Close())

		if closeErr != nil {
			state.Errorf("Test of capture.OpenFile failed, cannot close pipe, error: %s", closeErr.Error())
		}
	}()

	for _, output := range []*os.File{writer, openTerminal(state, true)} {
		useStdout(state, output)
		file, openErr := OpenFile(StreamPath)

		if (openErr != nil) || (file != output) {
			state.Errorf("Test of capture.OpenFile failed, stdout %s should be the stream, error: %v", output.Name(), openErr)
			return
		}
	}
}

// Test if capture.OpenFile returns with the expected errors: a directory that is not there, a file whose mode or owner can't be changed, and stdout that is a terminal.
func TestOpenFileNegative(state *testing.T) {
	_, err := OpenFile(filepath.Join(state.TempDir(), "missing", "capture.pcapng"))

	if !errors.Is(err, ErrOpenFile) || !errors.Is(err, fs.ErrNotExist) {
		state.Errorf("Test of capture.OpenFile failed, error should be %v, error: %v", ErrOpenFile, err)
		return
	}

	// root changes the mode and the owner of every file
	if os.Geteuid() != 0 {
		// the device belongs to root, the user can write it but not change it
		_, err = OpenFile(os.DevNull)

		if !errors.Is(err, ErrOpenFile) || !errors.Is(err, fs.ErrPermission) {
			state.Errorf("Test of capture.OpenFile failed, a file of root should fail with %v, error: %v", ErrOpenFile, err)
			return
		}

		state.Setenv(sudoUIDVariable, "0")
		state.Setenv(sudoGIDVariable, "0")
		_, err = OpenFile(filepath.Join(state.TempDir(), "root.pcapng"))

		if !errors.Is(err, ErrOpenFile) || !errors.Is(err, fs.ErrPermission) {
			state.Errorf("Test of capture.OpenFile failed, a file for root should fail with %v, error: %v", ErrOpenFile, err)
			return
		}
	}

	useStdout(state, openTerminal(state, false))
	_, err = OpenFile(StreamPath)

	if !errors.Is(err, ErrTerminal) {
		state.Errorf("Test of capture.OpenFile failed, error should be %v, error: %v", ErrTerminal, err)
		return
	}
}

// Test if capture.WaitReaderGone returns with the expected output: the reader of a pipe or the peer of a socket went away, the context was cancelled first, or the output is not open.
func TestWaitReaderGonePositive(state *testing.T) {
	reader, writer, err := os.Pipe()

	if err != nil {
		state.Fatalf("Test of capture.WaitReaderGone failed, cannot make pipe, error: %s", err.Error())
	}

	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)

	if err != nil {
		state.Fatalf("Test of capture.WaitReaderGone failed, cannot make sockets, error: %s", errors.Join(err, reader.Close(), writer.Close()).Error())
	}

	local, peer := os.NewFile(uintptr(sockets[0]), "local"), os.NewFile(uintptr(sockets[1]), "peer")

	defer func() {
		closeErr := errors.Join(writer.Close(), local.Close())

		if closeErr != nil {
			state.Errorf("Test of capture.WaitReaderGone failed, cannot close, error: %s", closeErr.Error())
		}
	}()

	// the reader is still there until the context ends
	ctx, cancel := context.WithTimeout(state.Context(), 10*time.Millisecond)
	isGone, err := WaitReaderGone(ctx, writer)
	cancel()

	if (err != nil) || isGone {
		state.Fatalf("Test of capture.WaitReaderGone failed, the reader should still be there, error: %v", err)
	}

	err = errors.Join(reader.Close(), peer.Close())

	if err != nil {
		state.Fatalf("Test of capture.WaitReaderGone failed, cannot close the readers, error: %s", err.Error())
	}

	for _, output := range []*os.File{writer, local} {
		isGone, err = WaitReaderGone(state.Context(), output)

		if (err != nil) || !isGone {
			state.Errorf("Test of capture.WaitReaderGone failed, the reader of %s should be gone, error: %v", output.Name(), err)
			return
		}
	}

	// a descriptor that is not open: nothing to watch
	notOpen := os.NewFile(uintptr(1<<20-1), "not open")
	isGone, err = WaitReaderGone(state.Context(), notOpen)

	if closeErr := notOpen.Close(); (err != nil) || isGone || (closeErr == nil) {
		state.Errorf("Test of capture.WaitReaderGone failed, an output that is not open should end the wait, close: %v, error: %v", closeErr, err)
		return
	}
}

// Test if capture.WaitReaderGone returns with the expected errors: a file that was closed and no file.
func TestWaitReaderGoneNegative(state *testing.T) {
	reader, writer, err := os.Pipe()

	if err == nil {
		err = errors.Join(reader.Close(), writer.Close())
	}

	if err != nil {
		state.Fatalf("Test of capture.WaitReaderGone failed, cannot make pipe, error: %s", err.Error())
	}

	for _, output := range []*os.File{writer, nil} {
		_, err = WaitReaderGone(state.Context(), output)

		if !errors.Is(err, ErrPollStream) {
			state.Errorf("Test of capture.WaitReaderGone failed, output %v, error should be %v, error: %v", output, ErrPollStream, err)
			return
		}
	}
}
