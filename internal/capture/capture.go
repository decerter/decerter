// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/pcapng"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	// -capture - writes the capture as a live pcapng stream to stdout
	StreamPath string = "-"
	// the file holds the secrets of the captured sessions
	fileMode os.FileMode = 0o600
	// sudo keeps the ids of the user who called it here
	sudoUIDVariable string = "SUDO_UID"
	sudoGIDVariable string = "SUDO_GID"
	// how long the reader sleeps when no flow waits for its secrets, it flushes the file, counts the drops and forgets idle flows when it wakes
	idleWake time.Duration = time.Second
	// packets that are already in packet_map when the capture is stopped are still written, a sender that keeps it full can't hold the stop up longer than this
	drainTimeout time.Duration = time.Second
	// how often a stream looks whether its reader is still there while no packet is written
	readerPollInterval time.Duration = 250 * time.Millisecond
)

// create the capture file for its owner only: it holds secrets, under sudo it goes to the user who called sudo
// StreamPath is stdout, which must not be a terminal: the stream is binary and holds secrets
func OpenFile(path string) (file *os.File, err error) {
	if path == StreamPath {
		_, termiosErr := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)

		if termiosErr == nil {
			err = ErrTerminal
			return
		}

		// without this a write to a pipe whose reader is gone ends the process at once, before a link is closed; ignored, the write fails with EPIPE and decerter stops itself
		signal.Ignore(syscall.SIGPIPE)
		file = os.Stdout
		return
	}

	file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrOpenFile, err)
		return
	}

	// a file that was there before keeps its old mode
	err = file.Chmod(fileMode)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrOpenFile, errors.Join(err, file.Close()))
		return
	}

	uid, uidErr := strconv.Atoi(os.Getenv(sudoUIDVariable))
	gid, gidErr := strconv.Atoi(os.Getenv(sudoGIDVariable))

	// not started with sudo
	if (uidErr != nil) || (gidErr != nil) {
		return
	}

	err = file.Chown(uid, gid)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrOpenFile, errors.Join(err, file.Close()))
		return
	}

	return
}

// read packet_map and write the packets as pcapng to output until the context is cancelled, then write what still waits and flush
// secretsBpfMaps is nil without the secrets uprobe, the packets are written without keys then
// a TLS flow is written behind the other flows: its packets wait from the ClientHello on until its secrets are there, so the file is ordered by time inside a flow but not across flows
// plaintext writes synthesized packets instead: the TCP streams are put in order, the TLS sessions decrypted and the payload written in new packets with the addresses and ports of the flow, no secrets are in the file
// the snaplen still cuts what the programs copy, a cut TCP packet is a hole in its stream; a synthesized packet is never cut
// stream writes every block to output at once, for a live reader; a file is written in larger pieces and flushed when the ring is empty
func Write(ctx context.Context, output io.Writer, stream bool, snaplen uint32, plaintext bool, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, logger *slog.Logger) (err error) {
	writerSnaplen := snaplen

	if plaintext {
		writerSnaplen = max(snaplen, SynthesizedLength)
	}

	writer, writerErr := pcapng.New(output, writerSnaplen, stream)

	if err = writerErr; err != nil {
		return
	}

	// the section and interface blocks are in the file at once, a capture without packets is a valid file too
	err = writer.Flush()

	if err != nil {
		return
	}

	bootOffset, offsetErr := bootTimeOffset()

	if err = offsetErr; err != nil {
		return
	}

	reader, readerErr := ringbuf.NewReader(captureBpfMaps[capturebpf.PacketMap])

	if err = readerErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrRead, err)
		return
	}

	defer func() {
		err = errors.Join(err, reader.Close())
	}()

	// the cancelled context wakes the reader, it gets the records that are in the ring by then and ErrFlushed after them
	stop := context.AfterFunc(ctx, func() {
		flushErr := reader.Flush()

		if flushErr != nil {
			logger.Error("Could not wake packet_map reader", "error", flushErr)
		}
	})
	defer stop()

	recorder := newRecorder(&writer, plaintext, bootOffset, captureBpfMaps, secretsBpfMaps, time.Now(), logger)
	var record ringbuf.Record
	var drainDeadline time.Time

	for {
		reader.SetDeadline(recorder.nextWake)
		readErr := reader.ReadInto(&record)
		now := time.Now()

		switch {
		case readErr == nil:
			packet, parseErr := capturebpf.ParsePacket(record.RawSample)

			if parseErr != nil {
				logger.Warn("Could not parse packet_map record", "error", parseErr)
				continue
			}

			err = recorder.handle(packet, now)
		case errors.Is(readErr, os.ErrDeadlineExceeded):
			// the ring is empty, so the file is brought up to date
			err = writer.Flush()
		case
			errors.Is(readErr, ringbuf.ErrFlushed),
			errors.Is(readErr, ringbuf.ErrClosed):
			logger.Debug("Context cancelled")
			err = recorder.finish()
			return
		default:
			err = errors.Join(fmt.Errorf("%w: %w", ErrRead, readErr), recorder.finish())
			return
		}

		// the output is gone or full, nothing more can be written
		if err != nil {
			return
		}

		if ctx.Err() != nil {
			if drainDeadline.IsZero() {
				drainDeadline = now.Add(drainTimeout)
			}

			if now.After(drainDeadline) {
				err = recorder.finish()
				return
			}
		}

		// under steady traffic the read never times out, so the clock is checked after every packet
		if !now.Before(recorder.nextWake) {
			err = recorder.tick(now)

			if err != nil {
				return
			}
		}
	}
}

// the reader of a stream that went away is only seen by the next write, and an idle capture may write nothing for a long time
// the write end of a pipe polls POLLERR once its last reader is closed, a socket POLLHUP; isGone is false when the context was cancelled first
func WaitReaderGone(ctx context.Context, output *os.File) (isGone bool, err error) {
	rawConn, connErr := output.SyscallConn()

	if err = connErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrPollStream, err)
		return
	}

	for ctx.Err() == nil {
		pollFds := []unix.PollFd{{Fd: 0, Events: 0, Revents: 0}}
		var pollErr error

		err = rawConn.Control(func(fd uintptr) {
			pollFds[0].Fd = int32(fd)
			_, pollErr = unix.Poll(pollFds, int(readerPollInterval.Milliseconds()))
		})

		if err == nil {
			err = pollErr
		}

		if errors.Is(err, unix.EINTR) {
			err = nil
			continue
		}

		if err != nil {
			err = fmt.Errorf("%w: %w", ErrPollStream, err)
			return
		}

		// POLLNVAL: the output is not open, there is no reader to watch
		if pollFds[0].Revents&unix.POLLNVAL != 0 {
			return
		}

		if pollFds[0].Revents&(unix.POLLERR|unix.POLLHUP) != 0 {
			isGone = true
			return
		}
	}

	return
}

// the programs stamp a packet with CLOCK_BOOTTIME, the offset to the wall clock is taken once so the timestamps of a capture never jump
func bootTimeOffset() (offset int64, err error) {
	var bootTime unix.Timespec

	err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTime)

	if err != nil {
		err = fmt.Errorf("read boot time clock: %w", err)
		return
	}

	offset = time.Now().UnixNano() - bootTime.Nano()
	return
}
