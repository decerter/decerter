// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/pcapng"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	// the file holds the secrets of the captured sessions
	fileMode os.FileMode = 0o600
	// sudo keeps the ids of the user who called it here
	sudoUIDVariable string = "SUDO_UID"
	sudoGIDVariable string = "SUDO_GID"
	// how long the reader sleeps when no flow waits for its secrets, it flushes the file, counts the drops and forgets idle flows when it wakes
	idleWake time.Duration = time.Second
	// packets that are already in packet_map when the capture is stopped are still written, a sender that keeps it full can't hold the stop up longer than this
	drainTimeout time.Duration = time.Second
)

// create the capture file for its owner only: it holds secrets, under sudo it goes to the user who called sudo
func OpenFile(path string) (file *os.File, err error) {
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
func Write(ctx context.Context, output io.Writer, snaplen uint32, plaintext bool, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, logger *slog.Logger) (err error) {
	writerSnaplen := snaplen

	if plaintext {
		writerSnaplen = max(snaplen, SynthesizedLength)
	}

	writer, writerErr := pcapng.New(output, writerSnaplen)

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
