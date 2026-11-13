// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	// capture -w - writes the capture as a live pcapng stream to stdout
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
// StreamPath is stdout, which must not be a person's terminal: the stream is binary and holds secrets
// a terminal in raw mode is accepted: adb exec-out gives the command a pty without output processing, echo or line editing, which carries the stream unchanged
func OpenFile(path string) (file *os.File, err error) {
	if path == StreamPath {
		termios, termiosErr := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)

		if (termiosErr == nil) && ((termios.Oflag&unix.OPOST != 0) || (termios.Lflag&(unix.ICANON|unix.ECHO) != 0)) {
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

// one reader of packet_map for every writer of the capture: the -w file, the captures and the streams of the API
// the scope is the --filter, the hub decides it once per flow and every writer gets the packets of the flows in scope, a writer decides its own filter after that
// sessions are the client randoms of the TLS and DTLS sessions at the start of the flows in scope, by cookie: a writer that joins later writes their DSB before their first packet
// with a history, every flow is decided with its first bytes, so the history gets the fields of its ClientHello, and ring keeps the latest packets for the pcap export
// gate belongs to the goroutine of Run, which changes flows only with the mutex held; the rest is guarded by mutex
type Hub struct {
	mutex          *sync.Mutex
	consumers      map[*Consumer]bool
	sessions       map[uint64][32]byte
	ring           *packetRing
	gate           gate
	flows          map[uint64]*hubFlow
	history        *history.History
	snaplen        uint32
	bootOffset     int64
	captureBpfMaps map[bpf.BpfMapName]*ebpf.Map
	secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map
	dropped        uint64
	doneChannel    chan struct{}
	logger         *slog.Logger
}

// a flow in scope the hub has seen: its id in the history, 0 when it is not there, and the payload bytes and packets of each direction, by tlsrecord.Direction
type hubFlow struct {
	historyID uint64
	traffic   [2]history.Counters
}

// secretsBpfMaps is nil without the secrets uprobe, the packets are written without keys then
// recorder is the history of the API, nil without it: then the flows are decided as early as the scope allows and no packet is kept
// isProxied is run mode: the packets are the ones of the proxy's upstream sockets, the proxy keeps the flows in the history, the hub only keeps their packets
func NewHub(snaplen uint32, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, scope *filter.Filter, recorder *history.History, isProxied bool, logger *slog.Logger) (hub *Hub, err error) {
	bootOffset, offsetErr := bootTimeOffset()

	if err = offsetErr; err != nil {
		return
	}

	hub = &Hub{
		mutex:          &sync.Mutex{},
		consumers:      map[*Consumer]bool{},
		sessions:       map[uint64][32]byte{},
		ring:           nil,
		gate:           newGate(scope, recorder != nil, captureBpfMaps, logger),
		flows:          map[uint64]*hubFlow{},
		history:        recorder,
		snaplen:        snaplen,
		bootOffset:     bootOffset,
		captureBpfMaps: captureBpfMaps,
		secretsBpfMaps: secretsBpfMaps,
		dropped:        0,
		doneChannel:    make(chan struct{}),
		logger:         logger,
	}

	if recorder != nil {
		hub.ring = newPacketRing(historyPacketBytes)
	}

	// the proxy opened and closes the flows of run mode in the history itself
	if isProxied {
		hub.history = nil
	}

	return
}

// read packet_map and hand the packets to the writers until the context is cancelled, then hand out what is still in the ring and close Done
// the writers finish their files when Done is closed
func (hub *Hub) Run(ctx context.Context) (err error) {
	defer close(hub.doneChannel)
	reader, readerErr := ringbuf.NewReader(hub.captureBpfMaps[capturebpf.PacketMap])

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
			hub.logger.Error("Could not wake packet_map reader", "error", flushErr)
		}
	})
	defer stop()

	var record ringbuf.Record
	var drainDeadline time.Time
	nextWake := time.Now().Add(idleWake)
	nextSweep := time.Now().Add(sweepInterval)

	for {
		reader.SetDeadline(nextWake)
		readErr := reader.ReadInto(&record)
		now := time.Now()

		switch {
		case readErr == nil:
			packet, parseErr := capturebpf.ParsePacket(record.RawSample)

			if parseErr != nil {
				hub.logger.Warn("Could not parse packet_map record", "error", parseErr)
				continue
			}

			// the record of the reader is used again, every writer and the history get this copy and only read it
			packet.Data = bytes.Clone(packet.Data)
			err = hub.gate.handle(packet, now, hub.emit)
		case errors.Is(readErr, os.ErrDeadlineExceeded):
		case
			errors.Is(readErr, ringbuf.ErrFlushed),
			errors.Is(readErr, ringbuf.ErrClosed):
			hub.logger.Debug("Context cancelled")
			err = hub.finish(now)
			return
		default:
			err = errors.Join(fmt.Errorf("%w: %w", ErrRead, readErr), hub.finish(now))
			return
		}

		if err != nil {
			return
		}

		if ctx.Err() != nil {
			if drainDeadline.IsZero() {
				drainDeadline = now.Add(drainTimeout)
			}

			if now.After(drainDeadline) {
				err = hub.finish(now)
				return
			}
		}

		// under steady traffic the read never times out, so the clock is checked after every packet
		if now.Before(nextWake) {
			continue
		}

		nextWake = now.Add(idleWake)
		err = hub.gate.decideLate(now, false, hub.emit)

		if err != nil {
			return
		}

		if !now.Before(nextSweep) {
			nextSweep = now.Add(sweepInterval)
			hub.countDropped()
			hub.gate.forgetOutOfScope(now)
			hub.forgetFlows(func(cookie uint64) (isOpen bool, err error) {
				isOpen, err = capturebpf.HasFlow(cookie, hub.captureBpfMaps)
				return
			})
		}
	}
}

// closed when the hub handed out its last packet, the writers finish then
func (hub *Hub) Done() (done <-chan struct{}) {
	done = hub.doneChannel
	return
}

// the flows that wait for their scope are decided without the bytes that did not come, the drops are counted a last time
func (hub *Hub) finish(now time.Time) (err error) {
	err = hub.gate.decideLate(now, true, hub.emit)
	hub.countDropped()
	return
}

// a packet of a flow in scope: the first one starts the flow in the history and notes the session of its ClientHello, then the ring and every writer get it
// it never waits for a writer, a writer whose queue is full loses the packet or, a stream, its place
func (hub *Hub) emit(cookie uint64, packet capturebpf.Packet, decided *gateFlow, now time.Time) (err error) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()
	tracked, ok := hub.flows[cookie]

	if !ok {
		tracked = &hubFlow{historyID: 0, traffic: [2]history.Counters{}}
		hub.flows[cookie] = tracked

		if decided.isTLS && (decided.hello.ClientRandom != [32]byte{}) {
			hub.sessions[cookie] = decided.hello.ClientRandom
		}

		// a flow without values was not in flow_map any more, the history can't name it
		if decided.hasValues {
			tracked.historyID = hub.history.OpenFlow(cookie, decided.values, decided.hello.ClientRandom)
		}
	}

	direction := tlsrecord.ClientDirection

	if packet.IsIngress {
		direction = tlsrecord.ServerDirection
	}

	header, isParsed := parsePacket(packet.Data)

	if isParsed && (packet.Length > uint32(header.payloadOffset)) {
		tracked.traffic[direction].Bytes += int64(packet.Length) - int64(header.payloadOffset)
	}

	if isParsed && (header.protocol == syscall.IPPROTO_UDP) {
		tracked.traffic[direction].Datagrams++
	}

	if hub.ring != nil {
		hub.ring.add(packet)
	}

	for current := range hub.consumers {
		hub.offer(current, packet)
	}

	return
}

// a flow whose socket left flow_map, or upstream_map in run mode, is closed: the history gets its counters, the next packet of its cookie starts a new flow
// hasFlow looks the socket up in both
func (hub *Hub) forgetFlows(hasFlow func(cookie uint64) (isOpen bool, err error)) {
	for cookie, tracked := range hub.flows {
		isOpen, lookupErr := hasFlow(cookie)

		if lookupErr != nil {
			hub.logger.Debug("Could not look up flow", "error", lookupErr, "cookie", cookie)
			continue
		}

		if isOpen {
			continue
		}

		hub.history.CloseFlow(tracked.historyID, tracked.traffic[tlsrecord.ClientDirection], tracked.traffic[tlsrecord.ServerDirection])
		hub.gate.forget(cookie)
		hub.mutex.Lock()
		delete(hub.flows, cookie)
		delete(hub.sessions, cookie)
		hub.mutex.Unlock()
	}
}

// warn when packets were lost since the last look, the reader was slower than the recorded sockets
func (hub *Hub) countDropped() {
	dropped, readErr := capturebpf.ReadDropped(hub.captureBpfMaps)

	if readErr != nil {
		hub.logger.Warn("Could not read dropped packets", "error", readErr)
		return
	}

	if dropped > hub.dropped {
		hub.logger.Warn("Dropped packets, packet_map was full", "dropped", dropped-hub.dropped, "droppedTotal", dropped)
	}

	hub.dropped = dropped
}
