// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	dialTimeout   time.Duration = 10 * time.Second
	acceptBackoff time.Duration = 100 * time.Millisecond
)

// one dual-stack socket for IPv4 and IPv6 clients, IPv4 peers show up IPv4-mapped (::ffff:127.0.0.1)
func ListenTCP(ctx context.Context, port uint16) (listener *net.TCPListener, err error) {
	listenConfig := net.ListenConfig{
		Control: controlTCP,
	}
	netListener, listenErr := listenConfig.Listen(ctx, "tcp", net.JoinHostPort("::", strconv.Itoa(int(port))))

	if err = listenErr; err != nil {
		err = fmt.Errorf("%w: tcp %d: %w", ErrListen, port, err)
		return
	}

	listener = netListener.(*net.TCPListener)
	return
}

// SO_BINDTODEVICE lo keeps the listener unreachable from the network
func controlTCP(network, address string, rawConnection syscall.RawConn) (err error) {
	controlErr := rawConnection.Control(func(fileDescriptor uintptr) {
		err = errors.Join(
			unix.SetsockoptInt(int(fileDescriptor), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0),
			unix.SetsockoptString(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo"),
		)
	})
	err = errors.Join(err, controlErr)
	return
}

// accept until the listener is closed by the context, every connection gets its own goroutine on waitGroup
// secretsBpfMaps are the maps of the secrets object, with them the TLS flows are decrypted next to the relay and printed, nil relays every flow without a look inside
func ServeTCP(ctx context.Context, listener *net.TCPListener, bpfMaps map[bpf.BpfMapName]*ebpf.Map, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, waitGroup *sync.WaitGroup, logger *slog.Logger) {
	// listener closer
	stop := context.AfterFunc(ctx, func() {
		closeErr := listener.Close()

		if closeErr != nil {
			logger.Error("Could not close tcp listener", "error", closeErr)
		}
	})
	defer stop()

	for {
		client, acceptErr := listener.AcceptTCP()

		if acceptErr != nil {
			if errors.Is(acceptErr, net.ErrClosed) {
				logger.Debug("Tcp listener closed")
				return
			}

			// temporary errors like EMFILE, try again after a short pause
			logger.Error("Could not accept tcp connection", "error", acceptErr)

			select {
			case <-ctx.Done():
				return
			case <-time.After(acceptBackoff):
			}

			continue
		}

		// proxied tcp connection
		waitGroup.Go(func() {
			handleTCP(ctx, client, bpfMaps, secretsBpfMaps, logger)
		})
	}
}

// look up the original destination of the client, dial it and copy both directions until both are done
func handleTCP(ctx context.Context, client *net.TCPConn, bpfMaps map[bpf.BpfMapName]*ebpf.Map, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, logger *slog.Logger) {
	startTime := time.Now()
	clientAddressPort := client.RemoteAddr().(*net.TCPAddr).AddrPort()
	localAddressPort := client.LocalAddr().(*net.TCPAddr).AddrPort()
	logger = logger.With("client", clientAddressPort)

	defer func() {
		closeErr := client.Close()

		if closeErr != nil {
			logger.Error("Could not close client connection", "error", closeErr)
		}
	}()

	cookie, flow, lookupErr := redirect.FlowByClient(clientAddressPort, syscall.IPPROTO_TCP, bpfMaps)

	if lookupErr != nil {
		logger.Warn("Could not find flow of client", "error", lookupErr)
		resetTCP(client, logger)
		return
	}

	logger = logger.With("cookie", cookie, "destination", flow.OriginalDestination)

	if isLoop(flow.OriginalDestination, localAddressPort) {
		logger.Warn("Could not proxy flow", "error", ErrLoop)
		resetTCP(client, logger)
		return
	}

	cmdline, processErr := processCmdline(flow.Tgid)

	if processErr != nil {
		logger.Debug("Could not read process info", "error", processErr, "tgid", flow.Tgid)
		cmdline = "?"
	}

	// the own tgid is excluded in connect4/6, so this dial is not redirected again
	dialer := net.Dialer{
		Timeout: dialTimeout,
	}
	upstreamConnection, dialErr := dialer.DialContext(ctx, "tcp", flow.OriginalDestination.String())

	if dialErr != nil {
		logger.Warn("Could not dial original destination", "error", dialErr)
		resetTCP(client, logger)
		return
	}

	upstream := upstreamConnection.(*net.TCPConn)

	defer func() {
		closeErr := upstream.Close()

		if closeErr != nil {
			logger.Error("Could not close upstream connection", "error", closeErr)
		}
	}()

	var observer *TLSObserver
	observerGroup := sync.WaitGroup{}

	if secretsBpfMaps != nil {
		observer = NewTLSObserver(flow, clientAddressPort, secretsBpfMaps)

		// tls observer of the flow, decrypts copies of the relayed bytes
		observerGroup.Go(func() {
			watchTLS(ctx, observer, logger)
		})
	}

	upBytes, downBytes := pipeTCP(ctx, client, upstream, observer, logger)

	// the records the observer still has are printed before the flow line
	if observer != nil {
		observer.Close()
		observerGroup.Wait()
	}

	printFlow(flow, cmdline, clientAddressPort, strconv.FormatInt(upBytes, 10)+"B", strconv.FormatInt(downBytes, 10)+"B", time.Since(startTime))
}

// a FIN from one side is forwarded as CloseWrite and the other direction keeps running, an error or shutdown aborts both
// observer gets a copy of both directions while it is active, nil relays without one
func pipeTCP(ctx context.Context, client *net.TCPConn, upstream *net.TCPConn, observer *TLSObserver, logger *slog.Logger) (upBytes int64, downBytes int64) {
	abortOnce := sync.Once{}
	abort := func() {
		abortOnce.Do(func() {
			// a deadline in the past unblocks both io.Copy calls without closing the sockets twice
			deadlineErr := errors.Join(client.SetDeadline(time.Unix(1, 0)), upstream.SetDeadline(time.Unix(1, 0)))

			if deadlineErr != nil {
				logger.Debug("Could not abort tcp flow", "error", deadlineErr)
			}
		})
	}
	stop := context.AfterFunc(ctx, abort)
	defer stop()
	waitGroup := sync.WaitGroup{}

	// client to upstream
	waitGroup.Go(func() {
		upBytes = copyHalf(upstream, client, tlsrecord.ClientDirection, observer, abort, logger.With("direction", "up"))
	})

	downBytes = copyHalf(client, upstream, tlsrecord.ServerDirection, observer, abort, logger.With("direction", "down"))
	waitGroup.Wait()
	return
}

// the client already saw its connect succeed, a RST on close is the nearest thing to a failed connect
func resetTCP(connection *net.TCPConn, logger *slog.Logger) {
	lingerErr := connection.SetLinger(0)

	if lingerErr != nil {
		logger.Debug("Could not set linger to reset tcp connection", "error", lingerErr)
	}
}

func copyHalf(destination *net.TCPConn, source *net.TCPConn, direction tlsrecord.Direction, observer *TLSObserver, abort func(), logger *slog.Logger) (written int64) {
	var copyErr error
	isFinished := false

	if observer != nil {
		written, isFinished, copyErr = copyObserved(destination, source, direction, observer, logger)
	}

	// without an observer, and for the rest of a flow it gave up on, io.Copy splices the stream in the kernel
	if (copyErr == nil) && !isFinished {
		copied, restErr := io.Copy(destination, source)
		written += copied
		copyErr = restErr
	}

	if copyErr != nil {
		logger.Debug("Could not copy tcp stream", "error", copyErr)
		abort()
		return
	}

	closeErr := destination.CloseWrite()

	if closeErr != nil {
		logger.Debug("Could not half-close tcp stream", "error", closeErr)
		abort()
	}

	return
}

// copy through user space while the observer wants a copy, isFinished is true at the end of the stream and false when the observer stopped first
// the observer gets its copy without waiting for it, so the relay is as fast as without one; the copy is handed over before the bytes go on, so the observer sees both directions in the order the peers do
func copyObserved(destination *net.TCPConn, source *net.TCPConn, direction tlsrecord.Direction, observer *TLSObserver, logger *slog.Logger) (written int64, isFinished bool, err error) {
	buffer := make([]byte, copyBufferLength)

	for observer.Active() {
		readCount, readErr := source.Read(buffer)

		if readCount > 0 {
			observer.Observe(direction, buffer[:readCount], logger)
			writeCount, writeErr := destination.Write(buffer[:readCount])
			written += int64(writeCount)

			if err = writeErr; err != nil {
				return
			}
		}

		if errors.Is(readErr, io.EOF) {
			isFinished = true
			return
		}

		if err = readErr; err != nil {
			return
		}
	}

	return
}
