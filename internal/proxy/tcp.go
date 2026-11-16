// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
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
// pipeline intercepts every flow instead: TLS records are held, decrypted, run through its rules and sealed again, plain tcp goes through the rules too; nil only relays or observes
// scope decides once per flow which flows are looked at: a flow out of scope is relayed as it is, without decryption, rules or a flow line; nil is every flow in scope
// recorder is the API's history, every flow in scope goes into it with what was decrypted or intercepted of it; nil records nothing
// captureBpfMaps are the maps of the capture object: every upstream socket goes into its upstream_map, so the API captures what goes on the wire; nil captures nothing
// httpLayer reads the HTTP/1 exchanges of the flows into recorder and runs the rules of layer http on them, nil reads none
func ServeTCP(ctx context.Context, listener *net.TCPListener, bpfMaps map[bpf.BpfMapName]*ebpf.Map, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, pipeline *intercept.Pipeline, httpLayer *HTTPLayer, scope *filter.Filter, recorder *history.History, waitGroup *sync.WaitGroup, logger *slog.Logger) {
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
			handleTCP(ctx, client, bpfMaps, secretsBpfMaps, captureBpfMaps, pipeline, httpLayer, scope, recorder, logger)
		})
	}
}

// look up the original destination of the client, dial it and copy both directions until both are done
func handleTCP(ctx context.Context, client *net.TCPConn, bpfMaps map[bpf.BpfMapName]*ebpf.Map, secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map, captureBpfMaps map[bpf.BpfMapName]*ebpf.Map, pipeline *intercept.Pipeline, httpLayer *HTTPLayer, scope *filter.Filter, recorder *history.History, logger *slog.Logger) {
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

	cookie, flow, lookupErr := flowByClient(clientAddressPort, syscall.IPPROTO_TCP, bpfMaps)

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
	}

	// the own tgid is excluded in connect4/6, so this dial is not redirected again
	upstreamConnection, upstreamCookie, dialErr := dialUpstream(ctx, "tcp", flow, cookie, dialTimeout, captureBpfMaps, logger)

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

		releaseUpstream(upstreamCookie, captureBpfMaps, logger)
	}()

	// the scope is decided before a byte goes on; a filter with a ClientHello field waits for the first client bytes, or the first server bytes of a protocol where the server speaks first
	// the history wants to know of every flow in scope whether it is TLS, so it waits for them too
	values := scopeValues(flow, cmdline, clientAddressPort, scope)
	result := isInScope(scope, values)
	var opening []TLSChunk
	var clientRandom [32]byte

	if (result == filter.UnknownResult) || ((result == filter.TrueResult) && (recorder != nil)) {
		openingChunks, isTLS, hello := readOpening(ctx, client, upstream, logger)
		opening = openingChunks
		values = values.WithClientHello(isTLS, hello.Version, hello.ServerName, hello.Protocols)
		clientRandom = hello.ClientRandom
		result = isInScope(scope, values)
	}

	if cmdline == "" {
		cmdline = "?"
	}

	if result != filter.TrueResult {
		logger.Debug("Tcp flow is out of scope, relaying it as it is")
		pipeTCP(ctx, client, upstream, opening, nil, logger)
		return
	}

	values = recordedValues(values, recorder)
	flowID := recorder.OpenFlow(cookie, values, clientRandom)
	recorder.SetUpstream(flowID, upstreamCookie)
	interceptFlow := intercept.FlowOf(flowID, cookie, flow, clientAddressPort, values)
	var flowHTTP *httpFlow

	if httpLayer != nil {
		flowHTTP = newHTTPFlow(flowID, recorder, *httpLayer)
	}

	if pipeline != nil {
		upBytes, downBytes := interceptTCP(ctx, client, upstream, opening, interceptFlow, pipeline, secretsBpfMaps, flowHTTP, recorder, logger)
		recorder.CloseFlow(flowID, history.Counters{Bytes: upBytes, Datagrams: 0}, history.Counters{Bytes: downBytes, Datagrams: 0})
		printFlow(flow, cmdline, clientAddressPort, strconv.FormatInt(upBytes, 10)+"B", strconv.FormatInt(downBytes, 10)+"B", time.Since(startTime))
		return
	}

	var observer *TLSObserver
	observerGroup := sync.WaitGroup{}

	if secretsBpfMaps != nil {
		observer = NewTLSObserver(interceptFlow, recorder, secretsBpfMaps)
		observer.http = flowHTTP

		// tls observer of the flow, decrypts copies of the relayed bytes
		observerGroup.Go(func() {
			watchTLS(ctx, observer, logger)
		})
	}

	upBytes, downBytes := pipeTCP(ctx, client, upstream, opening, observer, logger)

	// the records the observer still has are printed before the flow line
	if observer != nil {
		observer.Close()
		observerGroup.Wait()
	}

	recorder.CloseFlow(flowID, history.Counters{Bytes: upBytes, Datagrams: 0}, history.Counters{Bytes: downBytes, Datagrams: 0})
	printFlow(flow, cmdline, clientAddressPort, strconv.FormatInt(upBytes, 10)+"B", strconv.FormatInt(downBytes, 10)+"B", time.Since(startTime))
}

// a FIN from one side is forwarded as CloseWrite and the other direction keeps running, an error or shutdown aborts both
// opening are the bytes read before the scope was decided, they go on first in the order they came
// observer gets a copy of both directions while it is active, nil relays without one
func pipeTCP(ctx context.Context, client *net.TCPConn, upstream *net.TCPConn, opening []TLSChunk, observer *TLSObserver, logger *slog.Logger) (upBytes int64, downBytes int64) {
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

	// a failed write aborts the flow, the copies below end at once then
	for _, chunk := range opening {
		destination := upstream

		if chunk.direction == tlsrecord.ServerDirection {
			destination = client
		}

		if observer != nil {
			observer.Observe(chunk.direction, chunk.data, logger)
		}

		written, writeErr := destination.Write(chunk.data)

		if chunk.direction == tlsrecord.ServerDirection {
			downBytes += int64(written)
		} else {
			upBytes += int64(written)
		}

		if writeErr != nil {
			logger.Debug("Could not write the opening bytes of the tcp flow", "error", writeErr)
			abort()
			break
		}
	}

	waitGroup := sync.WaitGroup{}
	var upCopied, downCopied int64

	// client to upstream
	waitGroup.Go(func() {
		upCopied = copyHalf(upstream, client, tlsrecord.ClientDirection, observer, abort, logger.With("direction", "up"))
	})

	downCopied = copyHalf(client, upstream, tlsrecord.ServerDirection, observer, abort, logger.With("direction", "down"))
	waitGroup.Wait()
	upBytes += upCopied
	downBytes += downCopied
	return
}

// what one side sent before the scope was decided
type openingRead struct {
	data  []byte
	isTLS bool
	hello tlsrecord.Hello
}

// read until a ClientHello field can be decided: the whole ClientHello the client sends first, the first client bytes that are no ClientHello, or the server speaking first
// the side that did not decide is stopped with a read deadline, what it read until then is kept; the end of a stream or an error decides too, the relay sees it again on its next read
// opening are the bytes read in the order the sides sent them, isTLS tells a ClientHello, which hello holds when it could be read
func readOpening(ctx context.Context, client *net.TCPConn, upstream *net.TCPConn, logger *slog.Logger) (opening []TLSChunk, isTLS bool, hello tlsrecord.Hello) {
	clientChannel := make(chan openingRead, 1)
	serverChannel := make(chan openingRead, 1)
	waitGroup := sync.WaitGroup{}
	cancel := func(connection *net.TCPConn) {
		deadlineErr := connection.SetReadDeadline(time.Unix(1, 0))

		if deadlineErr != nil {
			logger.Debug("Could not stop the opening read", "error", deadlineErr)
		}
	}
	stop := context.AfterFunc(ctx, func() {
		cancel(client)
		cancel(upstream)
	})
	defer stop()

	// client opening reader
	waitGroup.Go(func() {
		clientChannel <- readClientOpening(client)
	})

	// server opening reader
	waitGroup.Go(func() {
		buffer := make([]byte, copyBufferLength)
		readCount, _ := upstream.Read(buffer)
		serverChannel <- openingRead{data: buffer[:readCount], isTLS: false, hello: tlsrecord.Hello{}}
	})

	var clientRead, serverRead openingRead
	isServerFirst := false

	select {
	case clientRead = <-clientChannel:
		cancel(upstream)
		serverRead = <-serverChannel
	case serverRead = <-serverChannel:
		isServerFirst = true
		cancel(client)
		clientRead = <-clientChannel
	}

	waitGroup.Wait()
	deadlineErr := errors.Join(client.SetReadDeadline(time.Time{}), upstream.SetReadDeadline(time.Time{}))

	if deadlineErr != nil {
		logger.Debug("Could not clear the opening read deadline", "error", deadlineErr)
	}

	clientChunk := TLSChunk{direction: tlsrecord.ClientDirection, data: clientRead.data}
	serverChunk := TLSChunk{direction: tlsrecord.ServerDirection, data: serverRead.data}

	if isServerFirst {
		opening = []TLSChunk{serverChunk, clientChunk}
	} else {
		opening = []TLSChunk{clientChunk, serverChunk}
		isTLS = clientRead.isTLS
		hello = clientRead.hello
	}

	opening = slices.DeleteFunc(opening, func(chunk TLSChunk) bool {
		return len(chunk.data) == 0
	})
	return
}

// the client's bytes until they are a whole ClientHello or are none; a ClientHello that can't be read is TLS without its fields
func readClientOpening(client *net.TCPConn) (result openingRead) {
	buffer := make([]byte, copyBufferLength)

	for {
		readCount, readErr := client.Read(buffer)
		result.data = append(result.data, buffer[:readCount]...)
		isClientHello, isDecided := tlsrecord.IsClientHello(result.data)

		if isDecided && !isClientHello {
			return
		}

		if isClientHello {
			hello, isComplete, helloErr := tlsrecord.ReadClientHello(result.data)
			result.isTLS = true

			if isComplete {
				result.hello = hello
				return
			}

			if helloErr != nil {
				return
			}
		}

		if readErr != nil {
			return
		}
	}
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
