// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/platform"
	"golang.org/x/sys/unix"
)

// the backend of one run: holds and rules only when the proxy intercepts, every hold event goes on the bus
func NewBackend(info Info, limits history.Limits, keyLog func(clientRandom [32]byte) (keyLog string, found bool, err error)) (backend *Backend) {
	bus := NewBus()
	backend = &Backend{
		Info:    info,
		History: history.New(limits, bus.Publish),
		Holds:   nil,
		Rules:   nil,
		Bus:     bus,
		KeyLog:  keyLog,
	}

	if info.IsInterceptCapable {
		backend.Holds = intercept.NewHoldQueue(info.HoldTimeout, func(event intercept.HoldEvent) {
			bus.Publish(holdEvent(event))
		})
		backend.Rules = intercept.NewRuleSet()
	}

	return
}

// the routes of the API, every one is an operation of api/openapi.yaml with the same method, path and operationId
func routes() (operations []route) {
	operations = []route{
		{method: http.MethodGet, path: "/status", operationID: "getStatus", handle: getStatus},
		{method: http.MethodGet, path: "/flows", operationID: "listFlows", handle: listFlows},
		{method: http.MethodGet, path: "/flows/{id}", operationID: "getFlow", handle: getFlow},
		{method: http.MethodGet, path: "/flows/{id}/messages", operationID: "listMessages", handle: listMessages},
		{method: http.MethodGet, path: "/messages/{id}", operationID: "getMessage", handle: getMessage},
		{method: http.MethodGet, path: "/events", operationID: "streamEvents", handle: streamEvents},
		{method: http.MethodPut, path: "/intercept", operationID: "setIntercept", handle: setIntercept},
		{method: http.MethodGet, path: "/holds", operationID: "listHolds", handle: listHolds},
		{method: http.MethodPut, path: "/holds/{id}", operationID: "editHold", handle: editHold},
		{method: http.MethodPost, path: "/holds/{id}/forward", operationID: "forwardHold", handle: forwardHold},
		{method: http.MethodPost, path: "/holds/{id}/drop", operationID: "dropHold", handle: dropHold},
		{method: http.MethodGet, path: "/rules", operationID: "listRules", handle: listRules},
		{method: http.MethodPost, path: "/rules", operationID: "addRule", handle: addRule},
		{method: http.MethodDelete, path: "/rules/{id}", operationID: "deleteRule", handle: deleteRule},
		{method: http.MethodGet, path: "/keylog", operationID: "exportKeylog", handle: exportKeylog},
	}
	return
}

// every route under /api/v1; a known path with another method is a JSON 405, anything else a JSON 404
func Handler(backend *Backend, logger *slog.Logger) (handler http.Handler) {
	mux := http.NewServeMux()
	paths := http.NewServeMux()

	for _, operation := range routes() {
		mux.HandleFunc(operation.method+" "+v1.BasePath+operation.path, func(writer http.ResponseWriter, request *http.Request) {
			logger.Debug("Api request", "method", request.Method, "path", request.URL.Path, "operationID", operation.operationID)
			operation.handle(backend, writer, request, logger)
		})

		// the same path twice with two methods registers it once
		if _, pattern := paths.Handler(&http.Request{Method: http.MethodGet, URL: &url.URL{Path: v1.BasePath + operation.path}}); pattern == "" {
			paths.HandleFunc(v1.BasePath+operation.path, http.NotFound)
		}
	}

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		if _, pattern := paths.Handler(request); pattern != "" {
			writeError(writer, http.StatusMethodNotAllowed, fmt.Errorf("%w: %s %s", ErrMethod, request.Method, request.URL.Path), logger)
			return
		}

		writeError(writer, http.StatusNotFound, fmt.Errorf("%w: %s %s", ErrNotFound, request.Method, request.URL.Path), logger)
	})

	handler = mux
	return
}

// create the socket before anything is attached, so a bad path stops decerter at once; nothing is served before Serve
// a socket file gets mode 0660 and the group decerter when the group exists, 0600 for root alone otherwise; a stale socket is replaced, a path that is no socket or a live socket is refused
// an abstract socket (@name) has no mode, its peers are checked with SO_PEERCRED: root, on Android also the shell user adb forward connects as, on Linux the primary group decerter
// dataDirectory is decerter's own directory, the socket's directory is given the group too when it is that one
func Listen(socketPath string, currentPlatform platform.Platform, logger *slog.Logger) (server *Server, err error) {
	groupID := lookupGroup(currentPlatform.Type, logger)
	policy := accessPolicyOf(socketPath, currentPlatform.Type, groupID)
	var listener *net.UnixListener
	path := ""

	if strings.HasPrefix(socketPath, "@") {
		listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})

		if err != nil {
			err = fmt.Errorf("%w %s: %w", ErrSocket, socketPath, err)
			logger.Error("Could not create api socket", "error", err)
			return
		}

		logger.Info("Control api listening", "socket", socketPath, "abstract", true, "allowedUIDs", policy.uids, "allowedGID", policy.gid)
	} else {
		listener, err = listenFile(socketPath, groupID, filepath.Dir(socketPath) == currentPlatform.DataDirectory)

		if err != nil {
			logger.Error("Could not create api socket", "error", err)
			return
		}

		path = socketPath

		if groupID < 0 {
			logger.Warn("The api socket is for root only, there is no group "+socketGroup+": create it with groupadd "+socketGroup+" and add the users who may drive decerter", "socket", socketPath, "mode", "0600")
		} else {
			logger.Info("Control api listening", "socket", socketPath, "mode", "0660", "group", socketGroup)
		}
	}

	server = &Server{
		listener:   peerListener{Listener: listener, policy: policy, logger: logger},
		httpServer: nil,
		path:       path,
		closeOnce:  &sync.Once{},
		closeErr:   nil,
	}
	return
}

// the gid of the group decerter, -1 when there is none; Android has no group database, its socket is abstract
func lookupGroup(platformType platform.Type, logger *slog.Logger) (groupID int64) {
	groupID = -1

	if platformType == platform.AndroidType {
		return
	}

	group, lookupErr := user.LookupGroup(socketGroup)

	if lookupErr != nil {
		logger.Debug("Could not find api socket group", "error", lookupErr, "group", socketGroup)
		return
	}

	gid, parseErr := strconv.ParseInt(group.Gid, 10, 64)

	if parseErr != nil {
		logger.Warn("Could not parse api socket group id", "error", parseErr, "group", socketGroup, "gid", group.Gid)
		return
	}

	groupID = gid
	return
}

// the policy of a socket: a file is checked by the kernel against its mode, an abstract socket by the peer's credentials
func accessPolicyOf(socketPath string, platformType platform.Type, groupID int64) (policy accessPolicy) {
	policy = accessPolicy{
		isChecked: strings.HasPrefix(socketPath, "@"),
		uids:      []uint32{0},
		gid:       groupID,
	}

	if platformType == platform.AndroidType {
		policy.uids = append(policy.uids, androidShellUID)
	}

	return
}

// root is always allowed, so is any peer of a socket file, which the kernel checked against the file's mode
func isPeerAllowed(uid uint32, gid uint32, policy accessPolicy) (isAllowed bool) {
	isAllowed = !policy.isChecked || slices.Contains(policy.uids, uid) || ((policy.gid >= 0) && (int64(gid) == policy.gid))
	return
}

// the socket file is made under a temporary name, given its mode and group and then renamed, so it is never reachable with a wider mode
// isOwnDirectory: the directory is decerter's data directory, it gets mode 0750 and the group, or 0700 without one
func listenFile(socketPath string, groupID int64, isOwnDirectory bool) (listener *net.UnixListener, err error) {
	err = removeStaleSocket(socketPath)

	if err != nil {
		return
	}

	directory := filepath.Dir(socketPath)
	err = os.MkdirAll(directory, 0o700)

	if err != nil {
		err = fmt.Errorf("%w %s: %w", ErrSocket, socketPath, err)
		return
	}

	mode := os.FileMode(0o600)
	directoryMode := os.FileMode(0o700)

	if groupID >= 0 {
		mode = 0o660
		directoryMode = 0o750
	}

	if isOwnDirectory {
		err = errors.Join(os.Chown(directory, 0, int(max(groupID, 0))), os.Chmod(directory, directoryMode))

		if err != nil {
			err = fmt.Errorf("%w %s: %w", ErrSocket, socketPath, err)
			return
		}
	}

	temporaryPath := socketPath + ".tmp" + strconv.Itoa(os.Getpid())
	removeErr := os.Remove(temporaryPath)

	if (removeErr != nil) && !errors.Is(removeErr, fs.ErrNotExist) {
		err = fmt.Errorf("%w %s: %w", ErrSocket, temporaryPath, removeErr)
		return
	}

	listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: temporaryPath, Net: "unix"})

	if err != nil {
		err = fmt.Errorf("%w %s: %w", ErrSocket, socketPath, err)
		return
	}

	// the server removes the socket by its final name
	listener.SetUnlinkOnClose(false)
	err = os.Chmod(temporaryPath, mode)

	if (err == nil) && (groupID >= 0) {
		err = os.Chown(temporaryPath, 0, int(groupID))
	}

	if err == nil {
		err = os.Rename(temporaryPath, socketPath)
	}

	if err != nil {
		err = fmt.Errorf("%w %s: %w", ErrSocket, socketPath, errors.Join(err, listener.Close(), os.Remove(temporaryPath)))
		listener = nil
	}

	return
}

// a socket left by a decerter that was killed is removed; anything that is not a socket stays and is refused, and so is a socket another server still answers on
func removeStaleSocket(socketPath string) (err error) {
	info, statErr := os.Lstat(socketPath)

	if errors.Is(statErr, fs.ErrNotExist) {
		return
	}

	if err = statErr; err != nil {
		err = fmt.Errorf("%w %s: %w", ErrSocket, socketPath, err)
		return
	}

	if info.Mode().Type() != fs.ModeSocket {
		err = fmt.Errorf("%w: %s has mode %s", ErrNotSocket, socketPath, info.Mode().String())
		return
	}

	connection, dialErr := net.DialTimeout("unix", socketPath, socketProbeTimeout)

	if dialErr == nil {
		err = fmt.Errorf("%w: %s", ErrSocketInUse, socketPath)
		err = errors.Join(err, connection.Close())
		return
	}

	err = os.Remove(socketPath)

	if err != nil {
		err = fmt.Errorf("%w %s: %w", ErrSocket, socketPath, err)
	}

	return
}

// a connection of a peer the policy does not allow is closed at once and logged, the server never sees it
func (listener peerListener) Accept() (connection net.Conn, err error) {
	for {
		connection, err = listener.Listener.Accept()

		if err != nil {
			return
		}

		uid, gid, pid, credentialsErr := peerCredentials(connection)

		if credentialsErr == nil && isPeerAllowed(uid, gid, listener.policy) {
			listener.logger.Debug("Api client connected", "uid", uid, "gid", gid, "pid", pid)
			return
		}

		listener.logger.Warn("Refused api client", "error", credentialsErr, "uid", uid, "gid", gid, "pid", pid)
		closeErr := connection.Close()

		if closeErr != nil {
			listener.logger.Debug("Could not close refused api client", "error", closeErr)
		}
	}
}

func peerCredentials(connection net.Conn) (uid uint32, gid uint32, pid int32, err error) {
	unixConnection, ok := connection.(*net.UnixConn)

	if !ok {
		err = ErrPeer
		return
	}

	rawConnection, rawErr := unixConnection.SyscallConn()

	if err = rawErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrPeer, err)
		return
	}

	var credentials *unix.Ucred
	var credentialsErr error
	controlErr := rawConnection.Control(func(fileDescriptor uintptr) {
		credentials, credentialsErr = unix.GetsockoptUcred(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})

	if err = errors.Join(controlErr, credentialsErr); err != nil {
		err = fmt.Errorf("%w: %w", ErrPeer, err)
		return
	}

	uid, gid, pid = credentials.Uid, credentials.Gid, credentials.Pid
	return
}

// serve until ctx is done, then let the requests finish for a moment, end the event streams and remove the socket
func (server *Server) Serve(ctx context.Context, backend *Backend, logger *slog.Logger) {
	server.httpServer = &http.Server{
		Handler:           Handler(backend, logger),
		ReadHeaderTimeout: readHeaderTimeout,
		// the event streams end with ctx
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}
	serveErrChannel := make(chan error, 1)

	// api http server
	go func() {
		serveErrChannel <- server.httpServer.Serve(server.listener)
	}()

	select {
	case <-ctx.Done():
		logger.Debug("Context cancelled")
	case serveErr := <-serveErrChannel:
		logger.Error("Could not serve control api", "error", serveErr)
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	shutdownErr := server.httpServer.Shutdown(shutdownCtx)

	if shutdownErr != nil {
		logger.Debug("Could not shut the control api down in time, closing it", "error", shutdownErr)
	}

	closeErr := server.Close()

	if closeErr != nil {
		logger.Error("Could not close control api", "error", closeErr)
	}
}

// close the listener and remove the socket file, once; also for a server that never served
func (server *Server) Close() (err error) {
	server.closeOnce.Do(func() {
		if server.httpServer != nil {
			server.closeErr = server.httpServer.Close()
		}

		closeErr := server.listener.Close()

		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}

		server.closeErr = errors.Join(server.closeErr, closeErr)

		if server.path == "" {
			return
		}

		removeErr := os.Remove(server.path)

		if !errors.Is(removeErr, fs.ErrNotExist) {
			server.closeErr = errors.Join(server.closeErr, removeErr)
		}
	})
	err = server.closeErr
	return
}
