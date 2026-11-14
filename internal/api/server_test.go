// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/capture"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/platform"
)

// a response writer whose writes fail, as the one of a client that went away
type failingWriter struct {
	header http.Header
	status int
}

func (writer *failingWriter) Header() (header http.Header) {
	header = writer.header
	return
}

func (writer *failingWriter) Write(data []byte) (count int, err error) {
	err = io.ErrClosedPipe
	return
}

func (writer *failingWriter) WriteHeader(status int) {
	writer.status = status
}

// the group database of a test: gid empty is a host without the group decerter, anything else the gid of the group, restored when the test ends
func setSocketGroup(state *testing.T, gid string) {
	previous := lookupSocketGroup
	lookupSocketGroup = func(name string) (group *user.Group, err error) {
		if gid == "" {
			err = user.UnknownGroupError(name)
			return
		}

		group = &user.Group{Gid: gid, Name: name}
		return
	}
	state.Cleanup(func() {
		lookupSocketGroup = previous
	})
}

// an HTTP client that reaches the server on the unix socket, a file or an abstract name
func socketClient(socketPath string) (client *http.Client) {
	client = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, address string) (connection net.Conn, err error) {
				dialer := net.Dialer{}
				connection, err = dialer.DialContext(ctx, "unix", socketPath)
				return
			},
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
	return
}

// GET /status over the socket
func getStatusOver(ctx context.Context, socketPath string) (status v1.Status, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+v1.HostName+v1.BasePath+"/status", nil)

	if err != nil {
		return
	}

	response, err := socketClient(socketPath).Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("status %d", response.StatusCode)
		return
	}

	err = json.NewDecoder(response.Body).Decode(&status)
	return
}

// Test if api.Server.Serve returns with the expected output: the API answers on the socket file until the context is cancelled, the file is removed then and a second Close changes nothing.
func TestServePositive(state *testing.T) {
	setSocketGroup(state, "")
	directory := state.TempDir()
	socketPath := filepath.Join(directory, "run", "api.sock")
	logger := slog.New(slog.DiscardHandler)
	currentPlatform := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: filepath.Join(directory, "data"), APISocket: socketPath}
	server, err := Listen(socketPath, currentPlatform, logger)

	if err != nil {
		state.Fatalf("Test of api.Server.Serve failed, cannot listen, error: %s", err.Error())
	}

	info := Info{Mode: v1.RunMode, Processing: v1.DecryptProcessing, Platform: "linux", Scope: "", Started: time.Now(), HoldTimeout: time.Minute, HasTLSSecrets: false, IsInterceptCapable: false}
	backend := NewBackend(info, history.DefaultLimits(), nil)
	ctx, cancel := context.WithCancel(state.Context())
	defer cancel()
	doneChannel := make(chan struct{})

	// api server
	go func() {
		defer close(doneChannel)
		server.Serve(ctx, backend, logger)
	}()

	status, err := getStatusOver(state.Context(), socketPath)

	if (err != nil) || (status.Mode != v1.RunMode) {
		state.Errorf("Test of api.Server.Serve failed, GET /status should answer over the socket, status: %+v, error: %v", status, err)
		return
	}

	cancel()
	<-doneChannel

	if _, statErr := os.Lstat(socketPath); !errors.Is(statErr, os.ErrNotExist) {
		state.Errorf("Test of api.Server.Serve failed, the socket should be removed when the server ends, error: %v", statErr)
		return
	}

	err = server.Close()

	if err != nil {
		state.Errorf("Test of api.Server.Close failed, a second close should return the first result, error: %s", err.Error())
		return
	}
}

// Test if api.Server.Serve returns with the expected errors: a listener that fails ends the server without the context.
func TestServeNegative(state *testing.T) {
	setSocketGroup(state, "")
	socketPath := filepath.Join(state.TempDir(), "api.sock")
	logger := slog.New(slog.DiscardHandler)
	currentPlatform := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "", APISocket: socketPath}
	server, err := Listen(socketPath, currentPlatform, logger)

	if err != nil {
		state.Fatalf("Test of api.Server.Serve failed, cannot listen, error: %s", err.Error())
	}

	// the listener is closed under the server, accept fails at once
	err = server.listener.Close()

	if err != nil {
		state.Fatalf("Test of api.Server.Serve failed, cannot close the listener, error: %s", err.Error())
	}

	backend := NewBackend(Info{Mode: v1.RunMode}, history.DefaultLimits(), nil)
	doneChannel := make(chan struct{})

	// api server
	go func() {
		defer close(doneChannel)
		server.Serve(state.Context(), backend, logger)
	}()

	select {
	case <-doneChannel:
	case <-time.After(10 * time.Second):
		state.Fatalf("Test of api.Server.Serve failed, a server whose listener is closed should end")
	}

	if _, statErr := os.Lstat(socketPath); !errors.Is(statErr, os.ErrNotExist) {
		state.Errorf("Test of api.Server.Serve failed, the socket should be removed, error: %v", statErr)
		return
	}
}

// Test if an abstract socket of api.Listen checks its peers: a peer in the group decerter is served, a peer that is neither root nor in the group is closed at once.
func TestPeerListenerPositive(state *testing.T) {
	if os.Geteuid() == 0 {
		state.Skip("root is always allowed, the refused peer needs another user")
	}

	logger := slog.New(slog.DiscardHandler)
	backend := NewBackend(Info{Mode: v1.CaptureMode}, history.DefaultLimits(), nil)
	positiveCases := []struct {
		Name      string
		GID       string
		Platform  platform.Type
		IsAllowed bool
	}{
		{Name: "group", GID: strconv.Itoa(os.Getegid()), Platform: platform.LinuxType, IsAllowed: true},
		{Name: "nogroup", GID: "", Platform: platform.LinuxType, IsAllowed: false},
		{Name: "othergroup", GID: strconv.Itoa(os.Getegid() + 1), Platform: platform.LinuxType, IsAllowed: false},
		// Android has no group database, only root and the shell user are allowed
		{Name: "android", GID: strconv.Itoa(os.Getegid()), Platform: platform.AndroidType, IsAllowed: false},
	}

	for _, positive := range positiveCases {
		setSocketGroup(state, positive.GID)
		socketPath := fmt.Sprintf("@decerter-test-%d-%s", os.Getpid(), positive.Name)
		currentPlatform := platform.Platform{Type: positive.Platform, SDK: 0, Release: "", DataDirectory: "", APISocket: socketPath}
		server, err := Listen(socketPath, currentPlatform, logger)

		if err != nil {
			state.Fatalf("Test of api.Listen failed, cannot listen on %s, error: %s", socketPath, err.Error())
		}

		ctx, cancel := context.WithCancel(state.Context())
		doneChannel := make(chan struct{})

		// api server
		go func() {
			defer close(doneChannel)
			server.Serve(ctx, backend, logger)
		}()

		status, err := getStatusOver(state.Context(), socketPath)
		cancel()
		<-doneChannel

		if positive.IsAllowed && ((err != nil) || (status.Mode != v1.CaptureMode)) {
			state.Errorf("Test of api.peerListener.Accept failed, case %s, a peer in the group should be served, status: %+v, error: %v", positive.Name, status, err)
			return
		}

		if !positive.IsAllowed && (err == nil) {
			state.Errorf("Test of api.peerListener.Accept failed, case %s, a peer outside the policy should be closed, status: %+v", positive.Name, status)
			return
		}
	}
}

// Test if api.peerCredentials returns with the expected output and errors: the ids of this process for a unix socket, ErrPeer for anything else.
func TestPeerCredentialsPositive(state *testing.T) {
	socketPath := filepath.Join(state.TempDir(), "peer.sock")
	listener, err := net.Listen("unix", socketPath)

	if err != nil {
		state.Fatalf("Test of api.peerCredentials failed, cannot listen, error: %s", err.Error())
	}

	client, err := net.Dial("unix", socketPath)

	if err != nil {
		state.Fatalf("Test of api.peerCredentials failed, cannot connect, error: %s", err.Error())
	}

	accepted, err := listener.Accept()

	if err != nil {
		state.Fatalf("Test of api.peerCredentials failed, cannot accept, error: %s", err.Error())
	}

	uid, gid, pid, err := peerCredentials(accepted)

	if (err != nil) || (uid != uint32(os.Geteuid())) || (gid != uint32(os.Getegid())) || (pid != int32(os.Getpid())) {
		state.Errorf("Test of api.peerCredentials function failed, the peer should be this process, uid: %d, gid: %d, pid: %d, error: %v", uid, gid, pid, err)
	}

	// a closed socket has no descriptor to ask
	err = errors.Join(accepted.Close(), client.Close(), listener.Close())

	if err != nil {
		state.Fatalf("Test of api.peerCredentials failed, cannot close, error: %s", err.Error())
	}

	_, _, _, err = peerCredentials(accepted)

	if !errors.Is(err, ErrPeer) {
		state.Errorf("Test of api.peerCredentials function failed, a closed socket should be %v, error: %v", ErrPeer, err)
	}

	first, second := net.Pipe()
	_, _, _, err = peerCredentials(first)

	if !errors.Is(err, ErrPeer) {
		state.Errorf("Test of api.peerCredentials function failed, a pipe should be %v, error: %v", ErrPeer, err)
	}

	err = errors.Join(first.Close(), second.Close())

	if err != nil {
		state.Errorf("Test of api.peerCredentials failed, cannot close the pipe, error: %s", err.Error())
	}
}

// Test if api.lookupGroup returns with the expected output: the gid of the group, -1 without the group, with a gid that is no number and on Android.
func TestLookupGroupPositive(state *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	positiveCases := []struct {
		GID      string
		Platform platform.Type
		Expected int64
	}{
		{GID: "1234", Platform: platform.LinuxType, Expected: 1234},
		{GID: "", Platform: platform.LinuxType, Expected: -1},
		{GID: "S-1-5-32", Platform: platform.LinuxType, Expected: -1},
		{GID: "1234", Platform: platform.AndroidType, Expected: -1},
	}

	for _, positive := range positiveCases {
		setSocketGroup(state, positive.GID)
		groupID := lookupGroup(positive.Platform, logger)

		if groupID != positive.Expected {
			state.Errorf("Test of api.lookupGroup function failed, gid %q on %s should be %d, gid: %d", positive.GID, positive.Platform, positive.Expected, groupID)
			return
		}
	}
}

// Test if api.Listen returns with the expected errors: a directory that can't be made, a path that can't be read, a temporary name that is taken, an abstract name that is taken, and without root a group or a data directory that can't be given to root.
func TestListenFileNegative(state *testing.T) {
	setSocketGroup(state, "")
	directory := state.TempDir()
	logger := slog.New(slog.DiscardHandler)
	filePath := filepath.Join(directory, "file")
	err := os.WriteFile(filePath, nil, 0o600)

	if err != nil {
		state.Fatalf("Test of api.Listen failed, cannot write a file, error: %s", err.Error())
	}

	// the path runs through a file: the stale check can't read it
	underFile := filepath.Join(filePath, "api.sock")
	_, err = Listen(underFile, platform.Platform{Type: platform.LinuxType, APISocket: underFile}, logger)

	if !errors.Is(err, ErrSocket) {
		state.Errorf("Test of api.Listen function failed, a path under a file should be %v, error: %v", ErrSocket, err)
		return
	}

	// the directory of the socket can't be made in a directory without write access
	if os.Geteuid() != 0 {
		locked := filepath.Join(directory, "locked")
		err = os.Mkdir(locked, 0o500)

		if err != nil {
			state.Fatalf("Test of api.Listen failed, cannot make a directory, error: %s", err.Error())
		}

		_, err = listenFile(filepath.Join(locked, "run", "api.sock"), -1, false)

		if !errors.Is(err, ErrSocket) {
			state.Errorf("Test of api.listenFile function failed, a directory that can't be made should be %v, error: %v", ErrSocket, err)
			return
		}

		// the socket can't be bound in it either
		_, err = listenFile(filepath.Join(locked, "api.sock"), -1, false)

		if !errors.Is(err, ErrSocket) {
			state.Errorf("Test of api.listenFile function failed, a directory without write access should be %v, error: %v", ErrSocket, err)
			return
		}

		// only root gives the socket to root and the group, and the data directory to root
		_, err = listenFile(filepath.Join(directory, "group.sock"), int64(os.Getegid()), false)

		if !errors.Is(err, ErrSocket) || !errors.Is(err, os.ErrPermission) {
			state.Errorf("Test of api.listenFile function failed, a socket that can't be given to root should be %v, error: %v", ErrSocket, err)
			return
		}

		if _, statErr := os.Lstat(filepath.Join(directory, "group.sock.tmp"+strconv.Itoa(os.Getpid()))); !errors.Is(statErr, os.ErrNotExist) {
			state.Errorf("Test of api.listenFile function failed, the temporary socket should be removed after an error, error: %v", statErr)
			return
		}

		_, err = listenFile(filepath.Join(directory, "data", "api.sock"), -1, true)

		if !errors.Is(err, ErrSocket) || !errors.Is(err, os.ErrPermission) {
			state.Errorf("Test of api.listenFile function failed, a data directory that can't be given to root should be %v, error: %v", ErrSocket, err)
			return
		}
	}

	// something that can't be removed has the temporary name of the socket
	socketPath := filepath.Join(directory, "taken.sock")
	temporaryPath := socketPath + ".tmp" + strconv.Itoa(os.Getpid())
	err = os.MkdirAll(filepath.Join(temporaryPath, "full"), 0o700)

	if err != nil {
		state.Fatalf("Test of api.Listen failed, cannot make a directory, error: %s", err.Error())
	}

	_, err = Listen(socketPath, platform.Platform{Type: platform.LinuxType, APISocket: socketPath}, logger)

	if !errors.Is(err, ErrSocket) {
		state.Errorf("Test of api.Listen function failed, a temporary name that is taken should be %v, error: %v", ErrSocket, err)
		return
	}

	// an abstract name another socket has
	abstractPath := fmt.Sprintf("@decerter-test-%d-taken", os.Getpid())
	currentPlatform := platform.Platform{Type: platform.LinuxType, APISocket: abstractPath}
	first, err := Listen(abstractPath, currentPlatform, logger)

	if err != nil {
		state.Fatalf("Test of api.Listen failed, cannot listen on %s, error: %s", abstractPath, err.Error())
	}

	_, err = Listen(abstractPath, currentPlatform, logger)

	if !errors.Is(err, ErrSocket) {
		state.Errorf("Test of api.Listen function failed, an abstract name that is taken should be %v, error: %v", ErrSocket, err)
	}

	err = first.Close()

	if err != nil {
		state.Errorf("Test of api.Server.Close failed, an abstract socket should close, error: %s", err.Error())
	}
}

// Test if api.Handler answers a parameter, an id or a body it can't read with a JSON 400, and something that is not there with a JSON 404.
func TestHandlerParametersNegative(state *testing.T) {
	test, err := newTestBackend(state.Context())

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot make the backend, error: %s", err.Error())
	}

	defer test.stop()
	logger := slog.New(slog.DiscardHandler)
	backend := test.backend
	hub, err := capture.NewHub(capturebpf.MaxSnaplen, nil, nil, nil, backend.History, false, logger)

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot make the hub, error: %s", err.Error())
	}

	backend.Captures, err = capture.NewCaptures(hub, state.TempDir(), logger)

	if err != nil {
		state.Fatalf("Test of api.Handler failed, cannot make the captures, error: %s", err.Error())
	}

	defer func() {
		if closeErr := backend.Captures.Close(); closeErr != nil {
			state.Errorf("Test of api.Handler failed, cannot remove the captures, error: %s", closeErr.Error())
		}
	}()

	server := httptest.NewServer(Handler(backend, logger))
	defer server.Close()
	exchange := strconv.FormatUint(test.exchange, 10)
	flow := strconv.FormatUint(test.tlsFlow, 10)
	message := strconv.FormatUint(test.request, 10)
	negativeCases := []apiCase{
		{Method: http.MethodGet, Path: "/flows?filter=%28%28", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows?limit=0", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows?limit=many", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows?cursor=first", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows/x", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows/x/messages", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows/" + flow + "/messages?limit=1001", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows/" + flow + "/messages?cursor=-1", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows/999999/messages", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/messages/x", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/messages/" + message + "?offset=-1", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/messages/" + message + "?length=all", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/messages/999999", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/flows/x/exchanges", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows/" + flow + "/exchanges?limit=0", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows/" + flow + "/exchanges?cursor=x", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows/999999/exchanges", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/exchanges/x", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/exchanges/999999", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/exchanges/x/body", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/exchanges/" + exchange + "/body?side=both", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/exchanges/" + exchange + "/body?offset=-1", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/exchanges/" + exchange + "/body?length=-1", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/exchanges/999999/body", Status: http.StatusNotFound},
		{Method: http.MethodPut, Path: "/intercept", Body: `{"enabled": `, Status: http.StatusBadRequest},
		{Method: http.MethodPut, Path: "/intercept", Body: `{"enabled": true} {"enabled": false}`, Status: http.StatusBadRequest},
		{Method: http.MethodPut, Path: "/intercept", Body: `{"enabled": true, "unknown": 1}`, Status: http.StatusBadRequest},
		{Method: http.MethodPut, Path: "/intercept", Body: `{"enabled": true, "direction": "sideways"}`, Status: http.StatusBadRequest},
		{Method: http.MethodPut, Path: "/intercept", Body: `{"enabled": true, "layer": "quic"}`, Status: http.StatusBadRequest},
		{Method: http.MethodPut, Path: "/intercept", Body: `{"enabled": true, "filter": "(("}`, Status: http.StatusBadRequest},
		{Method: http.MethodPut, Path: "/holds/x", Body: `{"payload": {"type": "text", "value": "x"}}`, Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/holds/x/forward", Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/holds/x/drop", Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/rules", Body: `[]`, Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/rules", Body: `{"direction": "sideways", "find": {"type": "text", "value": "a"}, "replace": {"type": "text", "value": "b"}}`, Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/rules", Body: `{"find": {"type": "hex", "value": "zz"}, "replace": {"type": "text", "value": "b"}}`, Status: http.StatusBadRequest},
		{Method: http.MethodDelete, Path: "/rules/x", Status: http.StatusBadRequest},
		{Method: http.MethodDelete, Path: "/rules/999999", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/keylog?filter=%28%28", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows/pcap?filter=%28%28", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/flows/pcap?format=pcap", Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/captures", Body: `{"filter": `, Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/captures", Body: `{"filter": "(("}`, Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/captures", Body: `{"filter": "http.request.method == \"GET\""}`, Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/captures/x/stop", Status: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/captures/999999/stop", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/captures/x/pcap", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/captures/999999/pcap", Status: http.StatusNotFound},
		{Method: http.MethodGet, Path: "/captures/stream?filter=%28%28", Status: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/captures/stream?plaintext=maybe", Status: http.StatusBadRequest},
	}

	for _, negative := range negativeCases {
		status, _, body, requestErr := send(state.Context(), server, negative.Method, v1.BasePath+negative.Path, negative.Body)

		if requestErr != nil {
			state.Fatalf("Test of api.Handler failed, %s %s, error: %s", negative.Method, negative.Path, requestErr.Error())
		}

		apiError := v1.Error{}

		if (status != negative.Status) || (json.Unmarshal(body, &apiError) != nil) || (apiError.Error == "") {
			state.Errorf("Test of api.Handler failed, %s %s %s should answer %d with a JSON error, status: %d, body: %s", negative.Method, negative.Path, negative.Body, negative.Status, status, body)
			return
		}
	}

	// the request of the HTTP/1.1 exchange has no body, its side is there with nothing in it; the side of an exchange without a response is not there
	status, _, body, err := send(state.Context(), server, http.MethodGet, v1.BasePath+"/exchanges/"+exchange+"/body?side=request", "")

	if (err != nil) || (status != http.StatusOK) {
		state.Errorf("Test of api.Handler failed, the body of a request without one should answer 200, status: %d, body: %s, error: %v", status, body, err)
		return
	}

	pending := backend.History.OpenExchange(test.udpFlow, "HTTP/1.1", v1.RequestSide, v1.HTTPMessage{HTTPHead: v1.HTTPHead{Method: "GET", Target: "/", Version: "HTTP/1.1"}, Time: time.Now(), Framing: v1.NoneFraming, State: v1.HeadHTTPState})
	status, _, body, err = send(state.Context(), server, http.MethodGet, v1.BasePath+"/exchanges/"+strconv.FormatUint(pending, 10)+"/body?side=response", "")

	if (err != nil) || (status != http.StatusNotFound) {
		state.Errorf("Test of api.Handler failed, the body of a response that did not come should answer 404, status: %d, body: %s, error: %v", status, body, err)
		return
	}
}

// Test if api.exportKeylog returns with the expected output and errors: a session the lookup no longer has is left out, a lookup that fails is a 500.
func TestExportKeylogNegative(state *testing.T) {
	test, err := newTestBackend(state.Context())

	if err != nil {
		state.Fatalf("Test of api.exportKeylog failed, cannot make the backend, error: %s", err.Error())
	}

	defer test.stop()
	logger := slog.New(slog.DiscardHandler)
	lookupErr := errors.New("map lookup failed")
	negativeCases := []struct {
		KeyLog func(clientRandom [32]byte) (keyLog string, found bool, err error)
		Status int
		Body   string
	}{
		{KeyLog: func(clientRandom [32]byte) (keyLog string, found bool, err error) { return }, Status: http.StatusOK, Body: ""},
		{KeyLog: func(clientRandom [32]byte) (keyLog string, found bool, err error) { err = lookupErr; return }, Status: http.StatusInternalServerError, Body: lookupErr.Error()},
	}

	for _, negative := range negativeCases {
		test.backend.KeyLog = negative.KeyLog
		server := httptest.NewServer(Handler(test.backend, logger))
		status, _, body, requestErr := send(state.Context(), server, http.MethodGet, v1.BasePath+"/keylog", "")
		server.Close()

		if (requestErr != nil) || (status != negative.Status) || !strings.Contains(string(body), negative.Body) || ((negative.Body == "") && (len(body) != 0)) {
			state.Errorf("Test of api.exportKeylog function failed, status should be %d with %q, status: %d, body: %s, error: %v", negative.Status, negative.Body, status, body, requestErr)
			return
		}
	}
}

// Test if the handlers of the API cope with a client that went away and with a value JSON can't encode: nothing panics, the encode error is a 500.
func TestWriteNegative(state *testing.T) {
	test, err := newTestBackend(state.Context())

	if err != nil {
		state.Fatalf("Test of api.writeJSON failed, cannot make the backend, error: %s", err.Error())
	}

	defer test.stop()
	logger := slog.New(slog.DiscardHandler)
	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusOK, map[string]any{"channel": make(chan int)}, logger)

	if recorder.Code != http.StatusInternalServerError {
		state.Errorf("Test of api.writeJSON function failed, a value that can't be encoded should answer 500, status: %d", recorder.Code)
		return
	}

	handler := Handler(test.backend, logger)

	for _, path := range []string{"/status", "/keylog", "/flows/pcap", "/events"} {
		writer := &failingWriter{header: http.Header{}, status: 0}
		request := httptest.NewRequestWithContext(state.Context(), http.MethodGet, v1.BasePath+path, nil)
		handler.ServeHTTP(writer, request)

		if writer.status != http.StatusOK {
			state.Errorf("Test of api.Handler failed, GET %s should answer 200 before its write fails, status: %d", path, writer.status)
			return
		}
	}

	// a writer without a write deadline can't take an event
	if writeEvent(http.NewResponseController(recorder), recorder, v1.Event{Type: v1.FlowOpenedEventType, Flow: nil}, logger) {
		state.Errorf("Test of api.writeEvent function failed, an event should not be written without a write deadline")
		return
	}
}

// Test if the capture handlers answer a capture whose file can't be opened or made with a JSON 500.
func TestCaptureHandlerNegative(state *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	info := Info{Mode: v1.CaptureMode, Processing: v1.RecordProcessing, Platform: "linux", Scope: "", Started: time.Now(), HoldTimeout: 0, HasTLSSecrets: false, IsInterceptCapable: false}
	backend := NewBackend(info, history.DefaultLimits(), nil)
	hub, err := capture.NewHub(capturebpf.MaxSnaplen, nil, nil, nil, backend.History, false, logger)

	if err != nil {
		state.Fatalf("Test of the capture handlers failed, cannot make the hub, error: %s", err.Error())
	}

	dataDirectory := state.TempDir()
	directory := filepath.Join(dataDirectory, capture.CaptureDirectoryName)
	backend.Captures, err = capture.NewCaptures(hub, dataDirectory, logger)

	if err != nil {
		state.Fatalf("Test of the capture handlers failed, cannot make the captures, error: %s", err.Error())
	}

	server := httptest.NewServer(Handler(backend, logger))
	defer server.Close()
	started := v1.Capture{}
	status, _, body, err := send(state.Context(), server, http.MethodPost, v1.BasePath+"/captures", "")

	if (err != nil) || (status != http.StatusCreated) || (json.Unmarshal(body, &started) != nil) {
		state.Fatalf("Test of the capture handlers failed, cannot start a capture, status: %d, body: %s, error: %v", status, body, err)
	}

	status, _, body, err = send(state.Context(), server, http.MethodPost, fmt.Sprintf("%s/captures/%d/stop", v1.BasePath, started.ID), "")

	if (err != nil) || (status != http.StatusOK) {
		state.Fatalf("Test of the capture handlers failed, cannot stop the capture, status: %d, body: %s, error: %v", status, body, err)
	}

	// the file of the stopped capture is gone
	entries, err := os.ReadDir(directory)

	if (err != nil) || (len(entries) != 1) {
		state.Fatalf("Test of the capture handlers failed, the capture should have one file, entries: %v, error: %v", entries, err)
	}

	// the name the next capture takes for its file is taken
	name := entries[0].Name()
	err = errors.Join(os.Remove(filepath.Join(directory, name)), os.WriteFile(filepath.Join(directory, strconv.FormatUint(started.ID+1, 10)+strings.TrimPrefix(name, strconv.FormatUint(started.ID, 10))), nil, 0o600))

	if err != nil {
		state.Fatalf("Test of the capture handlers failed, cannot change the files, error: %s", err.Error())
	}

	negativeCases := []apiCase{
		{Method: http.MethodGet, Path: fmt.Sprintf("/captures/%d/pcap", started.ID), Status: http.StatusInternalServerError},
		{Method: http.MethodPost, Path: "/captures", Status: http.StatusInternalServerError},
	}

	for _, negative := range negativeCases {
		answered, _, answer, requestErr := send(state.Context(), server, negative.Method, v1.BasePath+negative.Path, "")
		apiError := v1.Error{}

		if (requestErr != nil) || (answered != negative.Status) || (json.Unmarshal(answer, &apiError) != nil) || (apiError.Error == "") {
			state.Errorf("Test of the capture handlers failed, %s %s should answer %d with a JSON error, status: %d, body: %s, error: %v", negative.Method, negative.Path, negative.Status, answered, answer, requestErr)
		}
	}

	err = backend.Captures.Close()

	if err != nil {
		state.Errorf("Test of the capture handlers failed, cannot remove the captures, error: %s", err.Error())
	}
}

// the streams of the bus
func subscriberCount(bus *Bus) (count int) {
	bus.mutex.Lock()
	defer bus.mutex.Unlock()
	count = len(bus.subscribers)
	return
}

// wait until the bus has count streams
func waitSubscribers(bus *Bus, count int) (err error) {
	deadline := time.Now().Add(10 * time.Second)

	for subscriberCount(bus) != count {
		if time.Now().After(deadline) {
			err = fmt.Errorf("the bus should have %d streams, streams: %d", count, subscriberCount(bus))
			return
		}

		time.Sleep(time.Millisecond)
	}

	return
}

// Test if the event stream of api.Handler ends a client that reads too slowly with the events it still had and an overflow event, and leaves the bus when its client goes away.
func TestStreamEventsNegative(state *testing.T) {
	backend := NewBackend(Info{Mode: v1.RunMode}, history.DefaultLimits(), nil)
	server := httptest.NewServer(Handler(backend, slog.New(slog.DiscardHandler)))
	defer server.Close()
	ctx, cancel := context.WithCancel(state.Context())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+v1.BasePath+"/events", nil)

	if err != nil {
		state.Fatalf("Test of api.streamEvents failed, cannot make the request, error: %s", err.Error())
	}

	response, err := server.Client().Do(request)

	if err != nil {
		state.Fatalf("Test of api.streamEvents failed, cannot connect, error: %s", err.Error())
	}

	err = waitSubscribers(backend.Bus, 1)

	if err != nil {
		state.Fatalf("Test of api.streamEvents failed, error: %s", err.Error())
	}

	// more than the socket buffers and the buffer of the stream hold while nobody reads: the writer blocks and the stream falls behind
	reason := strings.Repeat("x", 64<<10)
	published := 4096

	for range published {
		backend.Bus.Publish(v1.Event{Type: v1.MessageEventType, Reason: reason})
	}

	reader := bufio.NewReaderSize(response.Body, 128<<10)
	var last sentEvent
	events := 0

	for {
		event, readErr := readEvent(reader)

		if readErr != nil {
			break
		}

		last = event
		events++
	}

	overflow := v1.Event{}

	if (last.name != string(v1.OverflowEventType)) || (json.Unmarshal(last.data, &overflow) != nil) || (overflow.Seq < uint64(eventBuffer)) || (overflow.Seq > uint64(published)) || (events < eventBuffer) || (events > published) {
		state.Errorf("Test of api.streamEvents failed, a stream that fell behind should end with an overflow event after the events it had, events: %d, last: %s id %s", events, last.name, last.id)
	}

	err = errors.Join(response.Body.Close(), waitSubscribers(backend.Bus, 0))

	if err != nil {
		state.Fatalf("Test of api.streamEvents failed, the stream should leave the bus, error: %s", err.Error())
	}

	// a client that goes away ends its stream
	second, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+v1.BasePath+"/events", nil)

	if err != nil {
		state.Fatalf("Test of api.streamEvents failed, cannot make the request, error: %s", err.Error())
	}

	response, err = server.Client().Do(second)

	if err != nil {
		state.Fatalf("Test of api.streamEvents failed, cannot connect, error: %s", err.Error())
	}

	err = waitSubscribers(backend.Bus, 1)
	cancel()
	closeErr := response.Body.Close()

	if (closeErr != nil) && !errors.Is(closeErr, context.Canceled) {
		err = errors.Join(err, closeErr)
	}

	err = errors.Join(err, waitSubscribers(backend.Bus, 0))

	if err != nil {
		state.Errorf("Test of api.streamEvents failed, the stream of a client that left should end, error: %s", err.Error())
	}
}
