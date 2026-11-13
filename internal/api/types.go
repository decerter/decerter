// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/capture"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
)

const (
	// the group whose members may use the socket on Linux, it is not created by decerter
	socketGroup string = "decerter"
	// Android's AID_SHELL, adbd runs as it without adb root and connects for adb forward localabstract:
	androidShellUID uint32 = 2000
	// the default window of a payload and the largest one a request may ask for
	defaultPayloadLength int = 4096
	maxPayloadLength     int = 64 << 10
	maxPayloadOffset     int = 1 << 30
	// pages of flows and of the messages of one flow
	defaultFlowLimit    int = 100
	maxFlowLimit        int = 100
	defaultMessageLimit int = 100
	maxMessageLimit     int = 1000
	// a request body: an edit of the largest datagram in hex fits
	maxRequestBytes int64 = 1 << 20
	// events a client of the stream may be behind before it is dropped, and the time one write to it may take
	eventBuffer       int           = 256
	eventWriteTimeout time.Duration = 10 * time.Second
	eventKeepalive    time.Duration = 15 * time.Second
	// one write of a block of the capture stream may take this long, a reader that stops reading ends the stream
	captureWriteTimeout time.Duration = 10 * time.Second
	// the answer of a live socket at the path, and the time the server has to finish its requests on shutdown
	socketProbeTimeout time.Duration = time.Second
	shutdownTimeout    time.Duration = 2 * time.Second
	readHeaderTimeout  time.Duration = 10 * time.Second
)

// what does not change while decerter runs
type Info struct {
	Mode               v1.Mode
	Processing         v1.Processing
	Platform           string
	Scope              string
	Started            time.Time
	HoldTimeout        time.Duration
	HasTLSSecrets      bool
	IsInterceptCapable bool
}

// what the server serves: the history of the run, the hold queue and the rules; Holds and Rules are nil without --intercept
// KeyLog looks up the NSS key log lines of a session, nil without the secrets uprobe; Bus carries the events of everything
// Captures are the captures, the stream and the captured packets: on decerter capture the packets of the recorded sockets, on decerter run the ones of the proxy's upstream sockets; nil without capture programs
type Backend struct {
	Info     Info
	History  *history.History
	Holds    *intercept.HoldQueue
	Rules    *intercept.RuleSet
	Bus      *Bus
	KeyLog   func(clientRandom [32]byte) (keyLog string, found bool, err error)
	Captures *capture.Captures
}

// the events of the server to every stream: a stream whose buffer is full is dropped instead of waiting for it
type Bus struct {
	mutex       *sync.Mutex
	sequence    uint64
	subscribers map[*subscriber]bool
}

// overflow is closed when the bus dropped the subscriber, lostSequence is the first event it did not get
type subscriber struct {
	events       chan v1.Event
	overflow     chan struct{}
	lostSequence uint64
}

// the server on the api socket; path is the socket file to remove on exit, empty for an abstract socket
type Server struct {
	listener   net.Listener
	httpServer *http.Server
	path       string
	closeOnce  *sync.Once
	closeErr   error
}

// who may connect: isChecked is false for a socket file, its mode and group decide; an abstract socket has neither, so the peer's uid or primary gid is checked, gid -1 is no group
type accessPolicy struct {
	isChecked bool
	uids      []uint32
	gid       int64
}

// a listener that refuses the connections of peers the policy does not allow
type peerListener struct {
	net.Listener
	policy accessPolicy
	logger *slog.Logger
}

// one operation of the API, its method and path as in api/openapi.yaml
type route struct {
	method      string
	path        string
	operationID string
	handle      func(backend *Backend, writer http.ResponseWriter, request *http.Request, logger *slog.Logger)
}
