// SPDX-License-Identifier: AGPL-3.0-only

package ui

import (
	"sync"
	"time"
)

const (
	// IPv4 loopback only, the port is picked by the kernel: one origin, one Host to check and one cookie
	listenAddress string = "127.0.0.1:0"
	// the random bytes of the token, it is written base64url without padding
	tokenBytes int = 32
	// the query parameter of the first load and the cookie that carries the token after it; cookies are not kept apart by port, so the port is in the name
	tokenParameter string = "token"
	cookiePrefix   string = "decerter-ui-"
	// the query parameter of the first load decerter ui --open hands to the browser, a code is good once and for codeLifetime
	codeParameter string        = "code"
	codeLifetime  time.Duration = 5 * time.Minute
	// the browser asks for it at the root of the origin, without the cookie
	faviconPath string = "/favicon.ico"
	// no inline script or style, nothing from another origin, never in a frame
	contentSecurityPolicy string = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	// the files of the page in the embedded web directory
	webDirectory string = "web"
	// how long the first answer of the api may take at start, and the headers of a proxied answer; the event stream answers its headers at once
	checkTimeout          time.Duration = 5 * time.Second
	maxStatusBytes        int64         = 1 << 20
	responseHeaderTimeout time.Duration = 30 * time.Second
	readHeaderTimeout     time.Duration = 10 * time.Second
	idleTimeout           time.Duration = 2 * time.Minute
	shutdownTimeout       time.Duration = 2 * time.Second
)

type Network string

const (
	// a socket file, or an abstract socket when the address starts with @
	UnixNetwork Network = "unix"
	// a loopback address, such as the host side of adb forward
	TCPNetwork Network = "tcp"
)

// where the control API is
type Target struct {
	Network Network
	Address string
}

// the secrets of one decerter ui: the token of the printed URL and of the cookie, the random path the page is served under, and the one-time code of --open
type Credentials struct {
	Token        string
	Prefix       string
	mutex        *sync.Mutex
	code         string
	codeDeadline time.Time
}

func (target Target) String() (text string) {
	text = string(target.Network) + ":" + target.Address
	return
}
