// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
)

var (
	// the socket
	ErrNotSocket   = errors.New("the api socket path exists and is not a socket")
	ErrSocketInUse = errors.New("another server answers on the api socket")
	ErrSocket      = errors.New("could not create the api socket")
	ErrTCPSocket   = errors.New("the api socket is a unix socket path or @name, an ip:port is only for the clients decerter ui and decerter mcp: write ./name for a socket file in the current directory")
	ErrPeer        = errors.New("could not read the credentials of the api client")
	// the requests
	ErrNotFound       = errors.New("not found")
	ErrMethod         = errors.New("method not allowed")
	ErrBadRequest     = errors.New("bad request")
	ErrNoInterception = errors.New("holding and rules need decerter run --intercept")
	ErrNoSecrets      = errors.New("decerter has no tls secrets, the secrets uprobe is not loaded")
	// the client
	ErrBrowser    = errors.New("the control api refuses requests from a browser, it takes no Origin or Sec-Fetch-Site header: use decerter ui")
	ErrHost       = errors.New("the control api takes only the host localhost or a loopback address, with or without a port, and decerter on its unix socket but not through adb forward")
	ErrNoCaptures = errors.New("this decerter captures no packets, captures, the capture stream and format=dsb need the capture programs: GET /api/v1/flows/pcap?format=plaintext exports the history")
)
