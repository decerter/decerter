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
	ErrPeer        = errors.New("could not read the credentials of the api client")
	// the requests
	ErrNotFound       = errors.New("not found")
	ErrMethod         = errors.New("method not allowed")
	ErrBadRequest     = errors.New("bad request")
	ErrNoInterception = errors.New("holding and rules need decerter run --intercept")
	ErrNoSecrets      = errors.New("decerter has no tls secrets, the secrets uprobe is not loaded")
	ErrNoCaptures     = errors.New("captures and the capture stream need decerter capture --api-socket, decerter run records no packets: GET /api/v1/flows/pcap?format=plaintext exports its history")
	ErrDSBRunMode     = errors.New("format=dsb needs decerter capture, decerter run has the messages of its proxy and no captured packets: use format=plaintext")
)
