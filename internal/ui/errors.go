// SPDX-License-Identifier: AGPL-3.0-only

package ui

import (
	"errors"
)

var (
	// the api address
	ErrAPIAddress  = errors.New("invalid api address")
	ErrNotLoopback = errors.New("a tcp api address must be a loopback ip address, such as 127.0.0.1:8080 of adb forward")
	// reaching the api
	ErrSocketPermission = errors.New("no permission to open the api socket, it is for root and the members of the group decerter: create the group with sudo groupadd decerter, add your user with sudo usermod -aG decerter $USER, log in again (or newgrp decerter) and restart decerter run so the socket gets the group")
	ErrNoSocket         = errors.New("there is no api socket at this path, start decerter with sudo decerter run --api-socket <path>, or give decerter ui the path with --api-socket")
	ErrNoServer         = errors.New("nothing answers at the api address, is decerter running with --api-socket (and, for Android, adb forward set up)")
	ErrRefused          = errors.New("the api server closed the connection, it does not let this user in: an abstract socket admits root and, on Linux, users whose primary group is decerter")
	ErrAPI              = errors.New("the api answered with an error")
	// the browser
	ErrToken     = errors.New("could not make the token")
	ErrHost      = errors.New("wrong host")
	ErrFetchSite = errors.New("not a same-origin request")
	ErrBadToken  = errors.New("wrong token")
	ErrCookie    = errors.New("no or wrong token cookie")
	ErrOrigin    = errors.New("wrong origin")
	ErrPath      = errors.New("only paths under /api/v1/ are forwarded to the api")
)
