// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"errors"
)

var (
	ErrListen      = errors.New("could not listen")
	ErrPacketInfo  = errors.New("no destination address in datagram control message")
	ErrLoop        = errors.New("original destination is the proxy itself")
	ErrProcessInfo = errors.New("could not read process info")
)
