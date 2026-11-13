// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"errors"
)

var (
	ErrListen     = errors.New("could not listen")
	ErrPacketInfo = errors.New("no destination address in datagram control message")
	ErrLoop       = errors.New("original destination is the proxy itself")
	ErrMark       = errors.New("could not set socket mark")
	ErrCookie     = errors.New("could not read socket cookie")
	// the uprobe saw no secrets of the session: the process has its own TLS library, or the handshake did not end in time
	ErrNoSecrets      = errors.New("no secrets for the tls session")
	ErrObserverBehind = errors.New("decryption is too far behind the relay")
	// a raw record after a split or dropped record would reach the peer with a sequence number it does not expect
	ErrChangedStream = errors.New("can't relay raw bytes after the tls records of the direction were changed")
)
