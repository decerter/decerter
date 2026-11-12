// SPDX-License-Identifier: AGPL-3.0-only

package tlsrecord

import (
	"errors"
)

var (
	ErrUnexpectedRecord       = errors.New("unexpected tls record")
	ErrRecordOverflow         = errors.New("tls record is longer than the protocol allows")
	ErrMalformedHandshake     = errors.New("malformed tls handshake message")
	ErrUnsupportedVersion     = errors.New("unsupported tls version")
	ErrUnsupportedCipherSuite = errors.New("unsupported tls cipher suite")
	ErrEarlyData              = errors.New("tls 1.3 early data is not supported")
	ErrRenegotiation          = errors.New("tls renegotiation is not supported")
	ErrSecrets                = errors.New("secrets do not fit the tls session")
	ErrBadRecordMAC           = errors.New("could not authenticate tls record")
	ErrHoldQueueFull          = errors.New("too many bytes wait for the tls secrets")
	ErrSeal                   = errors.New("could not seal tls record")
)
