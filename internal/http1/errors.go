// SPDX-License-Identifier: AGPL-3.0-only

package http1

import (
	"errors"
)

var (
	// why a side of a conn stopped parsing, the rest of its stream is not HTTP/1 to the parser
	ErrMalformed   = errors.New("malformed http/1 message")
	ErrHeadTooLong = errors.New("http/1 head is too long")
	ErrHTTP2       = errors.New("http/2 connection preface")
	ErrUpgrade     = errors.New("protocol switched by 101 switching protocols")
	ErrConnect     = errors.New("tunnel of a connect request")
	ErrClosed      = errors.New("stream ended")
	// an edited form that is not a message, it goes on as it was written
	ErrNoHeadEnd = errors.New("no empty line ends the head")
)
