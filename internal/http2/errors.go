// SPDX-License-Identifier: AGPL-3.0-only

package http2

import (
	"errors"
)

var (
	// why a conn stopped parsing, the rest of both streams is not read
	ErrPreface       = errors.New("the client did not start with the http/2 connection preface")
	ErrFrameTooLarge = errors.New("http/2 frame larger than the max frame size of its receiver")
	ErrFrame         = errors.New("malformed http/2 frame")
	ErrFrameOrder    = errors.New("http/2 header block interrupted")
	ErrHPACK         = errors.New("hpack decoding failed")
	// what the editor could not do right, the receiver may see broken frames
	ErrEditOrder          = errors.New("http/2 bytes went on out of their order")
	ErrHeaderListTooLarge = errors.New("http/2 header block too large to encode again")
	// an edit form that is no HTTP/2 message
	ErrForm = errors.New("malformed http/2 edit form")
)
