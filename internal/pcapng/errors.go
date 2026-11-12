// SPDX-License-Identifier: AGPL-3.0-only

package pcapng

import (
	"errors"
)

var (
	ErrWrite       = errors.New("could not write pcapng block")
	ErrSnaplen     = errors.New("snaplen must be positive")
	ErrPacketSize  = errors.New("packet is longer than its original length or the snaplen")
	ErrCommentSize = errors.New("packet comment is longer than an option")
)
