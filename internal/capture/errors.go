// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"errors"
)

var (
	ErrOpenFile   = errors.New("could not open capture file")
	ErrRead       = errors.New("could not read packet_map")
	ErrTerminal   = errors.New("stdout is a terminal, the capture stream is binary and holds secrets: pipe it into a reader or redirect it to a file")
	ErrPollStream = errors.New("could not poll capture stream")
)
