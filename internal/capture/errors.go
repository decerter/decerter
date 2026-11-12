// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"errors"
)

var (
	ErrOpenFile = errors.New("could not open capture file")
	ErrRead     = errors.New("could not read packet_map")
)
