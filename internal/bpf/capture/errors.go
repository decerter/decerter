// SPDX-License-Identifier: AGPL-3.0-only

package capture

import (
	"errors"
)

var (
	ErrSnaplen     = errors.New("snaplen must be between 1 and 262144")
	ErrShortRecord = errors.New("packet_map record is too short")
)
