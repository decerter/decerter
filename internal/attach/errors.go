// SPDX-License-Identifier: AGPL-3.0-only

package attach

import (
	"errors"
)

var (
	ErrAttach = errors.New("could not attach bpf program")
)
