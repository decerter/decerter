// SPDX-License-Identifier: AGPL-3.0-only

package redirect

import (
	"errors"
)

var (
	ErrUnknownClient = errors.New("client endpoint not in client_map")
	ErrUnknownFlow   = errors.New("socket cookie not in flow_map")
)
