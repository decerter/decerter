// SPDX-License-Identifier: AGPL-3.0-only

package route

import (
	"errors"
)

var (
	ErrRouteDump      = errors.New("could not dump routing tables")
	ErrRouteSubscribe = errors.New("could not subscribe to route events")
)
