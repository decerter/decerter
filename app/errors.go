// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"errors"
)

var (
	// a filter alone would select every process of the machine
	ErrNoProcess = errors.New("the filter selects no process: give --uid or --pid, or a proc.uid or proc.pid term (== or in, also several of them joined by ||) at the top level of the filter, joined to the rest by &&")
)
