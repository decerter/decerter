// SPDX-License-Identifier: AGPL-3.0-only

package intercept

import (
	"errors"
)

var (
	ErrVerdict = errors.New("unknown verdict of intercept rule")
	// a match rule that can't be built
	ErrDirections = errors.New("invalid directions")
	ErrLayer      = errors.New("invalid layer")
	ErrValueType  = errors.New("invalid value type")
	ErrFind       = errors.New("invalid find value")
	ErrReplace    = errors.New("invalid replace value")
	// the hold queue has no message of that id, it was never held or is decided already
	ErrNotHeld = errors.New("no held message with this id")
)
