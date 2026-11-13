// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"errors"
)

var (
	ErrNoPackage = errors.New("--package is required")
)
