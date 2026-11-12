// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"errors"
)

var (
	ErrNotAndroid = errors.New("not running on Android, there are no netd hooks to restore")
)
