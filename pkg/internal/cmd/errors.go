// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"errors"
)

var (
	ErrNotAndroid        = errors.New("not running on Android, there are no netd hooks to restore")
	ErrPackageNotAndroid = errors.New("--package needs Android, the uid of a package comes from /data/system/packages.list there; on Linux select with --uid or --pid")
	ErrLibraryUnknown    = errors.New("a Flutter or Chromium library of the app can't be hooked, its TLS is relayed without decryption")
	ErrSetupAsRoot       = errors.New("decerter android setup runs as your user, not as root: adb as root starts a second adb server, and the emulator and its AVDs belong to your user")
)
