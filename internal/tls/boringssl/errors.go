// SPDX-License-Identifier: AGPL-3.0-only

package boringssl

import (
	"errors"
)

var (
	ErrOpenLibrary     = errors.New("could not open library")
	ErrLibraryNotFound = errors.New("could not find library")
	ErrReadDebugData   = errors.New("could not read .gnu_debugdata section")
	ErrNoLogSecret     = errors.New("could not find ssl_log_secret, the library is not a BoringSSL decerter can hook")
	ErrNotLoaded       = errors.New("ssl_log_secret is not in a loaded segment")
	ErrUnknownRelease  = errors.New("no BoringSSL offsets for Android release")
)
