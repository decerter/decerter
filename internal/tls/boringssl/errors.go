// SPDX-License-Identifier: AGPL-3.0-only

package boringssl

import (
	"errors"
)

var (
	ErrOpenLibrary         = errors.New("could not open library")
	ErrLibraryNotFound     = errors.New("could not find library")
	ErrReadDebugData       = errors.New("could not read .gnu_debugdata section")
	ErrNoLogSecret         = errors.New("could not find ssl_log_secret, the library is not a BoringSSL decerter can hook")
	ErrNotLoaded           = errors.New("ssl_log_secret is not in a loaded segment")
	ErrUnknownRelease      = errors.New("no BoringSSL offsets for Android release")
	ErrUnsupportedMachine  = errors.New("no ssl_log_secret finder for the machine")
	ErrReadSegment         = errors.New("could not read a loaded segment")
	ErrNoLabels            = errors.New("no key log label in the library, it has no BoringSSL")
	ErrNoLabelCalls        = errors.New("could not find ssl_log_secret through its key log labels")
	ErrAmbiguousLabelCalls = errors.New("could not tell ssl_log_secret apart through its key log labels")
	ErrReadAPK             = errors.New("could not read apk")
	ErrCompressedLibrary   = errors.New("the library is compressed in the apk, a uprobe needs it stored")
	ErrUnalignedLibrary    = errors.New("the library is not page aligned in the apk, Android can't map it from there")
	ErrNoDartVersion       = errors.New("no Dart version string in libflutter.so")
	ErrUnknownDartVersion  = errors.New("no BoringSSL offsets for the Dart version of the Flutter engine")
	ErrWrongMachine        = errors.New("the library is for another architecture")
)
