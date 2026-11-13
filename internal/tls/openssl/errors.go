// SPDX-License-Identifier: AGPL-3.0-only

package openssl

import (
	"errors"
)

var (
	ErrOpenLibrary         = errors.New("could not open library")
	ErrNoRodata            = errors.New("could not find .rodata section")
	ErrReadRodata          = errors.New("could not read .rodata section")
	ErrNoVersion           = errors.New("could not find OpenSSL version string")
	ErrUnknownVersion      = errors.New("no offsets for OpenSSL version")
	ErrVersionFormat       = errors.New("OpenSSL version is not x.y.z")
	ErrUnknownArchitecture = errors.New("no OpenSSL offsets for architecture")
	ErrLibraryNotFound     = errors.New("could not find library")
)
