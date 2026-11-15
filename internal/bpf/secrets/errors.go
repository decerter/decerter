// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"errors"
)

var (
	ErrUnknownTLSVersion = errors.New("unknown TLS version in secrets event")
	ErrUnknownCipher     = errors.New("unknown TLS 1.3 cipher suite")
	ErrSecretLength      = errors.New("TLS 1.3 secret length is not 32 or 48")
	ErrRingbufRead       = errors.New("could not read the secrets ringbuf, gave up after repeated failures")
	// the secrets object is generated for amd64 and arm64
	ErrUnsupportedArchitecture = errors.New("secrets uprobe is not built for this architecture")
	// the BoringSSL uprobe read a version that does not fit the label
	ErrLayoutMismatch = errors.New("libssl does not match the BoringSSL offsets of this Android release, no secrets are read")
)
