// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"errors"
)

var (
	ErrUnknownTLSVersion = errors.New("unknown TLS version in secrets event")
	ErrUnknownCipher     = errors.New("unknown TLS 1.3 cipher suite")
	// the secrets object is generated for amd64 only until the arm64 uprobe build
	ErrUnsupportedArchitecture = errors.New("secrets uprobe is not built for this architecture")
)
