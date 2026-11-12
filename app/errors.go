// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"errors"
)

var (
	// Android apps use BoringSSL from Conscrypt, not a system OpenSSL
	ErrNoAndroidSecrets = errors.New("no system OpenSSL on Android, TLS secrets of Conscrypt apps are not supported yet")
)
