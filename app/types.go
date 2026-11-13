// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"github.com/decerter/decerter/internal/tls/boringssl"
)

// one BoringSSL library the ssl_log_secret uprobe is attached to, its index in boringssl_layout_map is the uprobe's attach cookie
// Path is the file the uprobe attaches to (Conscrypt's libssl, an apk or an extracted libflutter.so) and Address the file offset of ssl_log_secret in it;
// Library says what it is for the logs, Package is the app of a Flutter library, empty for Conscrypt
type boringsslHook struct {
	Path    string
	Address uint64
	Offset  boringssl.Offset
	Library string
	Package string
}
