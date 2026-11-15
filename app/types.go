// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"github.com/decerter/decerter/internal/tls/boringssl"
	"github.com/decerter/decerter/internal/tls/openssl"
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

// one OpenSSL libssl the stash_ssl and store_secrets uprobes are attached to, its index in openssl_layout_map is the uprobes' attach cookie
// Library has the path the uprobes attach to, its version and offsets; Pid is the selected process the libssl was found mapped in (through
// /proc/<pid>/root, so a container's own libssl), 0 for --libssl and the libssl.so.3 and libssl.so.4 of the linker cache; Process is its name
type opensslHook struct {
	Library openssl.Library
	Pid     int
	Process string
}

// a library of the linker cache whose version has no offsets, Err names the nearest known version and the make command
type unknownOpenssl struct {
	Library openssl.Library
	Err     error
}

// the /proc/<pid>/maps text of a selected process
type processMaps struct {
	Pid  int
	Maps string
}
