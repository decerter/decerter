// SPDX-License-Identifier: AGPL-3.0-only

package openssl

import (
	"debug/elf"
	"errors"
	"fmt"
	"regexp"
)

// the version string lives in libcrypto's .rodata, libssl.so.3 has none
var versionRegexp = regexp.MustCompile(`OpenSSL (\d+\.\d+\.\d+)`)

// Offset holds the per-version, per-architecture struct offsets the secrets
// uprobe reads. Version, ClientRandom, Session and the traffic secrets are
// offsets into SSL_CONNECTION; MasterKey and MasterKeyLength are offsets into
// SSL_SESSION. Type is the SSL type field (SSL_TYPE_SSL_CONNECTION vs the QUIC
// types) and sits inside the embedded ssl_st base. SSLConnection is the delta
// from the SSL * the public API hands out to the SSL_CONNECTION: subtract it
// from the SSL * before applying the other offsets. For OpenSSL >= 3.2 the
// embedded base is the first member, so the delta is zero.
type Offset struct {
	Type                   uint64
	Version                uint64
	ClientRandom           uint64
	Session                uint64
	MasterKey              uint64
	MasterKeyLength        uint64
	ClientAppTrafficSecret uint64
	ServerAppTrafficSecret uint64
	SSLConnection          uint64
}

// read the "OpenSSL x.y.z" string from libcrypto's .rodata and return the version
func DetectVersion(libcryptoPath string) (version string, err error) {
	file, openErr := elf.Open(libcryptoPath)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrOpenLibrary, libcryptoPath, err)
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	section := file.Section(".rodata")

	if section == nil {
		err = fmt.Errorf("%w: %s", ErrNoRodata, libcryptoPath)
		return
	}

	data, readErr := section.Data()

	if err = readErr; err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrReadRodata, libcryptoPath, err)
		return
	}

	match := versionRegexp.FindSubmatch(data)

	if match == nil {
		err = fmt.Errorf("%w: %s", ErrNoVersion, libcryptoPath)
		return
	}

	version = string(match[1])
	return
}

// pick the offsets for a detected version, with an error that names the make command
func GetOffset(version string) (offset Offset, err error) {
	var ok bool

	if offset, ok = offsets[version]; !ok {
		err = fmt.Errorf("%w: %s, run make generate-openssl-offsets OPENSSL_VERSIONS=openssl-%s", ErrUnknownVersion, version, version)
		return
	}

	return
}
