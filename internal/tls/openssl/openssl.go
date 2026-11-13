// SPDX-License-Identifier: AGPL-3.0-only

package openssl

import (
	"debug/elf"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// the version string lives in libcrypto's .rodata, libssl.so.3 has none
var versionRegexp = regexp.MustCompile(`OpenSSL (\d+\.\d+\.\d+)`)

// Offset holds the per-version, per-architecture struct offsets the secrets
// uprobe reads. Version, ClientRandom, Session, the traffic secrets, the
// handshake secret and the handshake traffic hash are offsets into
// SSL_CONNECTION (the SSL itself up to 3.1); MasterKey, MasterKeyLength and
// SessionCipher are offsets into SSL_SESSION; CipherId is the offset of the id
// field inside SSL_CIPHER, the cipher SessionCipher points at. Type is the SSL
// type field (SSL_TYPE_SSL_CONNECTION vs the QUIC types) and sits inside the
// embedded ssl_st base; HasType is false up to 3.1, which has neither the field
// nor QUIC objects. SSLConnection is the delta from the SSL * the public API
// hands out to the SSL_CONNECTION: subtract it from the SSL * before applying
// the other offsets. From 3.2 on the embedded base is the first member, so the
// delta is zero. HandshakeSecret and HandshakeTrafficHash let Go derive the
// handshake traffic secrets with HKDF-Expand-Label, which TLS 1.3 does not
// store in the connection; tshark decrypts no TLS 1.3 stream without them.
type Offset struct {
	HasType                bool
	Type                   uint64
	SSLConnection          uint64
	Version                uint64
	ClientRandom           uint64
	Session                uint64
	MasterKey              uint64
	MasterKeyLength        uint64
	ClientAppTrafficSecret uint64
	ServerAppTrafficSecret uint64
	HandshakeSecret        uint64
	HandshakeTrafficHash   uint64
	SessionCipher          uint64
	CipherId               uint64
}

// the releases First to Last of one x.y series share these offsets, every release in between was probed
type offsetRange struct {
	First  string
	Last   string
	Offset Offset
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

// pick the offsets for a detected version on an architecture, an unknown version names the nearest known one and the make command that probes every release
func GetOffset(version string, architecture string) (offset Offset, err error) {
	ranges, ok := offsets[architecture]

	if !ok {
		err = fmt.Errorf("%w: %s", ErrUnknownArchitecture, architecture)
		return
	}

	parsed, parseErr := parseVersion(version)

	if parseErr != nil {
		err = fmt.Errorf("%w: %w on %s", ErrUnknownVersion, parseErr, architecture)
		return
	}

	for _, current := range ranges {
		first := tableVersion(current.First)
		last := tableVersion(current.Last)

		if (slices.Compare(parsed[:], first[:]) >= 0) && (slices.Compare(parsed[:], last[:]) <= 0) {
			offset = current.Offset
			return
		}
	}

	err = fmt.Errorf("%w: %s on %s, the nearest known version is %s, run make generate-openssl-offsets for the newer releases and rebuild", ErrUnknownVersion, version, architecture, nearestVersion(parsed, ranges))
	return
}

// "x.y.z" as three numbers
func parseVersion(version string) (parsed [3]int, err error) {
	parts := strings.Split(version, ".")

	if len(parts) != len(parsed) {
		err = fmt.Errorf("%w: %q", ErrVersionFormat, version)
		return
	}

	for index, part := range parts {
		number, convertErr := strconv.Atoi(part)

		if (convertErr != nil) || (number < 0) {
			err = fmt.Errorf("%w: %q", ErrVersionFormat, version)
			return
		}

		parsed[index] = number
	}

	return
}

// a version of the generated table, which only holds versions parseVersion takes (checked by the table test)
func tableVersion(version string) (parsed [3]int) {
	parsed, _ = parseVersion(version)
	return
}

// the first or last version of a range closest to version, a series counts 1000 patches and a major 1000 series, a tie takes the older one
func nearestVersion(version [3]int, ranges []offsetRange) (nearest string) {
	position := func(parsed [3]int) (value int) {
		value = (parsed[0]*1000+parsed[1])*1000 + parsed[2]
		return
	}
	bestDistance := 0

	for _, current := range ranges {
		for _, candidate := range []string{current.First, current.Last} {
			distance := position(tableVersion(candidate)) - position(version)
			isCloser := max(distance, -distance) < max(bestDistance, -bestDistance)
			isOlderTie := (max(distance, -distance) == max(bestDistance, -bestDistance)) && (distance < bestDistance)

			if (nearest == "") || isCloser || isOlderTie {
				nearest = candidate
				bestDistance = distance
			}
		}
	}

	return
}
