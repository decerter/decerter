#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

# usage: VERSION=v0.1.0 LDFLAGS="…" SOURCE_DATE_EPOCH=… tools/release/release.sh
#
# make release calls this with the version, the -ldflags of the build and the commit time. For linux/amd64 and
# linux/arm64 it builds the static binary (-trimpath, -buildvcs=false, no build id), writes the THIRD_PARTY_NOTICES
# of that binary's dependencies with go-licenses (the full license texts, per architecture since their dependencies
# could differ), and packs decerter_<version>_linux_<arch>.tar.gz in DIST (default dist) with one top-level directory:
# decerter, LICENSE, LICENSE-Go.txt (the BSD license of the Go standard library and of the parts of internal/tlsrecord
# derived from crypto/tls), README.md, THIRD_PARTY_NOTICES, docs/ and api/openapi.yaml. Then SHA256SUMS of both.
#
# The tarballs are reproducible from the same commit and Go toolchain: entries sorted by name, owner and group 0,
# every mtime the commit time, fixed modes, gzip without a name or time stamp.
# A dirty tree is refused unless ALLOW_DIRTY=1, the version then ends in -dirty.
set -euo pipefail

: "${VERSION:?VERSION is not set}"
: "${LDFLAGS:?LDFLAGS is not set}"
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is not set}"
GO_LICENSES="${GO_LICENSES:-$(go env GOPATH)/bin/go-licenses}"
DIST="${DIST:-dist}"
ARCHITECTURES="${ARCHITECTURES:-amd64 arm64}"

cd "$(git rev-parse --show-toplevel)"

# untracked files count too: a stray .go file in a package would be built into the binary
if [ -n "$(git status --porcelain)" ] && [ "${ALLOW_DIRTY:-0}" != 1 ]; then
	echo "the work tree is not clean, commit or stash first (or ALLOW_DIRTY=1 for a test build):" >&2
	git status --short >&2
	exit 1
fi

if [ ! -x "$GO_LICENSES" ]; then
	echo "go-licenses is not at $GO_LICENSES, make install-go-licenses installs it" >&2
	exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$DIST"
tarballs=()

for arch in $ARCHITECTURES; do
	name="decerter_${VERSION}_linux_${arch}"
	directory="$work/$name"
	mkdir -p "$directory/docs" "$directory/api"

	GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -buildvcs=false -tags netgo,osusergo -ldflags="$LDFLAGS" -o "$directory/decerter" ./cmd/decerter

	if ! file "$directory/decerter" | grep -q 'statically linked'; then
		echo "the $arch binary is not statically linked: $(file "$directory/decerter")" >&2
		exit 1
	fi

	# the packages of the binary only, the module itself is AGPL and in LICENSE
	GOOS=linux GOARCH="$arch" CGO_ENABLED=0 GOFLAGS=-tags=netgo,osusergo "$GO_LICENSES" report ./cmd/decerter --ignore github.com/decerter/decerter --template tools/release/notices.tpl > "$directory/THIRD_PARTY_NOTICES" 2> "$work/go-licenses-$arch.log" || {
		cat "$work/go-licenses-$arch.log" >&2
		exit 1
	}

	cp LICENSE README.md "$directory/"
	cp internal/tlsrecord/LICENSE-Go.txt "$directory/LICENSE-Go.txt"
	cp docs/*.md "$directory/docs/"
	cp api/openapi.yaml "$directory/api/"
	find "$directory" -type d -exec chmod 0755 {} +
	find "$directory" -type f -exec chmod 0644 {} +
	chmod 0755 "$directory/decerter"

	tar --create --format=gnu --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" --directory "$work" "$name" | gzip -9 -n > "$DIST/$name.tar.gz"
	tarballs+=("$name.tar.gz")
	echo "$DIST/$name.tar.gz"
done

(cd "$DIST" && sha256sum "${tarballs[@]}" > SHA256SUMS)
echo "$DIST/SHA256SUMS"
