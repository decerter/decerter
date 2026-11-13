#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

# usage: tools/release/version.sh
#
# Prints the version of the work tree for decerter --version and the release tarballs: the form of git describe --tags,
# v0.1.0 on a tag and v0.1.0-3-gabc1234 three commits after it; before the first tag v0.0.0-<n>-g<short hash>, where
# n is the number of commits since the root commit, as git describe would print it with a v0.0.0 tag on the root.
# -dirty is added when a tracked file has uncommitted changes, as git describe --dirty does. Outside a git work tree
# the version is development.
set -euo pipefail

if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
	echo development
	exit 0
fi

if git describe --tags --match 'v[0-9]*' --dirty 2> /dev/null; then
	exit 0
fi

dirty=""
git update-index -q --refresh > /dev/null 2>&1 || true

if ! git diff-index --quiet HEAD --; then
	dirty="-dirty"
fi

echo "v0.0.0-$(($(git rev-list --count HEAD) - 1))-g$(git rev-parse --short HEAD)$dirty"
