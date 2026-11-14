#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

# usage: tools/bpfdrift/check.sh
#
# make check-bpf-objects calls this. It keeps a copy of the bpf2go output in internal/bpf, runs make generate-bpf-objects
# and compares the result with the copy: the Go files byte for byte, the objects by content with tools/bpfdrift, because
# clang orders the BTF of one source differently when it is built from another path. An object that is the same by
# content gets its committed bytes back, so only real changes are left in the work tree. Needs clang-21, llvm-strip-21
# and the committed bpf/vmlinux.h.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# bpf2go writes bpf_<target>.go and bpf_<target>.o next to the package that generates them
list_output() {
	find internal/bpf -type f \( -name 'bpf_*.go' -o -name 'bpf_*.o' \) | sort
}

list_output > "$work/before"

while IFS= read -r file; do
	mkdir -p "$work/saved/$(dirname "$file")"
	cp "$file" "$work/saved/$file"
done < "$work/before"

"${MAKE:-make}" generate-bpf-objects
list_output > "$work/after"
go build -o "$work/bpfdrift" ./tools/bpfdrift
status=0

if ! diff "$work/before" "$work/after" >&2; then
	echo "make generate-bpf-objects wrote other files than the ones in internal/bpf" >&2
	status=1
fi

while IFS= read -r file; do
	[ -f "$file" ] || continue

	case "$file" in
	*.go)
		if ! cmp -s "$work/saved/$file" "$file"; then
			diff -u "$work/saved/$file" "$file" >&2 || true
			status=1
		fi
		;;
	*.o)
		if "$work/bpfdrift" "$work/saved/$file" "$file"; then
			cp "$work/saved/$file" "$file"
		else
			status=1
		fi
		;;
	esac
done < "$work/before"

if [ "$status" -eq 0 ]; then
	echo "the bpf objects in internal/bpf are what make generate-bpf-objects builds"
else
	echo "the bpf objects in internal/bpf differ from what make generate-bpf-objects builds, the new ones are in the work tree" >&2
fi

exit "$status"
