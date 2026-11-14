#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

# usage: tools/offsetgen/offsetgen.sh all > internal/tls/openssl/offsets_gen.go
#        tools/offsetgen/offsetgen.sh openssl-3.6.2 [openssl-3.5.4 ...] > internal/tls/openssl/offsets_gen.go
#
# "all" is every OpenSSL 3.x and 4.x release tag of the upstream repository;
# alpha, beta and other pre-release tags are skipped. 4.x (libssl.so.4) keeps
# the 3.2+ SSL_CONNECTION layout with other offsets, so one probe serves both. For each release: download the
# release tarball and its .sha256 once into the cache (OPENSSL_CACHE, default
# ~/.cache/decerter-openssl), check the SHA-256, then for amd64 and arm64 configure
# it (linux-x86_64 / linux-aarch64), generate the internal headers, compile
# tools/offsetgen/openssl_offset.c against the release's own ssl/ssl_local.h
# with clang --target and read the offsets from the assembly, so nothing is run
# for the other architecture. The arm64 compile needs the aarch64 glibc headers
# (ARM64_SYSROOT, default /usr/aarch64-linux-gnu, Debian's
# libc6-dev-arm64-cross), the amd64 one the host's or AMD64_SYSROOT.
#
# The table groups the releases of one x.y series whose offsets are equal into
# ranges; a range only spans releases that follow each other in the release
# list, so every version inside a range was probed. A tag without a release
# (3.0.6 was withdrawn and has no tarball) is no release: "all" skips it and
# names it in the table, and the range around it covers it. OpenSSL sources are
# never vendored; the work trees live under a temp dir that is removed on exit.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
probe="${here}/openssl_offset.c"
repo="${OPENSSL_REPO:-https://github.com/openssl/openssl.git}"
download="${OPENSSL_DOWNLOAD:-https://github.com/openssl/openssl/releases/download}"
cache="${OPENSSL_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/decerter-openssl}"
clang="${CLANG:-clang}"
jobs="${OFFSETGEN_JOBS:-$(nproc)}"
release_pattern='^openssl-[34]\.[0-9]+\.[0-9]+$'

# the headers clang compiles the probe with: a sysroot's include dir, or the host's own for the host architecture
include_flags() {
	local arch="$1" triple="$2" sysroot="$3" host

	host="$(uname -m)"

	if [[ -z "${sysroot}" ]] && [[ "${host}" == "${triple%%-*}" ]]
	then
		return
	fi

	sysroot="${sysroot:-/usr/${triple}}"

	if [[ ! -f "${sysroot}/include/stdlib.h" ]]
	then
		echo "offsetgen: no ${arch} glibc headers in ${sysroot}/include, install the cross headers (Debian: libc6-dev-${arch}-cross) or set ${arch^^}_SYSROOT" >&2
		return 1
	fi

	printf '%s\n' -nostdlibinc -isystem "${sysroot}/include"
}

# download the tarball of one release into the cache once and check it against the published SHA-256, returns 2 when the tag has no release
fetch() {
	local tag="$1" tarball="${cache}/${1}.tar.gz" expected actual status

	if [[ ! -f "${tarball}.sha256" ]]
	then
		status="$(curl --silent --show-error --location --output "${tarball}.sha256.part" --write-out '%{http_code}' "${download}/${tag}/${tag}.tar.gz.sha256")"

		# a tag without a release, like the withdrawn 3.0.6, is no release
		if [[ "${status}" == "404" ]]
		then
			rm -f "${tarball}.sha256.part"
			return 2
		fi

		if [[ "${status}" != "200" ]]
		then
			echo "offsetgen: ${tag}.tar.gz.sha256 download failed with HTTP ${status}" >&2
			rm -f "${tarball}.sha256.part"
			return 1
		fi

		mv "${tarball}.sha256.part" "${tarball}.sha256"
	fi

	if [[ ! -f "${tarball}" ]]
	then
		curl --fail --silent --show-error --location --output "${tarball}.part" "${download}/${tag}/${tag}.tar.gz"
		mv "${tarball}.part" "${tarball}"
	fi

	# the .sha256 file holds the hash, older ones also the file name
	expected="$(awk '{ print $1; exit }' "${tarball}.sha256")"
	actual="$(sha256sum "${tarball}" | awk '{ print $1 }')"

	if [[ "${expected}" != "${actual}" ]]
	then
		echo "offsetgen: ${tag}.tar.gz has SHA-256 ${actual}, the release says ${expected}, remove it from ${cache} to download it again" >&2
		return 1
	fi
}

# configure one release for one architecture and print one line: version architecture name=value ...
probe_release() {
	local tag="$1" arch="$2" work="$3" target triple sysroot src flags_text flags

	case "${arch}" in
	amd64) target=linux-x86_64; triple=x86_64-linux-gnu; sysroot="${AMD64_SYSROOT:-}" ;;
	arm64) target=linux-aarch64; triple=aarch64-linux-gnu; sysroot="${ARM64_SYSROOT:-}" ;;
	*) echo "offsetgen: unknown architecture ${arch}" >&2; return 1 ;;
	esac

	# an assignment, so a missing sysroot stops the script
	flags_text="$(include_flags "${arch}" "${triple}" "${sysroot}")"
	flags=()

	if [[ -n "${flags_text}" ]]
	then
		mapfile -t flags <<< "${flags_text}"
	fi
	src="${work}/${tag}-${arch}"
	mkdir -p "${src}"
	tar -xzf "${cache}/${tag}.tar.gz" -C "${src}" --strip-components 1
	# no-shared no-tests keeps the configure fast; the layout the probe reads is
	# the default one, the distribution libraries are checked against it by the
	# distro e2e test (see README.md)
	if ! (cd "${src}" && CC="${clang}" ./Configure "${target}" no-shared no-tests && make -s build_generated) > "${src}.log" 2>&1
	then
		cat "${src}.log" >&2
		return 1
	fi

	"${clang}" --target="${triple}" -std=gnu11 -O2 -S -o "${src}/probe.s" -I"${src}" -I"${src}/include" "${flags[@]}" "${probe}"
	# x86_64 emits .quad, aarch64 .xword for the 8 byte constants, a zero may come as .zero 8
	awk -v tag="${tag}" -v arch="${arch}" '
		/^decerter_offset_[a-z0-9_]+:/ { name = substr($1, 17, length($1) - 17); next }
		name != "" && ($1 == ".quad" || $1 == ".xword") { value[name] = $2; order[++count] = name; name = ""; next }
		name != "" && $1 == ".zero" { value[name] = 0; order[++count] = name; name = ""; next }
		END {
			version = value["version_major"] "." value["version_minor"] "." value["version_patch"]

			if ("openssl-" version != tag) { print "offsetgen: " tag " probe says version " version > "/dev/stderr"; exit 1 }

			line = version " " arch

			for (index_ = 1; index_ <= count; index_++) {
				if (order[index_] !~ /^version_(major|minor|patch)$/) { line = line " " order[index_] "=" value[order[index_]] }
			}

			print line
		}' "${src}/probe.s"
	rm -rf "${src}" "${src}.log"
}

# the probe of one release, run in parallel by xargs: fetch, then both architectures into the result file
if [[ "${1:-}" == "--probe" ]]
then
	tag="$2"
	work="$3"
	status=0
	fetch "${tag}" || status=$?

	if [[ "${status}" == 2 ]]
	then
		touch "${work}/${tag}.withdrawn"
		exit 0
	fi

	if [[ "${status}" != 0 ]]
	then
		exit 1
	fi

	for arch in amd64 arm64
	do
		probe_release "${tag}" "${arch}" "${work}"
	done > "${work}/${tag}.offsets"

	exit 0
fi

mkdir -p "${cache}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# every final 3.x and 4.x release in version order, the ranges are checked against it
git ls-remote --tags --refs "${repo}" 'refs/tags/openssl-3.*' 'refs/tags/openssl-4.*' | awk '{ sub("refs/tags/", "", $2); print $2 }' | grep -E "${release_pattern}" | sort -V > "${work}/releases"

if [[ "$*" == "all" ]]
then
	cp "${work}/releases" "${work}/tags"
else
	for tag in "$@"
	do
		if ! grep -qxF "${tag}" "${work}/releases"
		then
			echo "offsetgen: ${tag} is not an OpenSSL 3.x or 4.x release tag (pre-releases are skipped)" >&2
			exit 1
		fi

		echo "${tag}"
	done | sort -uV > "${work}/tags"
fi

xargs -P "${jobs}" -I '{}' "${BASH_SOURCE[0]}" --probe '{}' "${work}" < "${work}/tags"
withdrawn=()

while read -r tag
do
	if [[ -f "${work}/${tag}.withdrawn" ]]
	then
		withdrawn+=("${tag#openssl-}")
		continue
	fi

	cat "${work}/${tag}.offsets"
	echo "${tag}" >> "${work}/probed"
done < "${work}/tags" > "${work}/offsets"

if [[ "$*" != "all" ]] && [[ "${#withdrawn[@]}" != 0 ]]
then
	echo "offsetgen: no release tarball for ${withdrawn[*]}" >&2
	exit 1
fi

# a withdrawn tag is no release: the releases around it follow each other, so a range may span it
grep -vxF -f <(printf 'openssl-%s\n' "${withdrawn[@]}") "${work}/releases" > "${work}/released" || true

printf '// SPDX-License-Identifier: AGPL-3.0-only\n\n'
printf '// Code generated by tools/offsetgen; DO NOT EDIT.\n\n'
printf 'package openssl\n\n'
printf '// %s releases from %s to %s, each range spans the releases from First to Last that follow each other\n' "$(wc -l < "${work}/probed")" "$(head -n 1 "${work}/probed" | cut -c 9-)" "$(tail -n 1 "${work}/probed" | cut -c 9-)"

if [[ "${#withdrawn[@]}" != 0 ]]
then
	printf '// tags without a release (withdrawn), not probed: %s\n' "${withdrawn[*]}"
fi

printf 'var offsets = map[string][]offsetRange{\n'

for arch in amd64 arm64
do
	printf '\t"%s": {\n' "${arch}"
	# one range per run of releases with the same x.y and offsets that follow each other in the release list
	awk -v arch="${arch}" '
		FILENAME == ARGV[1] { position[substr($1, 9)] = FNR; next }
		$2 != arch { next }
		{
			split($1, part, ".")
			series = part[1] "." part[2]
			offsets = ""

			for (field = 3; field <= NF; field++) { offsets = offsets " " $field }

			if ((first != "") && ((series != last_series) || (offsets != last_offsets) || (position[$1] != position[last] + 1))) { flush() }

			if (first == "") { first = $1; fields = offsets }

			last = $1
			last_series = series
			last_offsets = offsets
		}
		function flush(   count, pair, field, name) {
			printf "\t\t{\n\t\t\tFirst: \"%s\",\n\t\t\tLast: \"%s\",\n\t\t\tOffset: Offset{\n", first, last
			count = split(substr(fields, 2), pair, " ")

			for (field = 1; field <= count; field++) {
				split(pair[field], name, "=")

				if (name[1] == "has_type") { printf "\t\t\t\t%s: %s,\n", camel(name[1]), (name[2] == 1) ? "true" : "false" }
				else { printf "\t\t\t\t%s: 0x%x,\n", camel(name[1]), name[2] }
			}

			printf "\t\t\t},\n\t\t},\n"
			first = ""
		}
		# the Go field names of the probe names, ssl_connection is an initialism
		function camel(name,   count, word, result, index_) {
			if (name == "ssl_connection") { return "SSLConnection" }

			count = split(name, word, "_")
			result = ""

			for (index_ = 1; index_ <= count; index_++) { result = result toupper(substr(word[index_], 1, 1)) substr(word[index_], 2) }

			return result
		}
		END { if (first != "") { flush() } }' "${work}/released" "${work}/offsets"
	printf '\t},\n'
done

printf '}\n'
