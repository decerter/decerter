#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

# usage: ANDROID_NDK=<ndk dir> tools/offsetgen/boringssl.sh conscrypt 15 [16 ...] > internal/tls/boringssl/offsets_gen.go
#        ANDROID_NDK=<ndk dir> tools/offsetgen/boringssl.sh flutter all|3.35.7 [3.50.0 ...] > internal/tls/boringssl/flutter_offsets_gen.go
#        ANDROID_NDK=<ndk dir> tools/offsetgen/boringssl.sh chrome [branches] [126.0.6452.4 160.0.8161.0@<commit> ...] > internal/tls/boringssl/chromium_offsets_gen.go
#
# Both modes compile tools/offsetgen/boringssl_offset.cc against the internal
# headers of one BoringSSL revision with the NDK's clang for x86_64 and
# aarch64 Android (bionic, libc++), and read the offsets from the assembly, so
# nothing is run for the other architecture. BoringSSL sources are never
# vendored.
#
# conscrypt: for each Android release, the android<release>-release branch of
# platform/external/boringssl, the BoringSSL Conscrypt is built from (its
# sources are under src/), picked by ro.build.version.release on the device.
#
# flutter: for each Flutter stable release ("all" is every x.y.z tag of
# flutter/flutter from FLUTTER_MIN_VERSION on, default 3.24.0): the engine
# revision from bin/internal/engine.version, and from the engine's DEPS (the
# flutter/flutter root since the monorepo, flutter/engine before) the Dart SDK
# revision and dart_boringssl_rev, the BoringSSL the engine builds into
# libflutter.so and dart:io's SecureSocket uses (it mirrors boringssl_rev of
# the Dart SDK's own DEPS). The Dart version is the one the Dart VM prints,
# made from the Dart SDK's tools/VERSION; decerter reads it from libflutter.so and
# picks the offsets by it. A Dart version pinned to two BoringSSL revisions
# fails the run. Revisions are fetched shallow into BORINGSSL_CACHE (default
# ~/.cache/decerter-boringssl) once; the table groups the revisions with equal
# offsets.
#
# chrome: Chrome, WebView and Cronet build BoringSSL from chromium/src's DEPS
# variable boringssl_revision. "branches" is, for every milestone from
# CHROME_MIN_MILESTONE (default 124) on, the release branch MAJOR.0.BUILD with
# the most version tags of chromium/src (the one stable, beta and the Play
# builds come from), with all its tags; a version given on its own (a Cronet
# built from a trunk build, for example) adds just that version. The DEPS of
# the first and the last tag of a branch are read through gitiles; when they
# differ the tags in between are bisected, so a BoringSSL roll on the branch
# gives two ranges of patch numbers. A build of a commit without a tag of its
# own (a chromium-browser-snapshots build) is given as version@commit. decerter reads the version from the library
# (Chrome/<version> of the user agent, or the libcronet.<version>.so name) and
# picks the offsets by branch and patch number. DEPS answers are cached in
# CHROMIUM_CACHE (default ~/.cache/decerter-chromium/deps).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
probe="${here}/boringssl_offset.cc"
android_repo="${BORINGSSL_REPO:-https://android.googlesource.com/platform/external/boringssl}"
upstream_repo="${BORINGSSL_UPSTREAM:-https://boringssl.googlesource.com/boringssl}"
flutter_repo="${FLUTTER_REPO:-https://github.com/flutter/flutter}"
raw="${GITHUB_RAW:-https://raw.githubusercontent.com}"
cache="${BORINGSSL_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/decerter-boringssl}"
minimum="${FLUTTER_MIN_VERSION:-3.24.0}"
chromium_repo="${CHROMIUM_REPO:-https://chromium.googlesource.com/chromium/src}"
chromium_cache="${CHROMIUM_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/decerter-chromium/deps}"
chrome_minimum="${CHROME_MIN_MILESTONE:-124}"
ndk="${ANDROID_NDK:?set ANDROID_NDK to an Android NDK directory}"
# the API level only picks the bionic headers, the structs the probe reads have no libc types
api="${ANDROID_API:-35}"
clang="${ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# the offsets of one checkout as "arch version version_in_s3 s3 client_random" lines, amd64 then arm64; root is where ssl/internal.h is
probe_offsets() {
	local root="$1" name="$2" arch

	for arch in amd64:x86_64 arm64:aarch64
	do
		# x86_64 emits .quad, aarch64 .xword for the 8 byte constants
		"${clang}" --target="${arch#*:}-linux-android${api}" -std=c++17 -O2 -Wno-invalid-offsetof -S -o "${work}/${name}-${arch%%:*}.s" -I"${root}" -I"${root}/include" "${probe}"
		awk -v arch="${arch%%:*}" '
			/^decerter_offset_[a-z0-9_]+:/ { name = substr($1, 17, length($1) - 17); next }
			name != "" && ($1 == ".quad" || $1 == ".xword") { value[name] = $2; name = "" }
			END {
				if (!("version" in value) || !("version_in_s3" in value) || !("s3" in value) || !("client_random" in value)) { exit 1 }
				printf "%s %d %d %d %d\n", arch, value["version"], value["version_in_s3"], value["s3"], value["client_random"]
			}' "${work}/${name}-${arch%%:*}.s"
	done
}

# one Offset literal from a probe line
offset_literal() {
	local arch version in_s3 s3 client_random

	read -r arch version in_s3 s3 client_random <<< "$1"
	printf '{Version: 0x%x, VersionInS3: %s, S3: 0x%x, ClientRandom: 0x%x}' "${version}" "$( ((in_s3 == 1)) && echo true || echo false)" "${s3}" "${client_random}"
}

conscrypt() {
	local release src line

	printf '// SPDX-License-Identifier: AGPL-3.0-only\n\n'
	printf '// Code generated by tools/offsetgen; DO NOT EDIT.\n\n'
	printf 'package boringssl\n\n'
	printf 'var offsets = map[string]map[string]Offset{\n'

	for release in "$@"
	do
		src="${work}/${release}"
		git clone --quiet --depth 1 --branch "android${release}-release" "${android_repo}" "${src}"
		printf '\t"%s": {\n' "${release}"

		while read -r line
		do
			printf '\t\t"%s": %s,\n' "${line%% *}" "$(offset_literal "${line}")"
		done < <(probe_offsets "${src}/src" "${release}")

		printf '\t},\n'
	done

	printf '}\n'
}

# a file of a GitHub repository at a revision, fails on a missing file
fetch_raw() {
	curl -sSfL "${raw}/$1/$2/$3"
}

# the value of a DEPS variable: 'name': 'value',
deps_variable() {
	sed -n -E "s/^[[:space:]]*'$1':[[:space:]]*'([^']+)',.*/\1/p" | head -n 1
}

# the version string the Dart VM prints, from tools/VERSION: x.y.z on stable, x.y.z-prerelease.patch.channel otherwise
dart_version() {
	awk '
		{ value[$1] = $2 }
		END {
			version = value["MAJOR"] "." value["MINOR"] "." value["PATCH"]
			if ((value["CHANNEL"] != "stable") || (value["PRERELEASE"] != 0) || (value["PRERELEASE_PATCH"] != 0)) {
				version = version "-" value["PRERELEASE"] "." value["PRERELEASE_PATCH"] "." value["CHANNEL"]
			}
			print version
		}'
}

# every stable x.y.z tag of flutter/flutter from the minimum on, in version order
flutter_releases() {
	git ls-remote --tags --refs "${flutter_repo}" | sed -n -E 's#.*refs/tags/([0-9]+\.[0-9]+\.[0-9]+)$#\1#p' | sort -t . -k1,1n -k2,2n -k3,3n | awk -v minimum="${minimum}" '
		BEGIN { split(minimum, low, ".") }
		{
			split($0, current, ".")
			for (index_ = 1; index_ <= 3; index_++) {
				if ((current[index_] + 0) > (low[index_] + 0)) { print; next }
				if ((current[index_] + 0) < (low[index_] + 0)) { next }
			}
			print
		}'
}

# a BoringSSL revision in the cache, fetched once
fetch_revision() {
	local revision="$1" directory="${cache}/$1"

	if [[ -f "${directory}/ssl/internal.h" ]]
	then
		return
	fi

	rm -rf "${directory}"
	mkdir -p "${directory}"
	git -C "${directory}" init --quiet
	git -C "${directory}" fetch --quiet --depth 1 "${upstream_repo}" "${revision}"
	git -C "${directory}" checkout --quiet FETCH_HEAD
}

flutter() {
	local versions=("$@") version engine deps dart_revision boringssl dart revision line releases=() revisions=() group key

	if [[ "${versions[*]}" == "all" ]]
	then
		mapfile -t versions < <(flutter_releases)
	fi

	declare -A dart_boringssl=() dart_flutter=() dart_engines=() offsets=() groups=()

	for version in "${versions[@]}"
	do
		engine="$(fetch_raw flutter/flutter "${version}" bin/internal/engine.version | tr -d '[:space:]')"
		# the engine moved into flutter/flutter (the monorepo) in early 2025, before it has its own repository
		deps="$(fetch_raw flutter/flutter "${version}" DEPS 2>/dev/null || fetch_raw flutter/engine "${engine}" DEPS)"
		dart_revision="$(deps_variable dart_revision <<< "${deps}")"
		boringssl="$(deps_variable dart_boringssl_rev <<< "${deps}")"

		if [[ -z "${dart_revision}" ]] || [[ -z "${boringssl}" ]]
		then
			echo "boringssl.sh: Flutter ${version}: no dart_revision or dart_boringssl_rev in the DEPS of engine ${engine}" >&2
			return 1
		fi

		dart="$(fetch_raw dart-lang/sdk "${dart_revision}" tools/VERSION | dart_version)"

		if [[ -n "${dart_boringssl[${dart}]:-}" ]] && [[ "${dart_boringssl[${dart}]}" != "${boringssl}" ]]
		then
			echo "boringssl.sh: Dart ${dart} has two BoringSSL revisions, ${dart_boringssl[${dart}]} and ${boringssl} (Flutter ${version}), it can't pick the offsets" >&2
			return 1
		fi

		if [[ -z "${dart_boringssl[${dart}]:-}" ]]
		then
			releases+=("${dart}")
		fi

		dart_boringssl["${dart}"]="${boringssl}"
		dart_flutter["${dart}"]="${dart_flutter[${dart}]:-}${dart_flutter[${dart}]:+ }${version}"

		if [[ " ${dart_engines[${dart}]:-} " != *" ${engine} "* ]]
		then
			dart_engines["${dart}"]="${dart_engines[${dart}]:-}${dart_engines[${dart}]:+ }${engine}"
		fi

		echo "boringssl.sh: Flutter ${version}: engine ${engine}, Dart ${dart}, BoringSSL ${boringssl}" >&2
	done

	for dart in "${releases[@]}"
	do
		revision="${dart_boringssl[${dart}]}"

		if [[ -n "${offsets[${revision}]:-}" ]]
		then
			continue
		fi

		fetch_revision "${revision}"
		offsets["${revision}"]="$(probe_offsets "${cache}/${revision}" "${revision}" | tr '\n' ';')"
		revisions+=("${revision}")
		groups["${offsets[${revision}]}"]="${groups[${offsets[${revision}]}]:-}${groups[${offsets[${revision}]}]:+ }${revision}"
	done

	printf '// SPDX-License-Identifier: AGPL-3.0-only\n\n'
	printf '// Code generated by tools/offsetgen; DO NOT EDIT.\n\n'
	printf 'package boringssl\n\n'
	printf '// %d Flutter releases from %s to %s, %d Dart versions, %d BoringSSL revisions, %d offset sets\n' "${#versions[@]}" "${versions[0]}" "${versions[-1]}" "${#releases[@]}" "${#revisions[@]}" "${#groups[@]}"
	printf 'var dartReleases = map[string]dartRelease{\n'

	for dart in "${releases[@]}"
	do
		printf '\t"%s": {\n' "${dart}"
		printf '\t\tRevision: "%s",\n' "${dart_boringssl[${dart}]}"
		printf '\t\tFlutter:  []string{"%s"},\n' "$(sed 's/ /", "/g' <<< "${dart_flutter[${dart}]}")"
		printf '\t\tEngines:  []string{"%s"},\n' "$(sed 's/ /", "/g' <<< "${dart_engines[${dart}]}")"
		printf '\t},\n'
	done

	printf '}\n\n'
	printf '// the BoringSSL revisions with equal offsets, in the order of their first Dart version\n'
	printf 'var revisionOffsets = []revisionOffset{\n'

	for revision in "${revisions[@]}"
	do
		key="${offsets[${revision}]}"
		group="${groups[${key}]:-}"

		# a group is printed at its first revision
		if [[ -z "${group}" ]]
		then
			continue
		fi

		unset "groups[${key}]"
		printf '\t{\n'
		printf '\t\tRevisions: []string{"%s"},\n' "$(sed 's/ /", "/g' <<< "${group}")"
		printf '\t\tOffsets: map[string]Offset{\n'

		while read -r -d ';' line
		do
			printf '\t\t\t"%s": %s,\n' "${line%% *}" "$(offset_literal "${line}")"
		done <<< "${key}"

		printf '\t\t},\n'
		printf '\t},\n'
	done

	printf '}\n'
}

# the boringssl_revision of a chromium/src tag, or of a commit for version@commit, from its DEPS through gitiles (base64 with format=TEXT),
# cached per version
chromium_boringssl() {
	local version="$1" file="${chromium_cache}/$1" reference="refs/tags/$1" revision

	if [[ -n "${commits[$1]:-}" ]]
	then
		reference="${commits[$1]}"
		file="${chromium_cache}/$1@${commits[$1]}"
	fi

	if [[ ! -s "${file}" ]]
	then
		mkdir -p "${chromium_cache}"
		revision="$(curl -sSfL "${chromium_repo}/+/${reference}/DEPS?format=TEXT" | base64 -d | deps_variable boringssl_revision)"

		if [[ ! "${revision}" =~ ^[0-9a-f]{40}$ ]]
		then
			echo "boringssl.sh: Chromium ${version}: no boringssl_revision in the DEPS of ${reference}" >&2
			return 1
		fi

		echo "${revision}" > "${file}"
	fi

	cat "${file}"
}

# the patch number ranges of one branch with the same BoringSSL as "first last revision" lines, from the sorted patch numbers in patches;
# the ends are read, a range whose ends differ is split in the middle until each range has one revision at both ends
chromium_ranges() {
	local branch="$1" low="$2" high="$3" low_revision high_revision middle

	low_revision="$(chromium_boringssl "${branch}.${patches[${low}]}")"
	high_revision="$(chromium_boringssl "${branch}.${patches[${high}]}")"

	if [[ "${low_revision}" == "${high_revision}" ]]
	then
		echo "${patches[${low}]} ${patches[${high}]} ${low_revision}"
		return
	fi

	if ((high == low + 1))
	then
		echo "${patches[${low}]} ${patches[${low}]} ${low_revision}"
		echo "${patches[${high}]} ${patches[${high}]} ${high_revision}"
		return
	fi

	middle=$(((low + high) / 2))
	chromium_ranges "${branch}" "${low}" "${middle}"
	chromium_ranges "${branch}" "${middle}" "${high}"
}

# adjacent ranges with the same revision as one, the bisection gives the middle tag to both halves
merge_ranges() {
	awk '
		{
			if ((count > 0) && (revision[count] == $3)) { last[count] = $2; next }
			count++; first[count] = $1; last[count] = $2; revision[count] = $3
		}
		END { for (index_ = 1; index_ <= count; index_++) { print first[index_], last[index_], revision[index_] } }'
}

chrome() {
	local arguments=("$@") tags argument branch major version line revisions=() revision key group first last count=0 branches=()
	local -a patches

	declare -A branch_ranges=() offsets=() groups=() covered=()
	# version@commit: a build of a commit between two tags, a snapshot
	declare -A commits=()
	tags="$(git ls-remote --tags --refs "${chromium_repo}" 'refs/tags/[0-9]*.0.*' | sed -n -E 's#.*refs/tags/([0-9]+\.0\.[0-9]+\.[0-9]+)$#\1#p' | sort -t . -k1,1n -k3,3n -k4,4n)"

	for argument in "${arguments[@]}"
	do
		if [[ "${argument}" == "branches" ]]
		then
			# the branch of each milestone: the MAJOR.0.BUILD with the most tags
			while read -r branch
			do
				branches+=("${branch}")
			done < <(awk -F . -v minimum="${chrome_minimum}" '
				($1 + 0) >= (minimum + 0) { count[$1 "." $2 "." $3]++ }
				END {
					for (branch in count) {
						split(branch, part, ".")
						if (count[branch] > best_count[part[1]]) { best_count[part[1]] = count[branch]; best[part[1]] = branch }
					}
					for (major in best) { if (best_count[major] > 1) { print best[major] } }
				}' <<< "${tags}" | sort -t . -k1,1n)

			continue
		fi

		if [[ "${argument}" =~ ^([0-9]+\.0\.[0-9]+\.[0-9]+)@([0-9a-f]{40})$ ]]
		then
			commits["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
			branches+=("${BASH_REMATCH[1]}")
			continue
		fi

		if [[ ! "${argument}" =~ ^[0-9]+\.0\.[0-9]+\.[0-9]+$ ]] || ! grep -q -x -F "${argument}" <<< "${tags}"
		then
			echo "boringssl.sh: ${argument} is no Chromium version tag of ${chromium_repo}" >&2
			return 1
		fi

		branches+=("${argument}")
	done

	for argument in "${branches[@]}"
	do
		if [[ "${argument}" =~ ^[0-9]+\.0\.[0-9]+$ ]]
		then
			branch="${argument}"
			mapfile -t patches < <(grep -F "${branch}." <<< "${tags}" | awk -F . -v branch="${branch}" '($1 "." $2 "." $3) == branch { print $4 }' | sort -n)
		else
			branch="${argument%.*}"
			patches=("${argument##*.}")
		fi

		if [[ -n "${covered[${argument}]:-}" ]] || [[ -n "${covered[${branch}]:-}" ]]
		then
			continue
		fi

		covered["${argument}"]=1

		if [[ "${argument}" == "${branch}" ]]
		then
			covered["${branch}"]=1
		fi

		while read -r first last revision
		do
			branch_ranges["${branch}"]="${branch_ranges[${branch}]:-}${first} ${last} ${revision};"
			count=$((count + 1))
			echo "boringssl.sh: Chromium ${branch}.${first} to ${branch}.${last}: BoringSSL ${revision}" >&2

			if [[ -n "${offsets[${revision}]:-}" ]]
			then
				continue
			fi

			fetch_revision "${revision}"
			offsets["${revision}"]="$(probe_offsets "${cache}/${revision}" "${revision}" | tr '\n' ';')"
			revisions+=("${revision}")
			groups["${offsets[${revision}]}"]="${groups[${offsets[${revision}]}]:-}${groups[${offsets[${revision}]}]:+ }${revision}"
		done < <(chromium_ranges "${branch}" 0 $((${#patches[@]} - 1)) | merge_ranges)
	done

	printf '// SPDX-License-Identifier: AGPL-3.0-only\n\n'
	printf '// Code generated by tools/offsetgen; DO NOT EDIT.\n\n'
	printf 'package boringssl\n\n'
	printf '// %d Chromium branches from milestone %s, %d ranges, %d BoringSSL revisions, %d offset sets\n' "${#branch_ranges[@]}" "${chrome_minimum}" "${count}" "${#revisions[@]}" "${#groups[@]}"
	printf 'var chromiumBranches = map[string][]chromiumRange{\n'

	for branch in $(printf '%s\n' "${!branch_ranges[@]}" | sort -t . -k1,1n -k3,3n)
	do
		printf '\t"%s": {\n' "${branch}"

		while read -r -d ';' first last revision
		do
			printf '\t\t{First: %d, Last: %d, Revision: "%s"},\n' "${first}" "${last}" "${revision}"
		done <<< "${branch_ranges[${branch}]}"

		printf '\t},\n'
	done

	printf '}\n\n'
	printf '// the BoringSSL revisions with equal offsets, in the order of their first branch\n'
	printf 'var chromiumRevisionOffsets = []revisionOffset{\n'

	for revision in "${revisions[@]}"
	do
		key="${offsets[${revision}]}"
		group="${groups[${key}]:-}"

		# a group is printed at its first revision
		if [[ -z "${group}" ]]
		then
			continue
		fi

		unset "groups[${key}]"
		printf '\t{\n'
		printf '\t\tRevisions: []string{"%s"},\n' "$(sed 's/ /", "/g' <<< "${group}")"
		printf '\t\tOffsets: map[string]Offset{\n'

		while read -r -d ';' line
		do
			printf '\t\t\t"%s": %s,\n' "${line%% *}" "$(offset_literal "${line}")"
		done <<< "${key}"

		printf '\t\t},\n'
		printf '\t},\n'
	done

	printf '}\n'
}

mode="${1:?usage: boringssl.sh conscrypt <release>... | flutter all|<version>... | chrome [branches] [<version>|<version>@<commit>...]}"
shift

case "${mode}" in
conscrypt)
	conscrypt "$@"
	;;
flutter)
	flutter "$@"
	;;
chrome)
	chrome "$@"
	;;
*)
	echo "boringssl.sh: unknown mode ${mode}, use conscrypt, flutter or chrome" >&2
	exit 1
	;;
esac
