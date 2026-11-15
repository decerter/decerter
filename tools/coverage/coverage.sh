#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only

# usage: tools/coverage/coverage.sh [unit] [e2e]
#
# make coverage calls this. It runs the unit tests (unit, the default), the Linux e2e tests with sudo (e2e) or both with
# -coverpkg over the whole module, so a test counts for every package it runs, and writes into COVERAGE_DIR (default
# coverage/, gitignored):
#
#   unit.out, e2e.out   the profiles of go test, as it writes them
#   e2e-children.out    the same for the processes the e2e tests run as decerter, counted as e2e
#   merged.out          the profiles of this run together, without the code that is not hand-written
#   functions.txt       go tool cover -func of merged.out, every function with its percentage
#   packages.txt        statements and percentage per package for unit, e2e and both, also printed
#   coverage.html       go tool cover -html of merged.out
#
# Left out of merged.out: the bpf2go output (*_bpfel.go, *_bpfeb.go), the generated offset tables (*_gen.go), the main of
# cmd/decerter, which only calls cmd.Execute, and the helpers under test/. The BPF C programs have no Go coverage, the e2e
# tests cover them. A profile of an earlier run is kept and merged when its suite is not run again, so
# "coverage.sh unit" after "coverage.sh e2e" still reports both. The exit status is the one of the tests.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"
directory="${COVERAGE_DIR:-coverage}"
module="$(go list -m)"
status=0
mkdir -p "$directory"

if [ "$#" -eq 0 ]; then
	set -- unit
fi

for suite in "$@"; do
	case "$suite" in
	unit)
		CGO_ENABLED=1 go test -race -count=1 -tags=unit -covermode=atomic -coverpkg="$module/..." -coverprofile="$directory/unit.out" ./... || status=1
		;;
	e2e)
		# root loads the bpf programs, as in make test-e2e; the profile is handed back to the user who ran sudo
		# the test binary also runs as decerter (decerter mcp, the distro OpenSSL cases, a capture that is stopped): those processes are not in the profile
		# of go test, they write their counters into DECERTER_E2E_COVERDIR, which the test user writes into too
		children="$(mktemp -d)"
		chmod 0777 "$children"
		sudo DECERTER_E2E_COVERDIR="$children" go test -tags=e2e -count=1 -covermode=atomic -coverpkg="$module/..." -coverprofile="$directory/e2e.out" ./test/e2e/ || status=1
		sudo chown -R "$(id -u):$(id -g)" "$directory/e2e.out" "$children" || status=1
		rm -f "$directory/e2e-children.out"

		if [ -n "$(ls -A "$children")" ]; then
			go tool covdata textfmt -i="$children" -o="$directory/e2e-children.out" || status=1
		fi

		rm -rf "$children"
		;;
	*)
		echo "usage: $0 [unit] [e2e]" >&2
		exit 2
		;;
	esac
done

# one profile without the generated code and the mains; go tool cover adds the counts of a block that is listed more than once
filter_profile() {
	grep -h -v -E '^mode:|(_bpfel|_bpfeb|_gen)\.go:|^'"$module"'/(cmd/decerter|test)/' "$@" || true
}

profiles=()

for suite in unit e2e e2e-children; do
	if [ -s "$directory/$suite.out" ]; then
		profiles+=("$directory/$suite.out")
	fi
done

if [ "${#profiles[@]}" -eq 0 ]; then
	echo "no coverage profile in $directory" >&2
	exit 1
fi

{
	echo "mode: atomic"
	filter_profile "${profiles[@]}"
} > "$directory/merged.out"

go tool cover -func="$directory/merged.out" > "$directory/functions.txt" || status=1
go tool cover -html="$directory/merged.out" -o "$directory/coverage.html" || status=1

# statements per package: a block counts once, covered when any profile ran it
{
	for suite in unit e2e e2e-children; do
		if [ -s "$directory/$suite.out" ]; then
			filter_profile "$directory/$suite.out" | sed "s|^|${suite%-children} |"
		fi
	done
} | awk -v module="$module/" '
{
	suite = $1
	suites[suite] = 1
	block = $2
	statements = $3
	count = $4
	file = block
	sub(/:[^:]*$/, "", file)
	directory = file
	sub(/\/[^\/]*$/, "", directory)
	sub(module, "", directory)

	if (!(block in total)) {
		total[block] = statements
		packages[directory] += statements
		all += statements
	}

	if (count > 0) {
		if (!((suite, block) in covered)) {
			covered[suite, block] = 1
			suiteCovered[suite, directory] += statements
			suiteAll[suite] += statements
		}

		if (!(block in mergedBlock)) {
			mergedBlock[block] = 1
			mergedCovered[directory] += statements
			mergedAll += statements
		}
	}
}

function percent(part, whole) {
	return (whole == 0) ? "-" : sprintf("%5.1f%%", 100 * part / whole)
}

# a suite that was not run has no column to fill
function suitePercent(suite, part, whole) {
	return (suite in suites) ? percent(part, whole) : "-"
}

END {
	printf "%-28s %10s %7s %7s %7s\n", "package", "statements", "unit", "e2e", "merged"

	for (name in packages) {
		printf "%-28s %10d %7s %7s %7s\n", name, packages[name], suitePercent("unit", suiteCovered["unit", name], packages[name]), suitePercent("e2e", suiteCovered["e2e", name], packages[name]), percent(mergedCovered[name], packages[name]) | "sort"
	}

	close("sort")
	printf "%-28s %10d %7s %7s %7s\n", "total", all, suitePercent("unit", suiteAll["unit"], all), suitePercent("e2e", suiteAll["e2e"], all), percent(mergedAll, all)
}' | tee "$directory/packages.txt"

echo "coverage report: $directory/packages.txt, $directory/functions.txt, $directory/coverage.html"
exit "$status"
