// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package scripttest

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// a clang++ that writes the probe's assembly with fixed offsets, or fails for the target prefix in FAKE_CLANG_FAIL, or writes no offsets for the one in FAKE_CLANG_EMPTY
	fakeClang string = `#!/usr/bin/env bash
out=""
target=""
while [[ $# -gt 0 ]]
do
	case "$1" in
	-o) out="$2"; shift ;;
	--target=*) target="${1#--target=}" ;;
	esac
	shift
done
if [[ -n "${FAKE_CLANG_FAIL:-}" ]] && [[ "${target}" == "${FAKE_CLANG_FAIL}"* ]]
then
	exit 1
fi
if [[ -n "${FAKE_CLANG_EMPTY:-}" ]] && [[ "${target}" == "${FAKE_CLANG_EMPTY}"* ]]
then
	: > "${out}"
	exit 0
fi
directive=.quad
if [[ "${target}" == aarch64* ]]
then
	directive=.xword
fi
printf 'decerter_offset_version:\n\t%s\t16\ndecerter_offset_version_in_s3:\n\t%s\t0\ndecerter_offset_s3:\n\t%s\t48\ndecerter_offset_client_random:\n\t%s\t208\n' "${directive}" "${directive}" "${directive}" "${directive}" > "${out}"
`
	amd64Line  string = `"amd64": {Version: 0x10, VersionInS3: false, S3: 0x30, ClientRandom: 0xd0},`
	arm64Line  string = `"arm64": {Version: 0x10, VersionInS3: false, S3: 0x30, ClientRandom: 0xd0},`
	revisionA  string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revisionB  string = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	chromeTag1 string = "130.0.6723.1"
	chromeTag2 string = "130.0.6723.2"
	chromeTag3 string = "130.0.6723.3"
	// a Dart SDK version file of a stable release
	dartVersion string = "CHANNEL stable\nMAJOR 3\nMINOR %s\nPATCH 0\nPRERELEASE 0\nPRERELEASE_PATCH 0\n"
)

// the environment of one run: a fake NDK, a local Conscrypt branch, a local chromium/src with three tags of one branch and the caches
type offsetgenSetup struct {
	directory     string
	environment   []string
	chromiumCache string
}

// newSetup builds the fake NDK, the repositories and the caches in a temporary directory
func newSetup(state *testing.T) (setup offsetgenSetup) {
	state.Helper()
	setup.directory = state.TempDir()
	clang := filepath.Join(setup.directory, "ndk", "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "clang++")
	conscrypt := filepath.Join(setup.directory, "conscrypt")
	chromium := filepath.Join(setup.directory, "chromium")
	boringsslCache := filepath.Join(setup.directory, "boringssl-cache")
	flutter := filepath.Join(setup.directory, "flutter")
	raw := filepath.Join(setup.directory, "raw")
	setup.chromiumCache = filepath.Join(setup.directory, "chromium-cache")
	setup.environment = append(os.Environ(),
		"HOME="+setup.directory,
		"XDG_CACHE_HOME="+setup.directory,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		"ANDROID_NDK="+filepath.Join(setup.directory, "ndk"),
		"BORINGSSL_REPO=file://"+conscrypt,
		"BORINGSSL_CACHE="+boringsslCache,
		"CHROMIUM_REPO=file://"+chromium,
		"CHROMIUM_CACHE="+setup.chromiumCache,
		"CHROME_MIN_MILESTONE=130",
		"FLUTTER_REPO=file://"+flutter,
		"GITHUB_RAW=file://"+raw,
		"FLUTTER_MIN_VERSION=3.24.0",
	)
	writeFile(state, clang, fakeClang, 0o755)
	writeFile(state, filepath.Join(conscrypt, "src", "ssl", "internal.h"), "", 0o644)
	run(state, setup.environment, conscrypt, "git", "init", "--quiet", "--initial-branch", "android15-release")
	run(state, setup.environment, conscrypt, "git", "add", ".")
	run(state, setup.environment, conscrypt, "git", "commit", "--quiet", "--message", "conscrypt")
	writeFile(state, filepath.Join(chromium, "DEPS"), "", 0o644)
	run(state, setup.environment, chromium, "git", "init", "--quiet")
	run(state, setup.environment, chromium, "git", "add", ".")
	run(state, setup.environment, chromium, "git", "commit", "--quiet", "--message", "chromium")

	for _, tag := range []string{chromeTag1, chromeTag2, chromeTag3} {
		run(state, setup.environment, chromium, "git", "tag", tag)
	}

	for _, revision := range []string{revisionA, revisionB} {
		writeFile(state, filepath.Join(boringsslCache, revision, "ssl", "internal.h"), "", 0o644)
	}

	// Flutter 3.23.0 is below the minimum, 3.24.0 and 3.24.1 have Dart 3.5.0 with BoringSSL A, 3.27.0 Dart 3.6.0 with B from the DEPS of its
	// engine repository (before the monorepo)
	writeFile(state, filepath.Join(flutter, "README"), "", 0o644)
	run(state, setup.environment, flutter, "git", "init", "--quiet")
	run(state, setup.environment, flutter, "git", "add", ".")
	run(state, setup.environment, flutter, "git", "commit", "--quiet", "--message", "flutter")
	releases := []struct {
		version  string
		engine   string
		dart     string
		minor    string
		revision string
		isEngine bool
	}{
		{version: "3.23.0", engine: "e0", dart: "d0", minor: "4", revision: revisionA, isEngine: false},
		{version: "3.24.0", engine: "e1", dart: "d1", minor: "5", revision: revisionA, isEngine: false},
		{version: "3.24.1", engine: "e2", dart: "d1", minor: "5", revision: revisionA, isEngine: false},
		{version: "3.27.0", engine: "e3", dart: "d3", minor: "6", revision: revisionB, isEngine: true},
	}

	for _, release := range releases {
		deps := "vars = {\n  'dart_revision': '" + release.dart + "',\n  'dart_boringssl_rev': '" + release.revision + "',\n}\n"
		depsPath := filepath.Join(raw, "flutter", "flutter", release.version, "DEPS")

		if release.isEngine {
			depsPath = filepath.Join(raw, "flutter", "engine", release.engine, "DEPS")
		}

		run(state, setup.environment, flutter, "git", "tag", release.version)
		writeFile(state, filepath.Join(raw, "flutter", "flutter", release.version, "bin", "internal", "engine.version"), release.engine+"\n", 0o644)
		writeFile(state, depsPath, deps, 0o644)
		writeFile(state, filepath.Join(raw, "dart-lang", "sdk", release.dart, "tools", "VERSION"), fmt.Sprintf(dartVersion, release.minor), 0o644)
	}

	return
}

// writeFile writes a file and its directories
func writeFile(state *testing.T, path string, content string, mode os.FileMode) {
	state.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		state.Fatalf("Could not create the directory of %s: %v", path, err)
	}

	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		state.Fatalf("Could not write %s: %v", path, err)
	}
}

// run runs a setup command that must succeed
func run(state *testing.T, environment []string, directory string, name string, arguments ...string) {
	state.Helper()
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = environment

	if output, err := command.CombinedOutput(); err != nil {
		state.Fatalf("Could not run %s %v: %v: %s", name, arguments, err, output)
	}
}

// runScript runs boringssl.sh with the setup and extra environment, and returns its stdout, stderr and error
func runScript(state *testing.T, setup offsetgenSetup, extra []string, arguments ...string) (stdout string, stderr string, err error) {
	state.Helper()
	var stdoutBuffer, stderrBuffer bytes.Buffer
	command := exec.Command("bash", append([]string{"../boringssl.sh"}, arguments...)...)
	command.Env = append(setup.environment, extra...)
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer
	err = command.Run()
	stdout = stdoutBuffer.String()
	stderr = stderrBuffer.String()
	return
}

// Test if tools/offsetgen/boringssl.sh returns with the expected output.
func TestBoringsslScriptPositive(state *testing.T) {
	setup := newSetup(state)
	writeFile(state, filepath.Join(setup.chromiumCache, chromeTag1), revisionA+"\n", 0o644)
	writeFile(state, filepath.Join(setup.chromiumCache, chromeTag3), revisionA+"\n", 0o644)
	writeFile(state, filepath.Join(setup.chromiumCache, chromeTag2+"@"+strings.Repeat("c", 40)), revisionB+"\n", 0o644)
	testCases := []struct {
		name      string
		arguments []string
		expected  []string
	}{
		{
			name:      "conscrypt",
			arguments: []string{"conscrypt", "15"},
			expected:  []string{"\t\"15\": {\n\t\t" + amd64Line + "\n\t\t" + arm64Line + "\n\t},\n"},
		},
		{
			name:      "chrome branch",
			arguments: []string{"chrome", "branches"},
			expected:  []string{`{First: 1, Last: 3, Revision: "` + revisionA + `"},`, `Revisions: []string{"` + revisionA + `"},`, "\t\t\t" + amd64Line + "\n\t\t\t" + arm64Line + "\n"},
		},
		{
			name:      "chrome branch and builds",
			arguments: []string{"chrome", "branches", chromeTag1, chromeTag2 + "@" + strings.Repeat("c", 40)},
			expected: []string{
				`{First: 1, Last: 3, Revision: "` + revisionA + `"},`,
				"var chromiumBuilds = map[string]string{\n\t\"" + chromeTag1 + `": "` + revisionA + "\",\n\t\"" + chromeTag2 + `": "` + revisionB + "\",\n}",
				"// 2 Chromium builds of no release branch, each with its BoringSSL revision; 2 BoringSSL revisions, 1 offset sets in all",
				`Revisions: []string{"` + revisionA + `", "` + revisionB + `"},`,
			},
		},
		{
			name:      "flutter all",
			arguments: []string{"flutter", "all"},
			expected: []string{
				"// 3 Flutter releases from 3.24.0 to 3.27.0, 2 Dart versions, 2 BoringSSL revisions, 1 offset sets",
				"\t\"3.5.0\": {\n\t\tRevision: \"" + revisionA + "\",\n\t\tFlutter:  []string{\"3.24.0\", \"3.24.1\"},\n\t\tEngines:  []string{\"e1\", \"e2\"},\n\t},",
				"\t\"3.6.0\": {\n\t\tRevision: \"" + revisionB + "\",\n\t\tFlutter:  []string{\"3.27.0\"},\n\t\tEngines:  []string{\"e3\"},\n\t},",
				`Revisions: []string{"` + revisionA + `", "` + revisionB + `"},`,
				"\t\t\t" + amd64Line + "\n\t\t\t" + arm64Line + "\n",
			},
		},
	}

	for _, testCase := range testCases {
		state.Run(testCase.name, func(state *testing.T) {
			stdout, stderr, err := runScript(state, setup, nil, testCase.arguments...)

			if err != nil {
				state.Fatalf("boringssl.sh failed: %v: %s", err, stderr)
			}

			for _, expected := range testCase.expected {
				if !strings.Contains(stdout, expected) {
					state.Errorf("The output has no %q:\n%s", expected, stdout)
				}
			}
		})
	}
}

// Test if tools/offsetgen/boringssl.sh returns with the expected errors.
func TestBoringsslScriptNegative(state *testing.T) {
	setup := newSetup(state)
	// the ends of the branch differ, so the middle tag is read, and it has no DEPS
	writeFile(state, filepath.Join(setup.chromiumCache, chromeTag1), revisionA+"\n", 0o644)
	writeFile(state, filepath.Join(setup.chromiumCache, chromeTag3), revisionB+"\n", 0o644)
	testCases := []struct {
		name      string
		arguments []string
		extra     []string
		expected  string
	}{
		{
			name:      "amd64 probe fails",
			arguments: []string{"conscrypt", "15"},
			extra:     []string{"FAKE_CLANG_FAIL=x86_64"},
			expected:  "boringssl.sh: 15: the amd64 probe does not compile",
		},
		{
			name:      "arm64 probe fails",
			arguments: []string{"conscrypt", "15"},
			extra:     []string{"FAKE_CLANG_FAIL=aarch64"},
			expected:  "boringssl.sh: 15: the arm64 probe does not compile",
		},
		{
			name:      "probe without offsets",
			arguments: []string{"conscrypt", "15"},
			extra:     []string{"FAKE_CLANG_EMPTY=x86_64"},
			expected:  "boringssl.sh: 15: the amd64 probe has no offsets",
		},
		{
			name:      "chrome probe fails",
			arguments: []string{"chrome", chromeTag1},
			extra:     []string{"FAKE_CLANG_FAIL=aarch64"},
			expected:  "boringssl.sh: " + revisionA + ": the arm64 probe does not compile",
		},
		{
			name:      "flutter probe fails",
			arguments: []string{"flutter", "all"},
			extra:     []string{"FAKE_CLANG_FAIL=x86_64"},
			expected:  "boringssl.sh: " + revisionA + ": the amd64 probe does not compile",
		},
		{
			name:      "chrome tag without deps",
			arguments: []string{"chrome", "branches"},
			extra:     nil,
			expected:  "boringssl.sh: Chromium " + chromeTag2 + ": no boringssl_revision",
		},
	}

	for _, testCase := range testCases {
		state.Run(testCase.name, func(state *testing.T) {
			stdout, stderr, err := runScript(state, setup, testCase.extra, testCase.arguments...)

			if err == nil {
				state.Fatalf("boringssl.sh succeeded, output:\n%s", stdout)
			}

			if !strings.Contains(stderr, testCase.expected) {
				state.Errorf("The errors have no %q:\n%s", testCase.expected, stderr)
			}
		})
	}
}
