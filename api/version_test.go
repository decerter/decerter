// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package api

import (
	"runtime"
	"strings"
	"testing"
)

// the build values of the Makefile for one test, put back after it
func setBuildValues(state *testing.T, version string, commit string, date string) {
	originalVersion, originalCommit, originalDate := buildVersion, gitCommit, buildDate
	buildVersion, gitCommit, buildDate = version, commit, date

	state.Cleanup(func() {
		buildVersion, gitCommit, buildDate = originalVersion, originalCommit, originalDate
	})
}

// Test if api.Version returns with the expected output: the values of the Makefile when they are set, otherwise what the build info has or unknown, always the Go version and platform.
func TestVersionPositive(state *testing.T) {
	platform := runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + ")"
	setBuildValues(state, "v1.2.3", "0123456789ab", "2026-11-15T00:00:00Z")
	version := Version()
	expected := "v1.2.3 (commit 0123456789ab, date 2026-11-15T00:00:00Z, " + platform

	if version != expected {
		state.Errorf("Test of api.Version function failed, version should be %q, version: %q", expected, version)
		return
	}

	// a test binary has no module version and no vcs settings in its build info
	setBuildValues(state, "", "", "")
	version = Version()

	if !strings.HasSuffix(version, ", "+platform) || !strings.Contains(version, " (commit ") || !strings.Contains(version, ", date ") || strings.HasPrefix(version, " ") {
		state.Errorf("Test of api.Version function failed, version should name a version, a commit, a date and %q, version: %q", platform, version)
		return
	}
}

// Test if api.valueOrUnknown returns with the expected output: the value, or unknown for an empty one.
func TestValueOrUnknownPositive(state *testing.T) {
	positiveCases := map[string]string{
		"":         "unknown",
		"abcdef12": "abcdef12",
	}

	for value, expected := range positiveCases {
		shown := valueOrUnknown(value)

		if shown != expected {
			state.Errorf("Test of api.valueOrUnknown function failed, value %q, shown should be %q, shown: %q", value, expected, shown)
			return
		}
	}
}
