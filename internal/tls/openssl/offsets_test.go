// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package openssl

import (
	"errors"
	"slices"
	"testing"
)

// Test if the generated offsets table holds both architectures with the same ranges, every range inside one x.y series, in order and without overlap, from 3.0.0 on.
func TestOffsetTablePositive(state *testing.T) {
	architectures := []string{"amd64", "arm64"}

	for _, architecture := range architectures {
		ranges := offsets[architecture]

		if (len(ranges) == 0) || (ranges[0].First != "3.0.0") {
			state.Errorf("Test of the offsets table failed, %s should start at 3.0.0, ranges: %d", architecture, len(ranges))
			return
		}

		previous := [3]int{}

		for index, current := range ranges {
			first, firstErr := parseVersion(current.First)
			last, lastErr := parseVersion(current.Last)

			if (firstErr != nil) || (lastErr != nil) || (first[0] != last[0]) || (first[1] != last[1]) || (slices.Compare(first[:], last[:]) > 0) {
				state.Errorf("Test of the offsets table failed, %s range %s to %s should be inside one series, errors: %v %v", architecture, current.First, current.Last, firstErr, lastErr)
				return
			}

			if (index > 0) && (slices.Compare(first[:], previous[:]) <= 0) {
				state.Errorf("Test of the offsets table failed, %s range %s to %s should come after the one before", architecture, current.First, current.Last)
				return
			}

			// a zero offset set would read the start of the SSL object for everything
			if (current.Offset.ClientRandom == 0) || (current.Offset.Session == 0) || (current.Offset.MasterKey == 0) || (current.Offset.HasType != (slices.Compare(first[:], []int{3, 2, 0}) >= 0)) {
				state.Errorf("Test of the offsets table failed, %s range %s to %s has an unexpected offset set: %+v", architecture, current.First, current.Last, current.Offset)
				return
			}

			previous = last
		}

		if (len(ranges) != len(offsets[architectures[0]])) || (ranges[len(ranges)-1].Last != offsets[architectures[0]][len(ranges)-1].Last) {
			state.Errorf("Test of the offsets table failed, %s should cover the same releases as %s", architecture, architectures[0])
			return
		}
	}
}

// Test if openssl.nearestVersion returns with the expected output.
func TestNearestVersionPositive(state *testing.T) {
	ranges := []offsetRange{{First: "3.0.0", Last: "3.0.4", Offset: Offset{}}, {First: "3.0.8", Last: "3.0.9", Offset: Offset{}}, {First: "3.2.0", Last: "3.2.1", Offset: Offset{}}}
	positiveCases := []struct {
		Version  [3]int
		Expected string
	}{
		{Version: [3]int{3, 0, 5}, Expected: "3.0.4"},
		{Version: [3]int{3, 0, 7}, Expected: "3.0.8"},
		// as far from 3.0.4 as from 3.0.8, the older one wins
		{Version: [3]int{3, 0, 6}, Expected: "3.0.4"},
		{Version: [3]int{3, 1, 0}, Expected: "3.0.9"},
		{Version: [3]int{3, 1, 999}, Expected: "3.2.0"},
		{Version: [3]int{2, 9, 9}, Expected: "3.0.0"},
	}

	for _, positive := range positiveCases {
		nearest := nearestVersion(positive.Version, ranges)

		if nearest != positive.Expected {
			state.Errorf("Test of openssl.nearestVersion function failed, version: %v, nearest should be %s, nearest: %s", positive.Version, positive.Expected, nearest)
			return
		}
	}
}

// Test if openssl.nearestVersion returns with the expected output for an empty table.
func TestNearestVersionNegative(state *testing.T) {
	nearest := nearestVersion([3]int{3, 6, 2}, nil)

	if nearest != "" {
		state.Errorf("Test of openssl.nearestVersion function failed, an empty table should have no nearest version, nearest: %s", nearest)
		return
	}
}

// Test if openssl.parseVersion returns with the expected output.
func TestParseVersionPositive(state *testing.T) {
	positiveCases := map[string][3]int{"3.0.0": {3, 0, 0}, "3.6.12": {3, 6, 12}, "10.20.30": {10, 20, 30}}

	for version, expected := range positiveCases {
		parsed, err := parseVersion(version)

		if (err != nil) || (parsed != expected) {
			state.Errorf("Test of openssl.parseVersion function failed, version: %s, parsed should be %v, parsed: %v, error: %v", version, expected, parsed, err)
			return
		}
	}
}

// Test if openssl.parseVersion returns with the expected errors.
func TestParseVersionNegative(state *testing.T) {
	negativeCases := []string{"", "3", "3.6", "3.6.2.1", "3.6.x", "3.-1.0", "3.6.2-dev", " 3.6.2"}

	for _, negative := range negativeCases {
		_, err := parseVersion(negative)

		if !errors.Is(err, ErrVersionFormat) {
			state.Errorf("Test of openssl.parseVersion function failed, version: %q, error should be %v, error: %v", negative, ErrVersionFormat, err)
			return
		}
	}
}
