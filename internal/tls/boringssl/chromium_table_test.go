// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package boringssl

import (
	"slices"
	"strings"
	"testing"
)

// Test if the generated Chromium tables are what tools/offsetgen/boringssl.sh chrome promises: every branch of the milestone table is MAJOR.0.BUILD
// with ranges in patch order that don't overlap, one branch per milestone, every revision has offsets for both architectures in exactly one group,
// the image's Chrome and at least 12 milestones are in the milestone table, and the explicit builds (the image's Cronet, the e2e snapshot) are in
// their own list and not in the milestone table.
func TestChromiumTablePositive(state *testing.T) {
	milestones := map[string]string{}

	for branch, ranges := range chromiumBranches {
		parts := strings.Split(branch, ".")

		if (len(parts) != 3) || (parts[1] != "0") || (len(ranges) == 0) {
			state.Errorf("Test of the Chromium table failed, %s is no MAJOR.0.BUILD branch with ranges: %+v", branch, ranges)
			continue
		}

		if other, found := milestones[parts[0]]; found {
			state.Errorf("Test of the Chromium table failed, milestone %s should have one release branch, branches: %s and %s", parts[0], other, branch)
		}

		milestones[parts[0]] = branch

		for index, current := range ranges {
			if (current.First > current.Last) || ((index > 0) && (current.First <= ranges[index-1].Last)) {
				state.Errorf("Test of the Chromium table failed, %s has a range out of order: %+v", branch, ranges)
			}

			groups := 0

			for _, group := range chromiumRevisionOffsets {
				if slices.Contains(group.Revisions, current.Revision) {
					groups++

					if (len(group.Offsets) != 2) || (group.Offsets["amd64"] != group.Offsets["arm64"]) {
						state.Errorf("Test of the Chromium table failed, %s should have the same offsets for amd64 and arm64: %+v", current.Revision, group.Offsets)
					}
				}
			}

			if groups != 1 {
				state.Errorf("Test of the Chromium table failed, revision %s of %s is in %d offset groups", current.Revision, branch, groups)
			}
		}
	}

	if len(milestones) < 12 {
		state.Errorf("Test of the Chromium table failed, it should cover at least 12 milestones, milestones: %d", len(milestones))
	}

	branch, patch, err := splitChromiumVersion("124.0.6367.219")
	found := slices.ContainsFunc(chromiumBranches[branch], func(current chromiumRange) (isIn bool) {
		isIn = (patch >= current.First) && (patch <= current.Last)
		return
	})

	if (err != nil) || !found {
		state.Errorf("Test of the Chromium table failed, Chrome 124.0.6367.219 of the decerter-a15 image should be in the milestone table, error: %v", err)
	}

	for _, version := range []string{"122.0.6238.4", "125.0.6383.0", "126.0.6452.4", "127.0.6493.0", "160.0.8161.0"} {
		buildBranch, _, splitErr := splitChromiumVersion(version)
		revision, isBuild := chromiumBuilds[version]
		groups := slices.IndexFunc(chromiumRevisionOffsets, func(group revisionOffset) (isIn bool) {
			isIn = slices.Contains(group.Revisions, revision)
			return
		})

		if (splitErr != nil) || !isBuild || (groups < 0) || (len(chromiumBranches[buildBranch]) != 0) {
			state.Errorf("Test of the Chromium table failed, %s of the decerter-a15 image or the e2e snapshot should be a build with offsets, apart from the milestone table, revision: %q, branch ranges: %+v, error: %v", version, revision, chromiumBranches[buildBranch], splitErr)
		}
	}
}

// Test if splitChromiumVersion and compareChromiumVersions return with the expected errors and order for versions that are no Chromium version.
func TestChromiumTableNegative(state *testing.T) {
	for _, version := range []string{"", "124", "124.0.6367", "124.1.6367.219", "124.0.6367.x", "v124.0.6367.219", "124.0.6367.99999999999999999999"} {
		if _, _, err := splitChromiumVersion(version); err == nil {
			state.Errorf("Test of splitChromiumVersion failed, %q should be no Chromium version", version)
		}
	}

	if (compareChromiumVersions("chrome", "1.0.0.0") >= 0) || (compareChromiumVersions("124.0.6367.9", "124.0.6367.10") >= 0) || (compareChromiumVersions("125.0.1.0", "124.0.9999.0") <= 0) {
		state.Errorf("Test of compareChromiumVersions failed, versions compare by their numbers, no version first")
	}

	if len(KnownChromiumVersions()) == 0 {
		state.Errorf("Test of KnownChromiumVersions failed, the table is empty")
	}
}
