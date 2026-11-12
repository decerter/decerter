// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// set at build time with -ldflags "-X github.com/decerter/decerter/api.buildVersion=…", see the Makefile
// empty values are taken from the build info Go writes into every binary: the module version and the vcs revision and time
var (
	buildVersion string
	gitCommit    string
	buildDate    string
)

// one line for decerter --version: version (commit …, date …, go version os/arch), the date is the build date from the Makefile or the commit time from the build info
func Version() (version string) {
	version, commit, date := buildVersion, gitCommit, buildDate
	info, ok := debug.ReadBuildInfo()

	if ok {
		if (version == "") && (info.Main.Version != "") {
			version = info.Main.Version
		}

		settings := map[string]string{}

		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}

		if commit == "" {
			commit = settings["vcs.revision"]

			// as long as git's short hashes usually are
			if len(commit) > 12 {
				commit = commit[:12]
			}

			if (commit != "") && (settings["vcs.modified"] == "true") {
				commit += "-dirty"
			}
		}

		if date == "" {
			date = settings["vcs.time"]
		}
	}

	if version == "" {
		version = "unknown"
	}

	version = fmt.Sprintf("%s (commit %s, date %s, %s %s/%s)", version, valueOrUnknown(commit), valueOrUnknown(date), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return
}

func valueOrUnknown(value string) (shown string) {
	shown = value

	if shown == "" {
		shown = "unknown"
	}

	return
}
