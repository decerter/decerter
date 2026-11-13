// SPDX-License-Identifier: AGPL-3.0-only

package android

import (
	"fmt"
	"strings"

	"github.com/decerter/decerter/internal/tls/boringssl"
)

// what decerter hooks for the TLS of one installed package, on the device: a Flutter app's libflutter.so with the offsets of its Dart version, or
// nothing of its own (Java apps use Conscrypt); one line per install directory, isKnown is false when a Flutter app can't be hooked
func DescribeTLS(name string, appDirectory string, architecture string) (lines []string, isKnown bool, err error) {
	directories, err := FindInstallDirectories(appDirectory, name)

	if err != nil {
		return
	}

	isKnown = true

	// apps of the system image are no Flutter apps, decerter only looks at installed apps
	if len(directories) == 0 {
		lines = append(lines, fmt.Sprintf("%s: no install directory in %s, a system app; Java TLS goes through Conscrypt", name, appDirectory))
		return
	}

	for _, directory := range directories {
		file, found, findErr := boringssl.FindFlutterLibrary(directory, architecture)

		switch {
		case findErr != nil:
			isKnown = false
			lines = append(lines, fmt.Sprintf("%s: Flutter app that can't be hooked, its TLS is relayed without decryption: %s", name, findErr.Error()))
			continue
		case !found:
			lines = append(lines, fmt.Sprintf("%s: no %s, not a Flutter app; Java TLS goes through Conscrypt", name, boringssl.FlutterLibraryName))
			continue
		default:
		}

		library, inspectErr := boringssl.InspectFlutter(file, architecture)

		if inspectErr != nil {
			isKnown = false
			lines = append(lines, fmt.Sprintf("%s: Flutter app with Dart %q, its TLS is relayed without decryption: %s", name, library.DartVersion, inspectErr.Error()))
			continue
		}

		where := file.Path

		if file.Entry != "" {
			where = file.Path + "!/" + file.Entry
		}

		lines = append(lines, fmt.Sprintf("%s: Flutter app with Dart %s (Flutter %s), BoringSSL offsets known, ssl_log_secret found through %d key log labels in %s", name, library.DartVersion, strings.Join(library.Flutter, ", "), library.Labels, where))
	}

	return
}
