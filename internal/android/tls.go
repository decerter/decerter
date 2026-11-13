// SPDX-License-Identifier: AGPL-3.0-only

package android

import (
	"fmt"
	"strings"

	"github.com/decerter/decerter/internal/tls/boringssl"
)

// what decerter hooks for the TLS of one installed package, on the device: a Flutter app's libflutter.so with the offsets of its Dart version, the Chromium
// libraries (Chrome, Trichrome, WebView, Cronet) of its install directories and of the Trichrome library it uses with the offsets of their version, or
// nothing of its own (Java apps use Conscrypt); one line per install directory and library, isKnown is false when a library can't be hooked
func DescribeTLS(selected Package, packages []Package, appDirectory string, architecture string) (lines []string, isKnown bool, err error) {
	name := selected.Name
	directories, err := FindInstallDirectories(appDirectory, name)

	if err != nil {
		return
	}

	isKnown = true
	trichromeLines, isTrichromeKnown, err := describeTrichrome(selected, packages, appDirectory, architecture)

	if err != nil {
		return
	}

	// apps of the system image are no Flutter apps, decerter only looks at installed apps
	if len(directories) == 0 {
		lines = append(lines, fmt.Sprintf("%s: no install directory in %s, a system app; Java TLS goes through Conscrypt, a Chromium library its processes map (its Cronet, Cronet of Play services, WebView) is looked for while decerter runs", name, appDirectory))
		isKnown = isTrichromeKnown
		lines = append(lines, trichromeLines...)
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
			chromiumLines, isChromiumKnown, chromiumErr := describeChromium(name, directory, "", architecture)

			if err = chromiumErr; err != nil {
				return
			}

			isKnown = isKnown && isChromiumKnown

			// Chrome's own directory has no library when its Trichrome library has it
			if (len(chromiumLines) == 0) && (len(trichromeLines) == 0) {
				lines = append(lines, fmt.Sprintf("%s: no %s and no Chromium library, not a Flutter or Chromium app; Java TLS goes through Conscrypt", name, boringssl.FlutterLibraryName))
			}

			lines = append(lines, chromiumLines...)
			continue
		default:
		}

		library, inspectErr := boringssl.InspectFlutter(file, architecture)

		if inspectErr != nil {
			isKnown = false
			lines = append(lines, fmt.Sprintf("%s: Flutter app with Dart %q, its TLS is relayed without decryption: %s", name, library.DartVersion, inspectErr.Error()))
			continue
		}

		lines = append(lines, fmt.Sprintf("%s: Flutter app with Dart %s (Flutter %s), BoringSSL offsets known, ssl_log_secret found through %d key log labels in %s", name, library.DartVersion, strings.Join(library.Flutter, ", "), library.Labels, where(library.File)))
	}

	isKnown = isKnown && isTrichromeKnown
	lines = append(lines, trichromeLines...)
	return
}

// the lines of the Trichrome libraries of Chrome and WebView built on Trichrome, they have their native code in the Trichrome library package
func describeTrichrome(selected Package, packages []Package, appDirectory string, architecture string) (lines []string, isKnown bool, err error) {
	isKnown = true

	for _, trichrome := range TrichromeLibraries(selected, packages) {
		trichromeDirectories, findErr := FindInstallDirectories(appDirectory, trichrome)

		if err = findErr; err != nil {
			return
		}

		for _, directory := range trichromeDirectories {
			chromiumLines, isChromiumKnown, chromiumErr := describeChromium(selected.Name, directory, trichrome, architecture)

			if err = chromiumErr; err != nil {
				return
			}

			isKnown = isKnown && isChromiumKnown
			lines = append(lines, chromiumLines...)
		}
	}

	return
}

// one line per Chromium library of an install directory, library names the Trichrome library package the directory belongs to, empty for the app's own
// a library that can't be read (compressed in the apk) or hooked (unknown version, no labels, 32 bit) gives isKnown false
func describeChromium(name string, directory string, library string, architecture string) (lines []string, isKnown bool, err error) {
	isKnown = true
	files, findErr := boringssl.FindChromiumLibraries(directory, architecture)
	from := ""

	if library != "" {
		from = " of " + library
	}

	if findErr != nil {
		isKnown = false
		lines = append(lines, fmt.Sprintf("%s: Chromium library%s that can't be hooked, its TLS is relayed without decryption: %s", name, from, findErr.Error()))
		return
	}

	for _, file := range files {
		inspected, inspectErr := boringssl.InspectChromium(file, architecture)

		if inspectErr != nil {
			isKnown = false
			lines = append(lines, fmt.Sprintf("%s: %s %q%s in %s, its TLS is relayed without decryption: %s", name, inspected.Product, inspected.Version, from, where(file), inspectErr.Error()))
			continue
		}

		lines = append(lines, fmt.Sprintf("%s: %s %s%s, BoringSSL offsets known, ssl_log_secret found through %d key log labels in %s", name, inspected.Product, inspected.Version, from, inspected.Labels, where(file)))
	}

	return
}

// a library's place: the path, with the entry inside an apk
func where(file boringssl.LibraryFile) (text string) {
	text = file.Path

	if file.Entry != "" {
		text = file.Path + "!/" + file.Entry
	}

	return
}
