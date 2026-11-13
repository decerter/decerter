// SPDX-License-Identifier: AGPL-3.0-only

package boringssl

import (
	"archive/zip"
	"cmp"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	// what a Chromium library is for the logs, by its name
	ChromeProduct  string = "Chrome"
	WebViewProduct string = "WebView"
	CronetProduct  string = "Cronet"
	// the binary manifest of an apk, a few KiB; more is not read
	manifestName    string = "AndroidManifest.xml"
	maxManifestSize int64  = 4 << 20
)

var (
	// the libraries Chromium's network stack is linked into, each with its own BoringSSL: Chrome and Trichrome's libmonochrome(_64).so (Chrome and
	// WebView in one), ChromePublic's libchrome.so, the standalone WebView's libwebviewchromium.so and Cronet's libcronet.<version>.so; the small
	// libmonochrome_64_*_partition.so and libchromium_android_linker.so have no TLS
	chromiumLibraryPattern = regexp.MustCompile(`^lib(monochrome(_64)?|chrome|webviewchromium|cronet\.[0-9]+\.0\.[0-9]+\.[0-9]+)\.so$`)
	// the version strings of a Chromium library, NUL terminated in .rodata, by preference: the product token of an official Chrome's user agent,
	// Cronet's own library name; MAJOR.0.BUILD.PATCH, BUILD has four digits or more. A bare version string is no help: ChromePublic and WebView
	// builds hold an older one of a component (153.0.8010.0 in 160.0.8161.0), WebView not even its own
	chromiumVersionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\x00Chrome/([0-9]{2,4}\.0\.[0-9]{4,6}\.[0-9]{1,5})\x00`),
		regexp.MustCompile(`\x00libcronet\.([0-9]{2,4}\.0\.[0-9]{4,6}\.[0-9]{1,5})\.so\x00`),
	}
	// the versionName of the apk in the string pool of its binary AndroidManifest.xml, UTF-16LE or UTF-8, NUL terminated: ChromePublic, WebView,
	// Trichrome; an app that embeds Cronet has its own versionName, which is no Chromium version
	manifestVersionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`((?:[0-9]\x00){2,4}\.\x000\x00\.\x00(?:[0-9]\x00){4,6}\.\x00(?:[0-9]\x00){1,5})\x00\x00`),
		regexp.MustCompile(`[^0-9.]([0-9]{2,4}\.0\.[0-9]{4,6}\.[0-9]{1,5})\x00`),
	}
	chromiumVersionNumbersPattern = regexp.MustCompile(`^([0-9]+)\.0\.([0-9]+)\.([0-9]+)$`)
)

// the Chromium libraries of an install directory (/data/app/~~…/<package>-…/): extracted lib/<isa>/ files when the package manager extracted them, and
// the stored lib/<abi>/ entries of base.apk and the split apks; a compressed or unaligned library is an error, none without an error is no Chromium app
func FindChromiumLibraries(installDirectory string, architecture string) (libraries []LibraryFile, err error) {
	apkABI, extractedISA, err := abiDirectories(architecture)

	if err != nil {
		return
	}

	entries, readErr := os.ReadDir(filepath.Join(installDirectory, "lib", extractedISA))

	if (readErr != nil) && !errors.Is(readErr, fs.ErrNotExist) {
		err = fmt.Errorf("%w: %w", ErrLibraryNotFound, readErr)
		return
	}

	for _, entry := range entries {
		if !chromiumLibraryPattern.MatchString(entry.Name()) || !entry.Type().IsRegular() {
			continue
		}

		info, infoErr := entry.Info()

		if err = infoErr; err != nil {
			err = fmt.Errorf("%w: %w", ErrLibraryNotFound, err)
			return
		}

		libraries = append(libraries, LibraryFile{Path: filepath.Join(installDirectory, "lib", extractedISA, entry.Name()), Entry: "", Offset: 0, Size: uint64(info.Size())})
	}

	apks, globErr := filepath.Glob(filepath.Join(installDirectory, "*.apk"))

	if err = globErr; err != nil {
		return
	}

	slices.Sort(apks)

	for _, apk := range apks {
		names, namesErr := apkEntries(apk, func(name string) (isLibrary bool) {
			isLibrary = (path.Dir(name) == "lib/"+apkABI) && chromiumLibraryPattern.MatchString(path.Base(name))
			return
		})

		if err = namesErr; err != nil {
			return
		}

		for _, name := range names {
			library, found, findErr := FindAPKEntry(apk, name)

			if err = findErr; err != nil {
				return
			}

			if found {
				libraries = append(libraries, library)
			}
		}
	}

	return
}

// the names of the entries of an apk that match
func apkEntries(apkPath string, match func(name string) (isMatch bool)) (names []string, err error) {
	reader, openErr := zip.OpenReader(apkPath)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrReadAPK, apkPath, err)
		return
	}

	defer func() {
		err = errors.Join(err, reader.Close())
	}()

	for _, file := range reader.File {
		if match(file.Name) {
			names = append(names, file.Name)
		}
	}

	return
}

// the stored entry of an apk whose bytes hold the file offset, from a mapping of the apk in /proc/<pid>/maps; not found when the offset is in no stored entry
func FindAPKEntryAt(apkPath string, offset uint64) (library LibraryFile, found bool, err error) {
	reader, openErr := zip.OpenReader(apkPath)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrReadAPK, apkPath, err)
		return
	}

	defer func() {
		err = errors.Join(err, reader.Close())
	}()

	for _, file := range reader.File {
		if file.Method != zip.Store {
			continue
		}

		dataOffset, offsetErr := file.DataOffset()

		if err = offsetErr; err != nil {
			err = fmt.Errorf("%w: %s: %s: %w", ErrReadAPK, apkPath, file.Name, err)
			return
		}

		if (offset >= uint64(dataOffset)) && (offset < uint64(dataOffset)+file.UncompressedSize64) {
			library = LibraryFile{Path: apkPath, Entry: file.Name, Offset: uint64(dataOffset), Size: file.UncompressedSize64}
			found = true
			return
		}
	}

	return
}

// a library file or apk entry name Chromium's network stack can be in
func IsChromiumLibraryName(name string) (isChromium bool) {
	isChromium = chromiumLibraryPattern.MatchString(path.Base(name))
	return
}

// the executable file mappings of a /proc/<pid>/maps text: start-end perms offset dev inode path, r-xp only; a deleted file (an app updated while
// it runs) is left out, a uprobe can't reach it by its path
func ExecutableMappings(maps string) (mappings []Mapping) {
	for line := range strings.Lines(maps) {
		fields := strings.Fields(line)

		if (len(fields) < 6) || (len(fields[1]) < 3) || (fields[1][2] != 'x') || !strings.HasPrefix(fields[5], "/") || strings.HasSuffix(strings.TrimSpace(line), "(deleted)") {
			continue
		}

		offset, parseErr := strconv.ParseUint(fields[2], 16, 64)

		if parseErr != nil {
			continue
		}

		mapping := Mapping{Path: strings.Join(fields[5:], " "), Offset: offset}

		if !slices.Contains(mappings, mapping) {
			mappings = append(mappings, mapping)
		}
	}

	return
}

// the Chromium library of an executable mapping: a library file of its own, or the stored apk entry that holds the mapping's offset; isChromium is false
// for any other file
func ChromiumMapping(mapping Mapping) (library LibraryFile, isChromium bool, err error) {
	if !strings.HasSuffix(mapping.Path, ".apk") {
		if !IsChromiumLibraryName(mapping.Path) {
			return
		}

		info, statErr := os.Stat(mapping.Path)

		if err = statErr; err != nil {
			err = fmt.Errorf("%w: %w", ErrLibraryNotFound, err)
			return
		}

		library = LibraryFile{Path: mapping.Path, Entry: "", Offset: 0, Size: uint64(info.Size())}
		isChromium = true
		return
	}

	library, found, err := FindAPKEntryAt(mapping.Path, mapping.Offset)

	if err != nil {
		return
	}

	isChromium = found && IsChromiumLibraryName(library.Entry)
	return
}

// read a Chromium library: its version, ssl_log_secret through its labels and the offsets of the BoringSSL its version builds with
// the library is filled as far as it was read, an unknown version (ErrUnknownChromiumVersion) still has the version and the hook
func InspectChromium(file LibraryFile, architecture string) (library ChromiumLibrary, err error) {
	library.File = file
	library.Product = chromiumProduct(file)
	opened, openErr := os.Open(file.Path)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrOpenLibrary, file.Path, err)
		return
	}

	defer func() {
		err = errors.Join(err, opened.Close())
	}()

	elfFile, elfErr := elf.NewFile(io.NewSectionReader(opened, int64(file.Offset), int64(file.Size)))

	if err = elfErr; err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrOpenLibrary, file.Path, err)
		return
	}

	err = checkMachine(elfFile, architecture)

	if err != nil {
		return
	}

	readOnly, code, err := readSegments(elfFile)

	if err != nil {
		return
	}

	library.Version, err = chromiumVersion(readOnly)

	// without a version of its own the library has the one of its apk, an extracted one the one of base.apk in its install directory
	if errors.Is(err, ErrNoChromiumVersion) {
		apk := file.Path

		if file.Entry == "" {
			apk = filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(file.Path))), "base.apk")
		}

		library.Version, err = manifestVersion(apk)
	}

	if err != nil {
		return
	}

	address, labels, err := findLogSecret(elfFile, readOnly, code)

	if err != nil {
		return
	}

	library.LogSecret = file.Offset + address
	library.Labels = labels
	library.Offset, library.Revision, err = GetChromiumOffset(library.Version, architecture)
	return
}

// Cronet and WebView by their library's name, every other one is Chrome's (Trichrome's libmonochrome also serves its WebView)
func chromiumProduct(file LibraryFile) (product string) {
	name := path.Base(filepath.ToSlash(file.Path))

	if file.Entry != "" {
		name = path.Base(file.Entry)
	}

	switch {
	case strings.HasPrefix(name, "libcronet."):
		product = CronetProduct
	case name == "libwebviewchromium.so":
		product = WebViewProduct
	default:
		product = ChromeProduct
	}

	return
}

// the version of the first kind of version string the library has, the newest one of that kind
func chromiumVersion(readOnly []segment) (version string, err error) {
	for _, pattern := range chromiumVersionPatterns {
		for _, current := range readOnly {
			version = newestVersion(pattern, current.data, version)
		}

		if version != "" {
			return
		}
	}

	err = ErrNoChromiumVersion
	return
}

// the newest version pattern finds in data and newest, its first group without the NULs of UTF-16; matches next to each other share a NUL, so the
// search goes on at the last byte of a match
func newestVersion(pattern *regexp.Regexp, data []byte, newest string) (version string) {
	version = newest

	for start := 0; start < len(data); {
		match := pattern.FindSubmatchIndex(data[start:])

		if match == nil {
			break
		}

		found := strings.ReplaceAll(string(data[start+match[2]:start+match[3]]), "\x00", "")

		if compareChromiumVersions(found, version) > 0 {
			version = found
		}

		start += match[1] - 1
	}

	return
}

// the Chromium version an apk's binary AndroidManifest.xml names as its versionName, ErrNoChromiumVersion without one or without the apk
func manifestVersion(apkPath string) (version string, err error) {
	reader, openErr := zip.OpenReader(apkPath)

	if openErr != nil {
		err = fmt.Errorf("%w, and %s can't be read for its versionName: %w", ErrNoChromiumVersion, apkPath, openErr)
		return
	}

	defer func() {
		err = errors.Join(err, reader.Close())
	}()

	manifest, openErr := reader.Open(manifestName)

	if openErr != nil {
		err = fmt.Errorf("%w, and %s has no %s: %w", ErrNoChromiumVersion, apkPath, manifestName, openErr)
		return
	}

	defer func() {
		err = errors.Join(err, manifest.Close())
	}()

	data, readErr := io.ReadAll(io.LimitReader(manifest, maxManifestSize))

	if err = readErr; err != nil {
		err = fmt.Errorf("%w: %s: %s: %w", ErrReadAPK, apkPath, manifestName, err)
		return
	}

	for _, pattern := range manifestVersionPatterns {
		version = newestVersion(pattern, data, version)
	}

	if version == "" {
		err = fmt.Errorf("%w, nor has the versionName of %s", ErrNoChromiumVersion, apkPath)
		return
	}

	return
}

// the offsets of the BoringSSL the Chromium version builds with, from the generated table: its branch MAJOR.0.BUILD and the range of patch numbers
// that holds its PATCH; an unknown version names the nearest known branch and the make command that adds it
func GetChromiumOffset(version string, architecture string) (offset Offset, revision string, err error) {
	branch, patch, parseErr := splitChromiumVersion(version)

	if err = parseErr; err != nil {
		return
	}

	for _, current := range chromiumBranches[branch] {
		if (patch < current.First) || (patch > current.Last) {
			continue
		}

		for _, group := range chromiumRevisionOffsets {
			if !slices.Contains(group.Revisions, current.Revision) {
				continue
			}

			var found bool

			if offset, found = group.Offsets[architecture]; !found {
				err = fmt.Errorf("%w: %s", ErrUnsupportedMachine, architecture)
				return
			}

			revision = current.Revision
			return
		}

		err = fmt.Errorf("%w: Chromium %s has BoringSSL %s without offsets in the table", ErrUnknownChromiumVersion, version, current.Revision)
		return
	}

	err = fmt.Errorf("%w: Chromium %s on %s, the nearest known is %s; run make generate-chrome-offsets CHROME_VERSIONS=\"branches %s\" and rebuild", ErrUnknownChromiumVersion, version, architecture, nearestChromiumVersion(version), version)
	return
}

// a Chromium version as its branch MAJOR.0.BUILD and patch number
func splitChromiumVersion(version string) (branch string, patch int, err error) {
	match := chromiumVersionNumbersPattern.FindStringSubmatch(version)

	if match == nil {
		err = fmt.Errorf("%w: %q is no MAJOR.0.BUILD.PATCH", ErrUnknownChromiumVersion, version)
		return
	}

	branch = match[1] + ".0." + match[2]
	patch, err = strconv.Atoi(match[3])

	if err != nil {
		err = fmt.Errorf("%w: %q: %w", ErrUnknownChromiumVersion, version, err)
		return
	}

	return
}

// the known version range closest to version, as first to last: the newest one before it, or the oldest one after it when there is none before
func nearestChromiumVersion(version string) (nearest string) {
	known := KnownChromiumVersions()

	for _, current := range known {
		first, _, _ := strings.Cut(current, " to ")

		if (nearest != "") && (compareChromiumVersions(first, version) > 0) {
			break
		}

		nearest = current
	}

	return
}

// the version ranges of the generated table, oldest first, as first to last (one version on its own)
func KnownChromiumVersions() (ranges []string) {
	type versionRange struct {
		first string
		last  string
	}

	known := []versionRange{}

	for branch, current := range chromiumBranches {
		for _, patches := range current {
			known = append(known, versionRange{first: branch + "." + strconv.Itoa(patches.First), last: branch + "." + strconv.Itoa(patches.Last)})
		}
	}

	slices.SortFunc(known, func(first versionRange, second versionRange) (order int) {
		order = compareChromiumVersions(first.first, second.first)
		return
	})

	for _, current := range known {
		if current.first == current.last {
			ranges = append(ranges, current.first)
			continue
		}

		ranges = append(ranges, current.first+" to "+current.last)
	}

	return
}

// order of two MAJOR.0.BUILD.PATCH versions by their numbers; a version without numbers sorts first
func compareChromiumVersions(first string, second string) (order int) {
	parse := func(version string) (numbers [3]int) {
		match := chromiumVersionNumbersPattern.FindStringSubmatch(version)

		if match == nil {
			numbers = [3]int{-1, -1, -1}
			return
		}

		for index := range 3 {
			numbers[index], _ = strconv.Atoi(match[index+1])
		}

		return
	}
	firstNumbers := parse(first)
	secondNumbers := parse(second)
	order = cmp.Or(slices.Compare(firstNumbers[:], secondNumbers[:]), strings.Compare(first, second))
	return
}
