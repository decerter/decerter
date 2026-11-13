// SPDX-License-Identifier: AGPL-3.0-only

package boringssl

import (
	"archive/zip"
	"bytes"
	"cmp"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	// the Flutter engine, its Dart VM links BoringSSL statically and dart:io's SecureSocket uses it
	FlutterLibraryName string = "libflutter.so"
	// Android maps a library from the apk only when it is stored and page aligned (extractNativeLibs false, the default of current Gradle builds)
	apkPageSize uint64 = 4096
	// the Flutter engine names its revision as a 40 hex digit string
	engineRevisionLength int = 40
)

var (
	// the version string the Dart VM prints: 3.9.2 (stable) (Wed Aug 27 03:49:40 2025 -0700) on "android_x64"
	dartVersionPattern = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?) \([a-z]+\) \([^)\x00]*\) on "android_[a-z0-9]+"`)
	// the version's numbers, a pre-release part sorts it before the release
	versionNumbersPattern = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)(-.*)?$`)
)

// the directories an app's libraries are in for the architecture decerter runs on: inside the apk lib/<abi>/, extracted lib/<isa>/ of the install directory
// 32 bit apps are not hooked: their libflutter.so is another ELF class the uprobe can't read with the 64 bit registers
func abiDirectories(architecture string) (apkABI string, extractedISA string, err error) {
	switch architecture {
	case "amd64":
		apkABI = "x86_64"
		extractedISA = "x86_64"
	case "arm64":
		apkABI = "arm64-v8a"
		extractedISA = "arm64"
	default:
		err = fmt.Errorf("%w: %s", ErrUnsupportedMachine, architecture)
	}

	return
}

// the libflutter.so of an app's install directory (/data/app/~~…/<package>-…/): the extracted lib/<isa>/libflutter.so when the package manager
// extracted it, otherwise the stored lib/<abi>/libflutter.so of base.apk or a split apk; none without an error is no Flutter app
func FindFlutterLibrary(installDirectory string, architecture string) (library LibraryFile, found bool, err error) {
	apkABI, extractedISA, err := abiDirectories(architecture)

	if err != nil {
		return
	}

	extractedPath := filepath.Join(installDirectory, "lib", extractedISA, FlutterLibraryName)
	info, statErr := os.Stat(extractedPath)

	if statErr == nil {
		library = LibraryFile{Path: extractedPath, Entry: "", Offset: 0, Size: uint64(info.Size())}
		found = true
		return
	}

	if !errors.Is(statErr, fs.ErrNotExist) {
		err = fmt.Errorf("%w: %w", ErrLibraryNotFound, statErr)
		return
	}

	apks, globErr := filepath.Glob(filepath.Join(installDirectory, "*.apk"))

	if err = globErr; err != nil {
		return
	}

	slices.Sort(apks)
	entry := "lib/" + apkABI + "/" + FlutterLibraryName

	for _, apk := range apks {
		library, found, err = FindAPKEntry(apk, entry)

		if err != nil || found {
			return
		}
	}

	return
}

// the bytes of a stored entry in an apk, which a uprobe can attach to at the entry's data offset plus the offset inside the entry
// a compressed or unaligned entry is an error: Android extracts or refuses those, the library is never mapped from the apk then
func FindAPKEntry(apkPath string, name string) (library LibraryFile, found bool, err error) {
	reader, openErr := zip.OpenReader(apkPath)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrReadAPK, apkPath, err)
		return
	}

	defer func() {
		err = errors.Join(err, reader.Close())
	}()

	index := slices.IndexFunc(reader.File, func(file *zip.File) (isEntry bool) {
		isEntry = (file.Name == name)
		return
	})

	if index < 0 {
		return
	}

	entry := reader.File[index]

	if entry.Method != zip.Store {
		err = fmt.Errorf("%w: %s in %s", ErrCompressedLibrary, name, apkPath)
		return
	}

	offset, offsetErr := entry.DataOffset()

	if err = offsetErr; err != nil {
		err = fmt.Errorf("%w: %s: %s: %w", ErrReadAPK, apkPath, name, err)
		return
	}

	if (uint64(offset) % apkPageSize) != 0 {
		err = fmt.Errorf("%w: %s at 0x%x in %s", ErrUnalignedLibrary, name, offset, apkPath)
		return
	}

	library = LibraryFile{Path: apkPath, Entry: name, Offset: uint64(offset), Size: entry.UncompressedSize64}
	found = true
	return
}

// read a libflutter.so: the Dart version, a known engine revision, ssl_log_secret through its labels and the offsets of the Dart version
// the library is filled as far as it was read, an unknown Dart version (ErrUnknownDartVersion) still has the version and the hook
func InspectFlutter(file LibraryFile, architecture string) (library FlutterLibrary, err error) {
	library.File = file
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

	library.DartVersion, err = dartVersion(readOnly)

	if err != nil {
		return
	}

	library.Engine = knownEngine(readOnly)
	address, labels, err := findLogSecret(elfFile, readOnly, code)

	if err != nil {
		return
	}

	library.LogSecret = file.Offset + address
	library.Labels = labels
	library.Offset, library.Revision, library.Flutter, err = GetFlutterOffset(library.DartVersion, architecture)
	return
}

// a uprobe of the 64 bit programs can only read a library of the architecture decerter runs on
func checkMachine(file *elf.File, architecture string) (err error) {
	expected := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[architecture]

	if (file.Machine != expected) || (file.Class != elf.ELFCLASS64) {
		err = fmt.Errorf("%w: %s %s, decerter runs on %s", ErrWrongMachine, file.Class, file.Machine, architecture)
		return
	}

	return
}

// the Dart version from the version string the Dart VM prints, in .rodata
func dartVersion(readOnly []segment) (version string, err error) {
	for _, current := range readOnly {
		match := dartVersionPattern.FindSubmatch(current.data)

		if match != nil {
			version = string(match[1])
			return
		}
	}

	err = ErrNoDartVersion
	return
}

// the first NUL terminated 40 hex digit string that is an engine revision of the table, empty when there is none
// the engine embeds its revision, other revisions (Skia, Dart) are strings of the same form
func knownEngine(readOnly []segment) (engine string) {
	engines := map[string]bool{}

	for _, release := range dartReleases {
		for _, current := range release.Engines {
			engines[current] = true
		}
	}

	for _, current := range readOnly {
		data := current.data

		for start := 0; ; {
			found := bytes.IndexByte(data[start:], 0)

			if found < 0 {
				break
			}

			end := start + found

			if (end-start == engineRevisionLength) && engines[string(data[start:end])] {
				engine = string(data[start:end])
				return
			}

			start = end + 1
		}
	}

	return
}

// the offsets of the BoringSSL revision the Flutter engine builds with the Dart version, from the generated table, and the Flutter releases
// it was generated from; an unknown Dart version names the nearest known one and the make command that adds it
func GetFlutterOffset(dartVersion string, architecture string) (offset Offset, revision string, flutter []string, err error) {
	release, ok := dartReleases[dartVersion]

	if !ok {
		nearest, nearestFlutter := nearestDartVersion(dartVersion)
		err = fmt.Errorf("%w: Dart %s on %s, the nearest known is Dart %s (Flutter %s); run make generate-flutter-offsets FLUTTER_VERSIONS=<the app's Flutter release> and rebuild", ErrUnknownDartVersion, dartVersion, architecture, nearest, strings.Join(nearestFlutter, ", "))
		return
	}

	for _, group := range revisionOffsets {
		if !slices.Contains(group.Revisions, release.Revision) {
			continue
		}

		offset, ok = group.Offsets[architecture]

		if !ok {
			err = fmt.Errorf("%w: %s", ErrUnsupportedMachine, architecture)
			return
		}

		revision = release.Revision
		flutter = release.Flutter
		return
	}

	err = fmt.Errorf("%w: Dart %s has BoringSSL %s without offsets in the table", ErrUnknownDartVersion, dartVersion, release.Revision)
	return
}

// the known Dart version closest to version: the newest one before it, or the oldest one after it when there is none before
func nearestDartVersion(version string) (nearest string, flutter []string) {
	for _, current := range KnownDartVersions() {
		if (nearest != "") && (compareVersions(current, version) > 0) {
			break
		}

		nearest = current
	}

	if nearest != "" {
		flutter = dartReleases[nearest].Flutter
	}

	return
}

// the Dart versions of the generated table, oldest first
func KnownDartVersions() (versions []string) {
	versions = slices.SortedFunc(maps.Keys(dartReleases), compareVersions)
	return
}

// order of two x.y.z[-pre] versions by their numbers, a pre-release before its release; a version without numbers sorts first
func compareVersions(first string, second string) (order int) {
	parse := func(version string) (numbers [4]int) {
		match := versionNumbersPattern.FindStringSubmatch(version)

		if match == nil {
			numbers = [4]int{-1, -1, -1, -1}
			return
		}

		for index := range 3 {
			numbers[index], _ = strconv.Atoi(match[index+1])
		}

		// the release itself after its pre-releases
		if match[4] == "" {
			numbers[3] = 1
		}

		return
	}
	firstNumbers := parse(first)
	secondNumbers := parse(second)
	order = cmp.Or(slices.Compare(firstNumbers[:], secondNumbers[:]), strings.Compare(first, second))
	return
}
