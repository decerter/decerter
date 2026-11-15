// SPDX-License-Identifier: AGPL-3.0-only

package openssl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/decerter/decerter/internal/platform"
)

// the libssl sonames decerter looks for by name, OpenSSL 3.x and 4.x; libcrypto has the same suffix
const (
	libsslPrefix    string = "libssl"
	libcryptoPrefix string = "libcrypto"
	// libssl.so.<major> and the versioned file names the soname links to (libssl.so.4.0.3), a mapping shows the file
	libsslPattern string = `^libssl\.so\.(\d+)(\.\d+)*$`
	// OpenSSL 1.1 and older are not supported, their mappings are skipped
	firstMajor int = 3
)

// glibc's cache of the dynamic linker (sysdeps/generic/dl-cache.h): a 48 byte header, 24 byte entries, strings addressed from the start of the header
const (
	linkerCachePath       string = "/etc/ld.so.cache"
	linkerCacheMagic      string = "glibc-ld.so.cache1.1"
	linkerCacheCountAt    int    = 20
	linkerCacheHeaderSize int    = 48
	linkerCacheEntrySize  int    = 24
)

var (
	// the sonames looked up in the linker cache, each one found is hooked: a host can have both (Fedora 45 with openssl3-libs)
	libsslNames  = []string{"libssl.so.3", "libssl.so.4"}
	libsslRegexp = regexp.MustCompile(libsslPattern)
	// flags of a libc6 ELF library for the architecture decerter runs on: FLAG_ELF_LIBC6 with FLAG_X8664_LIB64 or FLAG_AARCH64_LIB64
	linkerCacheFlags = map[string]uint32{
		"amd64": 0x0303,
		"arm64": 0x0a03,
	}
	// searched when there is no linker cache (musl) or the library is not in it
	libraryDirectories = []string{
		"/usr/lib/x86_64-linux-gnu",
		"/usr/lib/aarch64-linux-gnu",
		"/usr/lib64",
		"/usr/lib",
		"/lib64",
		"/lib",
		"/usr/local/lib",
	}
)

// override is the --libssl flag, the one library hooked then; empty means every libssl.so.3 and libssl.so.4 the dynamic linker would load for a process
// without its own search path, a host with both gets both; the version string is only in libcrypto, it is taken from the directory of libssl
func FindLibssl(override string) (libraries []Library, err error) {
	paths := []string{override}

	if override == "" {
		paths = findLibraries(libsslNames, findLibrary)
	}

	if len(paths) == 0 {
		err = fmt.Errorf("%w: %s, give its path with --libssl", ErrLibraryNotFound, strings.Join(libsslNames, " or "))
		return
	}

	for _, path := range paths {
		_, statErr := os.Stat(path)

		if err = statErr; err != nil {
			err = fmt.Errorf("%w: %w", ErrLibraryNotFound, err)
			return
		}

		libraries = append(libraries, Library{Libssl: path, Libcrypto: LibcryptoPath(path), Version: "", Offset: Offset{}})
	}

	return
}

// the path of each name find resolves, in the order of names, a path two names resolve to only once
func findLibraries(names []string, find func(name string) (path string)) (paths []string) {
	for _, name := range names {
		path := find(name)

		if (path != "") && !slices.Contains(paths, path) {
			paths = append(paths, path)
		}
	}

	return
}

// libcrypto next to libssl with the same suffix: libssl.so.3 → libcrypto.so.3, libssl.so.4.0.3 → libcrypto.so.4.0.3; a file not named libssl* gets
// libcrypto.so.3 like before 4.x
func LibcryptoPath(libsslPath string) (libcryptoPath string) {
	directory, name := filepath.Split(libsslPath)
	suffix, isLibssl := strings.CutPrefix(name, libsslPrefix)

	if !isLibssl {
		suffix = ".so.3"
	}

	libcryptoPath = filepath.Join(directory, libcryptoPrefix+suffix)
	return
}

// the libssl files of OpenSSL 3 and newer a process maps executable, from the text of /proc/<pid>/maps, as the process sees them (its mount namespace)
func MappedLibssl(maps string) (paths []string) {
	for _, mapping := range platform.ExecutableMappings(maps) {
		match := libsslRegexp.FindStringSubmatch(filepath.Base(mapping.Path))

		if match == nil {
			continue
		}

		major, convertErr := strconv.Atoi(match[1])

		if (convertErr != nil) || (major < firstMajor) || slices.Contains(paths, mapping.Path) {
			continue
		}

		paths = append(paths, mapping.Path)
	}

	return
}

// the version of the library's libcrypto and its offsets on the architecture, an unknown version names the nearest known one
func Inspect(library Library, architecture string) (inspected Library, err error) {
	inspected = library
	version, err := DetectVersion(library.Libcrypto)

	if err != nil {
		return
	}

	inspected.Version = version
	offset, err := GetOffset(version, architecture)

	if err != nil {
		return
	}

	inspected.Offset = offset
	return
}

func findLibrary(name string) (path string) {
	cache, readErr := os.ReadFile(linkerCachePath)

	if readErr == nil {
		path = findInLinkerCache(cache, name, linkerCacheFlags[runtime.GOARCH])
	}

	if path != "" {
		return
	}

	for _, directory := range libraryDirectories {
		candidate := filepath.Join(directory, name)

		if _, statErr := os.Stat(candidate); statErr == nil {
			path = candidate
			return
		}
	}

	return
}

// the first entry with the name and the flags of the architecture wins like in the dynamic linker, entries of glibc-hwcaps subdirectories (hwcap set) are skipped
func findInLinkerCache(cache []byte, name string, flags uint32) (path string) {
	// an old format cache can come first in the file, the new format header follows it
	start := bytes.Index(cache, []byte(linkerCacheMagic))

	if (start < 0) || (len(cache) < start+linkerCacheHeaderSize) {
		return
	}

	cache = cache[start:]
	count := int(binary.NativeEndian.Uint32(cache[linkerCacheCountAt:]))

	for index := range count {
		entryAt := linkerCacheHeaderSize + index*linkerCacheEntrySize

		if len(cache) < entryAt+linkerCacheEntrySize {
			return
		}

		entry := cache[entryAt : entryAt+linkerCacheEntrySize]
		entryFlags := binary.NativeEndian.Uint32(entry[0:])
		hwcap := binary.NativeEndian.Uint64(entry[16:])

		if (entryFlags != flags) || (hwcap != 0) {
			continue
		}

		if cacheString(cache, binary.NativeEndian.Uint32(entry[4:])) == name {
			path = cacheString(cache, binary.NativeEndian.Uint32(entry[8:]))
			return
		}
	}

	return
}

// a NUL terminated string of the cache, empty if the offset is outside of it
func cacheString(cache []byte, offset uint32) (text string) {
	if int64(offset) >= int64(len(cache)) {
		return
	}

	end := bytes.IndexByte(cache[offset:], 0)

	if end < 0 {
		return
	}

	text = string(cache[offset : int(offset)+end])
	return
}
