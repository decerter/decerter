// SPDX-License-Identifier: AGPL-3.0-only

package openssl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	libsslName    string = "libssl.so.3"
	libcryptoName string = "libcrypto.so.3"
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

// override is the --libssl flag, empty means the libssl the dynamic linker would load for a process without its own search path
// the version string is only in libcrypto, it is taken from the directory of libssl
func FindLibssl(override string) (libsslPath string, libcryptoPath string, err error) {
	libsslPath = override

	if libsslPath == "" {
		libsslPath = findLibrary(libsslName)
	}

	if libsslPath == "" {
		err = fmt.Errorf("%w: %s, give its path with --libssl", ErrLibraryNotFound, libsslName)
		return
	}

	_, err = os.Stat(libsslPath)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrLibraryNotFound, err)
		return
	}

	libcryptoPath = filepath.Join(filepath.Dir(libsslPath), libcryptoName)
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
