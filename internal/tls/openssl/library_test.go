// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package openssl

import (
	"encoding/binary"
	"os"
	"runtime"
	"slices"
	"testing"
)

// one entry of a test linker cache
type cacheEntry struct {
	Flags uint32
	Name  string
	Path  string
	Hwcap uint64
}

const (
	libsslName    string = "libssl.so.3"
	libssl4Name   string = "libssl.so.4"
	libcryptoName string = "libcrypto.so.3"
	x8664Flags    uint32 = 0x0303
	i386Flags     uint32 = 0x0003
	libsslPath    string = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	hwcapsPath    string = "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libssl.so.3"
	libssl32bit   string = "/usr/lib/i386-linux-gnu/libssl.so.3"
)

// Test if openssl.findInLinkerCache returns with the expected output.
func TestFindInLinkerCachePositive(state *testing.T) {
	// a glibc-hwcaps entry and the 32 bit library come first and are skipped, the first fitting entry wins
	entries := []cacheEntry{
		{Flags: x8664Flags, Name: libsslName, Path: hwcapsPath, Hwcap: 1 << 62},
		{Flags: i386Flags, Name: libsslName, Path: libssl32bit, Hwcap: 0},
		{Flags: x8664Flags, Name: libcryptoName, Path: "/usr/lib/x86_64-linux-gnu/libcrypto.so.3", Hwcap: 0},
		{Flags: x8664Flags, Name: libsslName, Path: libsslPath, Hwcap: 0},
		{Flags: x8664Flags, Name: libsslName, Path: "/lib/libssl.so.3", Hwcap: 0},
	}
	positiveCases := []struct {
		Cache    []byte
		Name     string
		Flags    uint32
		Expected string
	}{
		{Cache: linkerCache(entries, false), Name: libsslName, Flags: x8664Flags, Expected: libsslPath},
		// an old format cache in front of the new one
		{Cache: linkerCache(entries, true), Name: libsslName, Flags: x8664Flags, Expected: libsslPath},
		{Cache: linkerCache(entries, false), Name: libsslName, Flags: i386Flags, Expected: libssl32bit},
		// not there: another name, an architecture without an entry, no cache at all, a cache cut inside its entries
		{Cache: linkerCache(entries, false), Name: "libssl.so.1.1", Flags: x8664Flags, Expected: ""},
		{Cache: linkerCache(entries, false), Name: libsslName, Flags: 0x0a03, Expected: ""},
		{Cache: []byte("ld.so-1.7.0"), Name: libsslName, Flags: x8664Flags, Expected: ""},
		{Cache: linkerCache(entries, false)[:linkerCacheHeaderSize+2*linkerCacheEntrySize], Name: libsslName, Flags: x8664Flags, Expected: ""},
		{Cache: linkerCache(entries, false)[:linkerCacheHeaderSize-1], Name: libsslName, Flags: x8664Flags, Expected: ""},
	}

	for index, positive := range positiveCases {
		path := findInLinkerCache(positive.Cache, positive.Name, positive.Flags)

		if path != positive.Expected {
			state.Errorf("Test of openssl.findInLinkerCache function failed, case %d, path should be %q, path: %q", index, positive.Expected, path)
			return
		}
	}

	// the string of an entry that points outside of the cache or has no NUL is empty
	cache := linkerCache(entries[3:4], false)
	binary.NativeEndian.PutUint32(cache[linkerCacheHeaderSize+8:], uint32(len(cache)))

	if path := findInLinkerCache(cache, libsslName, x8664Flags); path != "" {
		state.Errorf("Test of openssl.findInLinkerCache function failed, path should be empty, path: %q", path)
		return
	}

	if text := cacheString([]byte("no nul"), 0); text != "" {
		state.Errorf("Test of openssl.cacheString function failed, text should be empty, text: %q", text)
		return
	}
}

// Test if openssl.findLibraries returns with the expected output: a host with libssl.so.3 and libssl.so.4 gets both, in the order of the names.
func TestFindLibrariesPositive(state *testing.T) {
	both := []cacheEntry{
		{Flags: x8664Flags, Name: libssl4Name, Path: "/lib64/libssl.so.4", Hwcap: 0},
		{Flags: x8664Flags, Name: libsslName, Path: "/lib64/libssl.so.3", Hwcap: 0},
		{Flags: x8664Flags, Name: "libcrypto.so.4", Path: "/lib64/libcrypto.so.4", Hwcap: 0},
	}
	// Fedora 45 without openssl3-libs, and a host where both names lead to one file
	only4 := []cacheEntry{{Flags: x8664Flags, Name: libssl4Name, Path: "/lib64/libssl.so.4", Hwcap: 0}}
	same := []cacheEntry{{Flags: x8664Flags, Name: libssl4Name, Path: "/lib64/libssl.so", Hwcap: 0}, {Flags: x8664Flags, Name: libsslName, Path: "/lib64/libssl.so", Hwcap: 0}}
	positiveCases := []struct {
		Name     string
		Entries  []cacheEntry
		Expected []string
	}{
		{Name: "both", Entries: both, Expected: []string{"/lib64/libssl.so.3", "/lib64/libssl.so.4"}},
		{Name: "only 4", Entries: only4, Expected: []string{"/lib64/libssl.so.4"}},
		{Name: "same file", Entries: same, Expected: []string{"/lib64/libssl.so"}},
	}

	for _, positive := range positiveCases {
		cache := linkerCache(positive.Entries, false)
		paths := findLibraries(libsslNames, func(name string) (path string) {
			path = findInLinkerCache(cache, name, x8664Flags)
			return
		})

		if !slices.Equal(paths, positive.Expected) {
			state.Errorf("Test of openssl.findLibraries function failed, case %q, paths should be %q, paths: %q", positive.Name, positive.Expected, paths)
			return
		}
	}
}

// Test if openssl.findLibraries returns with the expected output when no name is found: no library, an architecture whose entries are missing, a 32 bit
// library only, or an OpenSSL 1.1 only.
func TestFindLibrariesNegative(state *testing.T) {
	entries := []cacheEntry{
		{Flags: i386Flags, Name: libssl4Name, Path: "/usr/lib/i386-linux-gnu/libssl.so.4", Hwcap: 0},
		{Flags: x8664Flags, Name: "libssl.so.1.1", Path: "/usr/lib/libssl.so.1.1", Hwcap: 0},
	}

	for _, flags := range []uint32{x8664Flags, 0x0a03} {
		cache := linkerCache(entries, false)
		paths := findLibraries(libsslNames, func(name string) (path string) {
			path = findInLinkerCache(cache, name, flags)
			return
		})

		if len(paths) != 0 {
			state.Errorf("Test of openssl.findLibraries function failed, flags 0x%04x, paths should be empty, paths: %q", flags, paths)
			return
		}
	}
}

// Test if openssl.findInLinkerCache returns with the expected output for the linker cache of this host, skipped without one.
func TestFindInLinkerCacheSystemPositive(state *testing.T) {
	cache, err := os.ReadFile(linkerCachePath)

	if err != nil {
		state.Skipf("Test of openssl.findInLinkerCache skipped, no linker cache on this host: %s", err.Error())
	}

	// the flags of the architecture the test runs on, like decerter itself
	flags, found := linkerCacheFlags[runtime.GOARCH]
	path := findInLinkerCache(cache, "libc.so.6", flags)

	if !found || (path == "") {
		state.Errorf("Test of openssl.findInLinkerCache function failed, libc.so.6 should be in %s", linkerCachePath)
		return
	}

	if _, statErr := os.Stat(path); statErr != nil {
		state.Errorf("Test of openssl.findInLinkerCache function failed, %s should exist, error: %s", path, statErr.Error())
		return
	}
}

// a new format cache (glibc's dl-cache.h): header with the magic and the entry count, the entries, then the strings, addressed from the start of the header
func linkerCache(entries []cacheEntry, withOld bool) (cache []byte) {
	header := make([]byte, linkerCacheHeaderSize)
	copy(header, linkerCacheMagic)
	binary.NativeEndian.PutUint32(header[linkerCacheCountAt:], uint32(len(entries)))
	stringsAt := linkerCacheHeaderSize + len(entries)*linkerCacheEntrySize
	stringData := []byte{}
	table := []byte{}

	for _, entry := range entries {
		nameAt := stringsAt + len(stringData)
		stringData = append(append(stringData, entry.Name...), 0)
		pathAt := stringsAt + len(stringData)
		stringData = append(append(stringData, entry.Path...), 0)
		table = binary.NativeEndian.AppendUint32(table, entry.Flags)
		table = binary.NativeEndian.AppendUint32(table, uint32(nameAt))
		table = binary.NativeEndian.AppendUint32(table, uint32(pathAt))
		table = binary.NativeEndian.AppendUint32(table, 0)
		table = binary.NativeEndian.AppendUint64(table, entry.Hwcap)
	}

	cache = append(append(header, table...), stringData...)

	// the old format: its magic, a count of 0 and padding to 8 bytes
	if withOld {
		cache = append([]byte("ld.so-1.7.0\x00\x00\x00\x00\x00"), cache...)
	}

	return
}
