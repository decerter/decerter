// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package openssl_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/tls/openssl"
)

// one section of a test ELF, Size is set only for a section whose data the file does not have
type section struct {
	Name string
	Type elf.SectionType
	Data []byte
	Size uint64
}

// Test if openssl.DetectVersion returns with the expected output.
func TestDetectVersionPositive(state *testing.T) {
	positiveCases := []struct {
		Rodata   string
		Expected string
	}{
		{Rodata: "\x00OpenSSL 3.6.2 7 Apr 2026\x00", Expected: "3.6.2"},
		// the first version string wins, the build options come later in libcrypto
		{Rodata: "x\x00OpenSSL 3.0.13 30 Jan 2024\x00compiler: gcc OpenSSL 9.9.9\x00", Expected: "3.0.13"},
	}

	for _, positive := range positiveCases {
		path, err := writeELF(state.TempDir(), []section{{Name: ".text", Type: elf.SHT_PROGBITS, Data: []byte{0xc3}}, {Name: ".rodata", Type: elf.SHT_PROGBITS, Data: []byte(positive.Rodata)}})

		if err != nil {
			state.Fatalf("Test of openssl.DetectVersion failed, cannot write ELF, error: %s", err.Error())
		}

		version, err := openssl.DetectVersion(path)

		if (err != nil) || (version != positive.Expected) {
			state.Errorf("Test of openssl.DetectVersion function failed, version should be %s, version: %s, error: %v", positive.Expected, version, err)
			return
		}
	}
}

// Test if openssl.DetectVersion returns with the expected output for the libcrypto of this host, skipped without one.
func TestDetectVersionSystemPositive(state *testing.T) {
	libraries, err := openssl.FindLibssl("")

	if err != nil {
		state.Skipf("Test of openssl.DetectVersion skipped, no OpenSSL 3 or 4 on this host: %s", err.Error())
	}

	for _, library := range libraries {
		if _, statErr := os.Stat(library.Libcrypto); statErr != nil {
			state.Skipf("Test of openssl.DetectVersion skipped, no libcrypto next to %s: %s", library.Libssl, statErr.Error())
		}

		version, err := openssl.DetectVersion(library.Libcrypto)

		if (err != nil) || !regexp.MustCompile(`^[34]\.\d+\.\d+$`).MatchString(version) {
			state.Errorf("Test of openssl.DetectVersion function failed, library: %s, version should be 3.x.y or 4.x.y, version: %s, error: %v", library.Libcrypto, version, err)
			return
		}
	}
}

// Test if openssl.DetectVersion returns with the expected errors.
func TestDetectVersionNegative(state *testing.T) {
	directory := state.TempDir()
	notELF := filepath.Join(directory, "libcrypto.so.3")
	err := os.WriteFile(notELF, []byte("not an ELF file"), 0o600)

	if err != nil {
		state.Fatalf("Test of openssl.DetectVersion failed, cannot write file, error: %s", err.Error())
	}

	noRodata, err := writeELF(state.TempDir(), []section{{Name: ".text", Type: elf.SHT_PROGBITS, Data: []byte{0xc3}}})

	if err != nil {
		state.Fatalf("Test of openssl.DetectVersion failed, cannot write ELF, error: %s", err.Error())
	}

	noVersion, err := writeELF(state.TempDir(), []section{{Name: ".rodata", Type: elf.SHT_PROGBITS, Data: []byte("BoringSSL\x00OpenSSL 3\x00")}})

	if err != nil {
		state.Fatalf("Test of openssl.DetectVersion failed, cannot write ELF, error: %s", err.Error())
	}

	// a .rodata that runs past the end of the file
	cutRodata, err := writeELF(state.TempDir(), []section{{Name: ".rodata", Type: elf.SHT_PROGBITS, Data: nil, Size: 1 << 20}})

	if err != nil {
		state.Fatalf("Test of openssl.DetectVersion failed, cannot write ELF, error: %s", err.Error())
	}

	negativeCases := []struct {
		Path string
		Err  error
	}{
		{Path: filepath.Join(directory, "missing.so"), Err: openssl.ErrOpenLibrary},
		{Path: notELF, Err: openssl.ErrOpenLibrary},
		{Path: noRodata, Err: openssl.ErrNoRodata},
		{Path: noVersion, Err: openssl.ErrNoVersion},
		{Path: cutRodata, Err: openssl.ErrReadRodata},
	}

	for _, negative := range negativeCases {
		_, err = openssl.DetectVersion(negative.Path)

		if !errors.Is(err, negative.Err) || !strings.Contains(err.Error(), negative.Path) {
			state.Errorf("Test of openssl.DetectVersion function failed, path: %s, error should be %v naming the path, error: %v", negative.Path, negative.Err, err)
			return
		}
	}
}

// Test if openssl.GetOffset returns with the expected output.
func TestGetOffsetPositive(state *testing.T) {
	// the 3.6.2 offsets were checked against Debian's libssl and SSLKEYLOGFILE in stages 7 to 9
	offset362 := openssl.Offset{
		HasType:                true,
		Type:                   0x0,
		SSLConnection:          0x0,
		Version:                0x48,
		ClientRandom:           0x188,
		Session:                0x900,
		MasterKey:              0x50,
		MasterKeyLength:        0x8,
		ClientAppTrafficSecret: 0x77c,
		ServerAppTrafficSecret: 0x7bc,
		HandshakeSecret:        0x5bc,
		HandshakeTrafficHash:   0x73c,
		SessionCipher:          0x2f8,
		CipherId:               0x18,
	}
	// up to 3.1 the SSL is the connection and has no type field, checked against Ubuntu 24.04's 3.0.13 in stage 29
	offset30 := openssl.Offset{
		HasType:                false,
		Type:                   0x0,
		SSLConnection:          0x0,
		Version:                0x0,
		ClientRandom:           0x160,
		Session:                0x918,
		MasterKey:              0x50,
		MasterKeyLength:        0x8,
		ClientAppTrafficSecret: 0x744,
		ServerAppTrafficSecret: 0x784,
		HandshakeSecret:        0x584,
		HandshakeTrafficHash:   0x704,
		SessionCipher:          0x2f8,
		CipherId:               0x18,
	}
	offset410 := offset362
	offset410.ClientRandom = 0x190
	offset410.Session = 0x948
	offset410.ClientAppTrafficSecret = 0x7c4
	offset410.ServerAppTrafficSecret = 0x804
	offset410.HandshakeSecret = 0x604
	offset410.HandshakeTrafficHash = 0x784
	positiveCases := []struct {
		Version      string
		Architecture string
		Expected     openssl.Offset
	}{
		{Version: "3.6.2", Architecture: "amd64", Expected: offset362},
		{Version: "3.6.2", Architecture: "arm64", Expected: offset362},
		// 3.5.x and 3.6.x share one layout
		{Version: "3.5.0", Architecture: "amd64", Expected: offset362},
		// the first and the last release of a range, and the withdrawn 3.0.6 inside one
		{Version: "3.0.0", Architecture: "amd64", Expected: offset30},
		{Version: "3.0.6", Architecture: "amd64", Expected: offset30},
		{Version: "3.0.13", Architecture: "arm64", Expected: offset30},
		{Version: "3.1.8", Architecture: "amd64", Expected: offset30},
		// OpenSSL 4.0 (libssl.so.4) kept the 3.5 layout, Fedora 45's 4.0.3 checked in stage 38; 4.1 moved everything from s3 on
		{Version: "4.0.0", Architecture: "amd64", Expected: offset362},
		{Version: "4.0.3", Architecture: "arm64", Expected: offset362},
		{Version: "4.1.0", Architecture: "amd64", Expected: offset410},
		{Version: "4.1.0", Architecture: "arm64", Expected: offset410},
	}

	for _, positive := range positiveCases {
		offset, err := openssl.GetOffset(positive.Version, positive.Architecture)

		if (err != nil) || (offset != positive.Expected) {
			state.Errorf("Test of openssl.GetOffset function failed, version: %s %s, offset should be %+v, offset: %+v, error: %v", positive.Version, positive.Architecture, positive.Expected, offset, err)
			return
		}
	}

	// 3.2.3 moved SSL_SESSION.cipher back and 3.2.4 grew the connection, so 3.2.2 to 3.2.4 are three ranges
	previous := openssl.Offset{}

	for _, version := range []string{"3.2.2", "3.2.3", "3.2.4"} {
		offset, err := openssl.GetOffset(version, "amd64")

		if (err != nil) || (offset == previous) || !offset.HasType {
			state.Errorf("Test of openssl.GetOffset function failed, version: %s, offset should differ from the release before, offset: %+v, error: %v", version, offset, err)
			return
		}

		previous = offset
	}
}

// Test if openssl.GetOffset returns with the expected errors.
func TestGetOffsetNegative(state *testing.T) {
	negativeCases := []struct {
		Version      string
		Architecture string
		Err          error
		Message      string
	}{
		// a patch release after the table, a series and a major after it, one before it
		{Version: "3.6.99", Architecture: "amd64", Err: openssl.ErrUnknownVersion, Message: "nearest known version is 3.6.5"},
		{Version: "3.7.0", Architecture: "arm64", Err: openssl.ErrUnknownVersion, Message: "nearest known version is 3.6.5"},
		// unknown 4.x: a patch release after the 4.0 range, a series after the table, a major after it
		{Version: "4.0.4", Architecture: "amd64", Err: openssl.ErrUnknownVersion, Message: "4.0.4 on amd64, the nearest known version is 4.0.3, run make generate-openssl-offsets"},
		{Version: "4.0.99", Architecture: "arm64", Err: openssl.ErrUnknownVersion, Message: "nearest known version is 4.0.3"},
		{Version: "4.2.0", Architecture: "amd64", Err: openssl.ErrUnknownVersion, Message: "nearest known version is 4.1.0"},
		{Version: "5.0.0", Architecture: "amd64", Err: openssl.ErrUnknownVersion, Message: "nearest known version is 4.1.0"},
		{Version: "1.1.1", Architecture: "amd64", Err: openssl.ErrUnknownVersion, Message: "nearest known version is 3.0.0"},
		{Version: "3.0.23", Architecture: "amd64", Err: openssl.ErrUnknownVersion, Message: "3.0.23 on amd64, the nearest known version is 3.0.22, run make generate-openssl-offsets"},
		// not x.y.z, no nearest version
		{Version: "3.6", Architecture: "amd64", Err: openssl.ErrVersionFormat, Message: `"3.6" on amd64`},
		{Version: "", Architecture: "amd64", Err: openssl.ErrVersionFormat, Message: `""`},
		{Version: "3.6.x", Architecture: "amd64", Err: openssl.ErrVersionFormat, Message: `"3.6.x"`},
		{Version: "3.6.2", Architecture: "riscv64", Err: openssl.ErrUnknownArchitecture, Message: "riscv64"},
	}

	for _, negative := range negativeCases {
		_, err := openssl.GetOffset(negative.Version, negative.Architecture)

		if !errors.Is(err, negative.Err) || !strings.Contains(err.Error(), negative.Message) {
			state.Errorf("Test of openssl.GetOffset function failed, version: %q %s, error should be %v naming %q, error: %v", negative.Version, negative.Architecture, negative.Err, negative.Message, err)
			return
		}
	}
}

// Test if openssl.FindLibssl returns with the expected output.
func TestFindLibsslPositive(state *testing.T) {
	directory := state.TempDir()
	positiveCases := []struct {
		Libssl    string
		Libcrypto string
	}{
		// libcrypto is taken from the directory of libssl with the same suffix, it does not have to exist yet
		{Libssl: "libssl.so.3", Libcrypto: "libcrypto.so.3"},
		{Libssl: "libssl.so.4", Libcrypto: "libcrypto.so.4"},
		{Libssl: "libssl.so.4.0.3", Libcrypto: "libcrypto.so.4.0.3"},
		// a file not named libssl gets libcrypto.so.3 like before 4.x
		{Libssl: "renamed.so", Libcrypto: "libcrypto.so.3"},
	}

	for _, positive := range positiveCases {
		libssl := filepath.Join(directory, positive.Libssl)
		err := os.WriteFile(libssl, nil, 0o600)

		if err != nil {
			state.Fatalf("Test of openssl.FindLibssl failed, cannot write file, error: %s", err.Error())
		}

		libraries, err := openssl.FindLibssl(libssl)
		expected := []openssl.Library{{Libssl: libssl, Libcrypto: filepath.Join(directory, positive.Libcrypto), Version: "", Offset: openssl.Offset{}}}

		if (err != nil) || !slices.Equal(libraries, expected) {
			state.Errorf("Test of openssl.FindLibssl function failed, libraries should be %+v, libraries: %+v, error: %v", expected, libraries, err)
			return
		}
	}
}

// Test if openssl.FindLibssl returns with the expected errors.
func TestFindLibsslNegative(state *testing.T) {
	_, err := openssl.FindLibssl(filepath.Join(state.TempDir(), "libssl.so.4"))

	if !errors.Is(err, openssl.ErrLibraryNotFound) || !errors.Is(err, os.ErrNotExist) {
		state.Errorf("Test of openssl.FindLibssl function failed, error should be %v, error: %v", openssl.ErrLibraryNotFound, err)
		return
	}
}

// Test if openssl.Inspect returns with the expected output for an OpenSSL 3 and an OpenSSL 4 libcrypto.
func TestInspectPositive(state *testing.T) {
	for _, version := range []string{"3.6.2", "4.0.3", "4.1.0"} {
		libcrypto, err := writeELF(state.TempDir(), []section{{Name: ".rodata", Type: elf.SHT_PROGBITS, Data: []byte("\x00OpenSSL " + version + " 29 Sep 2026\x00")}})

		if err != nil {
			state.Fatalf("Test of openssl.Inspect failed, cannot write ELF, error: %s", err.Error())
		}

		expected, err := openssl.GetOffset(version, "amd64")

		if err != nil {
			state.Fatalf("Test of openssl.Inspect failed, no offsets for %s, error: %s", version, err.Error())
		}

		library, err := openssl.Inspect(openssl.Library{Libssl: "/usr/lib64/libssl.so.4", Libcrypto: libcrypto, Version: "", Offset: openssl.Offset{}}, "amd64")

		if (err != nil) || (library.Version != version) || (library.Offset != expected) || (library.Libssl != "/usr/lib64/libssl.so.4") {
			state.Errorf("Test of openssl.Inspect function failed, version should be %s with %+v, library: %+v, error: %v", version, expected, library, err)
			return
		}
	}
}

// Test if openssl.Inspect returns with the expected errors: an unknown 4.x names the nearest known version and keeps the version it read.
func TestInspectNegative(state *testing.T) {
	libcrypto, err := writeELF(state.TempDir(), []section{{Name: ".rodata", Type: elf.SHT_PROGBITS, Data: []byte("\x00OpenSSL 4.0.9 1 Jan 2027\x00")}})

	if err != nil {
		state.Fatalf("Test of openssl.Inspect failed, cannot write ELF, error: %s", err.Error())
	}

	negativeCases := []struct {
		Libcrypto string
		Version   string
		Err       error
		Message   string
	}{
		{Libcrypto: libcrypto, Version: "4.0.9", Err: openssl.ErrUnknownVersion, Message: "4.0.9 on amd64, the nearest known version is 4.0.3"},
		{Libcrypto: filepath.Join(state.TempDir(), "libcrypto.so.4"), Version: "", Err: openssl.ErrOpenLibrary, Message: "libcrypto.so.4"},
	}

	for _, negative := range negativeCases {
		library, err := openssl.Inspect(openssl.Library{Libssl: "libssl.so.4", Libcrypto: negative.Libcrypto, Version: "", Offset: openssl.Offset{}}, "amd64")

		if !errors.Is(err, negative.Err) || !strings.Contains(err.Error(), negative.Message) || (library.Version != negative.Version) || (library.Offset != openssl.Offset{}) {
			state.Errorf("Test of openssl.Inspect function failed, error should be %v naming %q with version %q, library: %+v, error: %v", negative.Err, negative.Message, negative.Version, library, err)
			return
		}
	}
}

// Test if openssl.MappedLibssl returns with the expected output.
func TestMappedLibsslPositive(state *testing.T) {
	maps := strings.Join([]string{
		"7f0000000000-7f0000020000 r--p 00000000 00:2a 1234 /usr/lib64/libssl.so.4.0.3",
		"7f0000020000-7f00000a0000 r-xp 00020000 00:2a 1234 /usr/lib64/libssl.so.4.0.3",
		"7f00000a0000-7f00000c0000 r-xp 00020000 00:2a 1235 /usr/lib/x86_64-linux-gnu/libssl.so.3",
		"7f00000c0000-7f00000e0000 r-xp 00020000 00:2a 1236 /opt/app dir/lib/libssl.so.3",
		// mapped twice executable, listed once
		"7f00000e0000-7f0000100000 r-xp 00040000 00:2a 1235 /usr/lib/x86_64-linux-gnu/libssl.so.3",
	}, "\n")
	expected := []string{"/usr/lib64/libssl.so.4.0.3", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "/opt/app dir/lib/libssl.so.3"}
	paths := openssl.MappedLibssl(maps)

	if !slices.Equal(paths, expected) {
		state.Errorf("Test of openssl.MappedLibssl function failed, paths should be %q, paths: %q", expected, paths)
		return
	}
}

// Test if openssl.MappedLibssl returns with the expected output for mappings that are no OpenSSL 3 or newer libssl.
func TestMappedLibsslNegative(state *testing.T) {
	maps := strings.Join([]string{
		// not executable, OpenSSL 1.1, libcrypto, a look-alike name, a deleted file, anonymous memory, a short line
		"7f0000000000-7f0000020000 r--p 00000000 00:2a 1234 /usr/lib64/libssl.so.4",
		"7f0000020000-7f00000a0000 r-xp 00020000 00:2a 1237 /usr/lib/libssl.so.1.1",
		"7f00000a0000-7f00000c0000 r-xp 00020000 00:2a 1238 /usr/lib64/libcrypto.so.4",
		"7f00000c0000-7f00000e0000 r-xp 00020000 00:2a 1239 /usr/lib64/libssl.so.3.bak",
		"7f00000e0000-7f0000100000 r-xp 00020000 00:2a 1240 /usr/lib64/libssl.so.3 (deleted)",
		"7f0000100000-7f0000120000 r-xp 00000000 00:00 0 [vdso]",
		"7f0000120000-7f0000140000 r-xp",
	}, "\n")

	if paths := openssl.MappedLibssl(maps); len(paths) != 0 {
		state.Errorf("Test of openssl.MappedLibssl function failed, paths should be empty, paths: %q", paths)
		return
	}
}

// a little-endian ELF64 shared object for x86-64 with the sections and no program headers: header, section data, .shstrtab, section headers
func writeELF(directory string, sections []section) (path string, err error) {
	sections = append(sections, section{Name: ".shstrtab", Type: elf.SHT_STRTAB, Data: nil, Size: 0})
	names := []byte{0}
	nameOffsets := []uint32{}

	for _, current := range sections {
		nameOffsets = append(nameOffsets, uint32(len(names)))
		names = append(names, current.Name...)
		names = append(names, 0)
	}

	sections[len(sections)-1].Data = names
	data := []byte{}
	headers := []elf.Section64{{}}
	headerLength := uint64(binary.Size(elf.Header64{}))

	for index, current := range sections {
		size := current.Size

		if size == 0 {
			size = uint64(len(current.Data))
		}

		headers = append(headers, elf.Section64{Name: nameOffsets[index], Type: uint32(current.Type), Off: headerLength + uint64(len(data)), Size: size, Addralign: 1})
		data = append(data, current.Data...)
	}

	header := elf.Header64{
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Shoff:     headerLength + uint64(len(data)),
		Ehsize:    uint16(headerLength),
		Shentsize: uint16(binary.Size(elf.Section64{})),
		Shnum:     uint16(len(headers)),
		Shstrndx:  uint16(len(headers) - 1),
	}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	output := bytes.Buffer{}

	for _, part := range []any{header, data, headers} {
		err = binary.Write(&output, binary.LittleEndian, part)

		if err != nil {
			err = fmt.Errorf("could not write ELF: %w", err)
			return
		}
	}

	path = filepath.Join(directory, "libcrypto.so.3")
	err = os.WriteFile(path, output.Bytes(), 0o600)
	return
}
