// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package boringssl_test

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/tls/boringssl"
)

// an apk with one entry written as it is, compressed with Deflate: data that is no Deflate stream fails when the entry is read
func writeRawAPK(path string, name string, data []byte) (err error) {
	output := &bytes.Buffer{}
	writer := zip.NewWriter(output)
	created, err := writer.CreateRaw(&zip.FileHeader{Name: name, Method: zip.Deflate, CRC32: 0, CompressedSize64: uint64(len(data)), UncompressedSize64: uint64(len(data))})

	if err != nil {
		return
	}

	_, err = created.Write(data)

	if err = errors.Join(err, writer.Close()); err != nil {
		return
	}

	err = os.WriteFile(path, output.Bytes(), 0o600)
	return
}

// Test if boringssl.FindChromiumLibraries and boringssl.FindFlutterLibrary return with the expected errors: a lib/<isa> that is no directory, an
// install directory whose name is no glob pattern.
func TestFindLibrariesPathNegative(state *testing.T) {
	notDirectory := state.TempDir()
	err := os.MkdirAll(filepath.Join(notDirectory, "lib"), 0o700)

	if err == nil {
		err = os.WriteFile(filepath.Join(notDirectory, "lib", "x86_64"), []byte("x"), 0o600)
	}

	if err != nil {
		state.Fatalf("Test of boringssl.FindChromiumLibraries failed, cannot create the app, error: %s", err.Error())
	}

	_, err = boringssl.FindChromiumLibraries(notDirectory, "amd64")

	if !errors.Is(err, boringssl.ErrLibraryNotFound) {
		state.Errorf("Test of boringssl.FindChromiumLibraries function failed, a file as lib/x86_64 should be %v, error: %v", boringssl.ErrLibraryNotFound, err)
		return
	}

	_, found, err := boringssl.FindFlutterLibrary(notDirectory, "amd64")

	if found || !errors.Is(err, boringssl.ErrLibraryNotFound) {
		state.Errorf("Test of boringssl.FindFlutterLibrary function failed, a file as lib/x86_64 should be %v, found: %v, error: %v", boringssl.ErrLibraryNotFound, found, err)
		return
	}

	badPattern := filepath.Join(state.TempDir(), "com.example[-a==")
	_, err = boringssl.FindChromiumLibraries(badPattern, "amd64")

	if !errors.Is(err, filepath.ErrBadPattern) {
		state.Errorf("Test of boringssl.FindChromiumLibraries function failed, error should be %v, error: %v", filepath.ErrBadPattern, err)
		return
	}

	_, found, err = boringssl.FindFlutterLibrary(badPattern, "amd64")

	if found || !errors.Is(err, filepath.ErrBadPattern) {
		state.Errorf("Test of boringssl.FindFlutterLibrary function failed, error should be %v, found: %v, error: %v", filepath.ErrBadPattern, found, err)
		return
	}
}

// Test if boringssl.InspectChromium and boringssl.InspectFlutter return with the expected errors for a library that is missing or no ELF file,
// and a libflutter.so without labels.
func TestInspectLibraryNegative(state *testing.T) {
	directory := state.TempDir()
	notELF := filepath.Join(directory, "libmonochrome_64.so")
	noLabels := filepath.Join(directory, "libflutter.so")
	data, _ := staticLibrary{Machine: elf.EM_X86_64, Labels: nil, DecoyLabels: 0, Version: knownDart, MergedLabel: false, TailCalls: false, TwoTargets: false, Strings: nil}.build()
	err := errors.Join(os.WriteFile(notELF, []byte("no ELF file"), 0o600), os.WriteFile(noLabels, data, 0o600))

	if err != nil {
		state.Fatalf("Test of boringssl.InspectChromium failed, cannot write the libraries, error: %s", err.Error())
	}

	for _, path := range []string{filepath.Join(directory, "missing.so"), notELF} {
		file := boringssl.LibraryFile{Path: path, Entry: "", Offset: 0, Size: 11}
		_, chromiumErr := boringssl.InspectChromium(file, "amd64")
		_, flutterErr := boringssl.InspectFlutter(file, "amd64")

		if !errors.Is(chromiumErr, boringssl.ErrOpenLibrary) || !errors.Is(flutterErr, boringssl.ErrOpenLibrary) {
			state.Errorf("Test of boringssl.InspectChromium function failed, %s should be %v, errors: %v, %v", path, boringssl.ErrOpenLibrary, chromiumErr, flutterErr)
			return
		}
	}

	library, err := boringssl.InspectFlutter(boringssl.LibraryFile{Path: noLabels, Entry: "", Offset: 0, Size: uint64(len(data))}, "amd64")

	if (err == nil) || (library.DartVersion != knownDart) || (library.LogSecret != 0) {
		state.Errorf("Test of boringssl.InspectFlutter function failed, a library without labels should fail after its version, library: %+v, error: %v", library, err)
		return
	}
}

// Test if boringssl.InspectChromium returns with the expected errors for an extracted library without a version string whose base.apk has no
// manifest, a manifest without a versionName or one that can't be read.
func TestInspectChromiumManifestNegative(state *testing.T) {
	data, _ := chromiumLibrary(elf.EM_X86_64, allLabels, nil)
	negativeCases := []struct {
		Name     string
		Write    func(apk string) (err error)
		Expected error
	}{
		{
			Name: "no manifest",
			Write: func(apk string) (err error) {
				err = writeAPK(apk, []apkEntry{{Name: "classes.dex", Data: []byte("dex"), Stored: false, Unaligned: false}})
				return
			},
			Expected: boringssl.ErrNoChromiumVersion,
		},
		{
			Name: "no versionName",
			Write: func(apk string) (err error) {
				err = writeAPK(apk, []apkEntry{{Name: "AndroidManifest.xml", Data: manifest("release", false), Stored: false, Unaligned: false}})
				return
			},
			Expected: boringssl.ErrNoChromiumVersion,
		},
		{
			Name: "a manifest that is no Deflate stream",
			Write: func(apk string) (err error) {
				err = writeRawAPK(apk, "AndroidManifest.xml", []byte{0xff, 0xff, 0xff, 0xff})
				return
			},
			Expected: boringssl.ErrReadAPK,
		},
	}

	for _, negative := range negativeCases {
		directory := state.TempDir()
		path := filepath.Join(directory, "lib", "x86_64", "libwebviewchromium.so")
		err := os.MkdirAll(filepath.Dir(path), 0o700)

		if err == nil {
			err = errors.Join(os.WriteFile(path, data, 0o600), negative.Write(filepath.Join(directory, "base.apk")))
		}

		if err != nil {
			state.Fatalf("Test of boringssl.InspectChromium failed, case %q, cannot write the app, error: %s", negative.Name, err.Error())
		}

		_, err = boringssl.InspectChromium(boringssl.LibraryFile{Path: path, Entry: "", Offset: 0, Size: uint64(len(data))}, "amd64")

		if !errors.Is(err, negative.Expected) {
			state.Errorf("Test of boringssl.InspectChromium function failed, case %q, error should be %v, error: %v", negative.Name, negative.Expected, err)
		}
	}
}

// Test if boringssl.FindLogSecret returns with the expected errors for MiniDebugInfo that is cut: the xz stream ends early, the section reaches
// past the end of the file.
func TestFindLogSecretDebugDataNegative(state *testing.T) {
	compressed, err := compress(bytes.Repeat([]byte("debug data "), 100))

	if err != nil {
		state.Fatalf("Test of boringssl.FindLogSecret failed, cannot compress, error: %s", err.Error())
	}

	truncated, err := writeLibrary(state.TempDir(), []section{{Name: ".gnu_debugdata", Type: elf.SHT_PROGBITS, Flags: 0, Data: compressed[:len(compressed)/2], Link: "", Entsize: 0}})

	if err != nil {
		state.Fatalf("Test of boringssl.FindLogSecret failed, cannot write ELF, error: %s", err.Error())
	}

	_, err = boringssl.FindLogSecret(truncated)

	if !errors.Is(err, boringssl.ErrReadDebugData) {
		state.Errorf("Test of boringssl.FindLogSecret function failed, a cut xz stream should be %v, error: %v", boringssl.ErrReadDebugData, err)
		return
	}

	// the section headers are [null, .text, .gnu_debugdata, .shstrtab], the size of .gnu_debugdata is made larger than the file
	library, err := buildELF([]section{{Name: ".text", Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Data: bytes.Repeat([]byte{0xcc}, textLength), Link: "", Entsize: 0}, {Name: ".gnu_debugdata", Type: elf.SHT_PROGBITS, Flags: 0, Data: compressed, Link: "", Entsize: 0}}, true)

	if err != nil {
		state.Fatalf("Test of boringssl.FindLogSecret failed, cannot build ELF, error: %s", err.Error())
	}

	sectionHeaders := binary.LittleEndian.Uint64(library[0x28:])
	sizeOffset := sectionHeaders + 2*uint64(binary.Size(elf.Section64{})) + 32
	binary.LittleEndian.PutUint64(library[sizeOffset:], uint64(len(library))*2)
	path := filepath.Join(state.TempDir(), "libssl.so")

	if err = os.WriteFile(path, library, 0o600); err != nil {
		state.Fatalf("Test of boringssl.FindLogSecret failed, cannot write ELF, error: %s", err.Error())
	}

	_, err = boringssl.FindLogSecret(path)

	if !errors.Is(err, boringssl.ErrReadDebugData) {
		state.Errorf("Test of boringssl.FindLogSecret function failed, a section past the end should be %v, error: %v", boringssl.ErrReadDebugData, err)
		return
	}
}

// Test if boringssl.GetFlutterOffset returns with the expected errors for a Dart version without numbers: the nearest known one is the oldest.
func TestGetFlutterOffsetVersionNegative(state *testing.T) {
	_, _, _, err := boringssl.GetFlutterOffset("main", "amd64")
	oldest := boringssl.KnownDartVersions()[0]

	if !errors.Is(err, boringssl.ErrUnknownDartVersion) || !strings.Contains(err.Error(), fmt.Sprintf("the nearest known is Dart %s ", oldest)) {
		state.Errorf("Test of boringssl.GetFlutterOffset function failed, error should be %v naming Dart %s, error: %v", boringssl.ErrUnknownDartVersion, oldest, err)
		return
	}
}
