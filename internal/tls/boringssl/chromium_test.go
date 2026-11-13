// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package boringssl_test

import (
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/tls/boringssl"
)

const (
	// Chrome of the decerter-a15 image, the table knows its branch, and a version it doesn't
	knownChrome   string = "124.0.6367.219"
	unknownChrome string = "999.0.9999.1"
	// apk entries of the Chromium test apks
	monochromeEntry string = "lib/x86_64/libmonochrome_64.so"
	cronetEntry     string = "lib/x86_64/libcronet.126.0.6452.4.so"
)

var (
	// the offsets of the BoringSSL Chrome 124 and Cronet 126 build with
	chromeOffset = boringssl.Offset{Version: 0x10, VersionInS3: false, S3: 0x30, ClientRandom: 0x30}
)

// a binary AndroidManifest.xml as far as the version search reads it: a string pool with the versionName, UTF-16LE (aapt) or UTF-8 (aapt2 --utf8),
// each string with its length before and a NUL after
func manifest(versionName string, utf16 bool) (data []byte) {
	data = []byte{0x03, 0x00, 0x08, 0x00, 0x01, 0x00, 0x1c, 0x00}

	for _, text := range []string{"versionName", versionName, "1.0.0.0"} {
		if !utf16 {
			data = append(append(append(data, byte(len(text)), byte(len(text))), text...), 0)
			continue
		}

		data = append(data, byte(len(text)), 0)

		for _, character := range text {
			data = append(data, byte(character), 0)
		}

		data = append(data, 0, 0)
	}

	return
}

// a Chromium test library with the strings given, every label and a decoy reached from one label
func chromiumLibrary(machine elf.Machine, labels []string, strings []string) (data []byte, logSecret uint64) {
	data, logSecret = staticLibrary{Machine: machine, Labels: labels, DecoyLabels: 1, Version: "", MergedLabel: false, TailCalls: false, TwoTargets: false, Strings: strings}.build()
	return
}

// Test if boringssl.FindChromiumLibraries returns with the expected output: extracted libraries, the stored ones of base.apk and a split apk, only
// Chromium names (no partition, linker or other library), the ABI directory of the architecture, nothing for another app.
func TestFindChromiumLibrariesPositive(state *testing.T) {
	directory := state.TempDir()
	library := []byte("\x7fELF library")
	err := errors.Join(
		writeAPK(filepath.Join(directory, "base.apk"), []apkEntry{
			{Name: "classes.dex", Data: []byte("dex"), Stored: false, Unaligned: false},
			{Name: monochromeEntry, Data: library, Stored: true, Unaligned: false},
			{Name: "lib/x86_64/libmonochrome_64_test_dummy_partition.so", Data: library, Stored: true, Unaligned: false},
			{Name: "lib/x86_64/libchromium_android_linker.so", Data: library, Stored: true, Unaligned: false},
			{Name: "lib/arm64-v8a/libmonochrome_64.so", Data: library, Stored: true, Unaligned: false},
			{Name: "lib/x86_64/libmonochrome_64.so.txt", Data: library, Stored: false, Unaligned: false},
		}),
		writeAPK(filepath.Join(directory, "split_cronet.apk"), []apkEntry{{Name: cronetEntry, Data: library, Stored: true, Unaligned: false}}),
		os.MkdirAll(filepath.Join(directory, "lib", "x86_64"), 0o700),
	)

	if err == nil {
		err = errors.Join(os.WriteFile(filepath.Join(directory, "lib", "x86_64", "libchrome.so"), library, 0o600), os.WriteFile(filepath.Join(directory, "lib", "x86_64", "libother.so"), library, 0o600))
	}

	if err != nil {
		state.Fatalf("Test of boringssl.FindChromiumLibraries failed, cannot write the app, error: %s", err.Error())
	}

	libraries, err := boringssl.FindChromiumLibraries(directory, "amd64")
	names := []string{}

	for _, current := range libraries {
		names = append(names, filepath.Base(current.Path)+"!"+current.Entry)

		if (current.Entry != "") && ((current.Offset%4096 != 0) || (current.Size != uint64(len(library)))) {
			state.Errorf("Test of boringssl.FindChromiumLibraries function failed, a stored entry should be page aligned with its size, library: %+v", current)
		}
	}

	expected := []string{"libchrome.so!", "base.apk!" + monochromeEntry, "split_cronet.apk!" + cronetEntry}

	if (err != nil) || !slices.Equal(names, expected) {
		state.Errorf("Test of boringssl.FindChromiumLibraries function failed, libraries should be %q, libraries: %q, error: %v", expected, names, err)
	}

	libraries, err = boringssl.FindChromiumLibraries(directory, "arm64")

	if (err != nil) || (len(libraries) != 1) || (libraries[0].Entry != "lib/arm64-v8a/libmonochrome_64.so") {
		state.Errorf("Test of boringssl.FindChromiumLibraries function failed, arm64 should find the arm64-v8a library, libraries: %+v, error: %v", libraries, err)
	}

	libraries, err = boringssl.FindChromiumLibraries(state.TempDir(), "amd64")

	if (err != nil) || (len(libraries) != 0) {
		state.Errorf("Test of boringssl.FindChromiumLibraries function failed, an empty directory has none, libraries: %+v, error: %v", libraries, err)
	}
}

// Test if boringssl.FindChromiumLibraries returns with the expected errors: a compressed or unaligned library, an apk that is no zip, an architecture
// without Android ABI.
func TestFindChromiumLibrariesNegative(state *testing.T) {
	negativeCases := []struct {
		Entries      []apkEntry
		Raw          []byte
		Architecture string
		Err          error
	}{
		{Entries: []apkEntry{{Name: monochromeEntry, Data: []byte("library"), Stored: false, Unaligned: false}}, Raw: nil, Architecture: "amd64", Err: boringssl.ErrCompressedLibrary},
		{Entries: []apkEntry{{Name: cronetEntry, Data: []byte("library"), Stored: true, Unaligned: true}}, Raw: nil, Architecture: "amd64", Err: boringssl.ErrUnalignedLibrary},
		{Entries: nil, Raw: []byte("not a zip"), Architecture: "amd64", Err: boringssl.ErrReadAPK},
		{Entries: []apkEntry{{Name: monochromeEntry, Data: []byte("library"), Stored: true, Unaligned: false}}, Raw: nil, Architecture: "riscv64", Err: boringssl.ErrUnsupportedMachine},
	}

	for index, negative := range negativeCases {
		directory := state.TempDir()
		apk := filepath.Join(directory, "base.apk")
		err := os.WriteFile(apk, negative.Raw, 0o600)

		if negative.Entries != nil {
			err = writeAPK(apk, negative.Entries)
		}

		if err != nil {
			state.Fatalf("Test of boringssl.FindChromiumLibraries failed, case %d, cannot write the apk, error: %s", index, err.Error())
		}

		_, err = boringssl.FindChromiumLibraries(directory, negative.Architecture)

		if !errors.Is(err, negative.Err) {
			state.Errorf("Test of boringssl.FindChromiumLibraries function failed, case %d, error should be %v, error: %v", index, negative.Err, err)
		}
	}
}

// Test if boringssl.InspectChromium returns with the expected output: the product by the library's name, the version by preference (Chrome's
// user agent token, Cronet's library name, the newest bare version), ssl_log_secret in the apk and the offsets of the version's branch.
func TestInspectChromiumPositive(state *testing.T) {
	positiveCases := []struct {
		Machine  elf.Machine
		Entry    string
		Strings  []string
		Product  string
		Version  string
		Revision string
	}{
		{Machine: elf.EM_X86_64, Entry: monochromeEntry, Strings: []string{"Chrome/" + knownChrome, "126.0.6452.4"}, Product: boringssl.ChromeProduct, Version: knownChrome, Revision: "4fa4804c8ab4521079af62dba5260a99c34b8a29"},
		{Machine: elf.EM_AARCH64, Entry: "lib/arm64-v8a/libmonochrome_64.so", Strings: []string{"Chrome/" + knownChrome}, Product: boringssl.ChromeProduct, Version: knownChrome, Revision: "4fa4804c8ab4521079af62dba5260a99c34b8a29"},
		{Machine: elf.EM_X86_64, Entry: cronetEntry, Strings: []string{"126.0.6452.4", "libcronet.126.0.6452.4.so", "10.0.2.2"}, Product: boringssl.CronetProduct, Version: "126.0.6452.4", Revision: "2db0eb3f96a5756298dcd7f9319e56a98585bd10"},
		{Machine: elf.EM_X86_64, Entry: "lib/x86_64/libchrome.so", Strings: []string{"153.0.8010.0", "Chrome/", "1.0.0.0"}, Product: boringssl.ChromeProduct, Version: "160.0.8161.0", Revision: "148a7b1f361dcf6708e9eb3b7c2134d0c5633e3e"},
		{Machine: elf.EM_X86_64, Entry: "lib/x86_64/libwebviewchromium.so", Strings: []string{"Chrome/" + knownChrome}, Product: boringssl.WebViewProduct, Version: knownChrome, Revision: "4fa4804c8ab4521079af62dba5260a99c34b8a29"},
	}

	for index, positive := range positiveCases {
		architecture := map[elf.Machine]string{elf.EM_X86_64: "amd64", elf.EM_AARCH64: "arm64"}[positive.Machine]
		data, logSecret := chromiumLibrary(positive.Machine, allLabels, positive.Strings)
		directory := state.TempDir()
		// the versionName of ChromePublic, the only version a library without one of its own gets
		err := writeAPK(filepath.Join(directory, "base.apk"), []apkEntry{{Name: "AndroidManifest.xml", Data: manifest("160.0.8161.0", true), Stored: false, Unaligned: false}, {Name: positive.Entry, Data: data, Stored: true, Unaligned: false}})

		if err != nil {
			state.Fatalf("Test of boringssl.InspectChromium failed, case %d, cannot write the apk, error: %s", index, err.Error())
		}

		files, err := boringssl.FindChromiumLibraries(directory, architecture)

		if (err != nil) || (len(files) != 1) {
			state.Fatalf("Test of boringssl.InspectChromium failed, case %d, cannot find the library, files: %+v, error: %v", index, files, err)
		}

		library, err := boringssl.InspectChromium(files[0], architecture)
		offset := chromeOffset

		if strings.HasPrefix(positive.Version, "160.") {
			offset = knownOffset
		}

		expected := boringssl.ChromiumLibrary{File: files[0], Product: positive.Product, Version: positive.Version, Revision: positive.Revision, Offset: offset, LogSecret: files[0].Offset + logSecret, Labels: len(allLabels) - 1}

		if (err != nil) || (library != expected) {
			state.Errorf("Test of boringssl.InspectChromium function failed, case %d, library should be %+v, library: %+v, error: %v", index, expected, library, err)
		}
	}
}

// Test if boringssl.InspectChromium returns with the expected output for an extracted library without a version of its own: the versionName of
// base.apk in its install directory, a UTF-8 string pool.
func TestInspectChromiumExtractedPositive(state *testing.T) {
	directory := state.TempDir()
	data, logSecret := chromiumLibrary(elf.EM_X86_64, allLabels, []string{"153.0.8010.0"})
	path := filepath.Join(directory, "lib", "x86_64", "libwebviewchromium.so")
	err := os.MkdirAll(filepath.Dir(path), 0o700)

	if err == nil {
		err = errors.Join(os.WriteFile(path, data, 0o600), writeAPK(filepath.Join(directory, "base.apk"), []apkEntry{{Name: "AndroidManifest.xml", Data: manifest(knownChrome, false), Stored: false, Unaligned: false}}))
	}

	if err != nil {
		state.Fatalf("Test of boringssl.InspectChromium failed, cannot write the app, error: %s", err.Error())
	}

	library, err := boringssl.InspectChromium(boringssl.LibraryFile{Path: path, Entry: "", Offset: 0, Size: uint64(len(data))}, "amd64")

	if (err != nil) || (library.Product != boringssl.WebViewProduct) || (library.Version != knownChrome) || (library.LogSecret != logSecret) || (library.Offset != chromeOffset) {
		state.Errorf("Test of boringssl.InspectChromium function failed, the extracted WebView should be %s from base.apk, library: %+v, error: %v", knownChrome, library, err)
	}
}

// Test if boringssl.InspectChromium returns with the expected errors: an unknown version and a patch outside the generated range (both with the
// version and the hook still read, the nearest known version and the make command), no version string (an address is none), no labels, another
// architecture than the one decerter runs on.
func TestInspectChromiumNegative(state *testing.T) {
	negativeCases := []struct {
		Machine      elf.Machine
		Labels       []string
		Strings      []string
		Architecture string
		Err          error
		Text         []string
	}{
		{Machine: elf.EM_X86_64, Labels: allLabels, Strings: []string{"Chrome/" + unknownChrome}, Architecture: "amd64", Err: boringssl.ErrUnknownChromiumVersion, Text: []string{unknownChrome, "the nearest known is 160.0.8161.0", "make generate-chrome-offsets CHROME_VERSIONS=\"branches " + unknownChrome + "\""}},
		{Machine: elf.EM_X86_64, Labels: allLabels, Strings: []string{"Chrome/124.0.6367.9999"}, Architecture: "amd64", Err: boringssl.ErrUnknownChromiumVersion, Text: []string{"124.0.6367.9999", "the nearest known is 124.0.6367.0 to 124.0.6367.257"}},
		{Machine: elf.EM_X86_64, Labels: allLabels, Strings: []string{"Chrome/100.0.4896.1"}, Architecture: "amd64", Err: boringssl.ErrUnknownChromiumVersion, Text: []string{"the nearest known is 122.0.6238.4"}},
		{Machine: elf.EM_X86_64, Labels: allLabels, Strings: []string{"10.0.2.2", "Chrome/", "1.0.0.0", "160.0.8161.0"}, Architecture: "amd64", Err: boringssl.ErrNoChromiumVersion, Text: []string{"base.apk"}},
		{Machine: elf.EM_X86_64, Labels: nil, Strings: []string{"Chrome/" + knownChrome}, Architecture: "amd64", Err: boringssl.ErrNoLabels, Text: nil},
		{Machine: elf.EM_AARCH64, Labels: allLabels, Strings: []string{"Chrome/" + knownChrome}, Architecture: "amd64", Err: boringssl.ErrWrongMachine, Text: []string{"amd64"}},
	}

	for index, negative := range negativeCases {
		data, logSecret := chromiumLibrary(negative.Machine, negative.Labels, negative.Strings)
		path := filepath.Join(state.TempDir(), "libmonochrome_64.so")
		err := os.WriteFile(path, data, 0o600)

		if err != nil {
			state.Fatalf("Test of boringssl.InspectChromium failed, case %d, cannot write the library, error: %s", index, err.Error())
		}

		library, err := boringssl.InspectChromium(boringssl.LibraryFile{Path: path, Entry: "", Offset: 0, Size: uint64(len(data))}, negative.Architecture)
		hasText := true

		for _, text := range negative.Text {
			hasText = hasText && (err != nil) && strings.Contains(err.Error(), text)
		}

		if !errors.Is(err, negative.Err) || !hasText {
			state.Errorf("Test of boringssl.InspectChromium function failed, case %d, error should be %v with %q, error: %v", index, negative.Err, negative.Text, err)
			continue
		}

		// the caller logs what was read before the version turned out unknown
		if errors.Is(err, boringssl.ErrUnknownChromiumVersion) && ((library.Version == "") || (library.LogSecret != logSecret)) {
			state.Errorf("Test of boringssl.InspectChromium function failed, case %d, the version and the hook should be read, library: %+v", index, library)
		}
	}
}

// Test if boringssl.GetChromiumOffset returns with the expected output: the first and last patch of a branch, a trunk build of the image's Cronet,
// the snapshot, and every range of the generated table has offsets for both architectures.
func TestGetChromiumOffsetPositive(state *testing.T) {
	positiveCases := []struct {
		Version  string
		Expected boringssl.Offset
	}{
		{Version: "124.0.6367.0", Expected: chromeOffset},
		{Version: "124.0.6367.257", Expected: chromeOffset},
		{Version: "126.0.6452.4", Expected: chromeOffset},
		{Version: "160.0.8161.0", Expected: knownOffset},
	}

	for _, positive := range positiveCases {
		for _, architecture := range []string{"amd64", "arm64"} {
			offset, revision, err := boringssl.GetChromiumOffset(positive.Version, architecture)

			if (err != nil) || (offset != positive.Expected) || (len(revision) != 40) {
				state.Errorf("Test of boringssl.GetChromiumOffset function failed, %s on %s should be %+v, offset: %+v, revision: %s, error: %v", positive.Version, architecture, positive.Expected, offset, revision, err)
			}
		}
	}

	known := boringssl.KnownChromiumVersions()

	if len(known) < 12 {
		state.Errorf("Test of boringssl.KnownChromiumVersions function failed, the table should cover at least 12 branches, known: %q", known)
	}

	for _, current := range known {
		first, last, _ := strings.Cut(current, " to ")

		for _, version := range []string{first, last} {
			if version == "" {
				continue
			}

			for _, architecture := range []string{"amd64", "arm64"} {
				if _, _, err := boringssl.GetChromiumOffset(version, architecture); err != nil {
					state.Errorf("Test of boringssl.GetChromiumOffset function failed, %s of the table should have offsets on %s, error: %s", version, architecture, err.Error())
				}
			}
		}
	}
}

// Test if boringssl.GetChromiumOffset returns with the expected errors: no MAJOR.0.BUILD.PATCH version, an unknown branch, a patch after the
// generated range, an architecture without Android build.
func TestGetChromiumOffsetNegative(state *testing.T) {
	negativeCases := []struct {
		Version      string
		Architecture string
		Err          error
		Text         string
	}{
		{Version: "124.1.6367.219", Architecture: "amd64", Err: boringssl.ErrUnknownChromiumVersion, Text: "MAJOR.0.BUILD.PATCH"},
		{Version: "chrome", Architecture: "amd64", Err: boringssl.ErrUnknownChromiumVersion, Text: "MAJOR.0.BUILD.PATCH"},
		{Version: "124.0.6366.1", Architecture: "amd64", Err: boringssl.ErrUnknownChromiumVersion, Text: "make generate-chrome-offsets"},
		{Version: "124.0.6367.258", Architecture: "amd64", Err: boringssl.ErrUnknownChromiumVersion, Text: "124.0.6367.0 to 124.0.6367.257"},
		{Version: knownChrome, Architecture: "riscv64", Err: boringssl.ErrUnsupportedMachine, Text: "riscv64"},
	}

	for _, negative := range negativeCases {
		_, _, err := boringssl.GetChromiumOffset(negative.Version, negative.Architecture)

		if !errors.Is(err, negative.Err) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of boringssl.GetChromiumOffset function failed, %s on %s, error should be %v with %q, error: %v", negative.Version, negative.Architecture, negative.Err, negative.Text, err)
		}
	}
}

// Test if boringssl.ExecutableMappings returns with the expected output: r-xp file mappings once each with their offset, a path with a space, no
// data, anonymous or deleted mapping.
func TestExecutableMappingsPositive(state *testing.T) {
	maps := `5c4d1e000000-5c4d1e002000 r--p 00000000 fe:05 1234                      /system/bin/app_process64
79af22718000-79af29d68000 r-xp 008cc000 fe:2e 32818                      /data/app/~~a==/com.google.android.trichromelibrary_636771938-b==/TrichromeLibrary.apk
79af29d68000-79af29d70000 r-xp 008cc000 fe:2e 32818                      /data/app/~~a==/com.google.android.trichromelibrary_636771938-b==/TrichromeLibrary.apk
79af73cca000-79af73ccb000 r-xp 00004000 fe:05 2426                       /system/lib64/libwebviewchromium_loader.so
79af80000000-79af80001000 r-xp 00000000 00:00 0                          [vdso]
79af80001000-79af80002000 r-xp 00000000 00:00 0
79af80002000-79af80003000 r-xp 00001000 fe:2e 999                        /data/app/~~c==/io.decerter-d==/base.apk (deleted)
79af80003000-79af80004000 r-xp 00002000 fe:2e 998                        /data/local/tmp/my lib/libcronet.126.0.6452.4.so
79af80004000-79af80005000 rw-p 00002000 fe:2e 998                        /data/local/tmp/my lib/libcronet.126.0.6452.4.so
`
	expected := []boringssl.Mapping{
		{Path: "/data/app/~~a==/com.google.android.trichromelibrary_636771938-b==/TrichromeLibrary.apk", Offset: 0x8cc000},
		{Path: "/system/lib64/libwebviewchromium_loader.so", Offset: 0x4000},
		{Path: "/data/local/tmp/my lib/libcronet.126.0.6452.4.so", Offset: 0x2000},
	}

	if mappings := boringssl.ExecutableMappings(maps); !slices.Equal(mappings, expected) {
		state.Errorf("Test of boringssl.ExecutableMappings function failed, mappings should be %+v, mappings: %+v", expected, mappings)
	}

	if mappings := boringssl.ExecutableMappings("garbage\n\n1-2 r-xp zz 00:00 0 /x\n"); len(mappings) != 0 {
		state.Errorf("Test of boringssl.ExecutableMappings function failed, broken lines should give none, mappings: %+v", mappings)
	}
}

// Test if boringssl.ChromiumMapping and boringssl.FindAPKEntryAt return with the expected output: the stored entry that holds a mapping of an apk,
// a Chromium library file of its own, nothing for an offset in no entry, another library or a non Chromium entry.
func TestChromiumMappingPositive(state *testing.T) {
	directory := state.TempDir()
	apk := filepath.Join(directory, "TrichromeLibrary.apk")
	data, _ := chromiumLibrary(elf.EM_X86_64, allLabels, []string{"Chrome/" + knownChrome})
	cronet := filepath.Join(directory, "libcronet.126.0.6452.4.so")
	err := errors.Join(
		writeAPK(apk, []apkEntry{{Name: "lib/x86_64/libcrashpad_handler_trampoline.so", Data: []byte("trampoline"), Stored: true, Unaligned: false}, {Name: monochromeEntry, Data: data, Stored: true, Unaligned: false}}),
		os.WriteFile(cronet, data, 0o600),
		os.WriteFile(filepath.Join(directory, "libssl.so"), data, 0o600),
	)

	if err != nil {
		state.Fatalf("Test of boringssl.ChromiumMapping failed, cannot write the files, error: %s", err.Error())
	}

	files, err := boringssl.FindChromiumLibraries(directory, "amd64")

	if (err != nil) || (len(files) != 1) {
		state.Fatalf("Test of boringssl.ChromiumMapping failed, cannot find the library, files: %+v, error: %v", files, err)
	}

	positiveCases := []struct {
		Mapping    boringssl.Mapping
		IsChromium bool
		Expected   boringssl.LibraryFile
	}{
		{Mapping: boringssl.Mapping{Path: apk, Offset: files[0].Offset + 0x1000}, IsChromium: true, Expected: files[0]},
		{Mapping: boringssl.Mapping{Path: apk, Offset: files[0].Offset}, IsChromium: true, Expected: files[0]},
		{Mapping: boringssl.Mapping{Path: cronet, Offset: 0x2000}, IsChromium: true, Expected: boringssl.LibraryFile{Path: cronet, Entry: "", Offset: 0, Size: uint64(len(data))}},
		{Mapping: boringssl.Mapping{Path: apk, Offset: files[0].Offset + files[0].Size + 0x100000}, IsChromium: false, Expected: boringssl.LibraryFile{}},
		{Mapping: boringssl.Mapping{Path: apk, Offset: 4096}, IsChromium: false, Expected: boringssl.LibraryFile{}},
		{Mapping: boringssl.Mapping{Path: filepath.Join(directory, "libssl.so"), Offset: 0}, IsChromium: false, Expected: boringssl.LibraryFile{}},
	}

	for index, positive := range positiveCases {
		library, isChromium, mappingErr := boringssl.ChromiumMapping(positive.Mapping)

		if positive.IsChromium {
			if (mappingErr != nil) || !isChromium || (library != positive.Expected) {
				state.Errorf("Test of boringssl.ChromiumMapping function failed, case %d, library should be %+v, library: %+v, isChromium: %v, error: %v", index, positive.Expected, library, isChromium, mappingErr)
			}

			continue
		}

		if (mappingErr != nil) || isChromium {
			state.Errorf("Test of boringssl.ChromiumMapping function failed, case %d, should be no Chromium library, library: %+v, error: %v", index, library, mappingErr)
		}
	}
}

// Test if boringssl.ChromiumMapping returns with the expected errors: an apk that is no zip, a Chromium library that is gone.
func TestChromiumMappingNegative(state *testing.T) {
	directory := state.TempDir()
	apk := filepath.Join(directory, "base.apk")
	err := os.WriteFile(apk, []byte("not a zip"), 0o600)

	if err != nil {
		state.Fatalf("Test of boringssl.ChromiumMapping failed, cannot write the apk, error: %s", err.Error())
	}

	negativeCases := []struct {
		Mapping boringssl.Mapping
		Err     error
	}{
		{Mapping: boringssl.Mapping{Path: apk, Offset: 0}, Err: boringssl.ErrReadAPK},
		{Mapping: boringssl.Mapping{Path: filepath.Join(directory, "libmonochrome_64.so"), Offset: 0}, Err: boringssl.ErrLibraryNotFound},
	}

	for index, negative := range negativeCases {
		_, _, mappingErr := boringssl.ChromiumMapping(negative.Mapping)

		if !errors.Is(mappingErr, negative.Err) {
			state.Errorf("Test of boringssl.ChromiumMapping function failed, case %d, error should be %v, error: %v", index, negative.Err, mappingErr)
		}
	}
}

// Test if boringssl.InspectChromium finds ssl_log_secret in real Chromium libraries where it was checked by hand in the disassembly (the function that
// tests ctx->keylog_callback, hex-encodes s3->client_random and calls the callback): Trichrome of Chrome 124 and Cronet 126 of the decerter-a15 image
// (adb pull to ~/.cache/decerter-chromium/image), the x86_64 ChromePublic and SystemWebView snapshot of the e2e tests and an arm64 ChromePublic snapshot
// of the same version; skipped for the files that aren't cached.
func TestInspectChromiumRealPositive(state *testing.T) {
	cache, cacheErr := os.UserCacheDir()

	if cacheErr != nil {
		state.Skipf("no cache directory: %s", cacheErr.Error())
	}

	positiveCases := []struct {
		APK          string
		Entry        string
		Version      string
		LogSecret    uint64
		Architecture string
	}{
		{APK: filepath.Join("image", "TrichromeLibrary.apk"), Entry: monochromeEntry, Version: knownChrome, LogSecret: 0x8cc000 + 0x34d1b00, Architecture: "amd64"},
		{APK: filepath.Join("image", "CronetDynamite.uncompressed.apk"), Entry: cronetEntry, Version: "126.0.6452.4", LogSecret: 0x5dc000 + 0x3a6f60, Architecture: "amd64"},
		{APK: filepath.Join("snapshot-AndroidDesktop_x64-1744338", "chrome-android-desktop", "apks", "ChromePublic.apk"), Entry: "lib/x86_64/libchrome.so", Version: "160.0.8161.0", LogSecret: 241259552, Architecture: "amd64"},
		{APK: filepath.Join("snapshot-AndroidDesktop_x64-1744338", "chrome-android-desktop", "apks", "SystemWebView.apk"), Entry: "lib/x86_64/libwebviewchromium.so", Version: "160.0.8161.0", LogSecret: 129023008, Architecture: "amd64"},
		{APK: filepath.Join("snapshot-Android_Arm64-1744436", "chrome-android", "apks", "ChromePublic.apk"), Entry: "lib/arm64-v8a/libchrome.so", Version: "160.0.8161.0", LogSecret: 218906496, Architecture: "arm64"},
	}
	checked := 0

	for _, positive := range positiveCases {
		apk := filepath.Join(cache, "decerter-chromium", positive.APK)

		if _, statErr := os.Stat(apk); statErr != nil {
			continue
		}

		file, found, err := boringssl.FindAPKEntry(apk, positive.Entry)

		if (err != nil) || !found {
			state.Errorf("Test of boringssl.InspectChromium failed, %s has no %s, error: %v", apk, positive.Entry, err)
			continue
		}

		library, err := boringssl.InspectChromium(file, positive.Architecture)

		if (err != nil) || (library.Version != positive.Version) || (library.LogSecret != positive.LogSecret) || (library.Labels != 7) {
			state.Errorf("Test of boringssl.InspectChromium function failed, %s should be %s with ssl_log_secret at 0x%x from 7 labels, library: %+v, error: %v", apk, positive.Version, positive.LogSecret, library, err)
		}

		checked++
	}

	if checked == 0 {
		state.Skip("no Chromium library in ~/.cache/decerter-chromium")
	}
}
