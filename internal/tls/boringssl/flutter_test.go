// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package boringssl_test

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/tls/boringssl"
)

const (
	// the test library has one PT_LOAD right after the headers, its addresses are the file offsets plus staticBase
	staticBase uint64 = 0x10000
	// rodata (labels, the version string) is padded to this, the code follows
	rodataSize int = 0x2000
	// a Dart version of the generated table and its offsets (Flutter 3.35.x)
	knownDart   string = "3.9.2"
	unknownDart string = "9.9.2"
	// the version string the Dart VM prints
	versionFormat string = "%s (stable) (Wed Aug 27 03:49:40 2025 -0700) on \"android_x64\""
	// apk entries of the test apks
	x86Entry   string = "lib/x86_64/libflutter.so"
	arm64Entry string = "lib/arm64-v8a/libflutter.so"
)

var (
	allLabels   = []string{"CLIENT_RANDOM", "CLIENT_EARLY_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET"}
	knownOffset = boringssl.Offset{Version: 0xd0, VersionInS3: true, S3: 0x30, ClientRandom: 0x30}
)

// what a test library has: the labels its call sites load, how many of them call a decoy instead, a version string, the first label stored as the
// tail of a longer string, and tail calls (jmp, b) instead of calls
type staticLibrary struct {
	Machine     elf.Machine
	Labels      []string
	DecoyLabels int
	Version     string
	MergedLabel bool
	TailCalls   bool
	TwoTargets  bool
}

// the library and the file offset of its ssl_log_secret
func (library staticLibrary) build() (file []byte, logSecret uint64) {
	headerSize := uint64(binary.Size(elf.Header64{}) + binary.Size(elf.Prog64{}))
	rodata := []byte("some other string\x00")
	labelAddresses := []uint64{}

	for index, label := range library.Labels {
		if (index == 0) && library.MergedLabel {
			rodata = append(rodata, "SSLKEYLOG_"...)
		}

		labelAddresses = append(labelAddresses, staticBase+headerSize+uint64(len(rodata)))
		rodata = append(append(rodata, label...), 0)
	}

	if library.Version != "" {
		rodata = append(append(rodata, fmt.Sprintf(versionFormat, library.Version)...), 0)
		// the engine revision of Flutter 3.35.7, the table knows it
		rodata = append(append(rodata, "035316565ad77281a75305515e4682e6c4c6f7ca"...), 0)
	}

	segment := append(rodata, make([]byte, rodataSize-len(rodata))...)
	address := func() (current uint64) {
		current = staticBase + headerSize + uint64(len(segment))
		return
	}
	// the call sites come first, each ends its function with ret; then the functions: target, a second one for the ambiguous case, a decoy and one
	// outlined helper per arm64 call site (the machine outliner's OUTLINED_FUNCTION_n)
	sites := len(library.Labels)
	siteSize := map[elf.Machine]int{elf.EM_X86_64: 7 + 3 + 1 + 5 + 1, elf.EM_AARCH64: 6 * 4}[library.Machine]
	targetsStart := address() + uint64(sites*siteSize)
	target := targetsStart
	second := targetsStart + 16
	decoy := targetsStart + 32

	for index, label := range labelAddresses {
		callee := target

		switch {
		case index < library.DecoyLabels:
			callee = decoy
		case library.TwoTargets && (index%2 == 1):
			callee = second
		default:
		}

		switch library.Machine {
		case elf.EM_X86_64:
			// lea rsi, [rip+label]; mov rdi, rbx; nop; call or jmp callee; ret
			next := address() + 7
			segment = append(segment, 0x48, 0x8d, 0x35)
			segment = binary.LittleEndian.AppendUint32(segment, uint32(int32(int64(label)-int64(next))))
			segment = append(segment, 0x48, 0x89, 0xdf, 0x90)
			opcode := byte(0xe8)

			if library.TailCalls {
				opcode = 0xe9
			}

			next = address() + 5
			segment = append(segment, opcode)
			segment = binary.LittleEndian.AppendUint32(segment, uint32(int32(int64(callee)-int64(next))))
			segment = append(segment, 0xc3)
		default:
			// adrp x1, label page; add x1, x1, #label low 12 bits; mov x0, x19; bl OUTLINED_FUNCTION_n; bl or b callee; ret
			pc := address()
			pages := int64(label&^0xfff)>>12 - int64(pc&^0xfff)>>12
			adrp := uint32(0x90000000) | (uint32(pages)&0x3)<<29 | ((uint32(pages)>>2)&0x7ffff)<<5 | 1
			add := uint32(0x91000000) | uint32(label&0xfff)<<10 | 1<<5 | 1
			segment = binary.LittleEndian.AppendUint32(segment, adrp)
			segment = binary.LittleEndian.AppendUint32(segment, add)
			segment = binary.LittleEndian.AppendUint32(segment, 0xaa1303e0)
			outlined := targetsStart + 48 + uint64(index)*16
			segment = binary.LittleEndian.AppendUint32(segment, 0x94000000|(uint32((int64(outlined)-int64(address()))>>2)&0x3ffffff))
			opcode := uint32(0x94000000)

			if library.TailCalls {
				opcode = 0x14000000
			}

			segment = binary.LittleEndian.AppendUint32(segment, opcode|(uint32((int64(callee)-int64(address()))>>2)&0x3ffffff))
			segment = binary.LittleEndian.AppendUint32(segment, 0xd65f03c0)
		}
	}

	// the functions: ret for each, 16 bytes apart
	for range 3 + sites {
		function := map[elf.Machine][]byte{elf.EM_X86_64: {0xc3}, elf.EM_AARCH64: {0xc0, 0x03, 0x5f, 0xd6}}[library.Machine]
		segment = append(segment, function...)
		segment = append(segment, make([]byte, 16-len(function))...)
	}

	logSecret = target - staticBase
	header := elf.Header64{
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(library.Machine),
		Version:   uint32(elf.EV_CURRENT),
		Phoff:     uint64(binary.Size(elf.Header64{})),
		Ehsize:    uint16(binary.Size(elf.Header64{})),
		Phentsize: uint16(binary.Size(elf.Prog64{})),
		Phnum:     1,
		Shentsize: uint16(binary.Size(elf.Section64{})),
	}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	program := elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Off: headerSize, Vaddr: staticBase + headerSize, Paddr: staticBase + headerSize, Filesz: uint64(len(segment)), Memsz: uint64(len(segment)), Align: 0x1000}
	output := bytes.Buffer{}

	for _, part := range []any{header, program, segment} {
		// a bytes.Buffer does not fail
		_ = binary.Write(&output, binary.LittleEndian, part)
	}

	file = output.Bytes()
	return
}

// one entry of a test apk: stored entries are page aligned unless Unaligned
type apkEntry struct {
	Name      string
	Data      []byte
	Stored    bool
	Unaligned bool
}

// an apk as the Android Gradle plugin writes it: stored libraries padded to a page with an extra field (zipalign's 0xd935); every entry is written
// raw, so the bytes in the buffer are where the next local header starts
func writeAPK(path string, entries []apkEntry) (err error) {
	output := &bytes.Buffer{}
	writer := zip.NewWriter(output)

	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.Name, Method: zip.Store, CRC32: crc32.ChecksumIEEE(entry.Data), UncompressedSize64: uint64(len(entry.Data))}
		data := entry.Data
		err = writer.Flush()

		if err != nil {
			return
		}

		if entry.Stored {
			dataStart := uint64(output.Len()) + 30 + uint64(len(entry.Name)) + 4
			padding := (4096 - dataStart%4096) % 4096

			if entry.Unaligned {
				padding = (padding + 1) % 4096
			}

			header.Extra = binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(nil, 0xd935), uint16(padding))
			header.Extra = append(header.Extra, make([]byte, padding)...)
		} else {
			compressed := &bytes.Buffer{}
			compressor, _ := flate.NewWriter(compressed, flate.BestCompression)
			_, err = compressor.Write(entry.Data)

			if err = errors.Join(err, compressor.Close()); err != nil {
				return
			}

			header.Method = zip.Deflate
			data = compressed.Bytes()
		}

		header.CompressedSize64 = uint64(len(data))
		created, createErr := writer.CreateRaw(header)

		if err = createErr; err != nil {
			return
		}

		_, err = created.Write(data)

		if err != nil {
			return
		}
	}

	err = writer.Close()

	if err != nil {
		return
	}

	err = os.WriteFile(path, output.Bytes(), 0o600)
	return
}

// Test if boringssl.FindLogSecretByLabels returns with the expected output: x86_64 and arm64 call sites, calls and tail calls, a label merged
// into a longer string, decoys reached from fewer labels.
func TestFindLogSecretByLabelsPositive(state *testing.T) {
	positiveCases := []staticLibrary{
		{Machine: elf.EM_X86_64, Labels: allLabels, DecoyLabels: 0, Version: "", MergedLabel: false, TailCalls: false, TwoTargets: false},
		{Machine: elf.EM_X86_64, Labels: allLabels, DecoyLabels: 2, Version: "", MergedLabel: true, TailCalls: true, TwoTargets: false},
		{Machine: elf.EM_X86_64, Labels: allLabels[:3], DecoyLabels: 0, Version: "", MergedLabel: false, TailCalls: false, TwoTargets: false},
		{Machine: elf.EM_AARCH64, Labels: allLabels, DecoyLabels: 0, Version: "", MergedLabel: false, TailCalls: false, TwoTargets: false},
		{Machine: elf.EM_AARCH64, Labels: allLabels, DecoyLabels: 3, Version: "", MergedLabel: true, TailCalls: true, TwoTargets: false},
	}

	for index, positive := range positiveCases {
		data, expected := positive.build()
		file, err := elf.NewFile(bytes.NewReader(data))

		if err != nil {
			state.Fatalf("Test of boringssl.FindLogSecretByLabels failed, case %d, cannot read the test ELF, error: %s", index, err.Error())
		}

		address, labels, err := boringssl.FindLogSecretByLabels(file)
		expectedLabels := len(positive.Labels) - positive.DecoyLabels

		if (err != nil) || (address != expected) || (labels != expectedLabels) {
			state.Errorf("Test of boringssl.FindLogSecretByLabels function failed, case %d, should be 0x%x from %d labels, address: 0x%x, labels: %d, error: %v", index, expected, expectedLabels, address, labels, err)
		}
	}
}

// Test if boringssl.FindLogSecretByLabels returns with the expected errors: no label, too few labels, two functions with as many labels, another machine.
func TestFindLogSecretByLabelsNegative(state *testing.T) {
	negativeCases := []struct {
		Library staticLibrary
		Err     error
	}{
		{Library: staticLibrary{Machine: elf.EM_X86_64, Labels: nil, DecoyLabels: 0, Version: "", MergedLabel: false, TailCalls: false, TwoTargets: false}, Err: boringssl.ErrNoLabels},
		{Library: staticLibrary{Machine: elf.EM_X86_64, Labels: allLabels[:2], DecoyLabels: 0, Version: "", MergedLabel: false, TailCalls: false, TwoTargets: false}, Err: boringssl.ErrNoLabelCalls},
		{Library: staticLibrary{Machine: elf.EM_AARCH64, Labels: allLabels[:6], DecoyLabels: 0, Version: "", MergedLabel: false, TailCalls: false, TwoTargets: true}, Err: boringssl.ErrAmbiguousLabelCalls},
		{Library: staticLibrary{Machine: elf.EM_386, Labels: allLabels, DecoyLabels: 0, Version: "", MergedLabel: false, TailCalls: false, TwoTargets: false}, Err: boringssl.ErrUnsupportedMachine},
	}

	for index, negative := range negativeCases {
		library := negative.Library
		machine := library.Machine

		// the i386 case has x86_64 code, only the machine differs
		if machine == elf.EM_386 {
			library.Machine = elf.EM_X86_64
		}

		data, _ := library.build()
		binary.LittleEndian.PutUint16(data[18:], uint16(machine))
		file, err := elf.NewFile(bytes.NewReader(data))

		if err != nil {
			state.Fatalf("Test of boringssl.FindLogSecretByLabels failed, case %d, cannot read the test ELF, error: %s", index, err.Error())
		}

		_, _, err = boringssl.FindLogSecretByLabels(file)

		if !errors.Is(err, negative.Err) {
			state.Errorf("Test of boringssl.FindLogSecretByLabels function failed, case %d, error should be %v, error: %v", index, negative.Err, err)
		}
	}
}

// Test if boringssl.FindFlutterLibrary and boringssl.FindAPKEntry return with the expected output: an extracted library first, the stored
// library of base.apk or a split apk at its page aligned data offset, nothing for an app without libflutter.so.
func TestFindFlutterLibraryPositive(state *testing.T) {
	library := []byte("an ELF")
	directory := state.TempDir()
	split := filepath.Join(directory, "split_config.x86_64.apk")
	err := errors.Join(
		writeAPK(filepath.Join(directory, "base.apk"), []apkEntry{{Name: "AndroidManifest.xml", Data: []byte("manifest"), Stored: false, Unaligned: false}, {Name: arm64Entry, Data: library, Stored: true, Unaligned: false}}),
		writeAPK(split, []apkEntry{{Name: "AndroidManifest.xml", Data: []byte("manifest"), Stored: false, Unaligned: false}, {Name: x86Entry, Data: library, Stored: true, Unaligned: false}}),
	)

	if err != nil {
		state.Fatalf("Test of boringssl.FindFlutterLibrary failed, cannot write the apks, error: %s", err.Error())
	}

	positiveCases := []struct {
		Architecture string
		Path         string
		Entry        string
	}{
		{Architecture: "amd64", Path: split, Entry: x86Entry},
		{Architecture: "arm64", Path: filepath.Join(directory, "base.apk"), Entry: arm64Entry},
	}

	for _, positive := range positiveCases {
		file, found, findErr := boringssl.FindFlutterLibrary(directory, positive.Architecture)

		if (findErr != nil) || !found || (file.Path != positive.Path) || (file.Entry != positive.Entry) || (file.Offset%4096 != 0) || (file.Size != uint64(len(library))) {
			state.Errorf("Test of boringssl.FindFlutterLibrary function failed, %s should be %s in %s, file: %+v, found: %v, error: %v", positive.Architecture, positive.Entry, positive.Path, file, found, findErr)
			continue
		}

		// the offset is where the bytes are
		content, readErr := os.ReadFile(file.Path)

		if (readErr != nil) || !bytes.Equal(content[file.Offset:file.Offset+file.Size], library) {
			state.Errorf("Test of boringssl.FindAPKEntry function failed, the bytes at 0x%x are not the library, error: %v", file.Offset, readErr)
		}
	}

	// an extracted library wins over the apk
	extracted := filepath.Join(directory, "lib", "x86_64", boringssl.FlutterLibraryName)
	err = errors.Join(os.MkdirAll(filepath.Dir(extracted), 0o700), os.WriteFile(extracted, library, 0o600))

	if err != nil {
		state.Fatalf("Test of boringssl.FindFlutterLibrary failed, cannot write the extracted library, error: %s", err.Error())
	}

	file, found, err := boringssl.FindFlutterLibrary(directory, "amd64")

	if (err != nil) || !found || (file != boringssl.LibraryFile{Path: extracted, Entry: "", Offset: 0, Size: uint64(len(library))}) {
		state.Errorf("Test of boringssl.FindFlutterLibrary function failed, the extracted library should win, file: %+v, found: %v, error: %v", file, found, err)
	}

	// an app without a Flutter library
	other := state.TempDir()
	err = writeAPK(filepath.Join(other, "base.apk"), []apkEntry{{Name: "lib/x86_64/libother.so", Data: library, Stored: true, Unaligned: false}})

	if err != nil {
		state.Fatalf("Test of boringssl.FindFlutterLibrary failed, cannot write the apk, error: %s", err.Error())
	}

	_, found, err = boringssl.FindFlutterLibrary(other, "amd64")

	if (err != nil) || found {
		state.Errorf("Test of boringssl.FindFlutterLibrary function failed, an app without libflutter.so should find nothing, found: %v, error: %v", found, err)
	}
}

// Test if boringssl.FindFlutterLibrary and boringssl.FindAPKEntry return with the expected errors: a compressed or unaligned library, an apk that is
// no zip, an architecture without Android ABI.
func TestFindFlutterLibraryNegative(state *testing.T) {
	negativeCases := []struct {
		Entries []apkEntry
		Raw     []byte
		Err     error
	}{
		{Entries: []apkEntry{{Name: x86Entry, Data: []byte("an ELF"), Stored: false, Unaligned: false}}, Raw: nil, Err: boringssl.ErrCompressedLibrary},
		{Entries: []apkEntry{{Name: x86Entry, Data: []byte("an ELF"), Stored: true, Unaligned: true}}, Raw: nil, Err: boringssl.ErrUnalignedLibrary},
		{Entries: nil, Raw: []byte("no zip"), Err: boringssl.ErrReadAPK},
	}

	for index, negative := range negativeCases {
		directory := state.TempDir()
		apk := filepath.Join(directory, "base.apk")
		err := os.WriteFile(apk, negative.Raw, 0o600)

		if negative.Entries != nil {
			err = writeAPK(apk, negative.Entries)
		}

		if err != nil {
			state.Fatalf("Test of boringssl.FindFlutterLibrary failed, case %d, cannot write the apk, error: %s", index, err.Error())
		}

		_, _, err = boringssl.FindFlutterLibrary(directory, "amd64")

		if !errors.Is(err, negative.Err) || !strings.Contains(err.Error(), apk) {
			state.Errorf("Test of boringssl.FindFlutterLibrary function failed, case %d, error should be %v naming the apk, error: %v", index, negative.Err, err)
		}
	}

	_, _, err := boringssl.FindFlutterLibrary(state.TempDir(), "riscv64")

	if !errors.Is(err, boringssl.ErrUnsupportedMachine) {
		state.Errorf("Test of boringssl.FindFlutterLibrary function failed, error should be %v, error: %v", boringssl.ErrUnsupportedMachine, err)
	}
}

// Test if boringssl.InspectFlutter returns with the expected output: the Dart version, the engine, ssl_log_secret in the apk and the offsets.
func TestInspectFlutterPositive(state *testing.T) {
	for _, machine := range []elf.Machine{elf.EM_X86_64, elf.EM_AARCH64} {
		architecture := map[elf.Machine]string{elf.EM_X86_64: "amd64", elf.EM_AARCH64: "arm64"}[machine]
		entry := map[elf.Machine]string{elf.EM_X86_64: x86Entry, elf.EM_AARCH64: arm64Entry}[machine]
		data, logSecret := staticLibrary{Machine: machine, Labels: allLabels, DecoyLabels: 1, Version: knownDart, MergedLabel: false, TailCalls: false, TwoTargets: false}.build()
		directory := state.TempDir()
		err := writeAPK(filepath.Join(directory, "base.apk"), []apkEntry{{Name: "classes.dex", Data: []byte("dex"), Stored: false, Unaligned: false}, {Name: entry, Data: data, Stored: true, Unaligned: false}})

		if err != nil {
			state.Fatalf("Test of boringssl.InspectFlutter failed, cannot write the apk, error: %s", err.Error())
		}

		file, _, err := boringssl.FindFlutterLibrary(directory, architecture)

		if err != nil {
			state.Fatalf("Test of boringssl.InspectFlutter failed, cannot find the library, error: %s", err.Error())
		}

		library, err := boringssl.InspectFlutter(file, architecture)
		expected := boringssl.FlutterLibrary{
			File:        file,
			DartVersion: knownDart,
			Engine:      "035316565ad77281a75305515e4682e6c4c6f7ca",
			Flutter:     library.Flutter,
			Revision:    "be5be0a4f5ebf00da151a06860deb11a0ffb609f",
			Offset:      knownOffset,
			LogSecret:   file.Offset + logSecret,
			Labels:      len(allLabels) - 1,
		}

		if (err != nil) || !slices.Contains(library.Flutter, "3.35.7") || !isSameLibrary(library, expected) {
			state.Errorf("Test of boringssl.InspectFlutter function failed, %s should be %+v, library: %+v, error: %v", architecture, expected, library, err)
		}
	}
}

// Test if boringssl.InspectFlutter returns with the expected errors: an unknown Dart version (with the version and the hook still read), no version
// string, another architecture than the one decerter runs on.
func TestInspectFlutterNegative(state *testing.T) {
	negativeCases := []struct {
		Library      staticLibrary
		Architecture string
		Err          error
		Text         string
	}{
		{Library: staticLibrary{Machine: elf.EM_X86_64, Labels: allLabels, DecoyLabels: 0, Version: unknownDart, MergedLabel: false, TailCalls: false, TwoTargets: false}, Architecture: "amd64", Err: boringssl.ErrUnknownDartVersion, Text: "make generate-flutter-offsets"},
		{Library: staticLibrary{Machine: elf.EM_X86_64, Labels: allLabels, DecoyLabels: 0, Version: "", MergedLabel: false, TailCalls: false, TwoTargets: false}, Architecture: "amd64", Err: boringssl.ErrNoDartVersion, Text: ""},
		{Library: staticLibrary{Machine: elf.EM_AARCH64, Labels: allLabels, DecoyLabels: 0, Version: knownDart, MergedLabel: false, TailCalls: false, TwoTargets: false}, Architecture: "amd64", Err: boringssl.ErrWrongMachine, Text: "amd64"},
	}

	for index, negative := range negativeCases {
		data, logSecret := negative.Library.build()
		path := filepath.Join(state.TempDir(), boringssl.FlutterLibraryName)
		err := os.WriteFile(path, data, 0o600)

		if err != nil {
			state.Fatalf("Test of boringssl.InspectFlutter failed, case %d, cannot write the library, error: %s", index, err.Error())
		}

		library, err := boringssl.InspectFlutter(boringssl.LibraryFile{Path: path, Entry: "", Offset: 0, Size: uint64(len(data))}, negative.Architecture)

		if !errors.Is(err, negative.Err) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of boringssl.InspectFlutter function failed, case %d, error should be %v with %q, error: %v", index, negative.Err, negative.Text, err)
			continue
		}

		// the caller logs what was read before the version turned out unknown
		if errors.Is(err, boringssl.ErrUnknownDartVersion) && ((library.DartVersion != unknownDart) || (library.LogSecret != logSecret)) {
			state.Errorf("Test of boringssl.InspectFlutter function failed, case %d, the version and the hook should be read, library: %+v", index, library)
		}
	}
}

// Test if boringssl.GetFlutterOffset returns with the expected output, and every Dart version of the generated table has offsets for both architectures.
func TestGetFlutterOffsetPositive(state *testing.T) {
	positiveCases := []struct {
		DartVersion  string
		Architecture string
		Expected     boringssl.Offset
	}{
		// Flutter 3.24 (Dart 3.5): the version still in ssl_st; 3.35.7 and 3.50.0 were checked on the emulator
		{DartVersion: "3.5.0", Architecture: "amd64", Expected: boringssl.Offset{Version: 0x10, VersionInS3: false, S3: 0x30, ClientRandom: 0x30}},
		{DartVersion: knownDart, Architecture: "amd64", Expected: knownOffset},
		{DartVersion: "3.14.0", Architecture: "arm64", Expected: knownOffset},
	}

	for _, positive := range positiveCases {
		offset, revision, flutter, err := boringssl.GetFlutterOffset(positive.DartVersion, positive.Architecture)

		if (err != nil) || (offset != positive.Expected) || (len(revision) != 40) || (len(flutter) == 0) {
			state.Errorf("Test of boringssl.GetFlutterOffset function failed, Dart %s on %s should be %+v, offset: %+v, revision: %s, flutter: %v, error: %v", positive.DartVersion, positive.Architecture, positive.Expected, offset, revision, flutter, err)
		}
	}

	for _, version := range boringssl.KnownDartVersions() {
		for _, architecture := range []string{"amd64", "arm64"} {
			_, _, _, err := boringssl.GetFlutterOffset(version, architecture)

			if err != nil {
				state.Errorf("Test of boringssl.GetFlutterOffset function failed, the table's Dart %s on %s has no offsets, error: %s", version, architecture, err.Error())
			}
		}
	}
}

// Test if boringssl.GetFlutterOffset returns with the expected errors: an unknown Dart version names the nearest known one, newer, between and older
// than the table, and the make command; an architecture without Android build.
func TestGetFlutterOffsetNegative(state *testing.T) {
	known := boringssl.KnownDartVersions()
	negativeCases := []struct {
		DartVersion  string
		Architecture string
		Err          error
		Nearest      string
	}{
		{DartVersion: "9.0.0", Architecture: "amd64", Err: boringssl.ErrUnknownDartVersion, Nearest: "Dart " + known[len(known)-1] + " "},
		{DartVersion: "3.9.99", Architecture: "arm64", Err: boringssl.ErrUnknownDartVersion, Nearest: "Dart 3.9.2 "},
		{DartVersion: "3.10.0-1.0.dev", Architecture: "amd64", Err: boringssl.ErrUnknownDartVersion, Nearest: "Dart 3.9.2 "},
		{DartVersion: "1.0.0", Architecture: "amd64", Err: boringssl.ErrUnknownDartVersion, Nearest: "Dart " + known[0] + " "},
		{DartVersion: knownDart, Architecture: "riscv64", Err: boringssl.ErrUnsupportedMachine, Nearest: ""},
	}

	for _, negative := range negativeCases {
		_, _, _, err := boringssl.GetFlutterOffset(negative.DartVersion, negative.Architecture)

		if !errors.Is(err, negative.Err) || !strings.Contains(err.Error(), negative.Nearest) || (errors.Is(err, boringssl.ErrUnknownDartVersion) && !strings.Contains(err.Error(), "make generate-flutter-offsets")) {
			state.Errorf("Test of boringssl.GetFlutterOffset function failed, Dart %s on %s should be %v naming %q, error: %v", negative.DartVersion, negative.Architecture, negative.Err, negative.Nearest, err)
		}
	}
}

// Test if boringssl.InspectFlutter finds ssl_log_secret in real Flutter engines: for each cached Flutter SDK (~/.cache/decerter-flutter/*/flutter or
// DECERTER_FLUTTER_SDKS) the unstripped engine of its artifacts, whose symbol says where the function is, and the stripped one of the e2e apk when it is
// cached; skipped without an SDK.
func TestInspectFlutterRealPositive(state *testing.T) {
	sdks := filepath.SplitList(os.Getenv("DECERTER_FLUTTER_SDKS"))

	if len(sdks) == 0 {
		cache, cacheErr := os.UserCacheDir()

		if cacheErr != nil {
			state.Skipf("no cache directory: %s", cacheErr.Error())
		}

		sdks, _ = filepath.Glob(filepath.Join(cache, "decerter-flutter", "*", "flutter"))
	}

	if len(sdks) == 0 {
		state.Skip("no Flutter SDK in ~/.cache/decerter-flutter/*/flutter and no DECERTER_FLUTTER_SDKS")
	}

	for _, sdk := range sdks {
		version := struct {
			FrameworkVersion string `json:"frameworkVersion"`
			DartSdkVersion   string `json:"dartSdkVersion"`
		}{}
		content, err := os.ReadFile(filepath.Join(sdk, "bin", "cache", "flutter.version.json"))

		if err == nil {
			err = json.Unmarshal(content, &version)
		}

		if err != nil {
			state.Errorf("Test of boringssl.InspectFlutter failed, cannot read the version of %s, error: %s", sdk, err.Error())
			continue
		}

		for _, architecture := range []string{"amd64", "arm64"} {
			artifact := map[string]string{"amd64": "android-x64-release", "arm64": "android-arm64-release"}[architecture]
			entry := map[string]string{"amd64": x86Entry, "arm64": arm64Entry}[architecture]
			expected, err := unstrippedLogSecret(filepath.Join(sdk, "bin", "cache", "artifacts", "engine", artifact, "flutter.jar"), entry, architecture, version.DartSdkVersion)

			if err != nil {
				state.Errorf("Test of boringssl.InspectFlutter function failed, Flutter %s on %s, error: %s", version.FrameworkVersion, architecture, err.Error())
				continue
			}

			// the e2e apks are cached next to the SDKs
			apks, _ := filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(sdk)), "e2e", version.FrameworkVersion+"-*.apk"))

			for _, apk := range apks {
				if strings.Contains(apk, "unknown") {
					continue
				}

				file, found, findErr := boringssl.FindAPKEntry(apk, entry)

				if (findErr != nil) || !found {
					state.Errorf("Test of boringssl.FindAPKEntry function failed, %s should have %s, error: %v", apk, entry, findErr)
					continue
				}

				library, inspectErr := boringssl.InspectFlutter(file, architecture)
				state.Logf("Flutter %s on %s: %s!/%s, ssl_log_secret at 0x%x through %d labels", version.FrameworkVersion, architecture, apk, entry, library.LogSecret, library.Labels)

				if (inspectErr != nil) || (library.LogSecret-file.Offset != expected) || (library.DartVersion != version.DartSdkVersion) {
					state.Errorf("Test of boringssl.InspectFlutter function failed, the stripped engine of %s on %s should have ssl_log_secret at 0x%x, library: %+v, error: %v", apk, architecture, expected, library, inspectErr)
				}
			}
		}
	}
}

// ssl_log_secret of the unstripped engine in flutter.jar, by its symbol, checked against the finder and the Dart version on the same file
func unstrippedLogSecret(jar string, entry string, architecture string, dartVersion string) (address uint64, err error) {
	reader, err := zip.OpenReader(jar)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, reader.Close())
	}()

	index := slices.IndexFunc(reader.File, func(file *zip.File) (isEntry bool) {
		isEntry = (file.Name == entry)
		return
	})

	if index < 0 {
		err = fmt.Errorf("%s has no %s", jar, entry)
		return
	}

	opened, err := reader.File[index].Open()

	if err != nil {
		return
	}

	data, readErr := io.ReadAll(opened)
	err = errors.Join(readErr, opened.Close())

	if err != nil {
		return
	}

	path := filepath.Join(os.TempDir(), fmt.Sprintf("decerter-unit-libflutter-%d.so", os.Getpid()))
	err = os.WriteFile(path, data, 0o600)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, os.Remove(path))
	}()

	file, err := elf.Open(path)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	symbols, err := file.Symbols()

	if err != nil {
		return
	}

	symbolIndex := slices.IndexFunc(symbols, func(symbol elf.Symbol) (isLogSecret bool) {
		isLogSecret = strings.HasPrefix(symbol.Name, "_ZN4bssl14ssl_log_secretE") && (elf.ST_TYPE(symbol.Info) == elf.STT_FUNC)
		return
	})

	if symbolIndex < 0 {
		err = fmt.Errorf("%s has no ssl_log_secret symbol", entry)
		return
	}

	for _, program := range file.Progs {
		value := symbols[symbolIndex].Value

		if (program.Type == elf.PT_LOAD) && ((program.Flags & elf.PF_X) != 0) && (value >= program.Vaddr) && (value < program.Vaddr+program.Filesz) {
			address = value - program.Vaddr + program.Off
		}
	}

	library, err := boringssl.InspectFlutter(boringssl.LibraryFile{Path: path, Entry: "", Offset: 0, Size: uint64(len(data))}, architecture)

	if err != nil {
		return
	}

	if (library.LogSecret != address) || (library.DartVersion != dartVersion) || (library.Labels != len(allLabels)) {
		err = fmt.Errorf("the unstripped engine should have ssl_log_secret at 0x%x (symbol) through %d labels and Dart %s, library: %+v", address, len(allLabels), dartVersion, library)
	}

	return
}

// a FlutterLibrary without comparing its slice
func isSameLibrary(first boringssl.FlutterLibrary, second boringssl.FlutterLibrary) (isSame bool) {
	isSame = (first.File == second.File) && (first.DartVersion == second.DartVersion) && (first.Engine == second.Engine) && (first.Revision == second.Revision) && (first.Offset == second.Offset) && (first.LogSecret == second.LogSecret) && (first.Labels == second.Labels)
	return
}
