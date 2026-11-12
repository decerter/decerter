// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package boringssl_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"

	"github.com/decerter/decerter/internal/tls/boringssl"
)

const (
	logSecretSymbol string = "_ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE"
	// the test ELF has one program header, .text is the first section and the only executable PT_LOAD maps it at textAddress
	textOffset  uint64 = 64 + 56
	textAddress uint64 = 0x10000 + textOffset
	textLength  int    = 64
)

// one section of a test ELF, Link names the section its strings are in
type section struct {
	Name    string
	Type    elf.SectionType
	Flags   elf.SectionFlag
	Data    []byte
	Link    string
	Entsize uint64
}

// one symbol of a test symbol table
type symbol struct {
	Name  string
	Type  elf.SymType
	Value uint64
}

type getOffsetCase struct {
	Release      string
	Architecture string
	Expected     boringssl.Offset
}

type getOffsetNegativeCase struct {
	Release      string
	Architecture string
}

func testGetOffset(positive getOffsetCase) (err error) {
	offset, getErr := boringssl.GetOffset(positive.Release, positive.Architecture)

	if err = getErr; err != nil {
		return
	}

	if offset != positive.Expected {
		err = fmt.Errorf("boringssl.GetOffset(%s, %s) return value was not %+v instead: %+v", positive.Release, positive.Architecture, positive.Expected, offset)
		return
	}

	return
}

// Test if boringssl.GetOffset returns with the expected output.
func TestGetOffsetPositive(state *testing.T) {
	// Android 15 was checked against the emulator's libssl.so (SSL_version, SSL_get_client_random), from 16 on the version is in SSL3_STATE
	positiveCases := []getOffsetCase{
		{
			Release:      "15",
			Architecture: "amd64",
			Expected:     boringssl.Offset{Version: 0x10, VersionInS3: false, S3: 0x30, ClientRandom: 0x30},
		},
		{
			Release:      "16",
			Architecture: "arm64",
			Expected:     boringssl.Offset{Version: 0xd0, VersionInS3: true, S3: 0x30, ClientRandom: 0x30},
		},
	}

	for _, positive := range positiveCases {
		err := testGetOffset(positive)

		if err != nil {
			state.Errorf("Test of boringssl.GetOffset failed, error: %s", err.Error())
			return
		}
	}
}

// Test if boringssl.GetOffset returns with the expected errors.
func TestGetOffsetNegative(state *testing.T) {
	// Android 14 has no 6.6 kernel, an empty release is a build.prop that could not be read, riscv64 has no Android build
	negativeCases := []getOffsetNegativeCase{
		{Release: "14", Architecture: "arm64"},
		{Release: "", Architecture: "amd64"},
		{Release: "15", Architecture: "riscv64"},
	}

	for _, negative := range negativeCases {
		_, err := boringssl.GetOffset(negative.Release, negative.Architecture)
		command := "make generate-boringssl-offsets BORINGSSL_RELEASES=" + negative.Release

		if !errors.Is(err, boringssl.ErrUnknownRelease) || !strings.Contains(err.Error(), command) || !strings.Contains(err.Error(), negative.Architecture) {
			state.Errorf("Test of boringssl.GetOffset function failed, error should be %v naming %q and the architecture, error: %v", boringssl.ErrUnknownRelease, command, err)
			return
		}
	}
}

// Test if boringssl.FindLogSecret returns with the expected errors.
func TestFindLogSecretNegative(state *testing.T) {
	notELF := filepath.Join(state.TempDir(), "libssl.so")
	err := os.WriteFile(notELF, []byte("not an ELF file"), 0o600)

	if err != nil {
		state.Fatalf("Test of boringssl.FindLogSecret failed, cannot write file, error: %s", err.Error())
	}

	_, err = boringssl.FindLogSecret(notELF)

	if !errors.Is(err, boringssl.ErrOpenLibrary) {
		state.Errorf("Test of boringssl.FindLogSecret function failed, error should be %v, error: %v", boringssl.ErrOpenLibrary, err)
		return
	}

	// the test binary is an ELF without ssl_log_secret, like an OpenSSL libssl
	executable, executableErr := os.Executable()

	if executableErr != nil {
		state.Fatalf("Test of boringssl.FindLogSecret failed, cannot find test binary, error: %s", executableErr.Error())
	}

	_, err = boringssl.FindLogSecret(executable)

	if !errors.Is(err, boringssl.ErrNoLogSecret) {
		state.Errorf("Test of boringssl.FindLogSecret function failed, error should be %v, error: %v", boringssl.ErrNoLogSecret, err)
		return
	}

	inside := textAddress + 0x10
	notXZ := []byte("not xz data")
	notELFData, err := compress([]byte("not an ELF file"))

	if err != nil {
		state.Fatalf("Test of boringssl.FindLogSecret failed, cannot compress, error: %s", err.Error())
	}

	negativeCases := []struct {
		Sections []section
		Err      error
	}{
		// the symbol is there but outside of the executable segment
		{Sections: symbolSections(".symtab", elf.SHT_SYMTAB, ".strtab", []symbol{{Name: logSecretSymbol, Type: elf.STT_FUNC, Value: 0x90000}}), Err: boringssl.ErrNotLoaded},
		// a symbol of that name that is no function, and a function of another name
		{Sections: symbolSections(".symtab", elf.SHT_SYMTAB, ".strtab", []symbol{{Name: logSecretSymbol, Type: elf.STT_OBJECT, Value: inside}}), Err: boringssl.ErrNoLogSecret},
		{Sections: symbolSections(".symtab", elf.SHT_SYMTAB, ".strtab", []symbol{{Name: "SSL_write", Type: elf.STT_FUNC, Value: inside}}), Err: boringssl.ErrNoLogSecret},
		// MiniDebugInfo that is not xz, and xz that is not an ELF
		{Sections: []section{{Name: ".gnu_debugdata", Type: elf.SHT_PROGBITS, Flags: 0, Data: notXZ, Link: "", Entsize: 0}}, Err: boringssl.ErrReadDebugData},
		{Sections: []section{{Name: ".gnu_debugdata", Type: elf.SHT_PROGBITS, Flags: 0, Data: notELFData, Link: "", Entsize: 0}}, Err: boringssl.ErrReadDebugData},
	}

	for index, negative := range negativeCases {
		path, writeErr := writeLibrary(state.TempDir(), negative.Sections)

		if writeErr != nil {
			state.Fatalf("Test of boringssl.FindLogSecret failed, cannot write ELF, error: %s", writeErr.Error())
		}

		_, err = boringssl.FindLogSecret(path)

		if !errors.Is(err, negative.Err) || !strings.Contains(err.Error(), path) {
			state.Errorf("Test of boringssl.FindLogSecret function failed, case %d, error should be %v naming the path, error: %v", index, negative.Err, err)
			return
		}
	}
}

// Test if boringssl.FindLogSecret returns with the expected output.
func TestFindLogSecretPositive(state *testing.T) {
	inside := textAddress + 0x10
	symbols := []symbol{{Name: "SSL_write", Type: elf.STT_FUNC, Value: textAddress}, {Name: logSecretSymbol, Type: elf.STT_FUNC, Value: inside}}
	// Android's libssl: .symtab stripped, the function symbols in an xz compressed ELF in .gnu_debugdata, their values the addresses of the outer file
	debugELF, err := buildELF(symbolSections(".symtab", elf.SHT_SYMTAB, ".strtab", symbols), false)

	if err != nil {
		state.Fatalf("Test of boringssl.FindLogSecret failed, cannot build debug ELF, error: %s", err.Error())
	}

	debugData, err := compress(debugELF)

	if err != nil {
		state.Fatalf("Test of boringssl.FindLogSecret failed, cannot compress, error: %s", err.Error())
	}

	positiveCases := [][]section{
		{{Name: ".gnu_debugdata", Type: elf.SHT_PROGBITS, Flags: 0, Data: debugData, Link: "", Entsize: 0}},
		symbolSections(".symtab", elf.SHT_SYMTAB, ".strtab", symbols),
		symbolSections(".dynsym", elf.SHT_DYNSYM, ".dynstr", symbols),
	}

	for index, positive := range positiveCases {
		path, writeErr := writeLibrary(state.TempDir(), positive)

		if writeErr != nil {
			state.Fatalf("Test of boringssl.FindLogSecret failed, cannot write ELF, error: %s", writeErr.Error())
		}

		address, findErr := boringssl.FindLogSecret(path)

		// the uprobe takes the file offset: the address minus the start of the segment plus its offset in the file
		if (findErr != nil) || (address != textOffset+0x10) {
			state.Errorf("Test of boringssl.FindLogSecret function failed, case %d, address should be 0x%x, address: 0x%x, error: %v", index, textOffset+0x10, address, findErr)
			return
		}
	}
}

// Test if boringssl.FindLibssl returns with the expected output.
func TestFindLibsslPositive(state *testing.T) {
	libssl := filepath.Join(state.TempDir(), "libssl.so")
	err := os.WriteFile(libssl, nil, 0o600)

	if err != nil {
		state.Fatalf("Test of boringssl.FindLibssl failed, cannot write file, error: %s", err.Error())
	}

	path, err := boringssl.FindLibssl(libssl)

	if (err != nil) || (path != libssl) {
		state.Errorf("Test of boringssl.FindLibssl function failed, path should be %s, path: %s, error: %v", libssl, path, err)
		return
	}
}

// Test if boringssl.FindLibssl returns with the expected errors.
func TestFindLibsslNegative(state *testing.T) {
	_, err := boringssl.FindLibssl(filepath.Join(state.TempDir(), "missing.so"))

	if !errors.Is(err, boringssl.ErrLibraryNotFound) {
		state.Errorf("Test of boringssl.FindLibssl function failed, error should be %v, error: %v", boringssl.ErrLibraryNotFound, err)
		return
	}
}

// a symbol table and its strings, every symbol is global and in .text
func symbolSections(name string, tableType elf.SectionType, stringsName string, symbols []symbol) (sections []section) {
	// the first symbol is the undefined one, all zero
	table := make([]byte, binary.Size(elf.Sym64{}))
	names := []byte{0}

	// Elf64_Sym: name, info, other, section index, value, size
	for _, current := range symbols {
		table = binary.LittleEndian.AppendUint32(table, uint32(len(names)))
		table = append(table, elf.ST_INFO(elf.STB_GLOBAL, current.Type), 0)
		table = binary.LittleEndian.AppendUint16(table, 1)
		table = binary.LittleEndian.AppendUint64(table, current.Value)
		table = binary.LittleEndian.AppendUint64(table, 8)
		names = append(append(names, current.Name...), 0)
	}

	sections = []section{
		{Name: name, Type: tableType, Flags: 0, Data: table, Link: stringsName, Entsize: uint64(binary.Size(elf.Sym64{}))},
		{Name: stringsName, Type: elf.SHT_STRTAB, Flags: 0, Data: names, Link: "", Entsize: 0},
	}
	return
}

// a libssl.so: .text mapped by one executable PT_LOAD, then the sections
func writeLibrary(directory string, sections []section) (path string, err error) {
	text := section{Name: ".text", Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Data: bytes.Repeat([]byte{0xcc}, textLength), Link: "", Entsize: 0}
	library, buildErr := buildELF(append([]section{text}, sections...), true)

	if err = buildErr; err != nil {
		return
	}

	path = filepath.Join(directory, "libssl.so")
	err = os.WriteFile(path, library, 0o600)
	return
}

// a little-endian ELF64 shared object for x86-64: header, one program header for the first section when withProgram, section data, .shstrtab, section headers
func buildELF(sections []section, withProgram bool) (file []byte, err error) {
	sections = append(slices.Clone(sections), section{Name: ".shstrtab", Type: elf.SHT_STRTAB, Flags: 0, Data: nil, Link: "", Entsize: 0})
	names := []byte{0}
	nameOffsets := []uint32{}

	for _, current := range sections {
		nameOffsets = append(nameOffsets, uint32(len(names)))
		names = append(append(names, current.Name...), 0)
	}

	sections[len(sections)-1].Data = names
	programs := []elf.Prog64{}
	dataStart := uint64(binary.Size(elf.Header64{}))

	if withProgram {
		dataStart += uint64(binary.Size(elf.Prog64{}))
		programs = append(programs, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Off: dataStart, Vaddr: textAddress, Paddr: textAddress, Filesz: uint64(len(sections[0].Data)), Memsz: uint64(len(sections[0].Data)), Align: 0x1000})
	}

	data := []byte{}
	headers := []elf.Section64{{}}

	for index, current := range sections {
		link := slices.IndexFunc(sections, func(candidate section) bool { return (current.Link != "") && (candidate.Name == current.Link) }) + 1
		address := uint64(0)

		if (current.Flags & elf.SHF_ALLOC) != 0 {
			address = textAddress
		}

		headers = append(headers, elf.Section64{Name: nameOffsets[index], Type: uint32(current.Type), Flags: uint64(current.Flags), Addr: address, Off: dataStart + uint64(len(data)), Size: uint64(len(current.Data)), Link: uint32(link), Info: 1, Addralign: 1, Entsize: current.Entsize})
		data = append(data, current.Data...)
	}

	header := elf.Header64{
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Shoff:     dataStart + uint64(len(data)),
		Ehsize:    uint16(binary.Size(elf.Header64{})),
		Phentsize: uint16(binary.Size(elf.Prog64{})),
		Phnum:     uint16(len(programs)),
		Shentsize: uint16(binary.Size(elf.Section64{})),
		Shnum:     uint16(len(headers)),
		Shstrndx:  uint16(len(headers) - 1),
	}

	if withProgram {
		header.Phoff = uint64(binary.Size(elf.Header64{}))
	}

	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	output := bytes.Buffer{}

	for _, part := range []any{header, programs, data, headers} {
		err = binary.Write(&output, binary.LittleEndian, part)

		if err != nil {
			err = fmt.Errorf("could not write ELF: %w", err)
			return
		}
	}

	file = output.Bytes()
	return
}

// xz as MiniDebugInfo uses it
func compress(data []byte) (compressed []byte, err error) {
	output := bytes.Buffer{}
	writer, writerErr := xz.NewWriter(&output)

	if err = writerErr; err != nil {
		return
	}

	_, err = writer.Write(data)
	err = errors.Join(err, writer.Close())
	compressed = output.Bytes()
	return
}
