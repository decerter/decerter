// SPDX-License-Identifier: AGPL-3.0-only

package boringssl

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ulikunitz/xz"
)

const (
	// Java apps get TLS from Conscrypt, which uses the BoringSSL of its APEX, the module is updated through Play
	ConscryptLibssl string = "/apex/com.android.conscrypt/lib64/libssl.so"
	// bssl::ssl_log_secret(const SSL *, const char *, bssl::Span<const uint8_t>), the mangled name pins the signature the uprobe reads its registers by
	logSecretSymbol string = "_ZN4bssl14ssl_log_secretEPK6ssl_stPKcNS_4SpanIKhEE"
	// Android strips .symtab and keeps the function symbols as an xz compressed ELF in this section (MiniDebugInfo)
	debugDataSection string = ".gnu_debugdata"
)

// override is the --libssl flag, empty means the libssl of the Conscrypt APEX
func FindLibssl(override string) (libsslPath string, err error) {
	libsslPath = override

	if libsslPath == "" {
		libsslPath = ConscryptLibssl
	}

	_, err = os.Stat(libsslPath)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrLibraryNotFound, err)
		return
	}

	return
}

// the file offset of ssl_log_secret for a uprobe, the symbol is internal: it is looked up in .symtab and .dynsym, then in the MiniDebugInfo of .gnu_debugdata
// a library without the symbol, an OpenSSL for example, gives ErrNoLogSecret
func FindLogSecret(libsslPath string) (address uint64, err error) {
	file, openErr := elf.Open(libsslPath)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrOpenLibrary, libsslPath, err)
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	value, found := symbolValue(file, logSecretSymbol)

	if !found {
		debugFile, debugErr := openDebugData(file)

		if err = debugErr; err != nil {
			err = fmt.Errorf("%s: %w", libsslPath, err)
			return
		}

		if debugFile != nil {
			value, found = symbolValue(debugFile, logSecretSymbol)
		}
	}

	if !found {
		err = fmt.Errorf("%w: %s", ErrNoLogSecret, libsslPath)
		return
	}

	address, found = fileOffset(file, value)

	if !found {
		err = fmt.Errorf("%w: %s: 0x%x", ErrNotLoaded, libsslPath, value)
		return
	}

	return
}

// pick the offsets by ro.build.version.release and the architecture decerter runs on, with an error that names the make command
func GetOffset(release string, architecture string) (offset Offset, err error) {
	var ok bool

	if offset, ok = offsets[release][architecture]; !ok {
		err = fmt.Errorf("%w: %q on %s, run make generate-boringssl-offsets BORINGSSL_RELEASES=%s", ErrUnknownRelease, release, architecture, release)
		return
	}

	return
}

// the value of a function symbol in .symtab or .dynsym, a missing table is no error
func symbolValue(file *elf.File, name string) (value uint64, found bool) {
	for _, readSymbols := range []func() ([]elf.Symbol, error){file.Symbols, file.DynamicSymbols} {
		symbols, readErr := readSymbols()

		if readErr != nil {
			continue
		}

		for _, symbol := range symbols {
			if (symbol.Name == name) && (elf.ST_TYPE(symbol.Info) == elf.STT_FUNC) && (symbol.Value != 0) {
				value = symbol.Value
				found = true
				return
			}
		}
	}

	return
}

// the ELF embedded in .gnu_debugdata, nil without the section
// its symbols have the virtual addresses of the outer file
func openDebugData(file *elf.File) (debugFile *elf.File, err error) {
	section := file.Section(debugDataSection)

	if section == nil {
		return
	}

	data, readErr := section.Data()

	if err = readErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrReadDebugData, err)
		return
	}

	reader, readerErr := xz.NewReader(bytes.NewReader(data))

	if err = readerErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrReadDebugData, err)
		return
	}

	raw, decompressErr := io.ReadAll(reader)

	if err = decompressErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrReadDebugData, err)
		return
	}

	debugFile, err = elf.NewFile(bytes.NewReader(raw))

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrReadDebugData, err)
		return
	}

	return
}

// a uprobe takes a file offset, the symbol value is a virtual address inside an executable PT_LOAD segment
func fileOffset(file *elf.File, value uint64) (offset uint64, found bool) {
	for _, program := range file.Progs {
		if (program.Type != elf.PT_LOAD) || ((program.Flags & elf.PF_X) == 0) {
			continue
		}

		if (value >= program.Vaddr) && (value < program.Vaddr+program.Filesz) {
			offset = value - program.Vaddr + program.Off
			found = true
			return
		}
	}

	return
}
