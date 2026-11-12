// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package boringssl_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/decerter/decerter/internal/tls/boringssl"
)

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

		if !errors.Is(err, boringssl.ErrUnknownRelease) {
			state.Errorf("Test of boringssl.GetOffset function failed, error should be %v, error: %v", boringssl.ErrUnknownRelease, err)
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
}

// Test if boringssl.FindLibssl returns with the expected errors.
func TestFindLibsslNegative(state *testing.T) {
	_, err := boringssl.FindLibssl(filepath.Join(state.TempDir(), "missing.so"))

	if !errors.Is(err, boringssl.ErrLibraryNotFound) {
		state.Errorf("Test of boringssl.FindLibssl function failed, error should be %v, error: %v", boringssl.ErrLibraryNotFound, err)
		return
	}
}
