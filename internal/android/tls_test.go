// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package android

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// an apk with one library: stored and padded to a page with zipalign's extra field, or compressed, which Android never maps
func writeLibraryAPK(path string, name string, data []byte, isStored bool) (err error) {
	output := &bytes.Buffer{}
	writer := zip.NewWriter(output)
	header := &zip.FileHeader{Name: name, Method: zip.Store, CRC32: crc32.ChecksumIEEE(data), UncompressedSize64: uint64(len(data))}
	content := data

	if isStored {
		padding := 4096 - (30+len(name)+4)%4096
		header.Extra = binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(nil, 0xd935), uint16(padding))
		header.Extra = append(header.Extra, make([]byte, padding)...)
	} else {
		compressed := &bytes.Buffer{}
		compressor, compressorErr := flate.NewWriter(compressed, flate.BestCompression)

		if err = compressorErr; err != nil {
			return
		}

		_, err = compressor.Write(data)

		if err = errors.Join(err, compressor.Close()); err != nil {
			return
		}

		header.Method = zip.Deflate
		content = compressed.Bytes()
	}

	header.CompressedSize64 = uint64(len(content))
	created, err := writer.CreateRaw(header)

	if err != nil {
		return
	}

	_, err = created.Write(content)

	if err = errors.Join(err, writer.Close()); err != nil {
		return
	}

	err = os.WriteFile(path, output.Bytes(), 0o600)
	return
}

// Test if android.DescribeTLS returns with the expected output for libraries in apks: a compressed libflutter.so or Chromium library can't be hooked,
// a stored Chromium library that is no ELF file is named with its apk entry; both Chromium apps get the QUIC line.
func TestDescribeTLSAPKPositive(state *testing.T) {
	appDirectory := state.TempDir()
	flutterDirectory := filepath.Join(appDirectory, "~~a==", "io.decerter.flutter-b==")
	cronetDirectory := filepath.Join(appDirectory, "~~c==", "io.decerter.cronet-d==")
	webViewDirectory := filepath.Join(appDirectory, "~~e==", "io.decerter.webview-f==")
	err := errors.Join(os.MkdirAll(flutterDirectory, 0o700), os.MkdirAll(cronetDirectory, 0o700), os.MkdirAll(webViewDirectory, 0o700))

	if err == nil {
		err = errors.Join(
			writeLibraryAPK(filepath.Join(flutterDirectory, "base.apk"), "lib/x86_64/libflutter.so", bytes.Repeat([]byte("flutter"), 100), false),
			writeLibraryAPK(filepath.Join(cronetDirectory, "base.apk"), "lib/x86_64/libmonochrome_64.so", bytes.Repeat([]byte("cronet"), 100), false),
			writeLibraryAPK(filepath.Join(webViewDirectory, "base.apk"), "lib/x86_64/libwebviewchromium.so", []byte("no ELF file"), true),
		)
	}

	if err != nil {
		state.Fatalf("Test of android.DescribeTLS failed, cannot create the apps, error: %s", err.Error())
	}

	positiveCases := []struct {
		Name       string
		Text       string
		IsChromium bool
	}{
		{Name: "io.decerter.flutter", Text: "io.decerter.flutter: Flutter app that can't be hooked, its TLS is relayed without decryption: ", IsChromium: false},
		{Name: "io.decerter.cronet", Text: "io.decerter.cronet: Chromium library that can't be hooked, its TLS is relayed without decryption: ", IsChromium: true},
		{Name: "io.decerter.webview", Text: "in " + filepath.Join(webViewDirectory, "base.apk") + "!/lib/x86_64/libwebviewchromium.so, its TLS is relayed without decryption", IsChromium: true},
	}

	for _, positive := range positiveCases {
		lines, isKnown, describeErr := DescribeTLS(Package{Name: positive.Name, UID: 10200, VersionCode: 0}, installedPackages, appDirectory, "amd64")

		if (describeErr != nil) || (len(lines) == 0) || !strings.Contains(lines[0], positive.Text) || isKnown || (IsChromiumApp(lines) != positive.IsChromium) {
			state.Errorf("Test of android.DescribeTLS function failed, %s should say %q, Chromium app %v, not known, lines: %q, isKnown: %v, error: %v", positive.Name, positive.Text, positive.IsChromium, lines, isKnown, describeErr)
		}
	}
}

// Test if android.DescribeTLS returns with the expected errors: a package name or a Trichrome library name that is no valid glob pattern.
func TestDescribeTLSNegative(state *testing.T) {
	appDirectory := state.TempDir()
	negativeCases := []struct {
		Selected Package
		Packages []Package
	}{
		{Selected: Package{Name: "io.decerter[", UID: 10200, VersionCode: 0}, Packages: installedPackages},
		{Selected: Package{Name: "com.android.chrome", UID: 10120, VersionCode: 5}, Packages: []Package{{Name: "com.android.chrome", UID: 10120, VersionCode: 5}, {Name: "com.google.android.trichromelibrary[_5", UID: 10160, VersionCode: 5}}},
	}

	for _, negative := range negativeCases {
		lines, isKnown, err := DescribeTLS(negative.Selected, negative.Packages, appDirectory, "amd64")

		if !errors.Is(err, ErrInstallDirectory) {
			state.Errorf("Test of android.DescribeTLS function failed, package %s, error should be %v, lines: %q, isKnown: %v, error: %v", negative.Selected.Name, ErrInstallDirectory, lines, isKnown, err)
		}
	}
}
