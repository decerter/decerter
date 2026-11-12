// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package platform_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/decerter/decerter/internal/platform"
)

type detectCase struct {
	BuildProp *string
	Expected  platform.Platform
}

const (
	buildProp string = "# begin build properties\nro.build.version.sdk=35\nro.build.version.release=15\nro.product.cpu.abi=x86_64\n\nnot a property\n"
	// a build.prop without the version, as a root-only file looks to a reader without root
	emptyBuildProp string = "# begin build properties\n"
	// Android 16: spaces around keys and values are trimmed, a later line wins, a value may hold another =
	android16BuildProp string = "ro.build.version.sdk = 35\n  ro.build.version.sdk=36  \nro.build.version.release = 16\nro.build.description=sdk_gphone64_x86_64-user 16 BP22.250325.006 13344233 release-keys,a=b\n"
	// a developer preview names its SDK, the release is a code name
	previewBuildProp string = "ro.build.version.sdk=Baklava\nro.build.version.release=Baklava\n# ro.build.version.release=15\n"
)

// write build.prop under a new root, nil writes nothing as on Linux
func makeRoot(directory string, content *string) (root string, err error) {
	root = directory

	if content == nil {
		return
	}

	err = os.MkdirAll(filepath.Join(root, "system"), 0o755)

	if err != nil {
		return
	}

	err = os.WriteFile(filepath.Join(root, "system", "build.prop"), []byte(*content), 0o600)
	return
}

func testDetect(directory string, positive detectCase) (err error) {
	root, makeErr := makeRoot(directory, positive.BuildProp)

	if err = makeErr; err != nil {
		return
	}

	detected := platform.Detect(root)

	if !reflect.DeepEqual(detected, positive.Expected) {
		err = fmt.Errorf("platform.Detect(%s) return value was not %+v instead: %+v", root, positive.Expected, detected)
		return
	}

	return
}

// Test if platform.Detect returns with the expected output.
func TestDetectPositive(state *testing.T) {
	positiveCases := []detectCase{
		{
			BuildProp: nil,
			Expected:  platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "/run/decerter", APISocket: "/run/decerter/api.sock"},
		},
		{
			BuildProp: new(buildProp),
			Expected:  platform.Platform{Type: platform.AndroidType, SDK: 35, Release: "15", DataDirectory: "/data/local/tmp/decerter.d", APISocket: "@decerter-api"},
		},
		{
			BuildProp: new(emptyBuildProp),
			Expected:  platform.Platform{Type: platform.AndroidType, SDK: 0, Release: "", DataDirectory: "/data/local/tmp/decerter.d", APISocket: "@decerter-api"},
		},
		{
			BuildProp: new(android16BuildProp),
			Expected:  platform.Platform{Type: platform.AndroidType, SDK: 36, Release: "16", DataDirectory: "/data/local/tmp/decerter.d", APISocket: "@decerter-api"},
		},
		{
			BuildProp: new(previewBuildProp),
			Expected:  platform.Platform{Type: platform.AndroidType, SDK: 0, Release: "Baklava", DataDirectory: "/data/local/tmp/decerter.d", APISocket: "@decerter-api"},
		},
	}

	for _, positive := range positiveCases {
		err := testDetect(state.TempDir(), positive)

		if err != nil {
			state.Errorf("Test of platform.Detect failed, error: %s", err.Error())
			return
		}
	}
}

// Test if platform.Detect returns with the expected output for a build.prop that exists but can't be read.
func TestDetectUnreadablePositive(state *testing.T) {
	// a directory in place of the file: it is there, so it is Android, but reading it fails even for root
	root := state.TempDir()
	err := os.MkdirAll(filepath.Join(root, "system", "build.prop"), 0o755)

	if err != nil {
		state.Fatalf("Test of platform.Detect failed, cannot create directory, error: %s", err.Error())
	}

	expected := platform.Platform{Type: platform.AndroidType, SDK: 0, Release: "", DataDirectory: "/data/local/tmp/decerter.d", APISocket: "@decerter-api"}
	detected := platform.Detect(root)

	if !reflect.DeepEqual(detected, expected) {
		state.Errorf("Test of platform.Detect function failed, platform should be %+v, platform: %+v", expected, detected)
		return
	}
}

// Test if platform.CreateDataDirectory returns with the expected output.
func TestCreateDataDirectoryPositive(state *testing.T) {
	directory := filepath.Join(state.TempDir(), "decerter.d")

	// a second call finds the directory and keeps it
	for range 2 {
		err := platform.CreateDataDirectory(directory)

		if err != nil {
			state.Errorf("Test of platform.CreateDataDirectory failed, error: %s", err.Error())
			return
		}
	}

	info, err := os.Stat(directory)

	if err != nil {
		state.Errorf("Test of platform.CreateDataDirectory failed, error: %s", err.Error())
		return
	}

	if !info.IsDir() || (info.Mode().Perm() != 0o700) {
		state.Errorf("Test of platform.CreateDataDirectory function failed, mode should be %v, mode: %v", os.ModeDir|0o700, info.Mode())
		return
	}
}

// Test if platform.CreateDataDirectory returns with the expected errors.
func TestCreateDataDirectoryNegative(state *testing.T) {
	// the binary /data/local/tmp/decerter is a file where a directory of the same name would have to be
	file := filepath.Join(state.TempDir(), "decerter")
	err := os.WriteFile(file, []byte{}, 0o755)

	if err != nil {
		state.Fatalf("Test of platform.CreateDataDirectory failed, cannot write file, error: %s", err.Error())
	}

	err = platform.CreateDataDirectory(file)

	if !errors.Is(err, platform.ErrDataDirectory) {
		state.Errorf("Test of platform.CreateDataDirectory function failed, error should be %v, error: %v", platform.ErrDataDirectory, err)
		return
	}
}
