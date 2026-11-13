// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package cmd

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/android"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/pkg/internal/logging"
)

const (
	// com.example.shared and com.example.other share a uid, android has the system uid
	testPackagesList string = "com.example.app 10092 0 /data/user/0/com.example.app default 3003 0 1 1 @null\ncom.example.shared 10120 0 /data/user/0/com.example.shared default 3003 0 1 1 @null\ncom.example.other 10120 0 /data/user/0/com.example.other default 3003 0 1 1 @null\nandroid 1000 0 /data/system platform none 0 35 1 @system\n"
)

var (
	androidPlatform = platform.Platform{Type: platform.AndroidType, SDK: 35, Release: "15", DataDirectory: platform.AndroidDataDirectory, APISocket: platform.AndroidAPISocket}
)

func writePackagesList(state *testing.T) (path string) {
	path = filepath.Join(state.TempDir(), "packages.list")
	err := os.WriteFile(path, []byte(testPackagesList), 0o600)

	if err != nil {
		state.Fatalf("Could not write packages.list, error: %s", err.Error())
	}

	return
}

// Test if cmd.selectPackages returns with the expected output: the uids of the packages join the uids of --uid once each, the rest of the selection stays, a shared uid is a warning.
func TestSelectPackagesPositive(state *testing.T) {
	path := writePackagesList(state)
	positiveCases := []struct {
		Selection redirect.Filter
		Names     []string
		Expected  redirect.Filter
		Warning   bool
	}{
		{Selection: redirect.Filter{UIDs: []uint32{1001}}, Names: nil, Expected: redirect.Filter{UIDs: []uint32{1001}}, Warning: false},
		{Selection: redirect.Filter{}, Names: []string{"com.example.app"}, Expected: redirect.Filter{UIDs: []uint32{10092}}, Warning: false},
		{Selection: redirect.Filter{UIDs: []uint32{10092}, Tgids: []uint32{42}, Comms: []string{"curl"}}, Names: []string{"com.example.app", "com.example.shared", "com.example.other"}, Expected: redirect.Filter{UIDs: []uint32{10092, 10120}, Tgids: []uint32{42}, Comms: []string{"curl"}}, Warning: true},
		{Selection: redirect.Filter{}, Names: []string{"android"}, Expected: redirect.Filter{UIDs: []uint32{1000}}, Warning: true},
	}

	for _, positive := range positiveCases {
		logs := &bytes.Buffer{}
		logger := logging.New(logs, slog.LevelInfo)
		original := positive.Selection.UIDs
		selection, err := selectPackages(positive.Selection, positive.Names, androidPlatform, path, &logger)

		if (err != nil) || !reflect.DeepEqual(selection, positive.Expected) {
			state.Errorf("Test of cmd.selectPackages function failed, names %q, selection should be %+v, selection: %+v, error: %v", positive.Names, positive.Expected, selection, err)
			return
		}

		// the uids of the flags are not changed behind the caller's back
		if (len(original) > 0) && !reflect.DeepEqual(positive.Selection.UIDs, original) {
			state.Errorf("Test of cmd.selectPackages function failed, the uids given changed: %v", positive.Selection.UIDs)
			return
		}

		if strings.Contains(logs.String(), `"msg":"The package shares its uid`) != positive.Warning {
			state.Errorf("Test of cmd.selectPackages function failed, names %q, a shared uid warning should be %v, logs: %s", positive.Names, positive.Warning, logs.String())
			return
		}
	}
}

// Test if cmd.selectPackages returns with the expected errors: a package on Linux, an unknown package with suggestions, a packages.list that can't be read.
func TestSelectPackagesNegative(state *testing.T) {
	path := writePackagesList(state)
	linux := platform.Platform{Type: platform.LinuxType, SDK: 0, Release: "", DataDirectory: "/run/decerter", APISocket: "/run/decerter/api.sock"}
	negativeCases := []struct {
		Platform platform.Platform
		Path     string
		Names    []string
		Expected error
		Text     string
	}{
		{Platform: linux, Path: path, Names: []string{"com.example.app"}, Expected: ErrPackageNotAndroid, Text: "on Linux select with --uid"},
		{Platform: androidPlatform, Path: path, Names: []string{"com.example.app", "com.example.ap"}, Expected: android.ErrUnknownPackage, Text: `unknown package "com.example.ap", the closest installed packages: com.example.app, `},
		{Platform: androidPlatform, Path: filepath.Join(state.TempDir(), "missing"), Names: []string{"com.example.app"}, Expected: android.ErrPackagesList, Text: "no such file"},
	}

	for _, negative := range negativeCases {
		logs := &bytes.Buffer{}
		logger := logging.New(logs, slog.LevelInfo)
		selection, err := selectPackages(redirect.Filter{UIDs: []uint32{1001}}, negative.Names, negative.Platform, negative.Path, &logger)

		if !errors.Is(err, negative.Expected) || !strings.Contains(err.Error(), negative.Text) || !strings.Contains(logs.String(), `"level":"ERROR"`) {
			state.Errorf("Test of cmd.selectPackages function failed, names %q, error should be %v with %q, selection: %+v, error: %v, logs: %s", negative.Names, negative.Expected, negative.Text, selection, err, logs.String())
			return
		}
	}
}
