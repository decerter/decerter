// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package android

import (
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	// lines of the emulator's packages.list, with a blank line; com.android.settings and android share the system uid
	packagesList string = `com.google.android.networkstack.tethering 1073 0 /data/user_de/0/com.google.android.networkstack.tethering network_stack:privapp:targetSdkVersion=35:partition=system 3002,3003,3007,3006,3005,3004 0 35 1 @system
com.android.proxyhandler 10092 0 /data/user_de/0/com.android.proxyhandler platform:privapp:targetSdkVersion=35:partition=system 3003 0 35 1 @system

com.android.chrome 10120 0 /data/user/0/com.android.chrome default:targetSdkVersion=34:partition=product 3003 0 1 1 @system
com.google.android.youtube 10167 0 /data/user/0/com.google.android.youtube default:targetSdkVersion=34:partition=product 3003 0 1545868784 1 @system
com.android.settings 1000 0 /data/user_de/0/com.android.settings platform:system_app:targetSdkVersion=35:partition=system 1065,3002,1023,3003,3001,1007,1077,2002 0 35 1 @system
android 1000 0 /data/system platform:system_app:targetSdkVersion=35 none 0 35 1 @system
`
)

var (
	installedPackages = []Package{
		{Name: "com.google.android.networkstack.tethering", UID: 1073},
		{Name: "com.android.proxyhandler", UID: 10092},
		{Name: "com.android.chrome", UID: 10120},
		{Name: "com.google.android.youtube", UID: 10167},
		{Name: "com.android.settings", UID: 1000},
		{Name: "android", UID: 1000},
	}
)

// Test if android.ParsePackages and android.ReadPackages return with the expected output.
func TestParsePackagesPositive(state *testing.T) {
	packages, err := ParsePackages(strings.NewReader(packagesList))

	if (err != nil) || !reflect.DeepEqual(packages, installedPackages) {
		state.Errorf("Test of android.ParsePackages function failed, packages should be %+v, packages: %+v, error: %v", installedPackages, packages, err)
		return
	}

	// a file without a line end at its end, as cat of a short list gives it
	path := filepath.Join(state.TempDir(), "packages.list")
	err = os.WriteFile(path, []byte("com.example.app 10200 1 /data/user/0/com.example.app default:targetSdkVersion=35 3003 0 1 1 @null"), 0o600)

	if err != nil {
		state.Fatalf("Test of android.ReadPackages failed, cannot write file, error: %s", err.Error())
	}

	packages, err = ReadPackages(path)

	if (err != nil) || !reflect.DeepEqual(packages, []Package{{Name: "com.example.app", UID: 10200}}) {
		state.Errorf("Test of android.ReadPackages function failed, packages: %+v, error: %v", packages, err)
		return
	}
}

// Test if android.ParsePackages and android.ReadPackages return with the expected errors.
func TestParsePackagesNegative(state *testing.T) {
	negativeCases := []string{
		"",
		"\n\n",
		"com.example.app\n",
		"com.example.app ten 0 /data/user/0/com.example.app\n",
		"com.example.app 4294967296 0 /data/user/0/com.example.app\n",
		"com.example.app -1 0 /data/user/0/com.example.app\n",
		packagesList + "com.example.broken\n",
	}

	for _, negative := range negativeCases {
		packages, err := ParsePackages(strings.NewReader(negative))

		if !errors.Is(err, ErrPackagesList) {
			state.Errorf("Test of android.ParsePackages function failed, input %q, error should be %v, packages: %+v, error: %v", negative, ErrPackagesList, packages, err)
			return
		}
	}

	_, err := ReadPackages(filepath.Join(state.TempDir(), "missing"))

	if !errors.Is(err, ErrPackagesList) || !errors.Is(err, os.ErrNotExist) {
		state.Errorf("Test of android.ReadPackages function failed, error should be %v and %v, error: %v", ErrPackagesList, os.ErrNotExist, err)
		return
	}
}

// Test if android.ResolvePackages returns with the expected output: each name's package, in the order of the names.
func TestResolvePackagesPositive(state *testing.T) {
	resolved, err := ResolvePackages([]string{"com.android.chrome", "com.android.proxyhandler"}, installedPackages)
	expected := []Package{{Name: "com.android.chrome", UID: 10120}, {Name: "com.android.proxyhandler", UID: 10092}}

	if (err != nil) || !reflect.DeepEqual(resolved, expected) {
		state.Errorf("Test of android.ResolvePackages function failed, resolved should be %+v, resolved: %+v, error: %v", expected, resolved, err)
		return
	}

	resolved, err = ResolvePackages(nil, installedPackages)

	if (err != nil) || (len(resolved) != 0) {
		state.Errorf("Test of android.ResolvePackages function failed, no name should resolve to nothing, resolved: %+v, error: %v", resolved, err)
		return
	}
}

// Test if android.ResolvePackages returns with the expected errors: an unknown name, also next to a known one, names the closest packages; a name matches exactly.
func TestResolvePackagesNegative(state *testing.T) {
	negativeCases := []struct {
		Names []string
		Text  string
	}{
		{Names: []string{"no.such.app"}, Text: `unknown package "no.such.app", the closest installed packages: `},
		{Names: []string{"com.android.proxyhandler", "proxyhandler"}, Text: `unknown package "proxyhandler", the closest installed packages: com.android.proxyhandler, `},
		{Names: []string{"com.android.Chrome"}, Text: `the closest installed packages: com.android.chrome, `},
		{Names: []string{"com.android.chrome "}, Text: `unknown package "com.android.chrome "`},
	}

	for _, negative := range negativeCases {
		resolved, err := ResolvePackages(negative.Names, installedPackages)

		if !errors.Is(err, ErrUnknownPackage) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of android.ResolvePackages function failed, names %q, error should contain %q, resolved: %+v, error: %v", negative.Names, negative.Text, resolved, err)
			return
		}
	}
}

// Test if android.SuggestPackages returns with the expected output: names that contain the query first and shortest first, then by edit distance, at most count.
func TestSuggestPackagesPositive(state *testing.T) {
	positiveCases := []struct {
		Name     string
		Count    int
		Expected []string
	}{
		{Name: "chrome", Count: 1, Expected: []string{"com.android.chrome"}},
		{Name: "ANDROID", Count: 3, Expected: []string{"android", "com.android.chrome", "com.android.settings"}},
		// a typo has no substring match, the edit distance decides
		{Name: "com.androd.chrome", Count: 2, Expected: []string{"com.android.chrome", "com.android.settings"}},
		{Name: "no.such.app", Count: 10, Expected: []string{"android", "com.android.chrome", "com.android.settings", "com.android.proxyhandler", "com.google.android.youtube", "com.google.android.networkstack.tethering"}},
	}

	for _, positive := range positiveCases {
		suggestions := SuggestPackages(positive.Name, installedPackages, positive.Count)

		if !reflect.DeepEqual(suggestions, positive.Expected) {
			state.Errorf("Test of android.SuggestPackages function failed, name %q, suggestions should be %q, suggestions: %q", positive.Name, positive.Expected, suggestions)
			return
		}
	}
}

// Test if android.SuggestPackages returns with the expected output when there is nothing to suggest.
func TestSuggestPackagesNegative(state *testing.T) {
	for _, packages := range [][]Package{nil, {}} {
		suggestions := SuggestPackages("com.android.chrome", packages, suggestionCount)

		if len(suggestions) != 0 {
			state.Errorf("Test of android.SuggestPackages function failed, no package should give no suggestion, suggestions: %q", suggestions)
			return
		}
	}

	suggestions := SuggestPackages("chrome", installedPackages, 0)

	if len(suggestions) != 0 {
		state.Errorf("Test of android.SuggestPackages function failed, count 0 should give no suggestion, suggestions: %q", suggestions)
		return
	}
}

// Test if android.editDistance returns with the expected output.
func TestEditDistancePositive(state *testing.T) {
	positiveCases := []struct {
		First    string
		Second   string
		Expected int
	}{
		{First: "", Second: "", Expected: 0},
		{First: "", Second: "abc", Expected: 3},
		{First: "kitten", Second: "sitting", Expected: 3},
		{First: "com.androd.chrome", Second: "com.android.chrome", Expected: 1},
		{First: "same", Second: "same", Expected: 0},
	}

	for _, positive := range positiveCases {
		distance := editDistance(positive.First, positive.Second)
		reverse := editDistance(positive.Second, positive.First)

		if (distance != positive.Expected) || (reverse != positive.Expected) {
			state.Errorf("Test of android.editDistance function failed, %q and %q should be %d apart, distance: %d and %d", positive.First, positive.Second, positive.Expected, distance, reverse)
			return
		}
	}
}

// Test if android.SharingPackages and android.IsSystemUID return with the expected output.
func TestSharingPackagesPositive(state *testing.T) {
	sharing := SharingPackages(Package{Name: "com.android.settings", UID: 1000}, installedPackages)

	if !reflect.DeepEqual(sharing, []string{"android"}) || !IsSystemUID(1000) || !IsSystemUID(1073) {
		state.Errorf("Test of android.SharingPackages function failed, settings should share uid 1000 with android, sharing: %q", sharing)
		return
	}
}

// Test if android.SharingPackages and android.IsSystemUID return with the expected output for an app with its own uid.
func TestSharingPackagesNegative(state *testing.T) {
	sharing := SharingPackages(Package{Name: "com.android.proxyhandler", UID: 10092}, installedPackages)

	if (len(sharing) != 0) || IsSystemUID(10092) || IsSystemUID(10000) {
		state.Errorf("Test of android.SharingPackages function failed, the proxy handler should share its uid with nobody, sharing: %q", sharing)
		return
	}
}

// Test if android.PackagesOfUID and android.FindInstallDirectories return with the expected output: the packages of a shared uid, the install
// directories of Android 11+ (<random>/<package>-<random>, two during an update) and of older releases, nothing for a system app.
func TestFindInstallDirectoriesPositive(state *testing.T) {
	if names := PackagesOfUID(1000, installedPackages); !reflect.DeepEqual(names, []string{"com.android.settings", "android"}) {
		state.Errorf("Test of android.PackagesOfUID function failed, uid 1000 should be settings and android, names: %q", names)
	}

	appDirectory := state.TempDir()
	expected := []string{filepath.Join(appDirectory, "~~a==", "io.decerter.app-b=="), filepath.Join(appDirectory, "~~c==", "io.decerter.app-d=="), filepath.Join(appDirectory, "io.decerter.old-1")}
	others := []string{filepath.Join(appDirectory, "~~e==", "io.decerter.application-f=="), filepath.Join(appDirectory, "~~g==", "io.decerter.app")}

	for _, directory := range append(slices.Clone(expected), others...) {
		err := os.MkdirAll(directory, 0o700)

		if err != nil {
			state.Fatalf("Test of android.FindInstallDirectories failed, cannot create %s, error: %s", directory, err.Error())
		}
	}

	// a file with the name of an install directory is no install directory
	err := os.WriteFile(filepath.Join(appDirectory, "io.decerter.app-file"), nil, 0o600)

	if err != nil {
		state.Fatalf("Test of android.FindInstallDirectories failed, cannot write a file, error: %s", err.Error())
	}

	positiveCases := []struct {
		Name     string
		Expected []string
	}{
		{Name: "io.decerter.app", Expected: expected[:2]},
		{Name: "io.decerter.old", Expected: expected[2:]},
		{Name: "com.android.settings", Expected: nil},
	}

	for _, positive := range positiveCases {
		directories, findErr := FindInstallDirectories(appDirectory, positive.Name)

		if (findErr != nil) || !reflect.DeepEqual(directories, positive.Expected) {
			state.Errorf("Test of android.FindInstallDirectories function failed, %s should be %q, directories: %q, error: %v", positive.Name, positive.Expected, directories, findErr)
		}
	}
}

// Test if android.PackagesOfUID and android.FindInstallDirectories return with the expected errors: no package for an unused uid, a name that is
// no glob pattern.
func TestFindInstallDirectoriesNegative(state *testing.T) {
	if names := PackagesOfUID(10999, installedPackages); len(names) != 0 {
		state.Errorf("Test of android.PackagesOfUID function failed, uid 10999 has no package, names: %q", names)
	}

	_, err := FindInstallDirectories(state.TempDir(), "io.decerter[")

	if !errors.Is(err, ErrInstallDirectory) {
		state.Errorf("Test of android.FindInstallDirectories function failed, error should be %v, error: %v", ErrInstallDirectory, err)
	}
}

// Test if android.DescribeTLS returns with the expected output: a system app, an app without libflutter.so, a Flutter app whose library has no Dart
// version (not hookable, isKnown false).
func TestDescribeTLSPositive(state *testing.T) {
	appDirectory := state.TempDir()
	flutterLibrary := filepath.Join(appDirectory, "~~a==", "io.decerter.flutter-b==", "lib", "x86_64", "libflutter.so")
	err := errors.Join(os.MkdirAll(filepath.Join(appDirectory, "~~c==", "io.decerter.java-d=="), 0o700), os.MkdirAll(filepath.Dir(flutterLibrary), 0o700))

	if err == nil {
		err = writeELF(flutterLibrary, elf.ELFCLASS64, elf.EM_X86_64, false)
	}

	if err != nil {
		state.Fatalf("Test of android.DescribeTLS failed, cannot create the apps, error: %s", err.Error())
	}

	positiveCases := []struct {
		Name    string
		Text    string
		IsKnown bool
	}{
		{Name: "com.android.proxyhandler", Text: "a system app; Java TLS goes through Conscrypt", IsKnown: true},
		{Name: "io.decerter.java", Text: "no libflutter.so, not a Flutter app", IsKnown: true},
		{Name: "io.decerter.flutter", Text: "its TLS is relayed without decryption", IsKnown: false},
	}

	for _, positive := range positiveCases {
		lines, isKnown, describeErr := DescribeTLS(positive.Name, appDirectory, "amd64")

		if (describeErr != nil) || (len(lines) != 1) || !strings.Contains(lines[0], positive.Text) || (isKnown != positive.IsKnown) {
			state.Errorf("Test of android.DescribeTLS function failed, %s should say %q, lines: %q, isKnown: %v, error: %v", positive.Name, positive.Text, lines, isKnown, describeErr)
		}
	}
}
