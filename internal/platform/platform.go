// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	// every Android system image has it, no Linux distribution does
	buildPropPath      string = "system/build.prop"
	sdkProperty        string = "ro.build.version.sdk"
	releaseProperty    string = "ro.build.version.release"
	linuxDataDirectory string = "/run/decerter"
	linuxAPISocket     string = "/run/decerter/api.sock"
	// decerter android setup pushes the binary here, so the data directory needs another name
	AndroidBinaryPath    string = "/data/local/tmp/decerter"
	AndroidDataDirectory string = "/data/local/tmp/decerter.d"
	// adbd can't connect to a socket file made by root in /data/local/tmp unless adbd runs as root, an abstract socket works with adb forward localabstract:decerter-api
	// an abstract socket has no file mode, the API server checks the peer with SO_PEERCRED
	AndroidAPISocket string = "@decerter-api"
	// in the data directory: the netd hooks a running decerter shared, decerter android restore puts them back from it after a SIGKILL
	NetdStateName string = "netd-hooks.json"
	// the installed apps with their uid, one line each, readable by root (system:package_info 0640)
	AndroidPackagesList string = "/data/system/packages.list"
	// where the package manager installs apps, each in <random>/<package>-<random>/ with base.apk and the extracted lib/<isa>/
	AndroidAppDirectory string = "/data/app"
)

// root is the filesystem root, / outside of tests
// the build properties are only read for the version, a build.prop that can't be read (decerter without root) still means Android
func Detect(root string) (platform Platform) {
	_, statErr := os.Stat(filepath.Join(root, buildPropPath))

	if statErr != nil {
		platform = Platform{
			Type:          LinuxType,
			SDK:           0,
			Release:       "",
			DataDirectory: linuxDataDirectory,
			APISocket:     linuxAPISocket,
		}
		return
	}

	// without the properties the version stays unknown, it is still Android
	properties, _ := readProperties(filepath.Join(root, buildPropPath))
	sdk, parseErr := strconv.Atoi(properties[sdkProperty])

	if parseErr != nil {
		sdk = 0
	}

	platform = Platform{
		Type:          AndroidType,
		SDK:           sdk,
		Release:       properties[releaseProperty],
		DataDirectory: AndroidDataDirectory,
		APISocket:     AndroidAPISocket,
	}
	return
}

// key=value lines, # starts a comment
func readProperties(path string) (properties map[string]string, err error) {
	properties = map[string]string{}
	file, openErr := os.Open(path)

	if err = openErr; err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if (line == "") || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, "=")

		if !found {
			continue
		}

		properties[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	err = scanner.Err()
	return
}

// only root may read or write the directory, it holds the state that puts netd's hooks back
// a file of the same name fails with ENOTDIR
func CreateDataDirectory(directory string) (err error) {
	err = os.MkdirAll(directory, 0o700)

	if err != nil {
		err = fmt.Errorf("%w: %s: %w", ErrDataDirectory, directory, err)
		return
	}

	return
}

// the executable file mappings of a /proc/<pid>/maps text: start-end perms offset dev inode path, r-xp only, each once; a deleted file (an app
// updated while it runs) is left out, a uprobe can't reach it by its path
func ExecutableMappings(maps string) (mappings []Mapping) {
	for line := range strings.Lines(maps) {
		fields := strings.Fields(line)

		if (len(fields) < 6) || (len(fields[1]) < 3) || (fields[1][2] != 'x') || !strings.HasPrefix(fields[5], "/") || strings.HasSuffix(strings.TrimSpace(line), "(deleted)") {
			continue
		}

		offset, parseErr := strconv.ParseUint(fields[2], 16, 64)

		if parseErr != nil {
			continue
		}

		mapping := Mapping{Path: strings.Join(fields[5:], " "), Offset: offset}

		if !slices.Contains(mappings, mapping) {
			mappings = append(mappings, mapping)
		}
	}

	return
}
