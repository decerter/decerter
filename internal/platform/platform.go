// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// every Android system image has it, no Linux distribution does
	buildPropPath   string = "system/build.prop"
	sdkProperty     string = "ro.build.version.sdk"
	releaseProperty string = "ro.build.version.release"
	// the binary is pushed to /data/local/tmp/decerter, so the directory needs another name
	androidDataDirectory string = "/data/local/tmp/decerter.d"
	linuxDataDirectory   string = "/run/decerter"
	// adbd can't connect to a socket file made by root in /data/local/tmp unless adbd runs as root, an abstract socket works with adb forward localabstract:decerter-api
	// an abstract socket has no file mode, the API server checks the peer with SO_PEERCRED
	androidAPISocket string = "@decerter-api"
	linuxAPISocket   string = "/run/decerter/api.sock"
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
		DataDirectory: androidDataDirectory,
		APISocket:     androidAPISocket,
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
