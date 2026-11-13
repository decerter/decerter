// SPDX-License-Identifier: AGPL-3.0-only

package android

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// read packages.list, only root may
func ReadPackages(path string) (packages []Package, err error) {
	file, openErr := os.Open(path)

	if err = openErr; err != nil {
		err = fmt.Errorf("%w: %w", ErrPackagesList, err)
		return
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	packages, err = ParsePackages(file)
	return
}

// one package a line: name, uid, debuggable, data directory, seinfo, gids, …; only the first two are used
// a line without a uid is an error, the file is written by the package manager and has none
func ParsePackages(reader io.Reader) (packages []Package, err error) {
	scanner := bufio.NewScanner(reader)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		fields := strings.Fields(scanner.Text())

		if len(fields) == 0 {
			continue
		}

		if len(fields) < 2 {
			err = fmt.Errorf("%w: line %d: %q has no uid", ErrPackagesList, lineNumber, scanner.Text())
			return
		}

		uid, parseErr := strconv.ParseUint(fields[1], 10, 32)

		if err = parseErr; err != nil {
			err = fmt.Errorf("%w: line %d: invalid uid %q: %w", ErrPackagesList, lineNumber, fields[1], err)
			return
		}

		packages = append(packages, Package{Name: fields[0], UID: uint32(uid)})
	}

	err = scanner.Err()

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrPackagesList, err)
		return
	}

	if len(packages) == 0 {
		err = fmt.Errorf("%w: no package in it", ErrPackagesList)
		return
	}

	return
}

// the package of each name, in the order of names; the first unknown name fails with the closest installed packages
func ResolvePackages(names []string, packages []Package) (resolved []Package, err error) {
	for _, name := range names {
		index := slices.IndexFunc(packages, func(installed Package) (isMatch bool) {
			isMatch = (installed.Name == name)
			return
		})

		if index < 0 {
			err = fmt.Errorf("%w %q, the closest installed packages: %s (adb shell pm list packages lists all of them)", ErrUnknownPackage, name, strings.Join(SuggestPackages(name, packages, suggestionCount), ", "))
			return
		}

		resolved = append(resolved, packages[index])
	}

	return
}

// the other packages with the uid of the package: a shared uid (android:sharedUserId) or a system uid selects all of them
func SharingPackages(selected Package, packages []Package) (names []string) {
	for _, installed := range packages {
		if (installed.UID == selected.UID) && (installed.Name != selected.Name) {
			names = append(names, installed.Name)
		}
	}

	return
}

// the packages with the uid, a shared uid has several
func PackagesOfUID(uid uint32, packages []Package) (names []string) {
	for _, installed := range packages {
		if installed.UID == uid {
			names = append(names, installed.Name)
		}
	}

	return
}

// the install directories of a package under appDirectory (/data/app): <random>/<package>-<random> since Android 11, <package>-<random> before
// during an update the old directory can still be there next to the new one, both are returned, sorted
func FindInstallDirectories(appDirectory string, name string) (directories []string, err error) {
	for _, pattern := range []string{filepath.Join(appDirectory, "*", name+"-*"), filepath.Join(appDirectory, name+"-*")} {
		matches, globErr := filepath.Glob(pattern)

		if err = globErr; err != nil {
			err = fmt.Errorf("%w: %w", ErrInstallDirectory, err)
			return
		}

		for _, match := range matches {
			info, statErr := os.Stat(match)

			if (statErr == nil) && info.IsDir() {
				directories = append(directories, match)
			}
		}
	}

	slices.Sort(directories)
	return
}

// a system uid is shared by system processes that are no app, such as system_server for 1000
func IsSystemUID(uid uint32) (isSystem bool) {
	isSystem = (uid < firstApplicationUID)
	return
}

// at most count installed package names closest to name: the ones that contain it first, shortest first, then by edit distance, ignoring case
func SuggestPackages(name string, packages []Package, count int) (suggestions []string) {
	type candidate struct {
		name       string
		isContains bool
		distance   int
	}

	query := strings.ToLower(name)
	candidates := []candidate{}

	for _, installed := range packages {
		lowered := strings.ToLower(installed.Name)
		candidates = append(candidates, candidate{
			name:       installed.Name,
			isContains: strings.Contains(lowered, query),
			distance:   editDistance(query, lowered),
		})
	}

	slices.SortStableFunc(candidates, func(first candidate, second candidate) (order int) {
		switch {
		case first.isContains && !second.isContains:
			order = -1
		case !first.isContains && second.isContains:
			order = 1
		case first.isContains:
			order = cmp.Or(cmp.Compare(len(first.name), len(second.name)), cmp.Compare(first.name, second.name))
		default:
			order = cmp.Or(cmp.Compare(first.distance, second.distance), cmp.Compare(first.name, second.name))
		}

		return
	})

	for _, suggestion := range candidates[:min(count, len(candidates))] {
		suggestions = append(suggestions, suggestion.name)
	}

	return
}

// Levenshtein distance of two strings, by byte: package names are ASCII
func editDistance(first string, second string) (distance int) {
	previous := make([]int, len(second)+1)
	current := make([]int, len(second)+1)

	for index := range previous {
		previous[index] = index
	}

	for firstIndex := range len(first) {
		current[0] = firstIndex + 1

		for secondIndex := range len(second) {
			substitution := previous[secondIndex]

			if first[firstIndex] != second[secondIndex] {
				substitution++
			}

			current[secondIndex+1] = min(previous[secondIndex+1]+1, current[secondIndex]+1, substitution)
		}

		previous, current = current, previous
	}

	distance = previous[len(second)]
	return
}
