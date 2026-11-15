// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/android"
	"github.com/decerter/decerter/internal/attach"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/tls/boringssl"
)

const (
	// how often the install directories and processes of the selected apps are looked at for a Flutter or Chromium library installed, updated or
	// mapped while decerter runs
	appRescan time.Duration = 2 * time.Second
)

var (
	// where the processes, the apps and the list of installed packages are, variables so the tests can give their own
	procDirectory = "/proc"
	appDirectory  = platform.AndroidAppDirectory
	packagesList  = platform.AndroidPackagesList
)

// only on Android: BoringSSL's ssl_log_secret in Conscrypt's libssl (or the --libssl given), in the libflutter.so of each selected Flutter app and in
// the Chromium libraries (Chrome, Trichrome, Cronet) of the selected apps and their processes
// a --libssl without ssl_log_secret is an OpenSSL (useBoringssl false, no error); with nothing to hook the error says why Conscrypt could not be
// hooked, with an app library to hook a Conscrypt error is a warning; seen holds every library looked at, for the rescan
func (app *App) findBoringsslHooks() (hooks []boringsslHook, useBoringssl bool, seen map[string]bool, err error) {
	seen = map[string]bool{}

	if app.platform.Type != platform.AndroidType {
		return
	}

	conscrypt, isOpenssl, conscryptErr := app.findConscrypt()

	if isOpenssl {
		return
	}

	useBoringssl = true

	if conscryptErr == nil {
		hooks = append(hooks, conscrypt)
	}

	hooks = append(hooks, app.findAppHooks(seen)...)

	if len(hooks) == 0 {
		err = conscryptErr
		return
	}

	if conscryptErr != nil {
		app.logger.Warn("Could not hook Conscrypt, the TLS of Java apps is relayed without secrets", "error", conscryptErr)
	}

	return
}

// Conscrypt's libssl, or the --libssl given, with the offsets of the Android release; a --libssl without ssl_log_secret is an OpenSSL (isOpenssl)
func (app *App) findConscrypt() (hook boringsslHook, isOpenssl bool, err error) {
	libsslPath, err := boringssl.FindLibssl(app.libssl)

	if err != nil {
		return
	}

	address, findErr := boringssl.FindLogSecret(libsslPath)

	if errors.Is(findErr, boringssl.ErrNoLogSecret) && (app.libssl != "") {
		isOpenssl = true
		return
	}

	if err = findErr; err != nil {
		return
	}

	offset, err := boringssl.GetOffset(app.platform.Release, runtime.GOARCH)

	if err != nil {
		return
	}

	hook = boringsslHook{
		Path:    libsslPath,
		Address: address,
		Offset:  offset,
		Library: "BoringSSL of Android " + app.platform.Release,
		Package: "",
	}
	return
}

// the installed packages of the selected uids and of the uids of the selected pids, and every installed package, from packages.list; a package list
// that can't be read is logged
func (app *App) selectedPackages() (selected []android.Package, packages []android.Package) {
	uids := slices.Clone(app.secretsUIDs())

	// a pid selects the app its process belongs to
	for _, tgid := range app.secretsTgids() {
		uid, found := processUID(int(tgid))

		if found && !slices.Contains(uids, uid) {
			uids = append(uids, uid)
		}
	}

	if len(uids) == 0 {
		return
	}

	packages, readErr := android.ReadPackages(packagesList)

	if readErr != nil {
		app.logger.Warn("Could not read the installed packages, no Flutter or Chromium app is hooked", "error", readErr, "fileName", packagesList)
		return
	}

	for _, installed := range packages {
		if slices.Contains(uids, installed.UID) {
			selected = append(selected, installed)
		}
	}

	return
}

// the owner of /proc/<pid>, the uid of the process
func processUID(pid int) (uid uint32, found bool) {
	info, statErr := os.Stat(filepath.Join(procDirectory, strconv.Itoa(pid)))

	if statErr != nil {
		return
	}

	status, isStatus := info.Sys().(*syscall.Stat_t)

	if isStatus {
		uid = status.Uid
		found = true
	}

	return
}

// the BoringSSL libraries of the selected apps not in seen yet: libflutter.so and the Chromium libraries of their install directories, and the
// Chromium libraries their running processes map (Cronet of Play services in its module directory, a library the install directories don't show)
func (app *App) findAppHooks(seen map[string]bool) (hooks []boringsslHook) {
	selected, packages := app.selectedPackages()
	hooks = append(hooks, app.findFlutterHooks(selected, seen)...)
	hooks = append(hooks, app.findChromiumHooks(selected, packages, seen)...)
	hooks = append(hooks, app.findMappedChromiumHooks(seen)...)
	return
}

// the libflutter.so of every package with known offsets, from its install directory under /data/app; seen holds every install directory looked at,
// one in it is skipped, so the rescan only reads new ones (an update installs the app into a new directory); an app whose library can't be hooked is logged, its TLS is relayed
func (app *App) findFlutterHooks(selected []android.Package, seen map[string]bool) (hooks []boringsslHook) {
	for _, current := range selected {
		name := current.Name
		directories, findErr := android.FindInstallDirectories(appDirectory, name)

		if findErr != nil {
			app.logger.Warn("Could not look for the app's install directory", "error", findErr, "package", name)
			continue
		}

		for _, directory := range directories {
			if seen["flutter:"+directory] {
				continue
			}

			seen["flutter:"+directory] = true
			file, found, libraryErr := boringssl.FindFlutterLibrary(directory, runtime.GOARCH)

			if libraryErr != nil {
				app.logger.Error("Could not hook the Flutter app, its TLS is relayed without secrets", "error", libraryErr, "package", name, "directory", directory)
				continue
			}

			if !found {
				app.logger.Debug("No Flutter library in the app", "package", name, "directory", directory)
				continue
			}

			library, inspectErr := boringssl.InspectFlutter(file, runtime.GOARCH)

			if inspectErr != nil {
				app.logger.Error("Could not hook the Flutter app, its TLS is relayed without secrets", "error", inspectErr, "package", name, "library", libraryName(file), "dartVersion", library.DartVersion, "engine", library.Engine)
				continue
			}

			description := fmt.Sprintf("Flutter %s (Dart %s, BoringSSL %s)", flutterReleases(library.Flutter), library.DartVersion, shortRevision(library.Revision))
			app.logger.Info("Found Flutter app", "package", name, "library", libraryName(file), "dartVersion", library.DartVersion, "flutter", library.Flutter, "engine", library.Engine, "boringssl", library.Revision, "logSecret", fmt.Sprintf("0x%x", library.LogSecret), "labels", library.Labels)
			hooks = append(hooks, boringsslHook{
				Path:    file.Path,
				Address: library.LogSecret,
				Offset:  library.Offset,
				Library: description,
				Package: name,
			})
		}
	}

	return
}

// the Chromium libraries of every package and of the Trichrome library it uses, from their install directories under /data/app, like
// findFlutterHooks; a library with an unknown version or without the labels is logged, its TLS is relayed
func (app *App) findChromiumHooks(selected []android.Package, packages []android.Package, seen map[string]bool) (hooks []boringsslHook) {
	for _, current := range selected {
		owners := append([]string{current.Name}, android.TrichromeLibraries(current, packages)...)

		for _, owner := range owners {
			directories, findErr := android.FindInstallDirectories(appDirectory, owner)

			if findErr != nil {
				app.logger.Warn("Could not look for the app's install directory", "error", findErr, "package", owner)
				continue
			}

			for _, directory := range directories {
				if seen["chromium:"+directory] {
					continue
				}

				seen["chromium:"+directory] = true
				libraries, libraryErr := boringssl.FindChromiumLibraries(directory, runtime.GOARCH)

				if libraryErr != nil {
					app.logger.Error("Could not hook Chromium's BoringSSL of the app, its TLS is relayed without secrets", "error", libraryErr, "package", current.Name, "directory", directory)
					continue
				}

				for _, file := range libraries {
					hook, isHook := app.inspectChromium(file, current.Name, seen)

					if isHook {
						hooks = append(hooks, hook)
					}
				}
			}
		}
	}

	return
}

// the Chromium libraries mapped executable by the processes of the selected uids and pids: a library file of its own, or a stored entry of an apk
// (a mapping of an apk at a file offset inside the entry); a mapping looked at is kept in seen, so the rescan reads only new ones
func (app *App) findMappedChromiumHooks(seen map[string]bool) (hooks []boringsslHook) {
	processes, err := app.selectedMaps()

	if err != nil {
		app.logger.Warn("Could not list the processes, no Chromium library they map is hooked", "error", err)
		return
	}

	for _, selected := range processes {
		process := processName(selected.Pid)

		for _, mapping := range platform.ExecutableMappings(selected.Maps) {
			key := "mapped:" + mapping.Path + "@" + strconv.FormatUint(mapping.Offset, 10)

			if seen[key] {
				continue
			}

			seen[key] = true
			file, isChromium, mappingErr := boringssl.ChromiumMapping(mapping)

			if mappingErr != nil {
				app.logger.Warn("Could not read a library the process maps", "error", mappingErr, "process", process, "pid", selected.Pid, "fileName", mapping.Path)
				continue
			}

			if !isChromium {
				continue
			}

			hook, isHook := app.inspectChromium(file, process, seen)

			if isHook {
				hooks = append(hooks, hook)
			}
		}
	}

	return
}

// the /proc/<pid>/maps text of every process of the selected uids and pids, none without a selection; a process gone meanwhile is left out
func (app *App) selectedMaps() (processes []processMaps, err error) {
	uids := app.secretsUIDs()
	tgids := app.secretsTgids()

	if (len(uids) == 0) && (len(tgids) == 0) {
		return
	}

	entries, err := os.ReadDir(procDirectory)

	if err != nil {
		return
	}

	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())

		if parseErr != nil {
			continue
		}

		uid, found := processUID(pid)

		if !found || (!slices.Contains(uids, uid) && !slices.Contains(tgids, uint32(pid))) {
			continue
		}

		maps, mapsErr := os.ReadFile(filepath.Join(procDirectory, entry.Name(), "maps"))

		if mapsErr != nil {
			continue
		}

		processes = append(processes, processMaps{Pid: pid, Maps: string(maps)})
	}

	return
}

// the package name of a process: its cmdline up to the first NUL, without the :name of a service process
func processName(pid int) (name string) {
	cmdline, readErr := os.ReadFile(filepath.Join(procDirectory, strconv.Itoa(pid), "cmdline"))

	if readErr != nil {
		return
	}

	name, _, _ = strings.Cut(string(cmdline), "\x00")
	name, _, _ = strings.Cut(name, ":")
	return
}

// a hook for one Chromium library not in seen yet, by its path and offset; a library that can't be hooked is logged with the nearest known version
func (app *App) inspectChromium(file boringssl.LibraryFile, owner string, seen map[string]bool) (hook boringsslHook, isHook bool) {
	key := file.Path + "@" + strconv.FormatUint(file.Offset, 10)

	if seen[key] {
		return
	}

	seen[key] = true
	library, inspectErr := boringssl.InspectChromium(file, runtime.GOARCH)

	if inspectErr != nil {
		app.logger.Error("Could not hook Chromium's BoringSSL of the app, its TLS is relayed without secrets", "error", inspectErr, "package", owner, "library", libraryName(file), "product", library.Product, "version", library.Version)
		return
	}

	app.logger.Info("Found Chromium library", "package", owner, "library", libraryName(file), "product", library.Product, "version", library.Version, "boringssl", library.Revision, "logSecret", fmt.Sprintf("0x%x", library.LogSecret), "labels", library.Labels)
	hook = boringsslHook{
		Path:    file.Path,
		Address: library.LogSecret,
		Offset:  library.Offset,
		Library: fmt.Sprintf("%s %s (BoringSSL %s)", library.Product, library.Version, shortRevision(library.Revision)),
		Package: owner,
	}
	isHook = true
	return
}

// attach the ssl_log_secret uprobe to a hook's library with its offsets at index of boringssl_layout_map, the index is the attach cookie
func (app *App) attachBoringssl(index uint32, hook boringsslHook) (closeFunction func() error, err error) {
	err = secrets.SetBoringsslLayout(index, hook.Offset, app.secretsBpfMaps)

	if err != nil {
		return
	}

	executable, err := attach.OpenExecutable(hook.Path)

	if err != nil {
		return
	}

	closeFunction, err = attach.AddUprobeAddress(executable, hook.Address, app.secretsBpfPrograms[secrets.LogSecret], uint64(index))

	if err != nil {
		return
	}

	app.logger.Info("Attached secrets uprobe", "libssl", hook.Path, "symbols", []string{"ssl_log_secret"}, "library", hook.Library, "package", hook.Package, "uids", app.secretsUIDs(), "pids", app.secretsTgids())
	return
}

// attach every BoringSSL hook, then watch them: a library with another layout than its offsets is reported once, a selected Flutter or Chromium app
// installed, updated or started while decerter runs is hooked; Conscrypt that can't be attached fails, an app library is logged and relayed without secrets
func (app *App) attachBoringsslHooks() (err error) {
	attached := []boringsslHook{}
	// closed together, each close waits in the kernel
	uprobeCloseFunctions := [](func() error){}

	defer func() {
		app.closeFunctions = append(app.closeFunctions, closeTogether(uprobeCloseFunctions))
	}()

	for _, hook := range app.boringsslHooks {
		if uint32(len(attached)) >= secrets.BoringsslLayouts(app.secretsBpfMaps) {
			app.logger.Error("Could not hook the app, too many BoringSSL libraries", "package", hook.Package, "library", hook.Library, "limit", secrets.BoringsslLayouts(app.secretsBpfMaps))
			continue
		}

		closeFunction, attachErr := app.attachBoringssl(uint32(len(attached)), hook)

		if attachErr != nil {
			if hook.Package == "" {
				err = attachErr
				app.logger.Error("Could not attach secrets uprobe", "error", err, "symbol", "ssl_log_secret", "libssl", hook.Path)
				return
			}

			app.logger.Error("Could not hook the app, its TLS is relayed without secrets", "error", attachErr, "package", hook.Package, "library", hook.Library, "libssl", hook.Path)
			continue
		}

		uprobeCloseFunctions = append(uprobeCloseFunctions, closeFunction)
		attached = append(attached, hook)
	}

	// BoringSSL layout checker and app rescan, it owns the hooks from here on
	app.waitGroup.Go(func() {
		app.watchBoringssl(attached, app.flutterSeen)
	})

	return
}

// a library with another layout than its offsets (a Conscrypt APEX updated apart from the release, a Flutter engine or Chromium built differently)
// makes the uprobe reject every secret instead of storing garbage: this says so once per library, its sessions stay without secrets
// on Android it also looks for selected Flutter and Chromium apps installed, updated or started while decerter runs and hooks them; their links are closed
// when it stops
func (app *App) watchBoringssl(hooks []boringsslHook, seen map[string]bool) {
	layoutTicker := time.NewTicker(layoutCheck)
	defer layoutTicker.Stop()
	rescanTicker := time.NewTicker(appRescan)
	defer rescanTicker.Stop()
	reported := map[int]bool{}
	linkCloseFunctions := [](func() error){}

	defer func() {
		closeErr := closeTogether(linkCloseFunctions)()

		if closeErr != nil {
			app.logger.Error("Could not close bpf resource", "error", closeErr)
		}
	}()

	for {
		select {
		case <-app.ctx.Done():
			app.logger.Debug("Context cancelled")
			return
		case <-layoutTicker.C:
			for index, hook := range hooks {
				if reported[index] {
					continue
				}

				count, layoutErr := secrets.CheckLayout(uint32(index), app.secretsBpfMaps)

				if count == 0 {
					if layoutErr != nil {
						app.logger.Warn("Could not check BoringSSL layout", "error", layoutErr)
					}

					continue
				}

				reported[index] = true
				app.logger.Error("Could not read TLS secrets", "error", layoutErr, "libssl", hook.Path, "library", hook.Library, "package", hook.Package, "release", app.platform.Release, "architecture", runtime.GOARCH)
			}
		case <-rescanTicker.C:
			if app.platform.Type != platform.AndroidType {
				continue
			}

			for _, hook := range app.findAppHooks(seen) {
				app.logger.Info("Found a library of a selected app installed, updated or started while decerter runs", "package", hook.Package, "library", hook.Library, "libssl", hook.Path)

				if uint32(len(hooks)) >= secrets.BoringsslLayouts(app.secretsBpfMaps) {
					app.logger.Error("Could not hook the app, too many BoringSSL libraries", "package", hook.Package, "library", hook.Library, "limit", secrets.BoringsslLayouts(app.secretsBpfMaps))
					continue
				}

				closeFunction, attachErr := app.attachBoringssl(uint32(len(hooks)), hook)

				if attachErr != nil {
					app.logger.Error("Could not hook the app, its TLS is relayed without secrets", "error", attachErr, "package", hook.Package, "library", hook.Library, "libssl", hook.Path)
					continue
				}

				linkCloseFunctions = append(linkCloseFunctions, closeFunction)
				hooks = append(hooks, hook)
			}
		}
	}
}

// the library's place for the logs: the path, with the entry inside an apk
func libraryName(file boringssl.LibraryFile) (name string) {
	name = file.Path

	if file.Entry != "" {
		name = file.Path + "!/" + file.Entry
	}

	return
}

// the Flutter releases of a Dart version, the first and the last when there are several
func flutterReleases(releases []string) (text string) {
	switch len(releases) {
	case 0:
		text = "unknown"
	case 1:
		text = releases[0]
	default:
		text = releases[0] + " to " + releases[len(releases)-1]
	}

	return
}

// a git revision as its first 12 hex digits
func shortRevision(revision string) (short string) {
	short = revision[:min(12, len(revision))]
	return
}
