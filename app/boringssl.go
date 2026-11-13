// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/android"
	"github.com/decerter/decerter/internal/attach"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/tls/boringssl"
)

const (
	// how often the install directories of the selected apps are looked at for a Flutter app installed or updated while decerter runs
	flutterRescan time.Duration = 2 * time.Second
)

// only on Android: BoringSSL's ssl_log_secret in Conscrypt's libssl (or the --libssl given) and in the libflutter.so of each selected Flutter app
// a --libssl without ssl_log_secret is an OpenSSL (useBoringssl false, no error); with nothing to hook the error says why Conscrypt could not be
// hooked, with a Flutter app to hook a Conscrypt error is a warning; seen holds every Flutter library looked at, for the rescan
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

	hooks = append(hooks, app.findFlutterHooks(app.selectedPackages(), seen)...)

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

// the installed packages of the selected uids and of the uids of the selected pids, from packages.list; a package list that can't be read is logged
func (app *App) selectedPackages() (names []string) {
	uids := slices.Clone(app.secretsUIDs())

	// a pid selects the app its process belongs to
	for _, tgid := range app.secretsTgids() {
		info, statErr := os.Stat("/proc/" + strconv.FormatUint(uint64(tgid), 10))

		if statErr != nil {
			continue
		}

		status, isStatus := info.Sys().(*syscall.Stat_t)

		if isStatus && !slices.Contains(uids, status.Uid) {
			uids = append(uids, status.Uid)
		}
	}

	if len(uids) == 0 {
		return
	}

	packages, readErr := android.ReadPackages(platform.AndroidPackagesList)

	if readErr != nil {
		app.logger.Warn("Could not read the installed packages, no Flutter app is hooked", "error", readErr, "fileName", platform.AndroidPackagesList)
		return
	}

	for _, uid := range uids {
		names = append(names, android.PackagesOfUID(uid, packages)...)
	}

	return
}

// the libflutter.so of every package with known offsets, from its install directory under /data/app; seen holds every library looked at by its
// path and offset, a library in it is skipped, so the rescan only reads new ones; an app whose library can't be hooked is logged, its TLS is relayed
func (app *App) findFlutterHooks(names []string, seen map[string]bool) (hooks []boringsslHook) {
	for _, name := range names {
		directories, findErr := android.FindInstallDirectories(platform.AndroidAppDirectory, name)

		if findErr != nil {
			app.logger.Warn("Could not look for the app's install directory", "error", findErr, "package", name)
			continue
		}

		for _, directory := range directories {
			file, found, libraryErr := boringssl.FindFlutterLibrary(directory, runtime.GOARCH)
			key := directory

			if found {
				key = file.Path + "@" + strconv.FormatUint(file.Offset, 10)
			}

			if seen[key] {
				continue
			}

			seen[key] = true

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

// attach every BoringSSL hook, then watch them: a library with another layout than its offsets is reported once, a selected Flutter app installed or
// updated while decerter runs is hooked; Conscrypt that can't be attached fails, a Flutter app is logged and relayed without secrets
func (app *App) attachBoringsslHooks() (err error) {
	attached := []boringsslHook{}
	// closed together, each close waits in the kernel
	uprobeCloseFunctions := [](func() error){}

	defer func() {
		app.closeFunctions = append(app.closeFunctions, closeTogether(uprobeCloseFunctions))
	}()

	for _, hook := range app.boringsslHooks {
		if uint32(len(attached)) >= secrets.BoringsslLayouts(app.secretsBpfMaps) {
			app.logger.Error("Could not hook the Flutter app, too many BoringSSL libraries", "package", hook.Package, "limit", secrets.BoringsslLayouts(app.secretsBpfMaps))
			continue
		}

		closeFunction, attachErr := app.attachBoringssl(uint32(len(attached)), hook)

		if attachErr != nil {
			if hook.Package == "" {
				err = attachErr
				app.logger.Error("Could not attach secrets uprobe", "error", err, "symbol", "ssl_log_secret", "libssl", hook.Path)
				return
			}

			app.logger.Error("Could not hook the Flutter app, its TLS is relayed without secrets", "error", attachErr, "package", hook.Package, "libssl", hook.Path)
			continue
		}

		uprobeCloseFunctions = append(uprobeCloseFunctions, closeFunction)
		attached = append(attached, hook)
	}

	// BoringSSL layout checker and Flutter rescan, it owns the hooks from here on
	app.waitGroup.Go(func() {
		app.watchBoringssl(attached, app.flutterSeen)
	})

	return
}

// a library with another layout than its offsets (a Conscrypt APEX updated apart from the release, a Flutter engine built differently) makes the
// uprobe reject every secret instead of storing garbage: this says so once per library, its sessions stay without secrets
// on Android it also looks for selected Flutter apps installed or updated while decerter runs and hooks them; their links are closed when it stops
func (app *App) watchBoringssl(hooks []boringsslHook, seen map[string]bool) {
	layoutTicker := time.NewTicker(layoutCheck)
	defer layoutTicker.Stop()
	rescanTicker := time.NewTicker(flutterRescan)
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

			for _, hook := range app.findFlutterHooks(app.selectedPackages(), seen) {
				app.logger.Info("Found a selected Flutter app installed or updated while decerter runs", "package", hook.Package, "libssl", hook.Path)

				if uint32(len(hooks)) >= secrets.BoringsslLayouts(app.secretsBpfMaps) {
					app.logger.Error("Could not hook the Flutter app, too many BoringSSL libraries", "package", hook.Package, "limit", secrets.BoringsslLayouts(app.secretsBpfMaps))
					continue
				}

				closeFunction, attachErr := app.attachBoringssl(uint32(len(hooks)), hook)

				if attachErr != nil {
					app.logger.Error("Could not hook the Flutter app, its TLS is relayed without secrets", "error", attachErr, "package", hook.Package, "libssl", hook.Path)
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
