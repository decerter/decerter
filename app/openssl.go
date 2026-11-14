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
	"syscall"
	"time"

	"github.com/decerter/decerter/internal/attach"
	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/tls/openssl"
)

// the libssl files decerter hooks: the --libssl given, nothing else then; otherwise libssl.so.3 and libssl.so.4 of the linker cache, both when the host has
// both, and the libssl.so.N (N 3 or newer) the selected processes map, so a process gets the library it actually loads, also a container's own
// a library of the linker cache or --libssl with an unknown version fails before anything is attached; one only a process maps is logged with the
// nearest known version and that process is relayed without secrets; seen holds the device and inode of every library looked at, for the rescan
func (app *App) findOpensslHooks() (hooks []opensslHook, seen map[string]bool, err error) {
	seen = map[string]bool{}
	libraries, findErr := openssl.FindLibssl(app.libssl)

	// without --libssl a host without OpenSSL can still have selected processes that map one (a container)
	if (findErr != nil) && ((app.libssl != "") || !errors.Is(findErr, openssl.ErrLibraryNotFound)) {
		err = findErr
		app.logger.Error("Could not find libssl", "error", err)
		return
	}

	for _, library := range libraries {
		inspected, inspectErr := openssl.Inspect(library, runtime.GOARCH)

		if err = inspectErr; err != nil {
			app.logger.Error("Could not get OpenSSL offsets", "error", err, "libssl", library.Libssl, "libcrypto", library.Libcrypto, "version", inspected.Version)
			return
		}

		seen[libraryKey(inspected.Libssl)] = true
		hooks = append(hooks, opensslHook{Library: inspected, Pid: 0, Process: ""})
	}

	if app.libssl != "" {
		return
	}

	hooks = append(hooks, app.findMappedOpenssl(seen)...)

	if len(hooks) == 0 {
		err = findErr
		app.logger.Error("Could not find libssl", "error", err)
		return
	}

	return
}

// the libssl files the processes of the selected uids and pids map that are not in seen yet, opened through /proc/<pid>/root so a container's file is
// found as its process sees it; a library is keyed by device and inode, uprobes are per inode
func (app *App) findMappedOpenssl(seen map[string]bool) (hooks []opensslHook) {
	uids := app.secretsUIDs()
	tgids := app.secretsTgids()

	if (len(uids) == 0) && (len(tgids) == 0) {
		return
	}

	entries, readErr := os.ReadDir("/proc")

	if readErr != nil {
		app.logger.Warn("Could not list the processes, no libssl they map is hooked", "error", readErr)
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

		maps, mapsErr := os.ReadFile("/proc/" + entry.Name() + "/maps")

		if mapsErr != nil {
			continue
		}

		for _, mapped := range openssl.MappedLibssl(string(maps)) {
			path := filepath.Join("/proc", entry.Name(), "root", mapped)
			key := libraryKey(path)

			// gone with its process, or hooked already
			if (key == "") || seen[key] {
				continue
			}

			seen[key] = true
			process := processName(pid)
			library := openssl.Library{Libssl: path, Libcrypto: openssl.LibcryptoPath(path), Version: "", Offset: openssl.Offset{}}
			inspected, inspectErr := openssl.Inspect(library, runtime.GOARCH)

			if inspectErr != nil {
				app.logger.Error("Could not hook the OpenSSL a selected process maps, its TLS is relayed without secrets", "error", inspectErr, "process", process, "pid", pid, "libssl", mapped, "version", inspected.Version)
				continue
			}

			app.logger.Info("Found OpenSSL library a selected process maps", "process", process, "pid", pid, "libssl", path, "version", inspected.Version)
			hooks = append(hooks, opensslHook{Library: inspected, Pid: pid, Process: process})
		}
	}

	return
}

// device and inode of a file, empty when it can't be read
func libraryKey(path string) (key string) {
	info, statErr := os.Stat(path)

	if statErr != nil {
		return
	}

	status, isStatus := info.Sys().(*syscall.Stat_t)

	if isStatus {
		key = fmt.Sprintf("%d:%d", status.Dev, status.Ino)
	}

	return
}

// attach the stash_ssl and store_secrets uprobes to every libssl function that carries a complete handshake, with the hook's offsets at index of
// openssl_layout_map as their attach cookie; one close function for all of its links
func (app *App) attachOpenssl(index uint32, hook opensslHook) (closeFunction func() error, err error) {
	err = secrets.SetOpensslLayout(index, hook.Library.Offset, app.secretsBpfMaps)

	if err != nil {
		return
	}

	executable, err := attach.OpenExecutable(hook.Library.Libssl)

	if err != nil {
		return
	}

	attachments := []struct {
		program  bpf.BpfProgramName
		isReturn bool
	}{
		{program: secrets.StashSsl, isReturn: false},
		{program: secrets.StoreSecrets, isReturn: true},
	}
	// closing a uprobe link waits in the kernel while it unregisters the probe, 60-180 ms each; one after the other the ten links made every shutdown take over a second, closed together they take about half as long, the kernel serialises the rest
	uprobeCloseFunctions := [](func() error){}

	for _, symbol := range secrets.SymbolHooks() {
		for _, attachment := range attachments {
			linkClose, attachErr := attach.AddUprobe(executable, symbol, app.secretsBpfPrograms[attachment.program], attachment.isReturn, uint64(index))

			if attachErr != nil {
				err = errors.Join(fmt.Errorf("%s return=%t: %w", symbol, attachment.isReturn, attachErr), closeTogether(uprobeCloseFunctions)())
				return
			}

			uprobeCloseFunctions = append(uprobeCloseFunctions, linkClose)
		}
	}

	closeFunction = closeTogether(uprobeCloseFunctions)
	app.logger.Info("Attached secrets uprobe", "libssl", hook.Library.Libssl, "symbols", secrets.SymbolHooks(), "library", "OpenSSL "+hook.Library.Version, "process", hook.Process, "pid", hook.Pid, "uids", app.secretsUIDs(), "pids", app.secretsTgids())
	return
}

// attach every OpenSSL hook, then watch for libssl files selected processes start to map while decerter runs (not with --libssl); --libssl and the
// libraries of the linker cache that can't be attached fail, a library a process maps is logged and relayed without secrets
func (app *App) attachOpensslHooks() (err error) {
	attached := uint32(0)
	// closed together, each close waits in the kernel
	uprobeCloseFunctions := [](func() error){}

	defer func() {
		app.closeFunctions = append(app.closeFunctions, closeTogether(uprobeCloseFunctions))
	}()

	for _, hook := range app.opensslHooks {
		closeFunction, attachErr := app.attachOpensslHook(attached, hook)

		if attachErr != nil {
			if hook.Pid == 0 {
				err = attachErr
				app.logger.Error("Could not attach secrets uprobe", "error", err, "libssl", hook.Library.Libssl)
				return
			}

			continue
		}

		uprobeCloseFunctions = append(uprobeCloseFunctions, closeFunction)
		attached++
	}

	if app.libssl != "" {
		return
	}

	// libssl rescan, it owns the links of the libraries it finds
	app.waitGroup.Go(func() {
		app.watchOpenssl(attached, app.opensslSeen)
	})

	return
}

// attach one hook at index when openssl_layout_map has room, a library a process maps that can't be attached is logged
func (app *App) attachOpensslHook(index uint32, hook opensslHook) (closeFunction func() error, err error) {
	if index >= secrets.OpensslLayouts(app.secretsBpfMaps) {
		err = fmt.Errorf("%w: %d", ErrTooManyLibraries, secrets.OpensslLayouts(app.secretsBpfMaps))
	} else {
		closeFunction, err = app.attachOpenssl(index, hook)
	}

	if (err != nil) && (hook.Pid != 0) {
		app.logger.Error("Could not hook the OpenSSL a selected process maps, its TLS is relayed without secrets", "error", err, "process", hook.Process, "pid", hook.Pid, "libssl", hook.Library.Libssl, "version", hook.Library.Version)
	}

	return
}

// every appRescan the selected processes are looked at for a libssl not hooked yet (a container or a program started while decerter runs), which is hooked
// at the next free index; the links are closed when it stops
func (app *App) watchOpenssl(attached uint32, seen map[string]bool) {
	rescanTicker := time.NewTicker(appRescan)
	defer rescanTicker.Stop()
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
		case <-rescanTicker.C:
			for _, hook := range app.findMappedOpenssl(seen) {
				closeFunction, attachErr := app.attachOpensslHook(attached, hook)

				if attachErr != nil {
					continue
				}

				linkCloseFunctions = append(linkCloseFunctions, closeFunction)
				attached++
			}
		}
	}
}
