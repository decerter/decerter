// SPDX-License-Identifier: AGPL-3.0-only

package android

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/tls/boringssl"
)

// the lines setup prints: a label and a text, the first write error is kept and later lines are dropped
type printer struct {
	output io.Writer
	err    error
}

func (printer *printer) line(label string, format string, args ...any) {
	if printer.err != nil {
		return
	}

	_, printer.err = fmt.Fprintf(printer.output, "%-8s %s\n", label, fmt.Sprintf(format, args...))
}

func (printer *printer) text(text string) {
	if printer.err != nil {
		return
	}

	_, printer.err = io.WriteString(printer.output, text)
}

// find adb, pick or boot the device, push the binary for its ABI, check the Conscrypt offsets and the package, forward the api socket and print the commands to run next
// a device decerter can't run on is refused before anything is changed on it; the steps are printed to output as they happen
func Setup(ctx context.Context, options Options, output io.Writer, logger *slog.Logger) (err error) {
	report := &printer{output: output, err: nil}

	defer func() {
		err = errors.Join(err, report.err)
	}()

	adb, info, err := connect(ctx, options, report, logger)

	if err != nil {
		return
	}

	err = CheckDevice(info)

	if err != nil {
		return
	}

	architecture, binary, err := deviceBinary(info, options)

	if err != nil {
		return
	}

	err = becomeRoot(ctx, &adb, info, report, logger)

	if err != nil {
		return
	}

	err = checkNotRunning(ctx, adb)

	if err != nil {
		return
	}

	if options.Package != "" {
		err = checkPackage(ctx, adb, options.Package, report, logger)

		if err != nil {
			return
		}
	}

	err = pushBinary(ctx, adb, binary, report)

	if err != nil {
		return
	}

	_, offsetErr := boringssl.GetOffset(info.Release, architecture)

	if offsetErr != nil {
		report.line("tls", "no Conscrypt offsets for Android %s, TLS of the apps is relayed without decryption", info.Release)
		logger.Warn("No Conscrypt offsets for the device's Android release, decerter on the device relays TLS without decrypting it", "error", offsetErr)
	} else {
		report.line("tls", "Conscrypt offsets for Android %s on %s", info.Release, info.ABI)
	}

	isChromium := false

	if options.Package != "" {
		isChromium = checkAppTLS(ctx, adb, options.Package, report, logger)
	}

	if isChromium {
		report.line("quic", "%s is a Chromium app, the device command gets --block-quic so it uses TLS over TCP, which decerter decrypts", options.Package)
	}

	if isChromium && slices.Contains(chromePackages, options.Package) {
		err = writeChromeFlags(ctx, adb, report)

		if err != nil {
			return
		}
	}

	port, err := forwardAPI(ctx, adb, options.Port, report)

	if err != nil {
		return
	}

	deviceCommand, uiCommand := NextCommands(adbCommand(adb.Path), adb.Serial, adb.Root, options.Package, isChromium, port, options.Command)
	report.text("\nStart decerter on the device, Ctrl-C stops it and puts netd's hooks back:\n  " + deviceCommand + "\n")

	if options.Package == "" {
		report.text("PACKAGE is the app's package name, adb shell pm list packages lists them.\n")
	}

	report.text("Then the UI on this machine, in another terminal:\n  " + uiCommand + "\n")
	report.text("Undo the setup with: " + shellQuote(options.Command) + " android setup --remove --serial " + shellQuote(adb.Serial) + "\n")
	return
}

// refused while decerter runs; put back netd's hooks a killed decerter left shared, then remove Chrome's flags file when setup wrote it and nobody changed it
// since, the binary, its data directory and the forwards of the api socket
func Remove(ctx context.Context, options Options, output io.Writer, logger *slog.Logger) (err error) {
	report := &printer{output: output, err: nil}

	defer func() {
		err = errors.Join(err, report.err)
	}()

	adb, info, err := connect(ctx, options, report, logger)

	if err != nil {
		return
	}

	err = becomeRoot(ctx, &adb, info, report, logger)

	if err != nil {
		return
	}

	err = checkNotRunning(ctx, adb)

	if err != nil {
		return
	}

	statePath := path.Join(platform.AndroidDataDirectory, platform.NetdStateName)
	hasBinary, binaryErr := adb.fileExists(ctx, platform.AndroidBinaryPath)
	hasState, stateErr := adb.fileExists(ctx, statePath)

	if err = errors.Join(binaryErr, stateErr); err != nil {
		return
	}

	// without the state file a restore has nothing to do; without the binary nothing can restore, so the state stays
	switch {
	case hasState && hasBinary:
		restoreOutput, restoreErr := adb.rootShell(ctx, platform.AndroidBinaryPath+" android restore 2>&1")

		if err = restoreErr; err != nil {
			err = fmt.Errorf("%w: decerter android restore: %s", err, restoreOutput)
			return
		}

		report.line("restore", "netd's hooks a killed decerter left shared are exclusive again")
	case hasState:
		logger.Warn("A killed decerter left netd's hooks shared and there is no binary to put them back, the data directory stays: run decerter android setup, then decerter android restore on the device", "state", statePath)
	}

	err = removeChromeFlags(ctx, adb, report)

	if err != nil {
		return
	}

	removePaths := platform.AndroidBinaryPath

	if !hasState || hasBinary {
		removePaths += " " + platform.AndroidDataDirectory
	}

	_, err = adb.rootShell(ctx, "rm -rf "+removePaths)

	if err != nil {
		return
	}

	if hasBinary {
		report.line("binary", "removed %s", removePaths)
	} else {
		report.line("binary", "no binary at %s, removed %s", platform.AndroidBinaryPath, removePaths)
	}

	forwards, err := adb.run(ctx, adbTimeout, "forward", "--list")

	if err != nil {
		return
	}

	for _, forward := range apiForwards(ParseForwards(forwards), adb.Serial) {
		_, err = adb.run(ctx, adbTimeout, "forward", "--remove", forward.Local)

		if err != nil {
			return
		}

		report.line("api", "removed adb forward %s %s", forward.Local, forward.Remote)
	}

	return
}

// find adb and the device, booting options.AVD when it doesn't run, and read what it is
func connect(ctx context.Context, options Options, report *printer, logger *slog.Logger) (adb ADB, info DeviceInfo, err error) {
	adbPath, err := FindADB()

	if err != nil {
		return
	}

	adb = ADB{Path: adbPath, Serial: "", Root: ""}
	report.line("adb", "%s", adbPath)
	devices, err := adb.devices(ctx)

	if err != nil {
		return
	}

	switch {
	case options.AVD != "":
		adb.Serial, err = findRunningAVD(ctx, adb, devices, options.AVD)

		if (err == nil) && (adb.Serial == "") {
			adb.Serial, err = bootAVD(ctx, adb, options.AVD, devices, report.output)
		}
	default:
		device, selectErr := SelectDevice(devices, options.Serial)
		adb.Serial, err = device.Serial, selectErr
	}

	if err != nil {
		return
	}

	infoOutput, err := adb.shell(ctx, deviceInfoCommand)

	if err != nil {
		return
	}

	info, err = ParseDeviceInfo(infoOutput)

	if err != nil {
		return
	}

	kind := "emulator"

	if !info.IsEmulator {
		kind = "real device, experimental"
		logger.Warn("Real devices are experimental: decerter was tested on the Android 15 x86_64 emulator only, not on a phone or on arm64", "serial", adb.Serial, "model", info.Model)
	}

	report.line("device", "%s, %s (%s)", adb.Serial, info.Model, kind)
	report.line("android", "%s (API level %d, %s build), %s, kernel %s", info.Release, info.SDK, info.BuildType, info.ABI, info.Kernel)
	return
}

// adbd as root through adb root; a rooted production build (Magisk, KernelSU) through su -c instead
// adb root restarts adbd, the connection drops and comes back
func becomeRoot(ctx context.Context, adb *ADB, info DeviceInfo, report *printer, logger *slog.Logger) (err error) {
	if info.UID == "0" {
		adb.Root = ADBRootType
		report.line("root", "adbd runs as root")
		return
	}

	output, rootErr := adb.run(ctx, adbTimeout, "root")

	if strings.Contains(output, "cannot run as root") {
		// adb shell exits with su's status, a missing su or a refused one is no root
		suOutput, suErr := adb.shell(ctx, "su -c 'id -u'")

		if !info.IsEmulator && (suErr == nil) && (strings.TrimSpace(suOutput) == "0") {
			adb.Root = SuRootType
			report.line("root", "su, adbd cannot run as root on this %s build", info.BuildType)
			logger.Warn("Root through su is experimental, decerter was tested with adb root on the emulator only")
			return
		}

		err = fmt.Errorf("%w: %s: adbd cannot run as root on this %s build, which a Google Play image is too; use a Google APIs image (such as system-images;android-35;google_apis;x86_64), or a device rooted with Magisk or KernelSU", ErrNoRoot, adb.Serial, info.BuildType)
		return
	}

	rootCtx, cancel := context.WithTimeout(ctx, rootTimeout)
	defer cancel()
	err = poll(rootCtx, func() (isDone bool, pollErr error) {
		uid, shellErr := adb.shell(rootCtx, "id -u")
		isDone = (shellErr == nil) && (strings.TrimSpace(uid) == "0")
		return
	})

	if err != nil {
		err = fmt.Errorf("%w: %s: adb root: %q: %w", ErrNoRoot, adb.Serial, strings.TrimSpace(output), errors.Join(rootErr, err))
		return
	}

	adb.Root = ADBRootType
	report.line("root", "adbd runs as root (adb root)")
	return
}

// a running decerter holds the binary and netd's hooks
func checkNotRunning(ctx context.Context, adb ADB) (err error) {
	pids, err := adb.decerterPids(ctx)

	if err != nil {
		return
	}

	if pids != "" {
		err = fmt.Errorf("%w: pid %s, Ctrl-C in its adb shell or adb shell kill %s stops it", ErrDecerterRunning, pids, pids)
	}

	return
}

// the static binary on the host for the device's ABI
func deviceBinary(info DeviceInfo, options Options) (architecture string, binary string, err error) {
	architecture, err = ArchitectureOf(info.ABI)

	if err != nil {
		return
	}

	binary, err = filepath.Abs(ChooseBinary(architecture, runtime.GOARCH, options.Executable, options.Binary))

	if err != nil {
		return
	}

	err = CheckBinary(binary, architecture)
	return
}

// push the binary to platform.AndroidBinaryPath and check that it runs there
func pushBinary(ctx context.Context, adb ADB, binary string, report *printer) (err error) {
	// the data directory has its own name, a directory here is from something else
	isDirectory, err := adb.shell(ctx, "if [ -d "+platform.AndroidBinaryPath+" ]; then echo yes; else echo no; fi")

	if err != nil {
		return
	}

	if strings.TrimSpace(isDirectory) == "yes" {
		err = fmt.Errorf("%w: %s is a directory, decerter's data directory is %s; remove it with adb shell rm -r %s", ErrBinaryPath, platform.AndroidBinaryPath, platform.AndroidDataDirectory, platform.AndroidBinaryPath)
		return
	}

	_, err = adb.run(ctx, pushTimeout, "push", binary, platform.AndroidBinaryPath)

	if err != nil {
		return
	}

	_, err = adb.shell(ctx, "chmod 755 "+platform.AndroidBinaryPath)

	if err != nil {
		return
	}

	version, versionErr := adb.shell(ctx, platform.AndroidBinaryPath+" "+binaryVersion)
	version = strings.TrimSpace(version)

	if versionErr != nil {
		err = fmt.Errorf("%w: %w", ErrBinaryNotWorking, versionErr)
		return
	}

	if !strings.HasPrefix(version, "decerter ") {
		err = fmt.Errorf("%w: %s %s printed %q", ErrBinaryNotWorking, platform.AndroidBinaryPath, binaryVersion, version)
		return
	}

	report.line("binary", "%s, %s, pushed from %s", platform.AndroidBinaryPath, version, binary)
	return
}

// the package from packages.list on the device, with the same resolution and suggestions as --package there
func checkPackage(ctx context.Context, adb ADB, name string, report *printer, logger *slog.Logger) (err error) {
	output, err := adb.rootShell(ctx, "cat "+platform.AndroidPackagesList)

	if err != nil {
		return
	}

	packages, err := ParsePackages(strings.NewReader(output))

	if err != nil {
		return
	}

	resolved, err := ResolvePackages([]string{name}, packages)

	if err != nil {
		return
	}

	report.line("package", "%s, uid %d", resolved[0].Name, resolved[0].UID)
	sharing := SharingPackages(resolved[0], packages)

	if (len(sharing) > 0) || IsSystemUID(resolved[0].UID) {
		logger.Warn("The package shares its uid, --package selects every process of the uid", "package", resolved[0].Name, "uid", resolved[0].UID, "sharing", sharing)
	}

	return
}

// decerter android tls on the device: whether the package is a Flutter or Chromium app and decerter knows its library's offsets; a library it can't hook is a
// warning, decerter still relays its TLS, only without decryption; isChromium is a Chromium app, hooked or not
func checkAppTLS(ctx context.Context, adb ADB, name string, report *printer, logger *slog.Logger) (isChromium bool) {
	output, tlsErr := adb.rootShell(ctx, platform.AndroidBinaryPath+" android tls --package "+shellQuote(name)+" 2>/dev/null")
	lines := []string{}

	for line := range strings.Lines(output) {
		lines = append(lines, strings.TrimSpace(line))
		report.line("app", "%s", strings.TrimSpace(line))
	}

	isChromium = IsChromiumApp(lines)

	if tlsErr != nil {
		logger.Warn("A Flutter or Chromium library decerter can't hook, its TLS is relayed without decryption: add its version with make generate-flutter-offsets or make generate-chrome-offsets", "package", name, "error", tlsErr)
	}

	return
}

// Chrome's flags file without the first-run screens, with a copy in the data directory that marks it as decerter's; a file of the user's own is kept
func writeChromeFlags(ctx context.Context, adb ADB, report *printer) (err error) {
	copyPath := path.Join(platform.AndroidDataDirectory, chromeCommandLineCopy)
	command := fmt.Sprintf("if [ -e %[1]s ] && ! cmp -s %[1]s %[2]s; then echo kept; else mkdir -p -m 700 %[3]s && echo %[4]s > %[2]s && cp %[2]s %[1]s && chmod 644 %[1]s && echo wrote; fi", chromeCommandLine, copyPath, platform.AndroidDataDirectory, shellQuote(chromeFlags))
	output, err := adb.rootShell(ctx, command)

	if err != nil {
		return
	}

	switch strings.TrimSpace(output) {
	case "wrote":
		report.line("chrome", "wrote %s: %s; Chrome reads it when it starts, setup --remove deletes it", chromeCommandLine, chromeFlags)
	case "kept":
		report.line("chrome", "kept %s, it is not the one setup writes; without --disable-fre Chrome's first-run screens hold the first page back", chromeCommandLine)
	default:
		err = fmt.Errorf("%w: %s: %q", ErrChromeFlags, chromeCommandLine, output)
	}

	return
}

// Chrome's flags file goes when it is still the one setup wrote, a file the user wrote or changed stays
func removeChromeFlags(ctx context.Context, adb ADB, report *printer) (err error) {
	copyPath := path.Join(platform.AndroidDataDirectory, chromeCommandLineCopy)
	command := fmt.Sprintf("if [ -e %[2]s ] && cmp -s %[1]s %[2]s; then rm -f %[1]s && echo removed; elif [ -e %[2]s ] && [ -e %[1]s ]; then echo kept; else echo none; fi", chromeCommandLine, copyPath)
	output, err := adb.rootShell(ctx, command)

	if err != nil {
		return
	}

	switch strings.TrimSpace(output) {
	case "removed":
		report.line("chrome", "removed %s, setup wrote it", chromeCommandLine)
	case "kept":
		report.line("chrome", "kept %s, it changed since setup wrote it", chromeCommandLine)
	case "none":
	default:
		err = fmt.Errorf("%w: %s: %q", ErrChromeFlags, chromeCommandLine, output)
	}

	return
}

// keep a forward of the device to the api socket on port, 0 keeps any existing one or lets adb pick a free port; other forwards of the device to the socket are removed
func forwardAPI(ctx context.Context, adb ADB, port uint16, report *printer) (forwardPort uint16, err error) {
	output, err := adb.run(ctx, adbTimeout, "forward", "--list")

	if err != nil {
		return
	}

	existing := apiForwards(ParseForwards(output), adb.Serial)
	local := "tcp:" + strconv.FormatUint(uint64(port), 10)

	if (port == 0) && (len(existing) > 0) {
		local = existing[0].Local
	}

	for _, forward := range existing {
		if forward.Local != local {
			_, err = adb.run(ctx, adbTimeout, "forward", "--remove", forward.Local)

			if err != nil {
				return
			}
		}
	}

	// adb prints the port it picked for tcp:0
	picked, err := adb.run(ctx, adbTimeout, "forward", local, "localabstract:"+apiSocketName)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrForward, err)
		return
	}

	if local == "tcp:0" {
		local = "tcp:" + strings.TrimSpace(picked)
	}

	parsed, err := strconv.ParseUint(strings.TrimPrefix(local, "tcp:"), 10, 16)

	if err != nil {
		err = fmt.Errorf("%w: %q: %w", ErrForward, local, err)
		return
	}

	forwardPort = uint16(parsed)
	report.line("api", "adb forward %s localabstract:%s", local, apiSocketName)
	return
}

// adb when PATH finds this adb, its path otherwise
func adbCommand(adbPath string) (command string) {
	pathADB, lookErr := exec.LookPath("adb")

	if (lookErr == nil) && (pathADB == adbPath) {
		command = "adb"
		return
	}

	command = shellQuote(adbPath)
	return
}

// the commands setup prints: decerter on the device with the api on its abstract socket, and decerter ui on the host through the forward
// -tt gives decerter a pty even when adb's stdin is no terminal: Ctrl-C reaches it, and when the adb client dies adbd closes the pty and decerter gets SIGHUP;
// without a package name the command has PACKAGE in its place; blockQuic adds --block-quic for a Chromium app
func NextCommands(adb string, serial string, root RootType, packageName string, blockQuic bool, port uint16, decerter string) (deviceCommand string, uiCommand string) {
	if packageName == "" {
		packageName = "PACKAGE"
	}

	run := platform.AndroidBinaryPath + " run --intercept --api-socket " + platform.AndroidAPISocket + " --package " + shellQuote(packageName)

	if blockQuic {
		run += " --block-quic"
	}

	// adb shell hands its arguments to sh on the device, which runs su -c with the whole command
	if root == SuRootType {
		run = `"su -c '` + run + `'"`
	}

	deviceCommand = adb + " -s " + shellQuote(serial) + " shell -tt " + run
	uiCommand = shellQuote(decerter) + " ui --api-socket " + net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(port), 10))
	return
}
