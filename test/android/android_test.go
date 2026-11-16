// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e_android

package android_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// everything the tests push lives here; decerter keeps its state in its own data directory next to it
	deviceDirectory string = "/data/local/tmp/decerter-e2e"
	dataDirectory   string = "/data/local/tmp/decerter.d"
	netdStatePath   string = dataDirectory + "/netd-hooks.json"
	// the emulator reaches the host's loopback through this address
	hostAddress  string        = "10.0.2.2"
	hostCIDR     string        = hostAddress + "/32"
	shellUID     uint32        = 2000
	inetGroup    uint32        = 3003
	buildTimeout time.Duration = 5 * time.Minute
	// an installed app with the INTERNET permission whose UID the clients borrow, netd refuses sockets to a UID without it
	appPackage string = "com.android.proxyhandler"
	// the binaries on the device; decerter is found by name with pidof
	decerterBinary   string = "decerter"
	clientBinary string = "client"
	decerterPackage  string = "github.com/decerter/decerter/cmd/decerter"
	dexName      string = "decerter-https.dex"
	caName       string = "ca.crt"
	ecdsaCAName  string = "ca-ecdsa.crt"
	// what decerter logs once it is attached, per mode
	redirectReady string = `"msg":"Redirecting flows"`
	captureReady  string = `"msg":"Capturing packets"`
	keylogReady   string = `"msg":"Attached secrets uprobe"`
	// a stopping decerter logs each hook it put back, decerter android restore logs the summary
	sharedLog   string = `"msg":"Shared netd cgroup hook"`
	stoppedLog  string = `"msg":"Restored netd cgroup hook"`
	restoredLog string = `"msg":"Netd hooks are exclusive again"`
	// with this directory of the host set, decerter is built with go build -cover and every decerter of the tests writes its coverage counters when it exits: the one
	// of the host into the directory, the ones on the device into deviceCoverDirectory, which teardown pulls into its "device" subdirectory; go tool covdata
	// reads both, make coverage does that
	coverDirectoryEnvironment string = "DECERTER_E2E_COVERDIR"
	deviceCoverDirectory      string = "/data/local/tmp/decerter-e2e-cover"
	coverPackages             string = "github.com/decerter/decerter/..."
)

var (
	errSkip = errors.New("android e2e skipped")
)

// one go build of the tests: the binary's name in the work directory, its package and its GOOS and GOARCH
type goBuild struct {
	Name         string
	Package      string
	OS           string
	Architecture string
}

var (
	// why the tests skip, empty when they run; dexSkipReason and tsharkSkipReason only skip the cases that need them
	skipReason       string
	dexSkipReason    string
	tsharkSkipReason string
	device           emulator
	workDirectory    string
	// the host directory of the coverage counters, empty when the tests don't measure coverage
	coverDirectory string
	appUID         uint32
	// the GOARCH of the emulator ABIs the tests build for, x86_64 and arm64-v8a
	deviceArchitectures = []string{"amd64", "arm64"}
	// the attach list of /sys/fs/cgroup before the first case, every case has to leave it like this
	baseline   string
	tsharkPath string
	// decerter android setup of TestMain: cold when it booted the AVD, otherwise against the running emulator
	setupResult setupRun
)

func TestMain(main *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "the Android e2e tests run as root (make test-e2e-android uses sudo): tshark reads the live capture with dumpcap")
		os.Exit(1)
	}

	start := time.Now()
	code := 1
	err := setup()

	switch {
	case err == nil:
		code = main.Run()
	case errors.Is(err, errSkip):
		skipReason = err.Error()
		fmt.Fprintf(os.Stderr, "skipping the Android e2e tests: %s\n", skipReason)
		code = main.Run()
	default:
		fmt.Fprintf(os.Stderr, "could not set up the Android e2e tests: %s\n", err.Error())
	}

	// one line for every case that skipped after the emulator dropped off adb, and the run fails
	if offline := deviceOffline(); offline != nil {
		fmt.Fprintf(os.Stderr, "the Android e2e tests failed, the emulator dropped off adb and every case after that skipped: %s\n", offline.Error())
		code = 1
	}

	teardownErr := teardown()

	if teardownErr != nil {
		fmt.Fprintf(os.Stderr, "could not tear down the Android e2e tests: %s\n", teardownErr.Error())
		code = 1
	}

	fmt.Fprintf(os.Stderr, "Android e2e wall time %s, emulator started by the tests: %v, booted by decerter android setup: %v\n", time.Since(start).Round(time.Second), device.process != nil, setupResult.BootedSerial != "")
	os.Exit(code)
}

// find the tools, build what goes to the device, connect to the emulator, push and take the baseline
// a missing SDK, AVD, root or app is errSkip, missing javac or d8 skips only the HTTPS cases, missing tshark only the capture, no Flutter SDK only the Flutter cases,
// no ChromePublic apk only the ChromePublic cases
func setup() (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout+bootTimeout)
	defer cancel()
	account, accountErr := invokingAccount()

	if err = accountErr; err != nil {
		return
	}

	sdk, sdkErr := findSDK(account)

	if err = sdkErr; err != nil {
		err = fmt.Errorf("%w: %w", errSkip, err)
		return
	}

	adb, adbErr := findADB(sdk)

	if err = adbErr; err != nil {
		err = fmt.Errorf("%w: %w", errSkip, err)
		return
	}

	workDirectory, err = os.MkdirTemp("", "decerter-android-e2e-")

	if err != nil {
		return
	}

	// adb runs as the invoking user and reads the files it pushes from here
	err = os.Chmod(workDirectory, 0o755)

	if err != nil {
		return
	}

	coverDirectory = os.Getenv(coverDirectoryEnvironment)
	err = buildBinaries(ctx)

	if err != nil {
		return
	}

	dexErr := buildDex(ctx, sdk)

	if dexErr != nil {
		dexSkipReason = dexErr.Error()
		fmt.Fprintf(os.Stderr, "the HTTPS cases will skip: %s\n", dexSkipReason)
	}

	// the Flutter cases skip without an SDK, a failed build fails them
	flutterApps, flutterSkipReason = buildFlutterApps(account, sdk)

	if flutterSkipReason != "" {
		fmt.Fprintf(os.Stderr, "the Flutter cases will skip: %s\n", flutterSkipReason)
	}

	// the ChromePublic cases skip without an apk, a failed doctored copy fails the negative one
	chromiumAPK, chromiumDoctored, chromiumSkipReason, chromiumErr = prepareChromium(ctx, account, sdk)

	if chromiumSkipReason != "" {
		fmt.Fprintf(os.Stderr, "the ChromePublic cases will skip: %s\n", chromiumSkipReason)
	}

	tsharkPath, err = exec.LookPath("tshark")

	if err != nil {
		tsharkSkipReason = "tshark is not installed: " + err.Error()
		err = nil
	}

	// decerter android setup boots the AVD itself when no emulator runs, that is the cold setup case
	setupResult, err = coldSetup(ctx, account, sdk, adb)

	if err != nil {
		return
	}

	device, err = connectEmulator(ctx, account, sdk, adb, filepath.Join(workDirectory, "emulator.log"))

	if errors.Is(err, errNoAVD) || errors.Is(err, errNoRoot) || errors.Is(err, errUnsupportedImage) {
		err = fmt.Errorf("%w: %w", errSkip, err)
		return
	}

	if err != nil {
		return
	}

	// the log of the emulator setup booted, an emulator that drops off adb points to it
	if setupResult.BootedSerial == device.Serial {
		device.LogPath = setupResult.BootLog
	}

	appUID, err = lookupAppUID(ctx, appPackage)

	if err != nil {
		err = fmt.Errorf("%w: %w", errSkip, err)
		return
	}

	if coverDirectory != "" {
		_, err = device.shell(ctx, "rm -rf "+deviceCoverDirectory+" && mkdir -p "+deviceCoverDirectory)

		if err != nil {
			return
		}
	}

	if !setupResult.IsCold {
		setupResult = runSetup(ctx, account, sdk, adb, "--serial", device.Serial, "--package", appPackage)
	}

	err = pushFiles(ctx)

	if err != nil {
		return
	}

	// a decerter killed in an earlier run left netd's hooks shared, the baseline has to be the pristine list
	isLeftOver, stateErr := deviceFileExists(ctx, netdStatePath)

	if err = stateErr; err != nil {
		return
	}

	if isLeftOver {
		fmt.Fprintf(os.Stderr, "restoring the netd hooks an earlier run left shared\n")
		_, err = device.shell(ctx, deviceDirectory+"/"+decerterBinary+" android restore")

		if err != nil {
			return
		}
	}

	baseline, err = attachList(ctx)

	if err != nil {
		return
	}

	fmt.Fprintf(os.Stderr, "device %s, app %s uid %d, attach list of /sys/fs/cgroup:\n%s", device.Serial, appPackage, appUID, baseline)
	return
}

// build decerter for the host, which runs decerter android setup and decerter ui, and decerter and the client for the emulator of either ABI: static linux binaries
// like make build and make build-arm64, named <name>-<arch>; the emulator's ABI is only known once it runs, and setup picks decerter-<arch> next to the
// host's decerter unless that is the Linux binary of the device's architecture
func buildBinaries(ctx context.Context) (err error) {
	goPath, lookErr := exec.LookPath("go")

	if err = lookErr; err != nil {
		return
	}

	builds := []goBuild{{Name: decerterBinary, Package: decerterPackage, OS: runtime.GOOS, Architecture: runtime.GOARCH}}

	for _, architecture := range deviceArchitectures {
		builds = append(builds,
			goBuild{Name: decerterBinary + "-" + architecture, Package: decerterPackage, OS: "linux", Architecture: architecture},
			goBuild{Name: clientBinary + "-" + architecture, Package: "./client", OS: "linux", Architecture: architecture},
		)
	}

	for _, build := range builds {
		arguments := []string{"build", "-trimpath", "-tags", "netgo,osusergo,e2e_android"}

		if (coverDirectory != "") && (build.Package == decerterPackage) {
			arguments = append(arguments, "-cover", "-covermode=atomic", "-coverpkg="+coverPackages)
		}

		arguments = append(arguments, "-o", filepath.Join(workDirectory, build.Name), build.Package)
		_, err = runHost(ctx, buildTimeout, []string{"GOOS=" + build.OS, "GOARCH=" + build.Architecture, "CGO_ENABLED=0"}, goPath, arguments...)

		if err != nil {
			return
		}
	}

	return
}

// javac and the SDK's d8 turn dex/*.java into one dex, d8 needs every class file (DecerterHttps$1 too)
func buildDex(ctx context.Context, sdk string) (err error) {
	javacPath, javacErr := exec.LookPath("javac")

	if err = javacErr; err != nil {
		return
	}

	d8Path, d8Err := findD8(sdk)

	if err = d8Err; err != nil {
		return
	}

	sources, globErr := filepath.Glob(filepath.Join("dex", "*.java"))

	if err = globErr; err != nil {
		return
	}

	classDirectory := filepath.Join(workDirectory, "classes")
	dexDirectory := filepath.Join(workDirectory, "dex")
	_, err = runHost(ctx, buildTimeout, nil, javacPath, append([]string{"--release", "11", "-d", classDirectory}, sources...)...)

	if err != nil {
		return
	}

	classes, classErr := filepath.Glob(filepath.Join(classDirectory, "*.class"))

	if err = errors.Join(classErr, os.MkdirAll(dexDirectory, 0o755)); err != nil {
		return
	}

	_, err = runHost(ctx, buildTimeout, nil, d8Path, append([]string{"--min-api", "30", "--output", dexDirectory}, classes...)...)

	if err != nil {
		return
	}

	err = os.Rename(filepath.Join(dexDirectory, "classes.dex"), filepath.Join(workDirectory, dexName))
	return
}

// the package's uid from pm, it must hold INTERNET
func lookupAppUID(ctx context.Context, packageName string) (uid uint32, err error) {
	packages, listErr := device.shell(ctx, "pm list packages -U "+packageName)

	if err = listErr; err != nil {
		return
	}

	for line := range strings.Lines(packages) {
		name, uidText, isFound := strings.Cut(strings.TrimSpace(line), " uid:")

		if !isFound || (name != "package:"+packageName) {
			continue
		}

		parsed, parseErr := strconv.ParseUint(uidText, 10, 32)

		if err = parseErr; err != nil {
			return
		}

		uid = uint32(parsed)
	}

	if uid == 0 {
		err = fmt.Errorf("%s is not installed, the clients need an app uid with the INTERNET permission", packageName)
		return
	}

	permissions, dumpErr := device.shell(ctx, "dumpsys package "+packageName)

	if err = dumpErr; err != nil {
		return
	}

	if !strings.Contains(permissions, "android.permission.INTERNET: granted=true") {
		err = fmt.Errorf("%s (uid %d) has no INTERNET permission", packageName, uid)
	}

	return
}

func pushFiles(ctx context.Context) (err error) {
	_, err = device.shell(ctx, "rm -rf "+deviceDirectory+" && mkdir -p "+deviceDirectory+" && chmod 755 "+deviceDirectory)

	if err != nil {
		return
	}

	// the binaries of the emulator's ABI, by their plain names on the device
	for _, name := range []string{decerterBinary, clientBinary} {
		err = device.push(ctx, filepath.Join(workDirectory, name+"-"+device.Architecture), deviceDirectory+"/"+name, "755")

		if err != nil {
			return
		}
	}

	// the dex trusts the server's certificate as its CA, for each certificate of the servers
	for _, certificate := range []string{"server_rsa", "server_ecdsa"} {
		certificatePath, absErr := filepath.Abs(filepath.Join("..", "e2e", "assets", certificate+".crt"))

		if err = absErr; err != nil {
			return
		}

		err = device.push(ctx, certificatePath, deviceDirectory+"/"+caFile(certificate), "644")

		if err != nil {
			return
		}
	}

	if dexSkipReason != "" {
		return
	}

	err = device.push(ctx, filepath.Join(workDirectory, dexName), deviceDirectory+"/"+dexName, "644")
	return
}

// the CA file on the device of a certificate of assets
func caFile(certificate string) (name string) {
	name = caName

	if certificate == "server_ecdsa" {
		name = ecdsaCAName
	}

	return
}

// compare the attach list with the baseline once more, remove what the tests put on the device, stop the emulator if the tests started it
func teardown() (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()

	// nothing on an offline emulator answers, it is only stopped
	isReachable := (device.Serial != "") && (deviceOffline() == nil)

	if (baseline != "") && isReachable {
		list, listErr := attachList(ctx)

		if err = listErr; (err == nil) && (list != baseline) {
			err = fmt.Errorf("the attach list of /sys/fs/cgroup is not the one from before the tests, before:\n%safter:\n%s", baseline, list)
		}
	}

	if isReachable && (coverDirectory != "") {
		err = errors.Join(err, pullCoverage(ctx))
	}

	if isReachable {
		err = errors.Join(err, uninstallFlutter(ctx), uninstallChromium(ctx))
		// sync before the emulator is killed, a removal still in the page cache would be lost
		_, removeErr := device.shell(ctx, "rm -rf "+deviceDirectory+" "+dataDirectory+" "+setupBinary+" "+chromeCommandLine+" && sync")
		removeErr = errors.Join(removeErr, removeAPIForwards(ctx))
		left, listErr := device.shell(ctx, "ls -A /data/local/tmp")
		err = errors.Join(err, removeErr, listErr)

		// files of others are left alone, but they are worth a line
		if strings.TrimSpace(left) != "" {
			fmt.Fprintf(os.Stderr, "/data/local/tmp is not empty after the tests:\n%s", left)
		}
	}

	err = errors.Join(err, device.stop(), stopBooted(setupResult))

	if workDirectory != "" {
		err = errors.Join(err, os.RemoveAll(workDirectory))
	}

	return
}

// the coverage counters the decerter processes of the device wrote, into the "device" subdirectory of the host's directory; nothing is left on the device
func pullCoverage(ctx context.Context) (err error) {
	_, err = device.run(ctx, pushTimeout, "pull", deviceCoverDirectory, filepath.Join(coverDirectory, "device"))
	_, removeErr := device.run(ctx, adbTimeout, "shell", "rm -rf "+deviceCoverDirectory)
	err = errors.Join(err, removeErr)
	return
}

// skip a case when the suite can't run on a device, or the emulator went offline in an earlier case
func requireDevice(state *testing.T) {
	if skipReason != "" {
		state.Skip(skipReason)
	}

	if offline := deviceOffline(); offline != nil {
		state.Skipf("skipped, an earlier case lost the emulator: %s", offline.Error())
	}
}

// the attach list of every cgroup attach type of /sys/fs/cgroup, from the client's raw BPF_PROG_QUERY
func attachList(ctx context.Context) (list string, err error) {
	list, err = device.shell(ctx, deviceDirectory+"/"+clientBinary+" query")
	return
}

func deviceFileExists(ctx context.Context, path string) (isExisting bool, err error) {
	output, shellErr := device.shell(ctx, "if [ -e "+path+" ]; then echo yes; else echo no; fi")

	if err = shellErr; err != nil {
		return
	}

	isExisting = (strings.TrimSpace(output) == "yes")
	return
}

// run a tool of the host as root with a timeout and extra environment, stdout is the output
func runHost(ctx context.Context, timeout time.Duration, environment []string, name string, arguments ...string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, name, arguments...)
	command.Env = append(os.Environ(), environment...)
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	output = stdout.String()

	if err != nil {
		err = fmt.Errorf("%s %s: %w: %s", name, strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()))
	}

	return
}
