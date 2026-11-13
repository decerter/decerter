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
	// the binaries on the device; decerter and rewrite are found by name with pidof
	decerterBinary    string = "decerter"
	rewriteBinary string = "rewrite"
	clientBinary  string = "client"
	dexName       string = "decerter-https.dex"
	caName        string = "ca.crt"
	// what decerter logs once it is attached, per mode
	redirectReady string = `"msg":"Redirecting flows"`
	captureReady  string = `"msg":"Capturing packets"`
	keylogReady   string = `"msg":"Attached secrets uprobe"`
	// a stopping decerter logs each hook it put back, decerter android restore logs the summary
	sharedLog   string = `"msg":"Shared netd cgroup hook"`
	stoppedLog  string = `"msg":"Restored netd cgroup hook"`
	restoredLog string = `"msg":"Netd hooks are exclusive again"`
)

var (
	errSkip = errors.New("android e2e skipped")
)

var (
	// why the tests skip, empty when they run; dexSkipReason and tsharkSkipReason only skip the cases that need them
	skipReason       string
	dexSkipReason    string
	tsharkSkipReason string
	device           emulator
	workDirectory    string
	appUID           uint32
	// the attach list of /sys/fs/cgroup before the first case, every case has to leave it like this
	baseline   string
	tsharkPath string
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

	teardownErr := teardown()

	if teardownErr != nil {
		fmt.Fprintf(os.Stderr, "could not tear down the Android e2e tests: %s\n", teardownErr.Error())
		code = 1
	}

	fmt.Fprintf(os.Stderr, "Android e2e wall time %s, emulator started by the tests: %v\n", time.Since(start).Round(time.Second), device.process != nil)
	os.Exit(code)
}

// find the tools, build what goes to the device, connect to the emulator, push and take the baseline
// a missing SDK, AVD, root or app is errSkip, missing javac or d8 skips only the HTTPS cases, missing tshark only the capture
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

	err = buildBinaries(ctx)

	if err != nil {
		return
	}

	dexErr := buildDex(ctx, sdk)

	if dexErr != nil {
		dexSkipReason = dexErr.Error()
		fmt.Fprintf(os.Stderr, "the HTTPS cases will skip: %s\n", dexSkipReason)
	}

	tsharkPath, err = exec.LookPath("tshark")

	if err != nil {
		tsharkSkipReason = "tshark is not installed: " + err.Error()
		err = nil
	}

	device, err = connectEmulator(ctx, account, sdk, adb, filepath.Join(workDirectory, "emulator.log"))

	if errors.Is(err, errNoAVD) || errors.Is(err, errNoRoot) || errors.Is(err, errUnsupportedImage) {
		err = fmt.Errorf("%w: %w", errSkip, err)
		return
	}

	if err != nil {
		return
	}

	appUID, err = lookupAppUID(ctx)

	if err != nil {
		err = fmt.Errorf("%w: %w", errSkip, err)
		return
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

// build decerter, the rewrite decerter and the client for the emulator: static linux/amd64 like make build
func buildBinaries(ctx context.Context) (err error) {
	goPath, lookErr := exec.LookPath("go")

	if err = lookErr; err != nil {
		return
	}

	packages := map[string]string{
		decerterBinary:    "github.com/decerter/decerter/cmd/decerter",
		rewriteBinary: "./rewrite",
		clientBinary:  "./client",
	}

	for name, buildPackage := range packages {
		_, err = runHost(ctx, buildTimeout, []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"}, goPath, "build", "-trimpath", "-tags", "netgo,osusergo,e2e_android", "-o", filepath.Join(workDirectory, name), buildPackage)

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
func lookupAppUID(ctx context.Context) (uid uint32, err error) {
	packages, listErr := device.shell(ctx, "pm list packages -U "+appPackage)

	if err = listErr; err != nil {
		return
	}

	for line := range strings.Lines(packages) {
		name, uidText, isFound := strings.Cut(strings.TrimSpace(line), " uid:")

		if !isFound || (name != "package:"+appPackage) {
			continue
		}

		parsed, parseErr := strconv.ParseUint(uidText, 10, 32)

		if err = parseErr; err != nil {
			return
		}

		uid = uint32(parsed)
	}

	if uid == 0 {
		err = fmt.Errorf("%s is not installed, the clients need an app uid with the INTERNET permission", appPackage)
		return
	}

	permissions, dumpErr := device.shell(ctx, "dumpsys package "+appPackage)

	if err = dumpErr; err != nil {
		return
	}

	if !strings.Contains(permissions, "android.permission.INTERNET: granted=true") {
		err = fmt.Errorf("%s (uid %d) has no INTERNET permission", appPackage, uid)
	}

	return
}

func pushFiles(ctx context.Context) (err error) {
	_, err = device.shell(ctx, "rm -rf "+deviceDirectory+" && mkdir -p "+deviceDirectory+" && chmod 755 "+deviceDirectory)

	if err != nil {
		return
	}

	for _, name := range []string{decerterBinary, rewriteBinary, clientBinary} {
		err = device.push(ctx, filepath.Join(workDirectory, name), deviceDirectory+"/"+name, "755")

		if err != nil {
			return
		}
	}

	certificatePath, absErr := filepath.Abs(filepath.Join("..", "e2e", "assets", "server_rsa.crt"))

	if err = absErr; err != nil {
		return
	}

	err = device.push(ctx, certificatePath, deviceDirectory+"/"+caName, "644")

	if (err != nil) || (dexSkipReason != "") {
		return
	}

	err = device.push(ctx, filepath.Join(workDirectory, dexName), deviceDirectory+"/"+dexName, "644")
	return
}

// compare the attach list with the baseline once more, remove what the tests put on the device, stop the emulator if the tests started it
func teardown() (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()

	if (baseline != "") && (device.Serial != "") {
		list, listErr := attachList(ctx)

		if err = listErr; (err == nil) && (list != baseline) {
			err = fmt.Errorf("the attach list of /sys/fs/cgroup is not the one from before the tests, before:\n%safter:\n%s", baseline, list)
		}
	}

	if device.Serial != "" {
		_, removeErr := device.shell(ctx, "rm -rf "+deviceDirectory+" "+dataDirectory)
		left, listErr := device.shell(ctx, "ls -A /data/local/tmp")
		err = errors.Join(err, removeErr, listErr)

		// files of others are left alone, but they are worth a line
		if strings.TrimSpace(left) != "" {
			fmt.Fprintf(os.Stderr, "/data/local/tmp is not empty after the tests:\n%s", left)
		}
	}

	err = errors.Join(err, device.stop())

	if workDirectory != "" {
		err = errors.Join(err, os.RemoveAll(workDirectory))
	}

	return
}

// skip a case when the suite can't run on a device
func requireDevice(state *testing.T) {
	if skipReason != "" {
		state.Skip(skipReason)
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
