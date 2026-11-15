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
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// the AVD of stage 6: system-images;android-35;google_apis;x86_64 (arm64-v8a on an Apple Silicon Mac), a userdebug build whose adbd may run as
	// root (the playstore images may not)
	avdName string = "decerter-a15"
	// a console port of its own, so the serial is known before the emulator is up
	emulatorPort   string = "5580"
	emulatorSerial string = "emulator-" + emulatorPort
	// the oldest Android the cgroup sharing was built for
	minimumSDKLevel int = 35
	// every adb call is killed after this long unless it says otherwise, a push of decerter takes a few seconds
	adbTimeout  time.Duration = 30 * time.Second
	pushTimeout time.Duration = 120 * time.Second
	// a cold boot of the AVD takes about 20 s on the dev box
	bootTimeout time.Duration = 5 * time.Minute
	// adb emu kill returns at once, the emulator process needs a few seconds
	stopTimeout  time.Duration = time.Minute
	pollInterval time.Duration = 250 * time.Millisecond
)

var (
	errNoSDK            = errors.New("no Android SDK")
	errNoAVD            = errors.New("no AVD")
	errNoRoot           = errors.New("adbd cannot run as root")
	errUnsupportedImage = errors.New("unsupported emulator image")
	errBootTimeout      = errors.New("the emulator did not boot in time")
	errOffline          = errors.New("the emulator went offline")
)

var (
	// the first adb error that said the emulator of the tests is gone, nil while it is there; the cases after it skip and TestMain fails with this one message
	offlineErr atomic.Pointer[error]
)

// the user who ran sudo: adb and the emulator run as this user, so they use its adb server, adb key and AVD; root when there is none
type hostAccount struct {
	Credential *syscall.Credential
	Home       string
}

// the device the tests run on and how to reach it; ABI and Architecture (its GOARCH) come from the running image; process is the emulator the tests
// started, nil for one that was running already
type emulator struct {
	SDK          string
	ADB          string
	Serial       string
	ABI          string
	Architecture string
	account      hostAccount
	process      *exec.Cmd
	waitErr      chan error
	logFile      *os.File
}

// the user behind sudo, from SUDO_UID and SUDO_GID
func invokingAccount() (account hostAccount, err error) {
	account = hostAccount{Credential: nil, Home: os.Getenv("HOME")}
	uidText := os.Getenv("SUDO_UID")

	if uidText == "" {
		return
	}

	entry, lookupErr := user.LookupId(uidText)

	if err = lookupErr; err != nil {
		return
	}

	uid, uidErr := strconv.ParseUint(entry.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(entry.Gid, 10, 32)

	if err = errors.Join(uidErr, gidErr); err != nil {
		return
	}

	account = hostAccount{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}, NoSetGroups: false},
		Home:       entry.HomeDir,
	}
	return
}

// ANDROID_SDK_ROOT, ANDROID_HOME or ~/Android/Sdk of the invoking user, with an emulator in it
func findSDK(account hostAccount) (sdk string, err error) {
	candidates := []string{os.Getenv("ANDROID_SDK_ROOT"), os.Getenv("ANDROID_HOME"), filepath.Join(account.Home, "Android", "Sdk")}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}

		_, statErr := os.Stat(filepath.Join(candidate, "emulator", "emulator"))

		if statErr == nil {
			sdk = candidate
			return
		}
	}

	err = fmt.Errorf("%w: no emulator/emulator in ANDROID_SDK_ROOT, ANDROID_HOME or %s", errNoSDK, filepath.Join(account.Home, "Android", "Sdk"))
	return
}

// ADB, then the adb on PATH, which is the one the running adb server usually came from, then the SDK's platform-tools
func findADB(sdk string) (adb string, err error) {
	adb = os.Getenv("ADB")

	if adb != "" {
		return
	}

	// the SDK's adb first like decerter android setup: the emulator starts it, and an adb of another version restarts its server
	adb = filepath.Join(sdk, "platform-tools", "adb")
	_, statErr := os.Stat(adb)

	if statErr == nil {
		return
	}

	adb, err = exec.LookPath("adb")

	if err != nil {
		err = fmt.Errorf("%w: no adb in platform-tools or on PATH: %w", errNoSDK, errors.Join(statErr, err))
	}

	return
}

// the newest d8 of the SDK's build-tools
func findD8(sdk string) (d8 string, err error) {
	matches, globErr := filepath.Glob(filepath.Join(sdk, "build-tools", "*", "d8"))

	if err = globErr; err != nil {
		return
	}

	if len(matches) == 0 {
		err = fmt.Errorf("no d8 in %s", filepath.Join(sdk, "build-tools"))
		return
	}

	slices.Sort(matches)
	d8 = matches[len(matches)-1]
	return
}

// the environment adb, the emulator and the SDK's tools get, nothing of root's but JAVA_HOME
func (account hostAccount) environment(sdk string) (environment []string) {
	environment = []string{
		"PATH=" + javaPath("/usr/local/bin:/usr/bin:/bin"),
		"HOME=" + account.Home,
		"LC_ALL=C",
		"ANDROID_SDK_ROOT=" + sdk,
		"ANDROID_HOME=" + sdk,
		"ANDROID_AVD_HOME=" + filepath.Join(account.Home, ".android", "avd"),
	}
	environment = append(environment, javaHome()...)

	// the decerter of the host writes its coverage counters here when it was built with -cover
	if coverDirectory != "" {
		environment = append(environment, "GOCOVERDIR="+coverDirectory)
	}

	return
}

// JAVA_HOME of the tests for apksigner, d8 and Gradle, empty without one: a Mac has no java on PATH, only a stub in /usr/bin that needs it
func javaHome() (environment []string) {
	home := os.Getenv("JAVA_HOME")

	if home != "" {
		environment = []string{"JAVA_HOME=" + home}
	}

	return
}

// path with JAVA_HOME's bin in front when JAVA_HOME is set
func javaPath(path string) (withJava string) {
	withJava = path
	home := os.Getenv("JAVA_HOME")

	if home != "" {
		withJava = filepath.Join(home, "bin") + ":" + path
	}

	return
}

// use an emulator adb already knows, or boot the AVD headless; then wait for the boot and make adbd root
func connectEmulator(ctx context.Context, account hostAccount, sdk string, adb string, logPath string) (device emulator, err error) {
	device = emulator{SDK: sdk, ADB: adb, Serial: "", ABI: "", Architecture: "", account: account, process: nil, waitErr: nil, logFile: nil}
	devices, devicesErr := device.run(ctx, adbTimeout, "devices")

	if err = devicesErr; err != nil {
		return
	}

	for line := range strings.Lines(devices) {
		fields := strings.Fields(line)

		if (len(fields) == 2) && strings.HasPrefix(fields[0], "emulator-") && (fields[1] == "device") {
			device.Serial = fields[0]
			break
		}
	}

	if device.Serial == "" {
		err = device.start(logPath)

		if err != nil {
			return
		}
	}

	err = device.waitForBoot(ctx)

	if err != nil {
		return
	}

	err = device.checkImage(ctx)

	if err != nil {
		return
	}

	err = device.root(ctx)
	return
}

// boot the AVD without a window, audio or snapshot; it runs as the invoking user, whose AVD it is
func (device *emulator) start(logPath string) (err error) {
	_, statErr := os.Stat(filepath.Join(device.account.Home, ".android", "avd", avdName+".ini"))

	if statErr != nil {
		err = fmt.Errorf("%w: %s is not in %s, create it from system-images;android-35;google_apis;x86_64, or arm64-v8a on an arm64 host: %w", errNoAVD, avdName, filepath.Join(device.account.Home, ".android", "avd"), statErr)
		return
	}

	logFile, createErr := os.Create(logPath)

	if err = createErr; err != nil {
		return
	}

	device.logFile = logFile
	device.Serial = emulatorSerial
	command := exec.Command(filepath.Join(device.SDK, "emulator", "emulator"), "-avd", avdName, "-port", emulatorPort, "-no-window", "-no-audio", "-no-boot-anim", "-gpu", "swiftshader_indirect", "-no-snapshot", "-no-metrics")
	command.Env = device.account.environment(device.SDK)
	command.Dir = "/"
	command.Stdout = logFile
	command.Stderr = logFile
	// its own process group: a ^C of go test does not reach it, the teardown stops it
	command.SysProcAttr = &syscall.SysProcAttr{Credential: device.account.Credential, Setpgid: true}
	err = command.Start()

	if err != nil {
		return
	}

	device.process = command
	device.waitErr = make(chan error, 1)

	// emulator process
	go func() {
		device.waitErr <- command.Wait()
	}()

	return
}

// sys.boot_completed is the last property a boot sets
func (device *emulator) waitForBoot(ctx context.Context) (err error) {
	bootCtx, cancel := context.WithTimeout(ctx, bootTimeout)
	defer cancel()
	_, err = device.run(bootCtx, bootTimeout, "wait-for-device")

	if err != nil {
		return
	}

	err = poll(bootCtx, func() (isDone bool, pollErr error) {
		select {
		case waitErr := <-device.waitErr:
			pollErr = fmt.Errorf("the emulator exited during the boot, see %s: %w", device.logFile.Name(), errors.Join(waitErr, errBootTimeout))
			return
		default:
		}

		output, shellErr := device.shell(bootCtx, "getprop sys.boot_completed")
		isDone = (shellErr == nil) && (strings.TrimSpace(output) == "1")
		return
	})

	if errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("%w: %w", errBootTimeout, err)
	}

	return
}

// x86_64 or arm64-v8a and Android 15 or newer; the ABI picks the binaries the tests push
func (device *emulator) checkImage(ctx context.Context) (err error) {
	abi, abiErr := device.shell(ctx, "getprop ro.product.cpu.abi")
	level, levelErr := device.shell(ctx, "getprop ro.build.version.sdk")

	if err = errors.Join(abiErr, levelErr); err != nil {
		return
	}

	device.ABI = strings.TrimSpace(abi)
	architectures := map[string]string{"x86_64": "amd64", "arm64-v8a": "arm64"}
	device.Architecture = architectures[device.ABI]
	sdkLevel, parseErr := strconv.Atoi(strings.TrimSpace(level))

	if (parseErr != nil) || (sdkLevel < minimumSDKLevel) || (device.Architecture == "") {
		err = fmt.Errorf("%w: %s is %s with API level %s, the tests need x86_64 or arm64-v8a and API level %d or newer", errUnsupportedImage, device.Serial, device.ABI, strings.TrimSpace(level), minimumSDKLevel)
	}

	return
}

// adb root restarts adbd, the connection drops and comes back; a production build (a playstore image) refuses
func (device *emulator) root(ctx context.Context) (err error) {
	uid, shellErr := device.shell(ctx, "id -u")

	if err = shellErr; err != nil {
		return
	}

	if strings.TrimSpace(uid) == "0" {
		return
	}

	output, rootErr := device.run(ctx, adbTimeout, "root")

	if strings.Contains(output, "cannot run as root") {
		err = fmt.Errorf("%w: %s, use a google_apis image instead of a playstore one", errNoRoot, strings.TrimSpace(output))
		return
	}

	// adb root may report the closed connection as an error, what counts is the uid after it
	rootCtx, cancel := context.WithTimeout(ctx, bootTimeout)
	defer cancel()
	err = poll(rootCtx, func() (isDone bool, pollErr error) {
		output, shellErr := device.shell(rootCtx, "id -u")
		isDone = (shellErr == nil) && (strings.TrimSpace(output) == "0")
		return
	})

	if err != nil {
		err = fmt.Errorf("%w: adb root: %q: %w", errNoRoot, output, errors.Join(rootErr, err))
	}

	return
}

// stop the emulator the tests started, an emulator that was running stays
func (device *emulator) stop() (err error) {
	if device.process == nil {
		return
	}

	defer func() {
		err = errors.Join(err, device.logFile.Close())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	_, killErr := device.run(ctx, adbTimeout, "emu", "kill")

	select {
	case <-device.waitErr:
		return
	case <-ctx.Done():
	}

	// adb could not reach the console, or the emulator hangs
	err = errors.Join(killErr, syscall.Kill(-device.process.Process.Pid, syscall.SIGKILL))
	<-device.waitErr
	return
}

// run adb with the device's serial as the invoking user, output is stdout; the call is killed after timeout
func (device *emulator) run(ctx context.Context, timeout time.Duration, arguments ...string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if device.Serial != "" {
		arguments = append([]string{"-s", device.Serial}, arguments...)
	}

	command := exec.CommandContext(commandCtx, device.ADB, arguments...)
	command.Env = device.account.environment(device.SDK)
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Credential: device.account.Credential}
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	output = stdout.String()

	if err != nil {
		err = fmt.Errorf("adb %s: %w: %s%s", strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()), strings.TrimSpace(output))
		device.checkOffline(stderr.String(), err)
	}

	return
}

// remember the first adb failure that says the device of the tests went away, once TestMain connected to it: an emulator that dropped off adb doesn't
// come back by itself, so the cases after it could only fail; during the boot and adb root the same errors are expected and only retried
func (device *emulator) checkOffline(stderr string, adbErr error) {
	if !isTestDevice(device.Serial) {
		return
	}

	// adb lost its transport, or the emulator is gone from its list
	for _, text := range []string{"device offline", "device '" + device.Serial + "' not found", "no devices/emulators found"} {
		if strings.Contains(stderr, text) {
			wrapped := fmt.Errorf("%w: %s: %w", errOffline, device.Serial, adbErr)
			offlineErr.CompareAndSwap(nil, &wrapped)
			return
		}
	}
}

// the emulator TestMain connected to, the global device is only set once it booted and adbd is root
func isTestDevice(serial string) (isTest bool) {
	isTest = (serial != "") && (serial == device.Serial)
	return
}

// the error that the emulator went offline, nil while it is there
func deviceOffline() (err error) {
	pointer := offlineErr.Load()

	if pointer != nil {
		err = *pointer
	}

	return
}

// run one shell command on the device, adb returns its exit status
func (device *emulator) shell(ctx context.Context, command string) (output string, err error) {
	output, err = device.run(ctx, adbTimeout, "shell", coverCommand(command))
	return
}

// the command with the directory a decerter built with -cover writes its coverage counters into, as it is without coverage
func coverCommand(command string) (covered string) {
	covered = command

	if coverDirectory != "" {
		covered = "export GOCOVERDIR=" + deviceCoverDirectory + "; " + command
	}

	return
}

// an adb exec-out that keeps running until it is killed, its stdout goes to stdout; the command gets a pty on the device, so its stderr has to be redirected there
func (device *emulator) execOut(ctx context.Context, command string) (process *exec.Cmd) {
	process = exec.CommandContext(ctx, device.ADB, "-s", device.Serial, "exec-out", coverCommand(command))
	process.Env = device.account.environment(device.SDK)
	process.Dir = "/"
	process.SysProcAttr = &syscall.SysProcAttr{Credential: device.account.Credential}
	process.WaitDelay = time.Second
	return
}

// push a host file to the device with its mode
func (device *emulator) push(ctx context.Context, source string, destination string, mode string) (err error) {
	_, err = device.run(ctx, pushTimeout, "push", source, destination)

	if err != nil {
		return
	}

	_, err = device.shell(ctx, "chmod "+mode+" "+destination)
	return
}

// call check every pollInterval until it is done, fails or ctx ends
func poll(ctx context.Context, check func() (isDone bool, err error)) (err error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		isDone, checkErr := check()

		if err = checkErr; (err != nil) || isDone {
			return
		}

		select {
		case <-ctx.Done():
			err = ctx.Err()
			return
		case <-ticker.C:
		}
	}
}
