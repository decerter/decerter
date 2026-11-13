// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e_android

package android_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
)

const (
	// where decerter android setup puts the binary, the data directory is dataDirectory next to it
	setupBinary string = "/data/local/tmp/decerter"
	// the forward of decerter android setup and the lines it prints before the two commands
	apiForward     string = "localabstract:decerter-api"
	deviceHeading  string = "Start decerter on the device"
	uiHeading      string = "Then the UI on this machine"
	sharedHookLine string = `"msg":"Shared netd cgroup hook"`
)

var (
	// the line of a setup that booted the AVD: boot     decerter-a15 as emulator-5554 without a window, its log is /tmp/decerter-emulator-….log
	bootPattern = regexp.MustCompile(`(?m)^boot +\S+ as (emulator-\d+) without a window, its log is (\S+)$`)
)

// one decerter android setup run as the invoking user: Output is its stdout, Log its stderr; BootedSerial and BootLog are the emulator it booted
type setupRun struct {
	Output       string
	Log          string
	Err          error
	IsCold       bool
	BootedSerial string
	BootLog      string
}

// a host command of the tests as the invoking user, run by the printed command line: decerter on the device through adb shell, or decerter ui
type userProcess struct {
	command *exec.Cmd
	stdout  lockedBuffer
	stderr  lockedBuffer
	exited  chan struct{}
}

// the browser side of decerter ui
type uiPage struct {
	client *http.Client
	host   string
	cookie *http.Cookie
}

// Test if decerter android setup of TestMain, from a cold emulator when none ran, left a working decerter on the device and a forward, and printed the two commands:
// decerter run on the device with --package decrypts the Conscrypt calls over TLS 1.3 and 1.2, decerter ui on the host shows the requests, and decerter stops and puts netd's hooks back.
func TestSetupPositive(state *testing.T) {
	requireDex(state)

	if setupResult.Err != nil {
		state.Fatalf("Test of the setup failed, error: %s, output:\n%s\nlog:\n%s", setupResult.Err.Error(), setupResult.Output, setupResult.Log)
	}

	state.Logf("decerter android setup, cold: %v, output:\n%s", setupResult.IsCold, setupResult.Output)
	expectedLines := []string{
		"device   " + device.Serial + ", ",
		"root     adbd runs as root",
		"binary   " + setupBinary + ", decerter ",
		"tls      Conscrypt offsets for Android 15 on x86_64",
		fmt.Sprintf("package  %s, uid %d", appPackage, appUID),
		// the test app is no Flutter app: a system app or one without libflutter.so
		"app      " + appPackage + ": ",
		"api      adb forward tcp:",
	}

	if setupResult.IsCold {
		expectedLines = append(expectedLines, "boot     "+avdName+" as "+device.Serial+" without a window")
	}

	for _, expected := range expectedLines {
		if !strings.Contains(setupResult.Output, "\n"+expected) && !strings.HasPrefix(setupResult.Output, expected) {
			state.Errorf("Test of the setup failed, the output should have a line %q, output:\n%s", expected, setupResult.Output)
		}
	}

	version, err := device.shell(state.Context(), setupBinary+" --version")

	if (err != nil) || !strings.HasPrefix(version, "decerter ") {
		state.Fatalf("Test of the setup failed, the pushed decerter should run, version: %q, error: %v", version, err)
	}

	port := setupForwardPort(state)
	deviceCommand, uiCommand := printedCommands(state, setupResult.Output)
	expectedDevice := fmt.Sprintf("adb -s %s shell -t %s run --intercept --api-socket @decerter-api --package %s", device.Serial, setupBinary, appPackage)
	expectedUI := fmt.Sprintf("%s ui --api-socket 127.0.0.1:%s", filepath.Join(workDirectory, decerterBinary), port)

	if (deviceCommand != expectedDevice) || (uiCommand != expectedUI) {
		state.Fatalf("Test of the setup failed, the commands should be %q and %q, commands: %q and %q", expectedDevice, expectedUI, deviceCommand, uiCommand)
	}

	// the printed command, as the user runs it; decerter logs on stderr through adb shell
	servers := startHTTPSServers(state, nil)
	decerter := startUserProcess(state, deviceCommand)
	waitText(state, "decerter run on the device", decerter.stderr, decerter.exited, redirectReady)
	selected := fmt.Sprintf(`"msg":"Selected package","package":%q,"uid":%d}`, appPackage, appUID)

	if !strings.Contains(decerter.stderr.String(), selected) {
		state.Errorf("Test of the setup failed, decerter should log %s, log:\n%s", selected, decerter.stderr.String())
	}

	for _, server := range servers {
		err = testDex(state.Context(), appUID, server, "/setup", "/setup")

		if err != nil {
			state.Errorf("Test of the setup failed, error: %s", err.Error())
		}
	}

	ui := startUserProcess(state, uiCommand)
	waitText(state, "decerter ui", ui.stdout, ui.exited, "\n")
	page := openUI(state, strings.TrimSpace(ui.stdout.String()))

	for _, server := range servers {
		request, requestErr := page.waitRequest(state.Context(), server.Port)

		if requestErr != nil {
			state.Errorf("Test of the setup failed, decerter ui should show the decrypted request to port %s, error: %s", server.Port, requestErr.Error())
			continue
		}

		if !strings.HasPrefix(request, `GET /setup HTTP/1.1\r\n`) {
			state.Errorf("Test of the setup failed, decerter ui should show GET /setup to port %s, message: %q", server.Port, request)
		}
	}

	ui.stop(state)

	// what Ctrl-C does to the adb shell: decerter stops and puts netd's hooks back, its adb shell ends
	_, err = device.shell(state.Context(), "kill -TERM $(pidof decerter)")

	if err != nil {
		state.Fatalf("Could not stop decerter, error: %s", err.Error())
	}

	decerter.wait(state)
	log := decerter.stderr.String()
	shared := strings.Count(log, sharedHookLine)

	if (shared == 0) || (strings.Count(log, stoppedLog) != shared) {
		state.Errorf("Test of the setup failed, decerter should log %s for each %s when it stops, log:\n%s", stoppedLog, sharedHookLine, log)
	}

	checkPristine(state)
}

// Test if decerter android setup refuses a device adb doesn't have, an AVD that doesn't exist, a binary that can't run on the device and a package that isn't installed, and changes nothing on the device.
func TestSetupNegative(state *testing.T) {
	guardDevice(state)
	negativeCases := []struct {
		Arguments []string
		Text      string
	}{
		{Arguments: []string{"--serial", "emulator-5998"}, Text: "no such device emulator-5998, adb sees " + device.Serial + " (device)"},
		{Arguments: []string{"--avd", "no-such-avd"}, Text: "unknown AVD no-such-avd, the AVDs of this user: "},
		{Arguments: []string{"--serial", device.Serial, "--binary", "/bin/ls"}, Text: "/bin/ls is dynamically linked"},
		{Arguments: []string{"--serial", device.Serial, "--package", "no.such.app"}, Text: `unknown package \"no.such.app\", the closest installed packages: `},
		{Arguments: []string{"--serial", device.Serial, "--remove", "--port", "8080"}, Text: "if any flags in the group [remove port] are set none of the others can be"},
	}
	before, err := device.run(state.Context(), adbTimeout, "forward", "--list")

	if err != nil {
		state.Fatalf("Could not list the forwards, error: %s", err.Error())
	}

	for _, negative := range negativeCases {
		result := runSetup(state.Context(), device.account, device.SDK, device.ADB, negative.Arguments...)

		if (result.Err == nil) || !strings.Contains(result.Log, negative.Text) {
			state.Errorf("Test of the setup failed, arguments %q should fail with %q, error: %v, output:\n%s\nlog:\n%s", negative.Arguments, negative.Text, result.Err, result.Output, result.Log)
		}

		if strings.Contains(result.Output, "binary   ") {
			state.Errorf("Test of the setup failed, arguments %q should push nothing, output:\n%s", negative.Arguments, result.Output)
		}
	}

	after, err := device.run(state.Context(), adbTimeout, "forward", "--list")

	if (err != nil) || (after != before) {
		state.Errorf("Test of the setup failed, the forwards should not change, before:\n%safter:\n%s, error: %v", before, after, err)
	}
}

// Test if decerter run --package with a name that isn't installed fails on the device with the closest installed packages, and attaches nothing.
func TestPackageNegative(state *testing.T) {
	guardDevice(state)

	for _, command := range []string{"run --package no.such.app", "capture -w - --package " + appPackage + ",no.such.app", "keylog --uid 0 --package no.such.app"} {
		output, err := device.shell(state.Context(), deviceDirectory+"/"+decerterBinary+" "+command+" 2>&1 >/dev/null")

		if (err == nil) || !strings.Contains(output, `unknown package \"no.such.app\", the closest installed packages: `) || strings.Contains(output, sharedHookLine) {
			state.Errorf("Test of --package failed, decerter %s should fail with the closest packages, error: %v, output:\n%s", command, err, output)
		}
	}

	checkPristine(state)
}

// Test if decerter android setup --remove is refused while decerter runs on the device and leaves the binary and the forward.
func TestSetupRemoveNegative(state *testing.T) {
	guardDevice(state)
	requireSetup(state)
	decerter := startSetupDecerter(state, "remove-negative")
	result := runSetup(state.Context(), device.account, device.SDK, device.ADB, "--remove", "--serial", device.Serial)

	if (result.Err == nil) || !strings.Contains(result.Log, "decerter runs on the device, stop it first") {
		state.Errorf("Test of the setup removal failed, it should be refused while decerter runs, error: %v, output:\n%s\nlog:\n%s", result.Err, result.Output, result.Log)
	}

	isPushed, err := deviceFileExists(state.Context(), setupBinary)

	if (err != nil) || !isPushed || (setupForwardPort(state) == "") {
		state.Errorf("Test of the setup removal failed, the binary and the forward should stay, binary: %v, error: %v", isPushed, err)
	}

	stopDeviceDecerter(state, decerter, true)
}

// Test if decerter android setup --remove after decerter was killed with SIGKILL puts netd's hooks back and leaves no binary, no data directory and no forward.
func TestSetupRemovePositive(state *testing.T) {
	guardDevice(state)
	requireSetup(state)
	decerter := startSetupDecerter(state, "remove")
	_, err := device.shell(state.Context(), "kill -9 $(pidof decerter)")

	if err == nil {
		err = decerter.waitStopped(state.Context())
	}

	if err != nil {
		state.Fatalf("Could not kill decerter, error: %s", err.Error())
	}

	result := runSetup(state.Context(), device.account, device.SDK, device.ADB, "--remove", "--serial", device.Serial)
	state.Logf("decerter android setup --remove, output:\n%s", result.Output)
	expectedLines := []string{
		"restore  netd's hooks a killed decerter left shared are exclusive again",
		"binary   removed " + setupBinary + " " + dataDirectory,
		"api      removed adb forward tcp:",
	}

	for _, expected := range expectedLines {
		if (result.Err != nil) || !strings.Contains(result.Output, "\n"+expected) {
			state.Errorf("Test of the setup removal failed, the output should have a line %q, error: %v, output:\n%s\nlog:\n%s", expected, result.Err, result.Output, result.Log)
		}
	}

	for _, path := range []string{setupBinary, dataDirectory} {
		isLeft, existsErr := deviceFileExists(state.Context(), path)

		if (existsErr != nil) || isLeft {
			state.Errorf("Test of the setup removal failed, %s should be gone, error: %v", path, existsErr)
		}
	}

	forwards, err := device.run(state.Context(), adbTimeout, "forward", "--list")

	if (err != nil) || strings.Contains(forwards, device.Serial+" tcp:") && strings.Contains(forwards, apiForward) {
		state.Errorf("Test of the setup removal failed, no forward to %s should be left, forwards:\n%s, error: %v", apiForward, forwards, err)
	}

	checkPristine(state)
}

// the setup of TestMain worked, so its binary is on the device
func requireSetup(state *testing.T) {
	if setupResult.Err != nil {
		state.Fatalf("decerter android setup of TestMain failed, error: %s", setupResult.Err.Error())
	}
}

// the pushed decerter in the background with the selection of the cases, its stderr in deviceDirectory/<name>.log
func startSetupDecerter(state *testing.T, name string) (decerter deviceDecerter) {
	decerter = deviceDecerter{Binary: decerterBinary, Name: name}
	command := fmt.Sprintf("cd %s && rm -f %s.log && (setsid %s run --package %s --dst-cidr %s </dev/null >/dev/null 2>%s.log &)", deviceDirectory, name, setupBinary, appPackage, hostCIDR, name)
	_, err := device.shell(state.Context(), command)

	if err != nil {
		state.Fatalf("Could not start the pushed decerter, error: %s", err.Error())
	}

	readyCtx, cancel := context.WithTimeout(state.Context(), readyTimeout)
	defer cancel()
	err = poll(readyCtx, func() (isDone bool, pollErr error) {
		log, logErr := decerter.log(readyCtx)
		isDone = (logErr == nil) && strings.Contains(log, redirectReady)
		return
	})

	if err != nil {
		log, _ := decerter.log(state.Context())
		state.Fatalf("Could not start the pushed decerter, error: %s, log:\n%s", err.Error(), log)
	}

	return
}

// the host port of the forward setup made to the api socket of the device, empty when there is none
func setupForwardPort(state *testing.T) (port string) {
	forwards, err := device.run(state.Context(), adbTimeout, "forward", "--list")

	if err != nil {
		state.Fatalf("Could not list the forwards, error: %s", err.Error())
	}

	for line := range strings.Lines(forwards) {
		fields := strings.Fields(line)

		if (len(fields) == 3) && (fields[0] == device.Serial) && (fields[2] == apiForward) {
			port = strings.TrimPrefix(fields[1], "tcp:")
		}
	}

	return
}

// the indented line under each heading of the setup output
func printedCommands(state *testing.T, output string) (deviceCommand string, uiCommand string) {
	lines := strings.Split(output, "\n")

	for index, line := range lines[:len(lines)-1] {
		switch {
		case strings.HasPrefix(line, deviceHeading):
			deviceCommand = strings.TrimPrefix(lines[index+1], "  ")
		case strings.HasPrefix(line, uiHeading):
			uiCommand = strings.TrimPrefix(lines[index+1], "  ")
		}
	}

	if (deviceCommand == "") || (uiCommand == "") {
		state.Fatalf("Test of the setup failed, the output should have both commands, output:\n%s", output)
	}

	return
}

// decerter android setup with arguments as the invoking user, with the adb of the tests so both use one adb server
func runSetup(ctx context.Context, account hostAccount, sdk string, adb string, arguments ...string) (result setupRun) {
	setupCtx, cancel := context.WithTimeout(ctx, bootTimeout+buildTimeout)
	defer cancel()
	command := userCommand(setupCtx, account, sdk, adb, filepath.Join(workDirectory, decerterBinary), append([]string{"android", "setup"}, arguments...)...)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	result = setupRun{Output: stdout.String(), Log: stderr.String(), Err: err, IsCold: false, BootedSerial: "", BootLog: ""}
	booted := bootPattern.FindStringSubmatch(result.Output)

	if booted != nil {
		result.BootedSerial, result.BootLog = booted[1], booted[2]
	}

	return
}

// setup boots the AVD when no emulator runs and the AVD is there; otherwise TestMain runs it against the running emulator later
func coldSetup(ctx context.Context, account hostAccount, sdk string, adb string) (result setupRun, err error) {
	probe := emulator{SDK: sdk, ADB: adb, Serial: "", account: account, process: nil, waitErr: nil, logFile: nil}
	devices, err := probe.run(ctx, adbTimeout, "devices")

	if err != nil {
		return
	}

	for line := range strings.Lines(devices) {
		fields := strings.Fields(line)

		if (len(fields) == 2) && strings.HasPrefix(fields[0], "emulator-") && (fields[1] == "device") {
			return
		}
	}

	_, statErr := os.Stat(filepath.Join(account.Home, ".android", "avd", avdName+".ini"))

	if statErr != nil {
		return
	}

	fmt.Fprintf(os.Stderr, "no emulator runs, decerter android setup --avd %s boots it\n", avdName)
	result = runSetup(ctx, account, sdk, adb, "--avd", avdName, "--package", appPackage)
	result.IsCold = true

	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "decerter android setup failed: %s\n%s%s", result.Err.Error(), result.Output, result.Log)
	}

	return
}

// stop the emulator setup booted and remove its log
func stopBooted(result setupRun) (err error) {
	if result.BootedSerial == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	booted := emulator{SDK: device.SDK, ADB: device.ADB, Serial: result.BootedSerial, account: device.account, process: nil, waitErr: nil, logFile: nil}
	_, err = booted.run(ctx, adbTimeout, "emu", "kill")

	if err != nil {
		return
	}

	err = poll(ctx, func() (isDone bool, pollErr error) {
		devices, pollErr := booted.run(ctx, adbTimeout, "devices")
		isDone = !strings.Contains(devices, result.BootedSerial+"\t")
		return
	})
	err = errors.Join(err, os.Remove(result.BootLog))
	return
}

// the forwards of the device to the api socket a failed case left
func removeAPIForwards(ctx context.Context) (err error) {
	forwards, err := device.run(ctx, adbTimeout, "forward", "--list")

	if err != nil {
		return
	}

	for line := range strings.Lines(forwards) {
		fields := strings.Fields(line)

		if (len(fields) == 3) && (fields[0] == device.Serial) && (fields[2] == apiForward) {
			_, removeErr := device.run(ctx, adbTimeout, "forward", "--remove", fields[1])
			err = errors.Join(err, removeErr)
		}
	}

	return
}

// a command of the host as the invoking user in adb's environment, with ADB set to the tests' adb
func userCommand(ctx context.Context, account hostAccount, sdk string, adb string, name string, arguments ...string) (command *exec.Cmd) {
	command = exec.CommandContext(ctx, name, arguments...)
	command.Env = append(account.environment(sdk), "ADB="+adb)
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Credential: account.Credential}
	command.WaitDelay = time.Second
	return
}

// run a printed command line with sh as the invoking user until it exits or the test ends
func startUserProcess(state *testing.T, commandLine string) (process *userProcess) {
	process = &userProcess{command: nil, stdout: newLockedBuffer(), stderr: newLockedBuffer(), exited: make(chan struct{})}
	process.command = userCommand(state.Context(), device.account, device.SDK, device.ADB, "/bin/sh", "-c", commandLine)
	process.command.Stdout = process.stdout
	process.command.Stderr = process.stderr
	err := process.command.Start()

	if err != nil {
		state.Fatalf("Could not run %s, error: %s", commandLine, err.Error())
	}

	// printed command, its exit status says nothing once the test stopped it
	go func() {
		_ = process.command.Wait()
		close(process.exited)
	}()

	state.Cleanup(func() {
		process.stop(state)
	})

	return
}

// SIGTERM, then wait; once it exited this does nothing
func (process *userProcess) stop(state *testing.T) {
	select {
	case <-process.exited:
		return
	default:
	}

	signalErr := process.command.Process.Signal(syscall.SIGTERM)

	if (signalErr != nil) && !errors.Is(signalErr, os.ErrProcessDone) {
		state.Errorf("Could not stop %s, error: %s", process.command.String(), signalErr.Error())
	}

	process.wait(state)
}

// wait until it exits, killed after readyTimeout
func (process *userProcess) wait(state *testing.T) {
	select {
	case <-process.exited:
	case <-time.After(readyTimeout):
		state.Errorf("%s did not exit, stderr:\n%s", process.command.String(), process.stderr.String())
		killErr := process.command.Process.Kill()

		if (killErr != nil) && !errors.Is(killErr, os.ErrProcessDone) {
			state.Errorf("Could not kill %s, error: %s", process.command.String(), killErr.Error())
		}

		<-process.exited
	}
}

// wait until output has text, failing when the process exits first
func waitText(state *testing.T, name string, output lockedBuffer, exited <-chan struct{}, text string) {
	readyCtx, cancel := context.WithTimeout(state.Context(), readyTimeout)
	defer cancel()
	err := poll(readyCtx, func() (isDone bool, pollErr error) {
		isDone = strings.Contains(output.String(), text)

		if isDone {
			return
		}

		select {
		case <-exited:
			pollErr = fmt.Errorf("%s exited before it printed %q", name, text)
		default:
		}

		return
	})

	if err != nil {
		state.Fatalf("Could not start %s, error: %s, output:\n%s", name, err.Error(), output.String())
	}
}

// the first load of the printed URL sets the cookie and redirects to / without the token
func openUI(state *testing.T, address string) (page uiPage) {
	parsed, err := url.Parse(address)

	if err != nil {
		state.Fatalf("Test of the setup failed, decerter ui should print its URL, output: %q, error: %s", address, err.Error())
	}

	page = uiPage{
		client: &http.Client{
			Timeout: adbTimeout,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		host:   parsed.Host,
		cookie: nil,
	}
	response, err := page.client.Get(address)

	if err != nil {
		state.Fatalf("Could not load the ui, error: %s", err.Error())
	}

	if closeErr := response.Body.Close(); closeErr != nil {
		state.Fatalf("Could not close the answer, error: %s", closeErr.Error())
	}

	cookies := response.Cookies()

	if (response.StatusCode != http.StatusSeeOther) || (len(cookies) != 1) {
		state.Fatalf("Test of the setup failed, the first load of the ui should set the cookie, status: %d, cookies: %v", response.StatusCode, cookies)
	}

	page.cookie = cookies[0]
	return
}

// GET an api path under /api/v1 through the ui the way the page does it
func (page uiPage) get(ctx context.Context, path string, result any) (err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+page.host+v1.BasePath+path, http.NoBody)

	if err != nil {
		return
	}

	request.AddCookie(page.cookie)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response, err := page.client.Do(request)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return
	}

	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("GET %s: status %d: %s", path, response.StatusCode, body)
		return
	}

	err = json.Unmarshal(body, result)
	return
}

// the escaped text of the first message up the flow of the app to the server on port, as the ui's flow list and message view show it
func (page uiPage) waitRequest(ctx context.Context, port string) (request string, err error) {
	requestCtx, cancel := context.WithTimeout(ctx, outputTimeout)
	defer cancel()
	err = poll(requestCtx, func() (isDone bool, pollErr error) {
		flows := v1.FlowList{}
		pollErr = page.get(requestCtx, "/flows", &flows)

		if pollErr != nil {
			return
		}

		index := slices.IndexFunc(flows.Flows, func(flow v1.Flow) (isMatch bool) {
			isMatch = strings.HasSuffix(flow.Destination, ":"+port) && (flow.Process.UID == appUID)
			return
		})

		if index < 0 {
			return
		}

		messages := v1.MessageList{}
		pollErr = page.get(requestCtx, fmt.Sprintf("/flows/%d/messages", flows.Flows[index].ID), &messages)

		if pollErr != nil {
			return
		}

		for _, message := range messages.Messages {
			if message.Direction != v1.UpDirection {
				continue
			}

			detail := v1.MessageDetail{}
			pollErr = page.get(requestCtx, fmt.Sprintf("/messages/%d", message.ID), &detail)
			request, isDone = detail.Payload.Escaped, (pollErr == nil)
			return
		}

		return
	})
	return
}
