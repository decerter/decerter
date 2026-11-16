// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e_android

package android_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// how long decerter may take to attach, to print a line or a secret, and to stop and put netd's hooks back
	readyTimeout  time.Duration = 30 * time.Second
	outputTimeout time.Duration = 15 * time.Second
	// app_process starts ART first, an HTTPS call takes one to two seconds
	dexTimeout string = "30"
	// a UDP session and its flow line end after this long without a datagram, instead of decerter's default 30 s
	udpIdleTimeout string = "2s"
)

// a decerter running in the background on the device, its stdout goes to <name>.out and its stderr to <name>.log in deviceDirectory
type deviceDecerter struct {
	Binary string
	Name   string
}

// Test if decerter run redirects the TCP and UDP flows of the app uid to the host, the client sees the original peer, and decerter prints a flow line for each.
func TestRedirectPositive(state *testing.T) {
	guardDevice(state)
	tcpPort, udpPort := startEchoServers(state)
	decerter := startDeviceDecerter(state, decerterBinary, "redirect", "run --udp-idle-timeout "+udpIdleTimeout+" --uid "+strconv.FormatUint(uint64(appUID), 10)+" --dst-cidr "+hostCIDR, redirectReady)

	for _, protocol := range []string{"tcp", "udp"} {
		port := map[string]string{"tcp": tcpPort, "udp": udpPort}[protocol]
		err := testEcho(state.Context(), appUID, protocol, port)

		if err != nil {
			state.Errorf("Test of the redirect failed, protocol: %s, error: %s", protocol, err.Error())
			continue
		}

		// a UDP flow line comes when the session is idle for udpIdleTimeout
		_, err = decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
			isFound = hasFlowLine(output, protocol, appUID, port)
			return
		})

		if err != nil {
			state.Errorf("Test of the redirect failed, no %s flow line of uid %d to port %s, error: %s", protocol, appUID, port, err.Error())
		}
	}

	stopDeviceDecerter(state, decerter, true)
}

// Test if decerter run leaves the flows of a uid it does not select alone: shell's TCP and UDP reach the host directly and get no flow line.
func TestRedirectNegative(state *testing.T) {
	guardDevice(state)
	tcpPort, udpPort := startEchoServers(state)
	decerter := startDeviceDecerter(state, decerterBinary, "redirect-negative", "run --udp-idle-timeout "+udpIdleTimeout+" --uid "+strconv.FormatUint(uint64(appUID), 10)+" --dst-cidr "+hostCIDR, redirectReady)

	for _, protocol := range []string{"tcp", "udp"} {
		port := map[string]string{"tcp": tcpPort, "udp": udpPort}[protocol]
		err := testEcho(state.Context(), shellUID, protocol, port)

		if err != nil {
			state.Errorf("Test of the redirect failed, protocol: %s, error: %s", protocol, err.Error())
		}
	}

	// the app's UDP flow is a marker: once its line is there, a line of shell's flows would be there too
	err := testEcho(state.Context(), appUID, "udp", udpPort)

	if err != nil {
		state.Fatalf("Test of the redirect failed, marker flow, error: %s", err.Error())
	}

	output, waitErr := decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
		isFound = hasFlowLine(output, "udp", appUID, udpPort)
		return
	})

	if waitErr != nil {
		state.Fatalf("Test of the redirect failed, no flow line of the marker, error: %s", waitErr.Error())
	}

	if strings.Contains(output, " uid="+strconv.FormatUint(uint64(shellUID), 10)+" ") {
		state.Errorf("Test of the redirect failed, shell's flows should have no flow line, output:\n%s", output)
	}

	stopDeviceDecerter(state, decerter, true)
}

// Test if decerter run --decrypt --package prints the request line of a Conscrypt call over TLS 1.3 and TLS 1.2, which reaches the server unchanged.
func TestDecryptPositive(state *testing.T) {
	requireDex(state)
	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "decrypt", "run --decrypt --package "+appPackage+" --dst-cidr "+hostCIDR, redirectReady)

	for _, server := range servers {
		err := testDex(state.Context(), appUID, server, "/decrypt", "/decrypt")

		if err != nil {
			state.Errorf("Test of the decryption failed, error: %s", err.Error())
			continue
		}

		_, err = decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
			isFound = hasDecryptedRequest(output, server, `GET /decrypt HTTP/1.1\r\n`)
			return
		})

		if err != nil {
			state.Errorf("Test of the decryption failed, no decrypted request to port %s, error: %s", server.Port, err.Error())
		}
	}

	checkSelectedPackage(state, decerter)
	stopDeviceDecerter(state, decerter, true)
}

// Test if decerter keylog prints exactly the key log lines the host server wrote for the app's TLS 1.3 and TLS 1.2 sessions.
func TestKeylogPositive(state *testing.T) {
	requireDex(state)
	serverKeyLog := newLockedBuffer()
	servers := startHTTPSServers(state, serverKeyLog)
	decerter := startDeviceDecerter(state, decerterBinary, "keylog", "keylog --package "+appPackage, keylogReady)

	for _, server := range servers {
		err := testDex(state.Context(), appUID, server, "/keylog", "/keylog")

		if err != nil {
			state.Fatalf("Test of the key log failed, error: %s", err.Error())
		}
	}

	expected := keyLogLines(serverKeyLog.String())

	if len(expected) == 0 {
		state.Fatalf("Test of the key log failed, the server wrote no key log")
	}

	output, err := decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
		isFound = isSubset(expected, keyLogLines(output))
		return
	})

	if err != nil {
		state.Errorf("Test of the key log failed, decerter should print every line of the server, server:\n%sdecerter:\n%s", serverKeyLog.String(), output)
	}

	stopDeviceDecerter(state, decerter, false)
	output, err = decerter.output(state.Context())

	if err != nil {
		state.Fatalf("Could not read the output of decerter, error: %s", err.Error())
	}

	if !isSubset(keyLogLines(output), expected) {
		state.Errorf("Test of the key log failed, decerter printed lines the server did not write, server:\n%sdecerter:\n%s", serverKeyLog.String(), output)
	}
}

// Test if decerter keylog prints no secret of a uid it does not select.
func TestKeylogNegative(state *testing.T) {
	requireDex(state)
	serverKeyLog := newLockedBuffer()
	servers := startHTTPSServers(state, serverKeyLog)
	decerter := startDeviceDecerter(state, decerterBinary, "keylog-negative", "keylog --package "+appPackage, keylogReady)

	for _, server := range servers {
		err := testDex(state.Context(), shellUID, server, "/keylog", "/keylog")

		if err != nil {
			state.Fatalf("Test of the key log failed, error: %s", err.Error())
		}
	}

	// the app's session is a marker: once its lines are there, lines of shell's sessions would be there too
	shellLines := keyLogLines(serverKeyLog.String())
	err := testDex(state.Context(), appUID, servers[0], "/keylog", "/keylog")

	if err != nil {
		state.Fatalf("Test of the key log failed, marker session, error: %s", err.Error())
	}

	markerLines := slices.DeleteFunc(keyLogLines(serverKeyLog.String()), func(line string) (isShell bool) {
		isShell = slices.Contains(shellLines, line)
		return
	})
	output, err := decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
		isFound = isSubset(markerLines, keyLogLines(output))
		return
	})

	if err != nil {
		state.Fatalf("Test of the key log failed, no lines of the marker session, error: %s", err.Error())
	}

	for _, line := range keyLogLines(output) {
		if slices.Contains(shellLines, line) {
			state.Errorf("Test of the key log failed, decerter printed a secret of shell's sessions: %s", line)
		}
	}

	stopDeviceDecerter(state, decerter, false)
}

// Test if tshark on the host finds the decrypted requests of the app's TLS 1.3 and TLS 1.2 calls in decerter capture -w - streamed over adb exec-out,
// and decerter stops and puts netd's hooks back once its adb exec-out is gone.
func TestCapturePositive(state *testing.T) {
	requireDex(state)

	if tsharkSkipReason != "" {
		state.Skip(tsharkSkipReason)
	}

	servers := startHTTPSServers(state, nil)
	tsharkOutput := startCapture(state, servers, appPackage)

	for _, server := range servers {
		err := testDex(state.Context(), appUID, server, "/capture", "/capture")

		if err != nil {
			state.Errorf("Test of the capture failed, error: %s", err.Error())
		}
	}

	// tshark prints a request once it has the packets and the secrets of its session
	output, err := tsharkOutput.wait(state.Context(), func(output string) (isFound bool) {
		isFound = true

		for _, server := range servers {
			isFound = isFound && slices.Contains(strings.Split(output, "\n"), server.Port+"\tGET\t/capture")
		}

		return
	})

	state.Logf("tshark printed:\n%s", output)

	if err != nil {
		state.Errorf("Test of the capture failed, tshark should find GET /capture to ports %s and %s, output:\n%s", servers[0].Port, servers[1].Port, output)
	}

	// the reader leaves: decerter stops at the next write or when the pty closes, and puts netd's hooks back
	tsharkOutput.stop(state)
	decerter := deviceDecerter{Binary: decerterBinary, Name: "capture"}
	err = decerter.waitStopped(state.Context())

	if err != nil {
		state.Fatalf("Test of the capture failed, decerter should stop once adb exec-out is gone, error: %s", err.Error())
	}

	checkRestored(state, decerter)
}

// Test if decerter android restore puts netd's hooks back after decerter run was killed with SIGKILL while it shared them.
func TestRestorePositive(state *testing.T) {
	guardDevice(state)
	decerter := startDeviceDecerter(state, decerterBinary, "restore", "run --package "+appPackage+" --dst-cidr "+hostCIDR, redirectReady)
	shared, err := attachList(state.Context())

	if err != nil {
		state.Fatalf("Could not query the attach list, error: %s", err.Error())
	}

	if shared == baseline {
		state.Fatalf("Test of the restore failed, decerter run should have shared netd's hooks, attach list:\n%s", shared)
	}

	_, err = device.shell(state.Context(), "kill -9 $(pidof "+decerter.Binary+")")

	if err != nil {
		state.Fatalf("Could not kill decerter, error: %s", err.Error())
	}

	err = decerter.waitStopped(state.Context())

	if err != nil {
		state.Fatalf("Test of the restore failed, decerter should be gone after kill -9, error: %s", err.Error())
	}

	isLeftOver, stateErr := deviceFileExists(state.Context(), netdStatePath)

	if (stateErr != nil) || !isLeftOver {
		state.Fatalf("Test of the restore failed, the killed decerter should leave %s, error: %v", netdStatePath, stateErr)
	}

	output, restoreErr := device.shell(state.Context(), deviceDirectory+"/"+decerterBinary+" android restore 2>&1")

	if restoreErr != nil {
		state.Fatalf("Test of the restore failed, error: %s", restoreErr.Error())
	}

	if !strings.Contains(output, restoredLog) {
		state.Errorf("Test of the restore failed, decerter android restore should log %s, output:\n%s", restoredLog, output)
	}

	checkPristine(state)
}

// Test if decerter android restore changes nothing when no decerter left netd's hooks shared.
func TestRestoreNegative(state *testing.T) {
	guardDevice(state)
	output, err := device.shell(state.Context(), deviceDirectory+"/"+decerterBinary+" android restore 2>&1")

	if err != nil {
		state.Fatalf("Test of the restore failed, error: %s", err.Error())
	}

	if !strings.Contains(output, `"msg":"No netd hook state, nothing to restore"`) {
		state.Errorf("Test of the restore failed, decerter android restore should find nothing to restore, output:\n%s", output)
	}

	checkPristine(state)
}

// decerter resolved --package to the app's uid, the one pm lists
func checkSelectedPackage(state *testing.T, decerter deviceDecerter) {
	log, err := decerter.log(state.Context())

	if err != nil {
		state.Fatalf("Could not read the log of %s, error: %s", decerter.Binary, err.Error())
	}

	selected := fmt.Sprintf(`"msg":"Selected package","package":%q,"uid":%d}`, appPackage, appUID)

	if !strings.Contains(log, selected) {
		state.Errorf("%s should log %s, log:\n%s", decerter.Binary, selected, log)
	}
}

// skip without a device, then compare the attach list with the baseline when the test ends, after a decerter that is still running was stopped and netd's hooks were restored
// it is the first cleanup of a test and so runs last, also when the test failed
func guardDevice(state *testing.T) {
	requireDevice(state)

	state.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
		defer cancel()
		err := cleanDevice(ctx)

		if err != nil {
			state.Errorf("Could not clean up the device, error: %s", err.Error())
		}

		list, listErr := attachList(ctx)

		if listErr != nil {
			state.Errorf("Could not query the attach list, error: %s", listErr.Error())
			return
		}

		if list != baseline {
			state.Errorf("The attach list of /sys/fs/cgroup changed, before:\n%safter:\n%s", baseline, list)
		}
	})
}

// the device and the dex
func requireDex(state *testing.T) {
	guardDevice(state)

	if dexSkipReason != "" {
		state.Skip(dexSkipReason)
	}
}

// stop every decerter of the tests with SIGTERM, SIGKILL if it hangs, and restore netd's hooks if one was killed
func cleanDevice(ctx context.Context) (err error) {
	for _, binary := range []string{decerterBinary} {
		decerter := deviceDecerter{Binary: binary, Name: ""}
		isRunning, runningErr := decerter.isRunning(ctx)

		if err = runningErr; (err != nil) || !isRunning {
			continue
		}

		_, err = device.shell(ctx, "kill -TERM $(pidof "+binary+")")

		if err == nil {
			err = decerter.waitStopped(ctx)
		}

		if err != nil {
			_, err = device.shell(ctx, "kill -9 $(pidof "+binary+")")
			err = errors.Join(err, decerter.waitStopped(ctx))
		}

		if err != nil {
			return
		}
	}

	isLeftOver, stateErr := deviceFileExists(ctx, netdStatePath)

	if err = stateErr; (err != nil) || !isLeftOver {
		return
	}

	_, err = device.shell(ctx, deviceDirectory+"/"+decerterBinary+" android restore")
	return
}

// start binary with arguments in the background and wait until it logged ready; setsid keeps it alive when the adb shell ends
func startDeviceDecerter(state *testing.T, binary string, name string, arguments string, ready string) (decerter deviceDecerter) {
	decerter = deviceDecerter{Binary: binary, Name: name}
	// the & has to cover only decerter: a backgrounded list would hold adb's stdout until decerter exits
	command := fmt.Sprintf("cd %s && rm -f %s.out %s.log && (setsid ./%s %s </dev/null >%s.out 2>%s.log &)", deviceDirectory, name, name, binary, arguments, name, name)
	_, err := device.shell(state.Context(), command)

	if err != nil {
		state.Fatalf("Could not start %s on the device, error: %s", binary, err.Error())
	}

	readyCtx, cancel := context.WithTimeout(state.Context(), readyTimeout)
	defer cancel()
	log := ""
	err = poll(readyCtx, func() (isDone bool, pollErr error) {
		log, pollErr = decerter.log(readyCtx)

		if (pollErr != nil) || strings.Contains(log, ready) {
			isDone = true
			return
		}

		isRunning, runningErr := decerter.isRunning(readyCtx)

		if (runningErr == nil) && !isRunning {
			pollErr = fmt.Errorf("%s exited", binary)
		}

		return
	})

	if err != nil {
		state.Fatalf("Could not start %s on the device, error: %s, log:\n%s", binary, err.Error(), log)
	}

	return
}

// stop the decerter with SIGTERM and check that it put netd's hooks back, isSharing is false for keylog, which attaches no cgroup hook
func stopDeviceDecerter(state *testing.T, decerter deviceDecerter, isSharing bool) {
	_, err := device.shell(state.Context(), "kill -TERM $(pidof "+decerter.Binary+")")

	if err != nil {
		state.Fatalf("Could not stop %s, error: %s", decerter.Binary, err.Error())
	}

	err = decerter.waitStopped(state.Context())

	if err != nil {
		state.Fatalf("Could not stop %s, error: %s", decerter.Binary, err.Error())
	}

	if isSharing {
		checkRestored(state, decerter)
		return
	}

	checkPristine(state)
}

// the decerter put back every netd hook it shared, removed its state file, and the attach list is the baseline
func checkRestored(state *testing.T, decerter deviceDecerter) {
	log, err := decerter.log(state.Context())

	if err != nil {
		state.Fatalf("Could not read the log of %s, error: %s", decerter.Binary, err.Error())
	}

	// every hook it shared, and at least one: the redirect and the capture need hooks netd holds
	shared := strings.Count(log, sharedLog)

	if (shared == 0) || (strings.Count(log, stoppedLog) != shared) {
		state.Errorf("%s should log %s for each %s when it stops, log:\n%s", decerter.Binary, stoppedLog, sharedLog, log)
	}

	checkPristine(state)
}

// no netd state file and the attach list is the baseline
func checkPristine(state *testing.T) {
	isLeftOver, err := deviceFileExists(state.Context(), netdStatePath)

	if err != nil {
		state.Fatalf("Could not look for the netd state file, error: %s", err.Error())
	}

	if isLeftOver {
		state.Errorf("%s should be gone", netdStatePath)
	}

	list, listErr := attachList(state.Context())

	if listErr != nil {
		state.Fatalf("Could not query the attach list, error: %s", listErr.Error())
	}

	if list != baseline {
		state.Errorf("The attach list of /sys/fs/cgroup is not the baseline, before:\n%safter:\n%s", baseline, list)
	}
}

func (decerter deviceDecerter) isRunning(ctx context.Context) (isRunning bool, err error) {
	output, shellErr := device.shell(ctx, "pidof "+decerter.Binary+" || true")

	if err = shellErr; err != nil {
		return
	}

	isRunning = (strings.TrimSpace(output) != "")
	return
}

func (decerter deviceDecerter) waitStopped(ctx context.Context) (err error) {
	stopCtx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	err = poll(stopCtx, func() (isDone bool, pollErr error) {
		isRunning, pollErr := decerter.isRunning(stopCtx)
		isDone = !isRunning
		return
	})
	return
}

func (decerter deviceDecerter) output(ctx context.Context) (output string, err error) {
	output, err = device.shell(ctx, "cat "+deviceDirectory+"/"+decerter.Name+".out")
	return
}

func (decerter deviceDecerter) log(ctx context.Context) (log string, err error) {
	log, err = device.shell(ctx, "cat "+deviceDirectory+"/"+decerter.Name+".log")
	return
}

// wait until the stdout of decerter passes check, output is the last one read
func (decerter deviceDecerter) waitOutput(ctx context.Context, check func(output string) (isFound bool)) (output string, err error) {
	outputCtx, cancel := context.WithTimeout(ctx, outputTimeout)
	defer cancel()
	err = poll(outputCtx, func() (isDone bool, pollErr error) {
		current, outputErr := decerter.output(outputCtx)

		// a cat cut off by the deadline must not hide what was read before
		if outputErr == nil {
			output = current
			isDone = check(output)
		}

		return
	})

	if err != nil {
		err = fmt.Errorf("%w, output:\n%s", err, output)
	}

	return
}

// a flow line of protocol from uid to the host server on port: tcp pid=… uid=… comm=… 10.0.2.2:port client=…
func hasFlowLine(output string, protocol string, uid uint32, port string) (isFound bool) {
	for line := range strings.Lines(output) {
		if strings.HasPrefix(line, protocol+" ") && strings.Contains(line, " uid="+strconv.FormatUint(uint64(uid), 10)+" ") && strings.Contains(line, " "+net.JoinHostPort(hostAddress, port)+" ") {
			isFound = true
			return
		}
	}

	return
}

// the escaped request line as the first line of a client record decrypted from the flow to the server, with the server's TLS version:
// tls pid=… uid=… comm=… 10.0.2.2:port client=… version=TLS1.3 suite=… direction=up sequence=… then the plaintext indented
func hasDecryptedRequest(output string, server httpsServer, request string) (isFound bool) {
	version := map[uint16]string{tls.VersionTLS13: "version=TLS1.3", tls.VersionTLS12: "version=TLS1.2"}[server.MaxVersion]
	isRecord := false

	for line := range strings.Lines(output) {
		if isRecord && (strings.TrimSpace(line) == request) {
			isFound = true
			return
		}

		isRecord = strings.HasPrefix(line, "tls ") && strings.Contains(line, " "+net.JoinHostPort(hostAddress, server.Port)+" ") && strings.Contains(line, " "+version+" ") && strings.Contains(line, " direction=up ")
	}

	return
}

// run the client as uid against the echo server on port: the answer has to be the echoed line from the original peer
func testEcho(ctx context.Context, uid uint32, protocol string, port string) (err error) {
	line := fmt.Sprintf("decerter android e2e %s uid %d", protocol, uid)
	peer := net.JoinHostPort(hostAddress, port)
	output, err := device.shell(ctx, fmt.Sprintf("su %d,%d,%d %s/%s %s %s '%s'", uid, uid, inetGroup, deviceDirectory, clientBinary, protocol, peer, line))

	if err != nil {
		return
	}

	expected := fmt.Sprintf("peer=%s answer=%q\n", peer, echoPrefix+line+"\n")

	if output != expected {
		err = fmt.Errorf("client output should be %q, output: %q", expected, output)
	}

	return
}

// run the dex as uid against path on the server: the body and what the server received have to be expected, with the server's TLS version
func testDex(ctx context.Context, uid uint32, server httpsServer, path string, expected string) (err error) {
	err = testDexSuite(ctx, uid, server, "server_rsa", path, expected, expected)
	return
}

// run the dex as uid against path on the server, trusting the certificate of assets: the server has to receive receivedPath over its TLS version and
// suite, and the dex has to print the suite of a pinned server and the body
func testDexSuite(ctx context.Context, uid uint32, server httpsServer, certificate string, path string, receivedPath string, body string) (err error) {
	command := fmt.Sprintf("su %d,%d,%d timeout %s app_process -Djava.class.path=%s/%s /system/bin DecerterHttps %s %s/%s 2>&1", uid, uid, inetGroup, dexTimeout, deviceDirectory, dexName, server.url(path), deviceDirectory, caFile(certificate))
	output, err := device.shell(ctx, command)

	if err != nil {
		return
	}

	lines := strings.Split(output, "\n")

	if !slices.Contains(lines, "body "+body) || ((server.CipherSuite != 0) && !slices.Contains(lines, "status 200 cipher "+tls.CipherSuiteName(server.CipherSuite))) {
		err = fmt.Errorf("the dex should get the body %q from port %s over %s, output:\n%s", body, server.Port, suiteName(server.CipherSuite), output)
		return
	}

	request, receivedErr := server.received()

	if err = receivedErr; err != nil {
		return
	}

	err = server.check(request, receivedPath)
	return
}

// the NSS key log lines of a text, without empty lines
func keyLogLines(text string) (lines []string) {
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)

		if line != "" {
			lines = append(lines, line)
		}
	}

	return
}

func isSubset(subset []string, set []string) (isContained bool) {
	isContained = true

	for _, line := range subset {
		isContained = isContained && slices.Contains(set, line)
	}

	return
}

// tshark reading decerter capture -w - from adb exec-out: output is what it printed so far
type liveCapture struct {
	adb    *exec.Cmd
	tshark *exec.Cmd
	output lockedBuffer
	errors lockedBuffer
}

// start adb exec-out with decerter capture --package packageName on the device and tshark on the host reading its stdout, and wait until decerter captures
// adb exec-out gives decerter a pty for stdout and stderr, so its stderr goes to capture.log on the device
func startCapture(state *testing.T, servers []httpsServer, packageName string) (capture *liveCapture) {
	capture = startCaptureWith(state, servers, "--package "+packageName)
	return
}

// startCapture with the selection and options of arguments
func startCaptureWith(state *testing.T, servers []httpsServer, arguments string) (capture *liveCapture) {
	reader, writer, pipeErr := os.Pipe()

	if pipeErr != nil {
		state.Fatalf("Could not create the capture pipe, error: %s", pipeErr.Error())
	}

	capture = &liveCapture{output: newLockedBuffer(), errors: newLockedBuffer()}
	decerter := deviceDecerter{Binary: decerterBinary, Name: "capture"}
	command := fmt.Sprintf("cd %s && rm -f capture.log && exec ./%s capture -w - %s --dst-cidr %s 2>%s/capture.log", deviceDirectory, decerterBinary, arguments, hostCIDR, deviceDirectory)
	capture.adb = device.execOut(state.Context(), command)
	capture.adb.Stdout = writer
	capture.adb.Stderr = capture.errors
	tsharkArguments := []string{"-l", "-n", "-i", "-"}

	for _, server := range servers {
		tsharkArguments = append(tsharkArguments, "-d", "tcp.port=="+server.Port+",tls")
	}

	tsharkArguments = append(tsharkArguments, "-Y", "http.request", "-T", "fields", "-E", "separator=/t", "-e", "tcp.dstport", "-e", "http.request.method", "-e", "http.request.uri")
	capture.tshark = exec.CommandContext(state.Context(), tsharkPath, tsharkArguments...)
	capture.tshark.Stdin = reader
	capture.tshark.Stdout = capture.output
	capture.tshark.Stderr = capture.errors
	capture.tshark.WaitDelay = time.Second
	tsharkErr := capture.tshark.Start()
	adbErr := capture.adb.Start()
	closeErr := errors.Join(reader.Close(), writer.Close())

	if err := errors.Join(tsharkErr, adbErr, closeErr); err != nil {
		state.Fatalf("Could not start the capture, error: %s", err.Error())
	}

	state.Cleanup(func() {
		capture.stop(state)
	})

	readyCtx, cancel := context.WithTimeout(state.Context(), readyTimeout)
	defer cancel()
	log := ""
	err := poll(readyCtx, func() (isDone bool, pollErr error) {
		log, pollErr = decerter.log(readyCtx)
		isDone = (pollErr == nil) && strings.Contains(log, captureReady)
		pollErr = nil
		return
	})

	if err != nil {
		state.Fatalf("Could not start the capture on the device, error: %s, log:\n%s, adb and tshark:\n%s", err.Error(), log, capture.errors.String())
	}

	return
}

// kill adb exec-out, which ends tshark's input, and wait for both; a second call does nothing
func (capture *liveCapture) stop(state *testing.T) {
	if capture.adb.ProcessState != nil {
		return
	}

	killErr := capture.adb.Process.Kill()

	if (killErr != nil) && !errors.Is(killErr, os.ErrProcessDone) {
		state.Errorf("Could not kill adb exec-out, error: %s", killErr.Error())
	}

	// the exit status of a killed adb says nothing, tshark ends at the end of its input
	_ = capture.adb.Wait()
	waitErr := capture.tshark.Wait()

	if waitErr != nil {
		state.Errorf("tshark failed, error: %s, output:\n%s", waitErr.Error(), capture.errors.String())
	}
}

// wait until tshark's output passes check
func (capture *liveCapture) wait(ctx context.Context, check func(output string) (isFound bool)) (output string, err error) {
	outputCtx, cancel := context.WithTimeout(ctx, outputTimeout)
	defer cancel()
	err = poll(outputCtx, func() (isDone bool, pollErr error) {
		output = capture.output.String()
		isDone = check(output)
		return
	})
	return
}
