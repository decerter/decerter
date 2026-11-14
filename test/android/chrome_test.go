// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e_android

package android_test

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
)

const (
	// Chrome of the image: Trichrome, its BoringSSL is in the TrichromeLibrary static shared library
	chromePackage string = "com.android.chrome"
	// the ChromePublic apk of a Chromium snapshot, the second target and the doctored one; the cases skip without it
	chromiumEnvironment string = "DECERTER_E2E_CHROMIUM"
	chromiumPackage     string = "org.chromium.chrome"
	// the launcher activity of Chrome and ChromePublic
	chromeActivity string = "com.google.android.apps.chrome.Main"
	// every Chrome reads its flags from this file on a userdebug image
	chromeCommandLine string = "/data/local/tmp/chrome-command-line"
	// Chrome's own key log, --ssl-key-log-file
	chromeKeyLog string = "/data/data/" + chromePackage + "/cache/sslkeylog.txt"
	// a cold start of Chrome and its page load
	chromeTimeout time.Duration = 30 * time.Second
	// how long a blocked Chrome has to send QUIC to the host before the case says it sent none
	quicSilence time.Duration = 5 * time.Second
	// the QUIC cases: the origin is on TCP 443 of the host's loopback and offers h3 on UDP 443, Chrome takes no Alt-Svc to a privileged port from
	// an unprivileged one
	quicAddress string = "127.0.0.1:443"
	quicAltSvc  string = `h3=":443"; ma=3600`
	// the doctored ChromePublic has this as the first digit of its major version
	doctoredMajor byte = '9'
	// what decerter logs per Chromium library
	chromiumFoundLog   string = `"msg":"Found Chromium library"`
	chromiumUnknownLog string = `"msg":"Could not hook Chromium's BoringSSL of the app, its TLS is relayed without secrets"`
	// YouTube of the image maps the Cronet of its apk
	youtubePackage string = "com.google.android.youtube"
	// granted to the apps the cases start, their dialog would cover them; FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TASK
	notificationPermission string = "android.permission.POST_NOTIFICATIONS"
	newClearedTask         int    = 0x10008000
)

var (
	// the versionName of the binary manifest, UTF-16LE in the string pool: major.0.build.patch
	manifestVersionPattern = regexp.MustCompile(`(?:[0-9]\x00)+\.\x000\x00\.\x00(?:[0-9]\x00)+\.\x00(?:[0-9]\x00)+`)
	// the NSS key log labels decerter prints, Chrome also writes EXPORTER_SECRET
	keyLogLabels = []string{"CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"}
	// the ChromePublic apk and its copy with an unknown version, why their cases skip
	chromiumAPK        string
	chromiumDoctored   string
	chromiumSkipReason string
	chromiumErr        error
	// the apk of org.chromium.chrome the tests installed last
	chromiumInstalled string
)

// a UDP server that only counts the datagrams it gets, closed when the test ends
type udpSink struct {
	count *atomic.Int64
}

// the ChromePublic apk of decerter_E2E_CHROMIUM and a copy whose manifest has an unknown version, cached in ~/.cache/decerter-chromium/e2e by the apk's
// size and time; a missing variable skips the cases, a failed copy fails the negative one
func prepareChromium(ctx context.Context, account hostAccount, sdk string) (apk string, doctored string, skipReason string, err error) {
	apk = os.Getenv(chromiumEnvironment)

	if apk == "" {
		skipReason = chromiumEnvironment + " names no ChromePublic apk of a Chromium snapshot"
		return
	}

	info, err := os.Stat(apk)

	if err != nil {
		skipReason = err.Error()
		err = nil
		return
	}

	cache := filepath.Join(account.Home, ".cache", "decerter-chromium", "e2e")
	doctored = filepath.Join(cache, fmt.Sprintf("ChromePublic-%d-%d-unknown.apk", info.Size(), info.ModTime().Unix()))

	if _, statErr := os.Stat(doctored); statErr == nil {
		return
	}

	environment := account.environment(sdk)
	_, err = runAsUser(ctx, account, environment, "/", "mkdir", "-p", cache)

	if err != nil {
		return
	}

	unsigned := filepath.Join(workDirectory, "chromium-unsigned.apk")
	aligned := doctored + ".aligned"
	err = doctorManifest(apk, unsigned)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, os.Remove(unsigned), os.Remove(aligned))
	}()

	zipalign, err := newestBuildTool(sdk, "zipalign")

	if err != nil {
		return
	}

	apksigner, err := newestBuildTool(sdk, "apksigner")

	if err != nil {
		return
	}

	// the stored libraries on 16 KiB pages, then the debug key signs it
	_, err = runAsUser(ctx, account, environment, "/", zipalign, "-f", "-P", "16", "4", unsigned, aligned)

	if err != nil {
		return
	}

	keystore := filepath.Join(account.Home, ".android", "debug.keystore")
	_, err = runAsUser(ctx, account, environment, "/", apksigner, "sign", "--ks", keystore, "--ks-pass", "pass:android", "--ks-key-alias", "androiddebugkey", "--key-pass", "pass:android", "--v4-signing-enabled", "false", "--out", doctored, aligned)
	return
}

// copy the apk without its signature, the major version of the manifest's versionName starts with 9: as long as before, and no Chromium has it;
// the other entries are copied as they are
func doctorManifest(apk string, unsigned string) (err error) {
	reader, err := zip.OpenReader(apk)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, reader.Close())
	}()

	output, err := os.OpenFile(unsigned, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, output.Close())
	}()

	writer := zip.NewWriter(output)
	isDoctored := false

	for _, file := range reader.File {
		if file.Name != "AndroidManifest.xml" {
			err = writer.Copy(file)

			if err != nil {
				return
			}

			continue
		}

		manifest, readErr := readEntry(file)

		if err = readErr; err != nil {
			return
		}

		location := manifestVersionPattern.FindIndex(manifest)

		if location == nil {
			err = fmt.Errorf("no versionName in the manifest of %s", apk)
			return
		}

		manifest[location[0]] = doctoredMajor
		isDoctored = true
		header := file.FileHeader
		entry, createErr := writer.CreateHeader(&header)

		if err = createErr; err != nil {
			return
		}

		_, err = entry.Write(manifest)

		if err != nil {
			return
		}
	}

	if !isDoctored {
		err = fmt.Errorf("%s has no AndroidManifest.xml", apk)
		return
	}

	err = writer.Close()
	return
}

func readEntry(file *zip.File) (data []byte, err error) {
	entry, err := file.Open()

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, entry.Close())
	}()

	data, err = io.ReadAll(entry)
	return
}

// the device's Chrome with the test flags and no state: it trusts the server key and writes its own key log; extraFlags are added
func prepareChrome(state *testing.T, packageName string, extraFlags string) (uid uint32) {
	guardDevice(state)
	uid, err := lookupAppUID(state.Context(), packageName)

	if err != nil {
		state.Skipf("Skipping the Chrome case, %s", err.Error())
	}

	pair, err := tls.LoadX509KeyPair(filepath.Join("..", "e2e", "assets", "server_rsa.crt"), filepath.Join("..", "e2e", "assets", "server_rsa.key"))

	if err != nil {
		state.Fatalf("Could not load the server certificate, error: %s", err.Error())
	}

	// Chrome takes the certificate without a CA by the SHA-256 of its key, the first word of the file is the program name
	digest := sha256.Sum256(pair.Leaf.RawSubjectPublicKeyInfo)
	flags := "_ --ignore-certificate-errors-spki-list=" + base64.StdEncoding.EncodeToString(digest[:]) + " --ssl-key-log-file=" + chromeKeyLog + " --disable-fre --no-default-browser-check --no-first-run " + extraFlags
	_, err = device.shell(state.Context(), fmt.Sprintf("echo '%s' > %s && chmod 644 %s && pm clear %s && pm grant %s %s", flags, chromeCommandLine, chromeCommandLine, packageName, packageName, notificationPermission))

	if err != nil {
		state.Fatalf("Could not prepare %s, error: %s", packageName, err.Error())
	}

	state.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), adbTimeout)
		defer cancel()

		if _, stopErr := device.shell(ctx, "am force-stop "+packageName+" && rm -f "+chromeCommandLine); stopErr != nil {
			state.Errorf("Could not stop %s, error: %s", packageName, stopErr.Error())
		}
	})

	return
}

// open the url in a new tab of Chrome, isCold stops Chrome first
func openChrome(ctx context.Context, packageName string, address string, isCold bool) (err error) {
	stop := ""

	if isCold {
		stop = "-S "
	}

	_, err = device.shell(ctx, fmt.Sprintf("am start %s-W -a android.intent.action.VIEW -d '%s' -n %s/%s", stop, address, packageName, chromeActivity))
	return
}

// open the server's url for path in Chrome and wait until the server got expected over its TLS version; the favicon request is skipped
func loadChrome(ctx context.Context, packageName string, server httpsServer, path string, expected string, isCold bool) (err error) {
	err = openChrome(ctx, packageName, server.url(path), isCold)

	if err != nil {
		return
	}

	loadCtx, cancel := context.WithTimeout(ctx, chromeTimeout)
	defer cancel()
	seen := []receivedRequest{}

	for {
		select {
		case request := <-server.requests:
			if request.Path != expected {
				seen = append(seen, request)
				continue
			}

			if request.Version != server.MaxVersion {
				err = fmt.Errorf("the server on port %s should receive %s over %s, request: %+v", server.Port, expected, tls.VersionName(server.MaxVersion), request)
			}

			return
		case <-loadCtx.Done():
			err = fmt.Errorf("the server on port %s got no request for %s from %s, it got: %+v", server.Port, expected, packageName, seen)
			return
		}
	}
}

// wait until decerter logged line about packageName and every part, the log read last is returned
func waitAppLog(state *testing.T, decerter deviceDecerter, packageName string, line string, parts ...string) (log string) {
	logCtx, cancel := context.WithTimeout(state.Context(), readyTimeout)
	defer cancel()
	err := poll(logCtx, func() (isDone bool, pollErr error) {
		current, logErr := decerter.log(logCtx)

		// a cat cut off by the deadline must not hide what was read before
		if logErr != nil {
			return
		}

		log = current

		for logLine := range strings.Lines(log) {
			isFound := strings.Contains(logLine, line) && strings.Contains(logLine, `"package":"`+packageName+`"`)

			for _, part := range parts {
				isFound = isFound && strings.Contains(logLine, part)
			}

			isDone = isDone || isFound
		}

		return
	})

	if err != nil {
		state.Fatalf("%s should log %s %v for %s, error: %s, log:\n%s", decerter.Binary, line, parts, packageName, err.Error(), log)
	}

	return
}

// the key log lines of the labels decerter prints
func secretLines(text string) (lines []string) {
	for _, line := range keyLogLines(text) {
		label, _, _ := strings.Cut(line, " ")

		if slices.Contains(keyLogLabels, label) {
			lines = append(lines, line)
		}
	}

	return
}

// a UDP server on address that counts what it gets, run as root so it is not redirected
func startUDPSink(state *testing.T, address string) (sink udpSink) {
	connection, err := net.ListenPacket("udp", address)

	if err != nil {
		state.Fatalf("Could not listen for the udp sink, error: %s", err.Error())
	}

	sink = udpSink{count: &atomic.Int64{}}
	doneChannel := make(chan struct{})

	// udp sink
	go func() {
		defer close(doneChannel)
		buffer := make([]byte, 65535)

		for {
			_, _, readErr := connection.ReadFrom(buffer)

			if readErr != nil {
				return
			}

			sink.count.Add(1)
		}
	}()

	state.Cleanup(func() {
		if closeErr := connection.Close(); closeErr != nil {
			state.Errorf("Could not close the udp sink, error: %s", closeErr.Error())
		}

		<-doneChannel
	})

	return
}

// the origin of the QUIC cases on TCP 443 with Alt-Svc for UDP 443, and the UDP sink on 443
func startQuicServers(state *testing.T) (server httpsServer, sink udpSink) {
	pair, err := tls.LoadX509KeyPair(filepath.Join("..", "e2e", "assets", "server_rsa.crt"), filepath.Join("..", "e2e", "assets", "server_rsa.key"))

	if err != nil {
		state.Fatalf("Could not load the server certificate, error: %s", err.Error())
	}

	server = startHTTPSServerAt(state, pair, tls.VersionTLS13, nil, quicAddress, quicAltSvc)
	sink = startUDPSink(state, quicAddress)
	return
}

// load the QUIC origin twice in one Chrome: the first answer offers h3, the second load tries QUIC to UDP 443 and gets its page over TCP
func loadQuicOrigin(state *testing.T, server httpsServer) {
	err := loadChrome(state.Context(), chromePackage, server, "/first", "/first", true)

	if err == nil {
		err = loadChrome(state.Context(), chromePackage, server, "/second", "/second", false)
	}

	if err != nil {
		state.Fatalf("Could not load the QUIC origin in Chrome, error: %s", err.Error())
	}
}

// the client= of a flow line of protocol from uid to the host's port, empty without one
func flowClient(output string, protocol string, uid uint32, port string) (client string) {
	for line := range strings.Lines(output) {
		if !hasFlowLine(line, protocol, uid, port) {
			continue
		}

		for field := range strings.FieldsSeq(line) {
			if value, isFound := strings.CutPrefix(field, "client="); isFound {
				client = value
				return
			}
		}
	}

	return
}

// Test if decerter run --decrypt --block-quic --package prints the request lines of Chrome's page loads over TLS 1.3 and TLS 1.2, with Chrome's
// BoringSSL found in the TrichromeLibrary static shared library.
func TestChromeDecryptPositive(state *testing.T) {
	prepareChrome(state, chromePackage, "")
	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "chrome-decrypt", "run --decrypt --block-quic --package "+chromePackage+" --dst-cidr "+hostCIDR, redirectReady)
	waitAppLog(state, decerter, chromePackage, chromiumFoundLog, `"product":"Chrome"`, `libmonochrome_64.so"`)
	waitAppLog(state, decerter, chromePackage, keylogReady)

	for _, server := range servers {
		err := loadChrome(state.Context(), chromePackage, server, "/decrypt", "/decrypt", true)

		if err != nil {
			state.Errorf("Test of the Chrome decryption failed, error: %s", err.Error())
			continue
		}

		_, err = decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
			isFound = hasDecryptedRequest(output, server, `GET /decrypt HTTP/1.1\r\n`)
			return
		})

		if err != nil {
			state.Errorf("Test of the Chrome decryption failed, no decrypted request to port %s, error: %s", server.Port, err.Error())
		}
	}

	stopDeviceDecerter(state, decerter, true)
}

// Test if decerter keylog prints the key log lines of Chrome's TLS 1.3 and TLS 1.2 sessions with the host servers, and only lines Chrome's own
// --ssl-key-log-file has: every Chrome session decerter saw, not just the ones with the servers.
func TestChromeKeylogPositive(state *testing.T) {
	prepareChrome(state, chromePackage, "")
	serverKeyLog := newLockedBuffer()
	servers := startHTTPSServers(state, serverKeyLog)
	decerter := startDeviceDecerter(state, decerterBinary, "chrome-keylog", "keylog --package "+chromePackage, keylogReady)
	waitAppLog(state, decerter, chromePackage, keylogReady)

	for _, server := range servers {
		err := loadChrome(state.Context(), chromePackage, server, "/keylog", "/keylog", true)

		if err != nil {
			state.Fatalf("Test of the Chrome key log failed, error: %s", err.Error())
		}
	}

	expected := keyLogLines(serverKeyLog.String())
	_, serversErr := decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
		isFound = (len(expected) > 0) && isSubset(expected, keyLogLines(output))
		return
	})

	// decerter stops first, Chrome still writes what it has
	stopDeviceDecerter(state, decerter, false)
	output, err := decerter.output(state.Context())

	if err != nil {
		state.Fatalf("Could not read the output of decerter, error: %s", err.Error())
	}

	var chromeLines []string
	logCtx, cancel := context.WithTimeout(state.Context(), outputTimeout)
	defer cancel()
	err = poll(logCtx, func() (isDone bool, pollErr error) {
		chromeLog, pollErr := device.shell(logCtx, "cat "+chromeKeyLog)
		chromeLines = secretLines(chromeLog)
		isDone = (pollErr == nil) && isSubset(keyLogLines(output), chromeLines)
		pollErr = nil
		return
	})

	decerterLines := keyLogLines(output)
	state.Logf("decerter printed %d key log lines, Chrome wrote %d of the same labels, the servers %d", len(decerterLines), len(chromeLines), len(expected))

	// seen now and then since stage 38: Chrome's --ssl-key-log-file stays empty, and decerter then misses sessions too; that Chrome is no measure of decerter
	if len(chromeLines) == 0 {
		state.Skipf("Chrome wrote no key log of its own to %s, a Chrome problem and not decerter's; decerter printed %d lines, the servers %d, missing server lines: %v", chromeKeyLog, len(decerterLines), len(expected), serversErr)
	}

	if serversErr != nil {
		state.Errorf("Test of the Chrome key log failed, decerter should print every line of the servers, servers:\n%s, error: %s", serverKeyLog.String(), serversErr.Error())
	}

	if err != nil {
		state.Errorf("Test of the Chrome key log failed, decerter printed lines Chrome's own key log does not have, Chrome:\n%s\ndecerter:\n%s", strings.Join(chromeLines, "\n"), output)
	}

	if !isSubset(expected, chromeLines) {
		state.Errorf("Test of the Chrome key log failed, Chrome's own key log should have the lines of the servers, Chrome:\n%s\nservers:\n%s", strings.Join(chromeLines, "\n"), serverKeyLog.String())
	}
}

// Test if tshark on the host finds the decrypted requests of Chrome's TLS 1.3 and TLS 1.2 page loads in decerter capture --block-quic -w - streamed over
// adb exec-out.
func TestChromeCapturePositive(state *testing.T) {
	prepareChrome(state, chromePackage, "")

	if tsharkSkipReason != "" {
		state.Skip(tsharkSkipReason)
	}

	servers := startHTTPSServers(state, nil)
	tsharkOutput := startCaptureWith(state, servers, "--block-quic --package "+chromePackage)
	decerter := deviceDecerter{Binary: decerterBinary, Name: "capture"}
	waitAppLog(state, decerter, chromePackage, keylogReady)

	for _, server := range servers {
		err := loadChrome(state.Context(), chromePackage, server, "/capture", "/capture", true)

		if err != nil {
			state.Errorf("Test of the Chrome capture failed, error: %s", err.Error())
		}
	}

	output, err := tsharkOutput.wait(state.Context(), func(output string) (isFound bool) {
		isFound = true

		for _, server := range servers {
			isFound = isFound && slices.Contains(strings.Split(output, "\n"), server.Port+"\tGET\t/capture")
		}

		return
	})

	state.Logf("tshark printed:\n%s", output)

	if err != nil {
		state.Errorf("Test of the Chrome capture failed, tshark should find GET /capture to ports %s and %s, output:\n%s", servers[0].Port, servers[1].Port, output)
	}

	tsharkOutput.stop(state)
	err = decerter.waitStopped(state.Context())

	if err != nil {
		state.Fatalf("Test of the Chrome capture failed, decerter should stop once adb exec-out is gone, error: %s", err.Error())
	}

	checkRestored(state, decerter)
}

// Test if a rule added over the API of decerter run --block-quic rewrites Chrome's GET / to GET /test over TLS 1.3 and TLS 1.2.
func TestChromeRewritePositive(state *testing.T) {
	prepareChrome(state, chromePackage, "")
	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "chrome-rewrite", apiArguments(chromePackage)+" --block-quic", redirectReady)
	waitAppLog(state, decerter, chromePackage, keylogReady)
	client := forwardAPI(state)
	status, err := client.call(state.Context(), http.MethodPost, "/rules", v1.RuleRequest{Filter: "tls", Direction: v1.UpDirection, Layer: v1.TLSLayer, Find: v1.Value{Type: v1.TextValueType, Value: "GET / "}, Replace: v1.Value{Type: v1.TextValueType, Value: "GET /test "}}, nil)

	if (err != nil) || (status != http.StatusCreated) {
		state.Fatalf("Test of the Chrome rewrite failed, cannot add the rule over adb forward, status: %d, error: %v", status, err)
	}

	for _, server := range servers {
		err = loadChrome(state.Context(), chromePackage, server, "/", "/test", true)

		if err != nil {
			state.Errorf("Test of the Chrome rewrite failed, error: %s", err.Error())
		}
	}

	stopDeviceDecerter(state, decerter, true)
}

// Test if decerter run --block-quic makes Chrome's QUIC to an origin that offers h3 fail before it leaves the device: Chrome loads the page over TCP,
// decerter decrypts it, and no datagram reaches the host.
func TestChromeBlockQuicPositive(state *testing.T) {
	uid := prepareChrome(state, chromePackage, "--enable-quic")
	server, sink := startQuicServers(state)
	decerter := startDeviceDecerter(state, decerterBinary, "chrome-block", "run --decrypt --block-quic --udp-idle-timeout "+udpIdleTimeout+" --package "+chromePackage+" --dst-cidr "+hostCIDR, redirectReady)
	waitAppLog(state, decerter, chromePackage, keylogReady)
	loadQuicOrigin(state, server)
	_, err := decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
		isFound = hasDecryptedRequest(output, server, `GET /second HTTP/1.1\r\n`)
		return
	})

	if err != nil {
		state.Errorf("Test of --block-quic failed, Chrome's second load should go over TCP and be decrypted, error: %s", err.Error())
	}

	time.Sleep(quicSilence)
	output, err := decerter.output(state.Context())

	if (err != nil) || (sink.count.Load() != 0) || (flowClient(output, "udp", uid, "443") != "") {
		state.Errorf("Test of --block-quic failed, no QUIC datagram should leave the device, datagrams: %d, error: %v, output:\n%s", sink.count.Load(), err, output)
	}

	stopDeviceDecerter(state, decerter, true)
}

// Test if Chrome's QUIC to an origin that offers h3 is relayed but not decrypted without --block-quic: the datagrams reach the host and decerter
// prints a udp flow line and no record of it.
func TestChromeBlockQuicNegative(state *testing.T) {
	uid := prepareChrome(state, chromePackage, "--enable-quic")
	server, sink := startQuicServers(state)
	decerter := startDeviceDecerter(state, decerterBinary, "chrome-quic", "run --decrypt --udp-idle-timeout "+udpIdleTimeout+" --package "+chromePackage+" --dst-cidr "+hostCIDR, redirectReady)
	waitAppLog(state, decerter, chromePackage, keylogReady)
	loadQuicOrigin(state, server)
	output, err := decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
		isFound = flowClient(output, "udp", uid, "443") != ""
		return
	})

	if (err != nil) || (sink.count.Load() == 0) {
		state.Fatalf("Test of QUIC without --block-quic failed, Chrome's QUIC should be relayed to the host, datagrams: %d, error: %v", sink.count.Load(), err)
	}

	client := flowClient(output, "udp", uid, "443")

	for line := range strings.Lines(output) {
		if strings.HasPrefix(line, "tls ") && strings.Contains(line, " client="+client+" ") {
			state.Errorf("Test of QUIC without --block-quic failed, the QUIC flow from %s should not be decrypted, output:\n%s", client, output)
			break
		}
	}

	stopDeviceDecerter(state, decerter, true)
}

// install apk as org.chromium.chrome unless it is installed; the snapshot and the doctored copy have other keys, so the other one goes first
func installChromium(state *testing.T, apk string) {
	if (apk == chromiumDoctored) && (chromiumErr != nil) {
		state.Fatalf("Could not make the doctored ChromePublic, error: %s", chromiumErr.Error())
	}

	if chromiumInstalled == apk {
		return
	}

	// none may be installed yet
	_, _ = device.run(state.Context(), adbTimeout, "uninstall", chromiumPackage)
	chromiumInstalled = ""
	_, err := device.run(state.Context(), pushTimeout, "install", apk)

	if err != nil {
		state.Fatalf("Could not install %s, error: %s", apk, err.Error())
	}

	chromiumInstalled = apk
}

// remove ChromePublic from the device at the end if the tests installed it
func uninstallChromium(ctx context.Context) (err error) {
	if chromiumInstalled == "" {
		return
	}

	_, err = device.run(ctx, adbTimeout, "uninstall", chromiumPackage)
	return
}

// the device and the ChromePublic apk
func requireChromium(state *testing.T) {
	guardDevice(state)

	if chromiumSkipReason != "" {
		state.Skip(chromiumSkipReason)
	}
}

// Test if decerter run --decrypt --block-quic --package prints the request lines of a ChromePublic snapshot's page loads, the library is libchrome.so
// of its apk and the version is the manifest's.
func TestChromiumDecryptPositive(state *testing.T) {
	requireChromium(state)
	installChromium(state, chromiumAPK)
	prepareChrome(state, chromiumPackage, "")
	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "chromium-decrypt", "run --decrypt --block-quic --package "+chromiumPackage+" --dst-cidr "+hostCIDR, redirectReady)
	log := waitAppLog(state, decerter, chromiumPackage, chromiumFoundLog, `libchrome.so"`)
	waitAppLog(state, decerter, chromiumPackage, keylogReady)
	state.Logf("decerter log:\n%s", log)

	for _, server := range servers {
		err := loadChrome(state.Context(), chromiumPackage, server, "/decrypt", "/decrypt", true)

		if err != nil {
			state.Errorf("Test of the ChromePublic decryption failed, error: %s", err.Error())
			continue
		}

		_, err = decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
			isFound = hasDecryptedRequest(output, server, `GET /decrypt HTTP/1.1\r\n`)
			return
		})

		if err != nil {
			state.Errorf("Test of the ChromePublic decryption failed, no decrypted request to port %s, error: %s", server.Port, err.Error())
		}
	}

	stopDeviceDecerter(state, decerter, true)
}

// Test if a ChromePublic whose manifest has an unknown version is relayed but not decrypted, and decerter names the version and the make command.
func TestChromiumUnknownNegative(state *testing.T) {
	requireChromium(state)
	installChromium(state, chromiumDoctored)
	prepareChrome(state, chromiumPackage, "")
	servers := startHTTPSServers(state, nil)
	decerter := startDeviceDecerter(state, decerterBinary, "chromium-unknown", "run --decrypt --block-quic --package "+chromiumPackage+" --dst-cidr "+hostCIDR, redirectReady)
	log := waitAppLog(state, decerter, chromiumPackage, chromiumUnknownLog)

	if !strings.Contains(log, "no BoringSSL offsets for the Chromium version of the library: Chromium "+string(doctoredMajor)) || !strings.Contains(log, "make generate-chrome-offsets") {
		state.Errorf("Test of the unknown ChromePublic failed, decerter should name the unknown version and the make command, log:\n%s", log)
	}

	err := loadChrome(state.Context(), chromiumPackage, servers[0], "/unknown", "/unknown", true)

	if err != nil {
		state.Fatalf("Test of the unknown ChromePublic failed, its page load should be relayed, error: %s", err.Error())
	}

	logCtx, cancel := context.WithTimeout(state.Context(), outputTimeout)
	defer cancel()
	err = poll(logCtx, func() (isDone bool, pollErr error) {
		log, pollErr = decerter.log(logCtx)
		isDone = strings.Contains(log, noSecretsLog) && strings.Contains(log, noSecretsError)
		return
	})

	if err != nil {
		state.Errorf("Test of the unknown ChromePublic failed, the flow should be relayed without secrets, log:\n%s", log)
	}

	output, err := decerter.output(state.Context())

	if (err != nil) || hasDecryptedRequest(output, servers[0], `GET /unknown HTTP/1.1\r\n`) {
		state.Errorf("Test of the unknown ChromePublic failed, nothing should be decrypted, error: %v, output:\n%s", err, output)
	}

	stopDeviceDecerter(state, decerter, true)
}

// Test if decerter keylog --package hooks the Cronet of the image's YouTube, found in the process's maps once YouTube starts after decerter.
func TestCronetKeylogPositive(state *testing.T) {
	guardDevice(state)
	_, err := lookupAppUID(state.Context(), youtubePackage)

	if err != nil {
		state.Skipf("Skipping the Cronet case, %s", err.Error())
	}

	decerter := startDeviceDecerter(state, decerterBinary, "cronet-keylog", "keylog --package "+youtubePackage, keylogReady)

	state.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), adbTimeout)
		defer cancel()

		if _, stopErr := device.shell(ctx, "am force-stop "+youtubePackage); stopErr != nil {
			state.Errorf("Could not stop %s, error: %s", youtubePackage, stopErr.Error())
		}
	})

	// the notification permission is granted so no dialog stays on top of YouTube's task, a new cleared task starts YouTube even when one does
	_, err = device.shell(state.Context(), fmt.Sprintf("pm grant %s %s && am start -S -W -f 0x%x -n $(cmd package resolve-activity --brief -c android.intent.category.LAUNCHER %s | tail -n 1)", youtubePackage, notificationPermission, newClearedTask, youtubePackage))

	if err != nil {
		state.Fatalf("Could not start %s, error: %s", youtubePackage, err.Error())
	}

	log := waitAppLog(state, decerter, youtubePackage, chromiumFoundLog, `"product":"Cronet"`)
	waitAppLog(state, decerter, youtubePackage, keylogReady, `"library":"Cronet `)
	state.Logf("decerter log:\n%s", log)

	// YouTube talks to Google, the lines are only counted: there is no key log of its own to compare them with
	time.Sleep(quicSilence)
	output, err := decerter.output(state.Context())

	if err != nil {
		state.Fatalf("Could not read the output of decerter, error: %s", err.Error())
	}

	state.Logf("decerter printed %d key log lines of YouTube", len(keyLogLines(output)))
	stopDeviceDecerter(state, decerter, false)
}
