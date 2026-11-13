// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e_android

package android_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	v1 "github.com/decerter/decerter/api"
)

const (
	// the Flutter SDKs to build the test app with, colon separated like PATH; the Flutter cases skip without one
	flutterEnvironment string = "DECERTER_E2E_FLUTTER"
	flutterPackage     string = "io.decerter.decerter_flutter"
	flutterActivity    string = flutterPackage + "/.MainActivity"
	// the first build of an SDK downloads Gradle and its plugins, later ones take a few seconds
	flutterBuildTimeout time.Duration = 15 * time.Minute
	// a cold start of the app and its one request
	flutterTimeout time.Duration = 30 * time.Second
	// both ABIs in one apk, the emulator runs the x86_64 one
	flutterPlatforms string = "android-x64,android-arm64"
	// the stored library of the emulator's ABI, the negative case changes its Dart version
	flutterEntry string = "lib/x86_64/libflutter.so"
	// what decerter logs per Flutter app
	flutterHookedLog  string = `"msg":"Attached secrets uprobe"`
	flutterUnknownLog string = `"msg":"Could not hook the Flutter app, its TLS is relayed without secrets"`
	flutterRescanLog  string = `"msg":"Found a library of a selected app installed, updated or started while decerter runs"`
	noSecretsLog      string = `"msg":"Could not decrypt tls flow, relaying without decryption"`
	noSecretsError    string = `"error":"no secrets for the tls session"`
)

var (
	// the version string the Dart VM prints, the negative case makes its major version unknown
	dartVersionPattern = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)? \([a-z]+\) \([^)\x00]*\) on "android_x64"`)
	flutterRun         atomic.Uint64
	// the Flutter test apps of TestMain, one per SDK; why the Flutter cases skip, empty when they run
	flutterApps       []flutterApp
	flutterSkipReason string
	// the apk on the device now and the uid of the app
	flutterInstalled string
	flutterUID       uint32
)

// the test app built with one Flutter SDK: the apk, and a copy whose engine prints a Dart version decerter doesn't know; err is why it is missing
type flutterApp struct {
	Version  string
	APK      string
	Doctored string
	err      error
}

// build the Flutter test app with each SDK of decerter_E2E_FLUTTER as the invoking user, cached in ~/.cache/decerter-flutter/e2e by Flutter release and sources
func buildFlutterApps(account hostAccount, sdk string) (apps []flutterApp, skipReason string) {
	sdks := filepath.SplitList(os.Getenv(flutterEnvironment))

	if len(sdks) == 0 {
		skipReason = "no Flutter SDK, set " + flutterEnvironment + " to one or more Flutter SDK directories (colon separated), make test-e2e-android uses ~/.cache/decerter-flutter/*/flutter"
		return
	}

	for _, flutterSDK := range sdks {
		app := buildFlutterApp(account, sdk, flutterSDK)

		if app.err != nil {
			fmt.Fprintf(os.Stderr, "could not build the Flutter test app with %s: %s\n", flutterSDK, app.err.Error())
		} else {
			fmt.Fprintf(os.Stderr, "Flutter %s test app: %s\n", app.Version, app.APK)
		}

		apps = append(apps, app)
	}

	return
}

func buildFlutterApp(account hostAccount, sdk string, flutterSDK string) (app flutterApp) {
	ctx, cancel := context.WithTimeout(context.Background(), flutterBuildTimeout)
	defer cancel()
	environment := flutterEnvironmentOf(account, sdk, flutterSDK)
	flutter := filepath.Join(flutterSDK, "bin", "flutter")
	app = flutterApp{Version: flutterSDK, APK: "", Doctored: "", err: nil}
	versionJSON, versionErr := runAsUser(ctx, account, environment, "/", flutter, "--version", "--machine")

	if app.err = versionErr; app.err != nil {
		return
	}

	version := struct {
		FrameworkVersion string `json:"frameworkVersion"`
	}{}
	// the tool may print a line of its own before the JSON
	_, versionText, _ := strings.Cut(versionJSON, "{")
	app.err = json.Unmarshal([]byte("{"+versionText), &version)

	if app.err != nil {
		return
	}

	app.Version = version.FrameworkVersion
	ndk, ndkErr := newestNDK(sdk)
	sourcesHash, hashErr := hashSources(filepath.Join("flutter"), ndk)

	if app.err = errors.Join(ndkErr, hashErr); app.err != nil {
		return
	}

	cache := filepath.Join(account.Home, ".cache", "decerter-flutter", "e2e")
	app.APK = filepath.Join(cache, app.Version+"-"+sourcesHash+".apk")
	app.Doctored = filepath.Join(cache, app.Version+"-"+sourcesHash+"-unknown-dart.apk")
	_, statErr := os.Stat(app.APK)

	if statErr != nil {
		app.err = buildFlutterAPK(ctx, account, environment, flutter, filepath.Base(ndk), cache, app.APK)

		if app.err != nil {
			return
		}
	}

	_, statErr = os.Stat(app.Doctored)

	if statErr != nil {
		app.err = doctorAPK(ctx, account, environment, sdk, app.APK, app.Doctored)
	}

	return
}

// flutter create for the SDK, the sources of test/android/flutter over it, INTERNET in the manifest and the SDK's own NDK instead of the one Flutter
// pins, then a release build of both ABIs; every step runs as the invoking user in the cache, the work tree is removed after
func buildFlutterAPK(ctx context.Context, account hostAccount, environment []string, flutter string, ndkVersion string, cache string, apk string) (err error) {
	_, err = runAsUser(ctx, account, environment, "/", "mkdir", "-p", cache)

	if err != nil {
		return
	}

	work, err := runAsUser(ctx, account, environment, "/", "mktemp", "-d", "-p", cache, "build.XXXXXX")

	if err != nil {
		return
	}

	work = strings.TrimSpace(work)

	defer func() {
		_, removeErr := runAsUser(context.Background(), account, environment, "/", "rm", "-rf", "--", work)
		err = errors.Join(err, removeErr)
	}()

	project := filepath.Join(work, "decerter_flutter")
	sources, err := filepath.Abs("flutter")

	if err != nil {
		return
	}

	manifest := filepath.Join(project, "android", "app", "src", "main", "AndroidManifest.xml")
	// the first runs in the work tree, the others in the project flutter create made
	steps := [][]string{
		{flutter, "create", "--org", "io.decerter", "--project-name", "decerter_flutter", "--platforms", "android", project},
		{"rm", "-rf", "--", filepath.Join(project, "test")},
		{"cp", "-r", "--", sources + "/.", project},
		{"sed", "-i", `s#<manifest xmlns:android="http://schemas.android.com/apk/res/android">#&\n    <uses-permission android:name="android.permission.INTERNET"/>#`, manifest},
		{"sed", "-i", `s#ndkVersion = flutter.ndkVersion#ndkVersion = "` + ndkVersion + `"#`, filepath.Join(project, "android", "app", "build.gradle.kts")},
		{flutter, "build", "apk", "--release", "--target-platform", flutterPlatforms},
		{"cp", "--", filepath.Join(project, "build", "app", "outputs", "flutter-apk", "app-release.apk"), apk},
	}

	for index, step := range steps {
		directory := project

		if index == 0 {
			directory = work
		}

		_, err = runAsUser(ctx, account, environment, directory, step[0], step[1:]...)

		if err != nil {
			return
		}
	}

	return
}

// the same apk with another major Dart version in the x86_64 libflutter.so: the bytes are changed in place (the entry is stored), its CRC in the
// local and the central header, then apksigner signs it again with the debug key that signed the build, so it installs over it
func doctorAPK(ctx context.Context, account hostAccount, environment []string, sdk string, apk string, doctored string) (err error) {
	data, err := os.ReadFile(apk)

	if err != nil {
		return
	}

	name := []byte(flutterEntry)
	localStart := -1

	// the local header whose name is the entry: signature, then the name at 30
	for offset := 0; offset+30+len(name) <= len(data); {
		found := bytes.Index(data[offset:], []byte("PK\x03\x04"))

		if found < 0 {
			break
		}

		start := offset + found

		if (start+30+len(name) <= len(data)) && (int(binary.LittleEndian.Uint16(data[start+26:])) == len(name)) && bytes.Equal(data[start+30:start+30+len(name)], name) {
			localStart = start
			break
		}

		offset = start + 4
	}

	centralStart := -1

	for offset := 0; offset+46+len(name) <= len(data); {
		found := bytes.Index(data[offset:], []byte("PK\x01\x02"))

		if found < 0 {
			break
		}

		start := offset + found

		if (start+46+len(name) <= len(data)) && (int(binary.LittleEndian.Uint16(data[start+28:])) == len(name)) && bytes.Equal(data[start+46:start+46+len(name)], name) {
			centralStart = start
			break
		}

		offset = start + 4
	}

	if (localStart < 0) || (centralStart < 0) || (binary.LittleEndian.Uint16(data[localStart+8:]) != 0) {
		err = fmt.Errorf("%s has no stored %s", apk, flutterEntry)
		return
	}

	dataStart := localStart + 30 + len(name) + int(binary.LittleEndian.Uint16(data[localStart+28:]))
	dataEnd := dataStart + int(binary.LittleEndian.Uint32(data[centralStart+20:]))
	location := dartVersionPattern.FindIndex(data[dataStart:dataEnd])

	if location == nil {
		err = fmt.Errorf("no Dart version string in %s of %s", flutterEntry, apk)
		return
	}

	// the major version's first digit becomes 9, 3.14.0 is 9.14.0: as long as before, and no Flutter release has it
	data[dataStart+location[0]] = '9'
	checksum := crc32.ChecksumIEEE(data[dataStart:dataEnd])
	binary.LittleEndian.PutUint32(data[localStart+14:], checksum)
	binary.LittleEndian.PutUint32(data[centralStart+16:], checksum)
	unsigned := doctored + ".unsigned"
	err = os.WriteFile(unsigned, data, 0o644)

	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, os.Remove(unsigned))
	}()

	apksigner, err := newestBuildTool(sdk, "apksigner")

	if err != nil {
		return
	}

	keystore := filepath.Join(account.Home, ".android", "debug.keystore")
	_, err = runAsUser(ctx, account, environment, "/", apksigner, "sign", "--ks", keystore, "--ks-pass", "pass:android", "--ks-key-alias", "androiddebugkey", "--key-pass", "pass:android", "--v4-signing-enabled", "false", "--out", doctored, unsigned)
	return
}

// what flutter, gradle and apksigner get: the invoking user's home, the SDKs, no analytics
func flutterEnvironmentOf(account hostAccount, sdk string, flutterSDK string) (environment []string) {
	environment = []string{
		"PATH=" + filepath.Join(flutterSDK, "bin") + ":/usr/local/bin:/usr/bin:/bin",
		"HOME=" + account.Home,
		"LC_ALL=C.UTF-8",
		"ANDROID_SDK_ROOT=" + sdk,
		"ANDROID_HOME=" + sdk,
		"FLUTTER_SUPPRESS_ANALYTICS=true",
		"DART_SUPPRESS_ANALYTICS=true",
		"CI=true",
	}
	return
}

// run a host command as the invoking user with a fixed environment, stdout is the output
func runAsUser(ctx context.Context, account hostAccount, environment []string, directory string, name string, arguments ...string) (output string, err error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = environment
	command.Dir = directory
	command.SysProcAttr = &syscall.SysProcAttr{Credential: account.Credential}
	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	output = stdout.String()

	if err != nil {
		err = fmt.Errorf("%s %s: %w: %s", name, strings.Join(arguments, " "), err, lastLines(stderr.String()+stdout.String(), 20))
	}

	return
}

func lastLines(text string, count int) (last string) {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	last = strings.Join(lines[max(0, len(lines)-count):], "\n")
	return
}

// the newest NDK of the SDK, the app is built with it instead of the NDK version Flutter would download
func newestNDK(sdk string) (ndk string, err error) {
	ndks, err := filepath.Glob(filepath.Join(sdk, "ndk", "*"))

	if err != nil {
		return
	}

	if len(ndks) == 0 {
		err = fmt.Errorf("no NDK in %s/ndk", sdk)
		return
	}

	slices.Sort(ndks)
	ndk = ndks[len(ndks)-1]
	return
}

// a tool of the newest build-tools of the SDK
func newestBuildTool(sdk string, name string) (tool string, err error) {
	tools, err := filepath.Glob(filepath.Join(sdk, "build-tools", "*", name))

	if err != nil {
		return
	}

	if len(tools) == 0 {
		err = fmt.Errorf("no %s in %s/build-tools", name, sdk)
		return
	}

	slices.Sort(tools)
	tool = tools[len(tools)-1]
	return
}

// the cache key of the apk: the test app's sources and the NDK
func hashSources(directory string, ndk string) (sum string, err error) {
	hash := sha256.New()
	_, err = hash.Write([]byte(filepath.Base(ndk) + "\n"))

	if err != nil {
		return
	}

	err = filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) (err error) {
		if (walkErr != nil) || entry.IsDir() {
			err = walkErr
			return
		}

		content, readErr := os.ReadFile(path)

		if err = readErr; err != nil {
			return
		}

		_, err = fmt.Fprintf(hash, "%s %d\n%s", path, len(content), content)
		return
	})
	sum = hex.EncodeToString(hash.Sum(nil))[:16]
	return
}

// the Flutter test apps, the case skips without a device or an SDK
func requireFlutter(state *testing.T) (apps []flutterApp) {
	guardDevice(state)

	if flutterSkipReason != "" {
		state.Skip(flutterSkipReason)
	}

	apps = flutterApps
	return
}

// install the apk unless it is installed, over the one there (same debug key, -d allows the older Flutter build); the app's uid stays the same
func installFlutter(state *testing.T, app flutterApp, apk string) {
	if app.err != nil {
		state.Fatalf("Could not build the Flutter %s test app, error: %s", app.Version, app.err.Error())
	}

	if flutterInstalled == apk {
		return
	}

	_, err := device.run(state.Context(), pushTimeout, "install", "-r", "-d", apk)

	if err != nil {
		state.Fatalf("Could not install the Flutter test app, error: %s", err.Error())
	}

	flutterInstalled = apk
	flutterUID, err = lookupAppUID(state.Context(), flutterPackage)

	if err != nil {
		state.Fatalf("Could not find the uid of the Flutter test app, error: %s", err.Error())
	}
}

// remove the test app from the device at the end
func uninstallFlutter(ctx context.Context) (err error) {
	if flutterInstalled == "" {
		return
	}

	_, err = device.run(ctx, adbTimeout, "uninstall", flutterPackage)
	return
}

// start the app (a cold start, the activity is stopped first) with the server's url for path, then read its result line from logcat:
// the body and what the server received have to be expected, with the server's TLS version
func testFlutter(ctx context.Context, server httpsServer, path string, expected string) (err error) {
	certificate, err := os.ReadFile(filepath.Join("..", "e2e", "assets", "server_rsa.crt"))

	if err != nil {
		return
	}

	id := fmt.Sprintf("run%d", flutterRun.Add(1))
	_, err = device.shell(ctx, fmt.Sprintf("am start -S -W -n %s --es url %s --es ca %s --es id %s", flutterActivity, server.url(path), base64.StdEncoding.EncodeToString(certificate), id))

	if err != nil {
		return
	}

	resultCtx, cancel := context.WithTimeout(ctx, flutterTimeout)
	defer cancel()
	prefix := "decerter-flutter " + id + " "
	result := ""
	err = poll(resultCtx, func() (isDone bool, pollErr error) {
		output, logcatErr := device.shell(resultCtx, "logcat -d -s flutter:I")

		if logcatErr != nil {
			return
		}

		for line := range strings.Lines(output) {
			if _, after, isFound := strings.Cut(line, prefix); isFound {
				result = strings.TrimSpace(after)
				isDone = true
				return
			}
		}

		return
	})

	if err != nil {
		err = fmt.Errorf("the Flutter app printed no result for %s: %w", id, err)
		return
	}

	if result != "status 200 body "+expected {
		err = fmt.Errorf("the Flutter app should get the body %q from port %s, result: %s", expected, server.Port, result)
		return
	}

	request, receivedErr := server.received()

	if err = receivedErr; err != nil {
		return
	}

	if (request.Path != expected) || (request.Version != server.MaxVersion) {
		err = fmt.Errorf("the server on port %s should receive %s over %s, request: %+v", server.Port, expected, tls.VersionName(server.MaxVersion), request)
	}

	return
}

// wait until decerter logged line about the Flutter test app, it is logged once the app's library is looked at
func waitFlutterLog(state *testing.T, decerter deviceDecerter, line string) (log string) {
	logCtx, cancel := context.WithTimeout(state.Context(), outputTimeout)
	defer cancel()
	err := poll(logCtx, func() (isDone bool, pollErr error) {
		log, pollErr = decerter.log(logCtx)

		for logLine := range strings.Lines(log) {
			isDone = isDone || (strings.Contains(logLine, line) && strings.Contains(logLine, `"package":"`+flutterPackage+`"`))
		}

		return
	})

	if err != nil {
		state.Fatalf("%s should log %s for %s, error: %s, log:\n%s", decerter.Binary, line, flutterPackage, err.Error(), log)
	}

	return
}

// Test if decerter run --decrypt --package prints the request line of the Flutter app's dart:io call over TLS 1.3 and TLS 1.2, for each Flutter release,
// the app started after decerter.
func TestFlutterDecryptPositive(state *testing.T) {
	for _, app := range requireFlutter(state) {
		state.Run(app.Version, func(state *testing.T) {
			installFlutter(state, app, app.APK)
			servers := startHTTPSServers(state, nil)
			decerter := startDeviceDecerter(state, decerterBinary, "flutter-decrypt", "run --decrypt --package "+flutterPackage+" --dst-cidr "+hostCIDR, redirectReady)
			waitFlutterLog(state, decerter, flutterHookedLog)

			for _, server := range servers {
				err := testFlutter(state.Context(), server, "/decrypt", "/decrypt")

				if err != nil {
					state.Errorf("Test of the Flutter decryption failed, error: %s", err.Error())
					continue
				}

				_, err = decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
					isFound = hasDecryptedRequest(output, server, `GET /decrypt HTTP/1.1\r\n`)
					return
				})

				if err != nil {
					state.Errorf("Test of the Flutter decryption failed, no decrypted request to port %s, error: %s", server.Port, err.Error())
				}
			}

			stopDeviceDecerter(state, decerter, true)
		})
	}
}

// Test if decerter keylog prints exactly the key log lines the host server wrote for the Flutter app's TLS 1.3 and TLS 1.2 sessions, after the app was
// updated while decerter ran, for each Flutter release.
func TestFlutterKeylogPositive(state *testing.T) {
	for _, app := range requireFlutter(state) {
		state.Run(app.Version, func(state *testing.T) {
			installFlutter(state, app, app.APK)
			serverKeyLog := newLockedBuffer()
			servers := startHTTPSServers(state, serverKeyLog)
			decerter := startDeviceDecerter(state, decerterBinary, "flutter-keylog", "keylog --package "+flutterPackage, keylogReady)
			waitFlutterLog(state, decerter, flutterHookedLog)

			// an update installs the app into a new directory, decerter finds it there and hooks it
			_, err := device.run(state.Context(), pushTimeout, "install", "-r", "-d", app.APK)

			if err != nil {
				state.Fatalf("Could not update the Flutter test app, error: %s", err.Error())
			}

			waitFlutterLog(state, decerter, flutterRescanLog)

			for _, server := range servers {
				err = testFlutter(state.Context(), server, "/keylog", "/keylog")

				if err != nil {
					state.Fatalf("Test of the Flutter key log failed, error: %s", err.Error())
				}
			}

			expected := keyLogLines(serverKeyLog.String())
			output, err := decerter.waitOutput(state.Context(), func(output string) (isFound bool) {
				isFound = (len(expected) > 0) && isSubset(expected, keyLogLines(output))
				return
			})

			if err != nil {
				state.Errorf("Test of the Flutter key log failed, decerter should print every line of the server, server:\n%sdecerter:\n%s", serverKeyLog.String(), output)
			}

			stopDeviceDecerter(state, decerter, false)
			output, err = decerter.output(state.Context())

			if err != nil {
				state.Fatalf("Could not read the output of decerter, error: %s", err.Error())
			}

			if !isSubset(keyLogLines(output), expected) {
				state.Errorf("Test of the Flutter key log failed, decerter printed lines the server did not write, server:\n%sdecerter:\n%s", serverKeyLog.String(), output)
			}
		})
	}
}

// Test if tshark on the host finds the decrypted requests of the Flutter app's TLS 1.3 and TLS 1.2 calls in decerter capture -w - streamed over
// adb exec-out, for each Flutter release.
func TestFlutterCapturePositive(state *testing.T) {
	apps := requireFlutter(state)

	if tsharkSkipReason != "" {
		state.Skip(tsharkSkipReason)
	}

	for _, app := range apps {
		state.Run(app.Version, func(state *testing.T) {
			installFlutter(state, app, app.APK)
			servers := startHTTPSServers(state, nil)
			tsharkOutput := startCapture(state, servers, flutterPackage)
			waitFlutterLog(state, deviceDecerter{Binary: decerterBinary, Name: "capture"}, flutterHookedLog)

			for _, server := range servers {
				err := testFlutter(state.Context(), server, "/capture", "/capture")

				if err != nil {
					state.Errorf("Test of the Flutter capture failed, error: %s", err.Error())
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
				state.Errorf("Test of the Flutter capture failed, tshark should find GET /capture to ports %s and %s, output:\n%s", servers[0].Port, servers[1].Port, output)
			}

			tsharkOutput.stop(state)
			decerter := deviceDecerter{Binary: decerterBinary, Name: "capture"}
			err = decerter.waitStopped(state.Context())

			if err != nil {
				state.Fatalf("Test of the Flutter capture failed, decerter should stop once adb exec-out is gone, error: %s", err.Error())
			}

			checkRestored(state, decerter)
		})
	}
}

// Test if a rule added over the API rewrites the Flutter app's GET / to GET /test over TLS 1.3 and TLS 1.2, for each Flutter release.
func TestFlutterRewritePositive(state *testing.T) {
	for _, app := range requireFlutter(state) {
		state.Run(app.Version, func(state *testing.T) {
			installFlutter(state, app, app.APK)
			servers := startHTTPSServers(state, nil)
			decerter := startDeviceDecerter(state, decerterBinary, "flutter-rewrite", apiArguments(flutterPackage), redirectReady)
			waitFlutterLog(state, decerter, flutterHookedLog)
			client := forwardAPI(state)
			status, err := client.call(state.Context(), http.MethodPost, "/rules", v1.RuleRequest{Filter: "tls", Direction: v1.UpDirection, Layer: v1.TLSLayer, Find: v1.Value{Type: v1.TextValueType, Value: "GET / "}, Replace: v1.Value{Type: v1.TextValueType, Value: "GET /test "}}, nil)

			if (err != nil) || (status != http.StatusCreated) {
				state.Fatalf("Test of the Flutter rewrite failed, cannot add the rule over adb forward, status: %d, error: %v", status, err)
			}

			for _, server := range servers {
				err = testFlutter(state.Context(), server, "/", "/test")

				if err != nil {
					state.Errorf("Test of the Flutter rewrite failed, error: %s", err.Error())
				}
			}

			stopDeviceDecerter(state, decerter, true)
		})
	}
}

// Test if a Flutter app whose engine prints an unknown Dart version is relayed but not decrypted, and decerter says why, for each Flutter release.
func TestFlutterUnknownNegative(state *testing.T) {
	for _, app := range requireFlutter(state) {
		state.Run(app.Version, func(state *testing.T) {
			installFlutter(state, app, app.Doctored)
			servers := startHTTPSServers(state, nil)
			decerter := startDeviceDecerter(state, decerterBinary, "flutter-unknown", "run --decrypt --package "+flutterPackage+" --dst-cidr "+hostCIDR, redirectReady)
			log := waitFlutterLog(state, decerter, flutterUnknownLog)

			if !strings.Contains(log, "no BoringSSL offsets for the Dart version of the Flutter engine: Dart 9.") || !strings.Contains(log, "make generate-flutter-offsets") {
				state.Errorf("Test of the unknown Flutter engine failed, decerter should name the unknown Dart version and the make command, log:\n%s", log)
			}

			err := testFlutter(state.Context(), servers[0], "/unknown", "/unknown")

			if err != nil {
				state.Fatalf("Test of the unknown Flutter engine failed, the app's request should be relayed, error: %s", err.Error())
			}

			logCtx, cancel := context.WithTimeout(state.Context(), outputTimeout)
			defer cancel()
			err = poll(logCtx, func() (isDone bool, pollErr error) {
				log, pollErr = decerter.log(logCtx)
				isDone = strings.Contains(log, noSecretsLog) && strings.Contains(log, noSecretsError)
				return
			})

			if err != nil {
				state.Errorf("Test of the unknown Flutter engine failed, the flow should be relayed without secrets, log:\n%s", log)
			}

			output, err := decerter.output(state.Context())

			if (err != nil) || hasDecryptedRequest(output, servers[0], `GET /unknown HTTP/1.1\r\n`) {
				state.Errorf("Test of the unknown Flutter engine failed, nothing should be decrypted, error: %v, output:\n%s", err, output)
			}

			stopDeviceDecerter(state, decerter, true)
		})
	}
}
