// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// a legacy call made during a capture and what the tools must find for it in the file
type capturedCall struct {
	Name    string
	Port    string
	IsTLS   bool
	IsHTTP2 bool
}

// Test if tshark finds the request of every legacy call in a capture, the TLS ones decrypted with the secrets of the file's DSB.
func TestCaptureDSBPositive(state *testing.T) {
	tsharkPath, lookErr := exec.LookPath("tshark")

	if lookErr != nil {
		state.Skipf("tshark is not installed, error: %s", lookErr.Error())
	}

	capturePath := filepath.Join(state.TempDir(), "capture.pcapng")
	calls := captureCalls(state, CaptureDecerterMode, capturePath)
	err := testTshark(state.Context(), tsharkPath, capturePath, calls, false)

	if err != nil {
		state.Errorf("Test of the DSB capture failed, error: %s", err.Error())
		return
	}

	// the TLS calls must be encrypted in the file, tshark had them from the DSB
	tcpdumpPath, tcpdumpErr := exec.LookPath("tcpdump")

	if tcpdumpErr != nil {
		state.Logf("tcpdump is not installed, the encryption of the TLS calls is not checked, error: %s", tcpdumpErr.Error())
		return
	}

	err = testEncrypted(state.Context(), tcpdumpPath, capturePath, calls)

	if err != nil {
		state.Errorf("Test of the DSB capture failed, error: %s", err.Error())
		return
	}
}

// Test if tcpdump -A finds the request of every legacy call in a plaintext capture, and tshark its path when it is installed.
func TestCapturePlaintextPositive(state *testing.T) {
	tcpdumpPath, lookErr := exec.LookPath("tcpdump")

	if lookErr != nil {
		state.Skipf("tcpdump is not installed, error: %s", lookErr.Error())
	}

	capturePath := filepath.Join(state.TempDir(), "plaintext.pcapng")
	calls := captureCalls(state, PlaintextDecerterMode, capturePath)
	err := testTcpdump(state.Context(), tcpdumpPath, capturePath, calls)

	if err != nil {
		state.Errorf("Test of the plaintext capture failed, error: %s", err.Error())
		return
	}

	// HPACK hides the HTTP/2 path from tcpdump -A, tshark reads it from the synthesized plaintext without any secret
	tsharkPath, tsharkErr := exec.LookPath("tshark")

	if tsharkErr != nil {
		state.Logf("tshark is not installed, the HTTP/2 paths of the plaintext capture are not checked, error: %s", tsharkErr.Error())
		return
	}

	err = testTshark(state.Context(), tsharkPath, capturePath, calls, true)

	if err != nil {
		state.Errorf("Test of the plaintext capture failed, error: %s", err.Error())
		return
	}
}

// run the legacy calls of both HTTP versions with decerter capturing into capturePath, decerter is stopped when they are done so the file is complete
// capture mode changes nothing, so every server must see the / curl asked for
func captureCalls(state *testing.T, mode decerterMode, capturePath string) (calls []capturedCall) {
	stop := startDecerter(state, mode, capturePath, nil)

	for _, isHTTP2 := range []bool{false, true} {
		for _, positive := range legacyCases(isHTTP2, "/") {
			server := startServer(state, positive.Server)
			output, curlErr := runCurl(state.Context(), testUser, curlArguments(positive, server.URL))

			if curlErr != nil {
				state.Fatalf("Could not run curl during the capture, case: %s, error: %s", positive.Name, curlErr.Error())
			}

			request, receivedErr := server.received()

			if (receivedErr != nil) || (request.Path != "/") || (output != "/") {
				state.Fatalf("Capture mode changed the request, case: %s, request: %+v, output: %q, error: %v", positive.Name, request, output, receivedErr)
			}

			address, parseErr := url.Parse(server.URL)

			if parseErr != nil {
				state.Fatalf("Could not parse the server url, error: %s", parseErr.Error())
			}

			calls = append(calls, capturedCall{
				Name:    fmt.Sprintf("%s http2=%v", positive.Name, isHTTP2),
				Port:    address.Port(),
				IsTLS:   positive.Server.Certificate != nil,
				IsHTTP2: isHTTP2,
			})
		}
	}

	stopErr := stop()

	if stopErr != nil {
		state.Fatalf("Could not stop decerter, error: %s", stopErr.Error())
	}

	return
}

// every call must show up as a GET of / to its port; the TLS ports are decoded as TLS unless the file is plaintext
// dataPorts are decoded as data: tshark neither reassembles nor dissects what went to them, a body of many megabytes costs it only the read then
func testTshark(ctx context.Context, tsharkPath string, capturePath string, calls []capturedCall, isPlaintext bool, dataPorts ...string) (err error) {
	arguments := []string{"-n", "-r", capturePath}

	for _, port := range dataPorts {
		arguments = append(arguments, "-d", fmt.Sprintf("tcp.port==%s,data", port))
	}

	for _, call := range calls {
		protocol := "http"

		switch {
		case call.IsTLS && !isPlaintext:
			protocol = "tls"
		case call.IsHTTP2:
			protocol = "http2"
		}

		arguments = append(arguments, "-d", fmt.Sprintf("tcp.port==%s,%s", call.Port, protocol))
	}

	arguments = append(arguments, "-Y", "http.request or http2.type == 1", "-T", "fields", "-E", "separator=/t", "-e", "tcp.dstport", "-e", "http.request.method", "-e", "http.request.uri", "-e", "http2.headers.method", "-e", "http2.headers.path")
	output, runErr := runCommandTimeout(ctx, tsharkTimeout, tsharkPath, arguments...)

	if err = runErr; err != nil {
		return
	}

	found := map[string]bool{}

	for line := range strings.Lines(output) {
		fields := strings.Split(strings.TrimRight(line, "\n"), "\t")

		if len(fields) != 5 {
			continue
		}

		if ((fields[1] == "GET") && (fields[2] == "/")) || ((fields[3] == "GET") && (fields[4] == "/")) {
			found[fields[0]] = true
		}
	}

	for _, call := range calls {
		if !found[call.Port] {
			err = fmt.Errorf("tshark found no GET / of %s to port %s, plaintext: %v, output:\n%s", call.Name, call.Port, isPlaintext, output)
			return
		}
	}

	return
}

// the HTTP/1.1 request line of a TLS call must not be in the file as text
func testEncrypted(ctx context.Context, tcpdumpPath string, capturePath string, calls []capturedCall) (err error) {
	for _, call := range calls {
		if !call.IsTLS || call.IsHTTP2 {
			continue
		}

		output, runErr := runCommand(ctx, tcpdumpPath, "-n", "-A", "-r", capturePath, "tcp dst port "+call.Port)

		if err = runErr; err != nil {
			return
		}

		if !strings.Contains(output, call.Port) || strings.Contains(output, "GET / HTTP/1.1") {
			err = fmt.Errorf("tcpdump -A should find the packets of %s to port %s, but not its request line, output:\n%s", call.Name, call.Port, output)
			return
		}
	}

	return
}

// tcpdump -A prints the payload as text: an HTTP/1.1 call shows its request line, an HTTP/2 call its connection preface
func testTcpdump(ctx context.Context, tcpdumpPath string, capturePath string, calls []capturedCall) (err error) {
	for _, call := range calls {
		expected := "GET / HTTP/1.1"

		if call.IsHTTP2 {
			expected = "PRI * HTTP/2.0"
		}

		output, runErr := runCommand(ctx, tcpdumpPath, "-n", "-A", "-r", capturePath, "tcp dst port "+call.Port)

		if err = runErr; err != nil {
			return
		}

		if !strings.Contains(output, expected) {
			err = fmt.Errorf("tcpdump -A found no %q of %s to port %s, output:\n%s", expected, call.Name, call.Port, output)
			return
		}
	}

	return
}

// Test if the DTLS session of the rewrite case is in a capture with the line the client sent: as text in a synthesized udp datagram of a plaintext capture, and decrypted by tshark from the DSB of a capture with secrets.
func TestCaptureDTLSPositive(state *testing.T) {
	tcpdumpPath, lookErr := exec.LookPath("tcpdump")

	if lookErr != nil {
		state.Skipf("tcpdump is not installed, error: %s", lookErr.Error())
	}

	for _, mode := range []decerterMode{PlaintextDecerterMode, CaptureDecerterMode} {
		state.Run(string(mode), func(state *testing.T) {
			capturePath := filepath.Join(state.TempDir(), "dtls.pcapng")
			stop := startDecerter(state, mode, capturePath, nil)
			server := startDTLSServer(state)
			_, err := runDTLSClient(state, testUser, server, "", dtlsLine, dtlsLine)

			if err != nil {
				state.Fatalf("Could not run the dtls session during the capture, error: %s", err.Error())
			}

			stopErr := stop()

			if stopErr != nil {
				state.Fatalf("Could not stop decerter, error: %s", stopErr.Error())
			}

			output, runErr := runCommand(state.Context(), tcpdumpPath, "-n", "-A", "-r", capturePath, "udp dst port "+server.Port)

			if runErr != nil {
				state.Fatalf("Could not read the capture, error: %s", runErr.Error())
			}

			// only the plaintext capture has the line as text
			if strings.Contains(output, dtlsLine) != (mode == PlaintextDecerterMode) {
				state.Errorf("Test of the DTLS capture failed, tcpdump -A should find %q: %v, output:\n%s", dtlsLine, mode == PlaintextDecerterMode, output)
				return
			}

			if mode == PlaintextDecerterMode {
				return
			}

			err = testTsharkDTLS(state, capturePath, server.Port)

			if err != nil {
				state.Errorf("Test of the DTLS capture failed, error: %s", err.Error())
				return
			}
		})
	}
}

// tshark decrypts the application data of the DTLS session to port with the secrets of the file's DSB, the client's line must be among it
func testTsharkDTLS(state *testing.T, capturePath string, port string) (err error) {
	tsharkPath, lookErr := exec.LookPath("tshark")

	if lookErr != nil {
		state.Logf("tshark is not installed, the DSB of the DTLS session is not checked, error: %s", lookErr.Error())
		return
	}

	output, runErr := runCommand(state.Context(), tsharkPath, "-n", "-r", capturePath, "-d", "udp.port=="+port+",dtls", "-Y", "data", "-T", "fields", "-E", "separator=/t", "-e", "udp.dstport", "-e", "data.data")

	if err = runErr; err != nil {
		return
	}

	expected := port + "\t" + hex.EncodeToString([]byte(dtlsLine+"\n"))

	if !slices.Contains(strings.Split(strings.TrimSpace(output), "\n"), expected) {
		err = fmt.Errorf("tshark decrypted no %q to port %s, output:\n%s", dtlsLine, port, output)
	}

	return
}
