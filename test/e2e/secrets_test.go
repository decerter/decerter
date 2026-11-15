// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Test if the secrets uprobes of decerter keylog print no key log line for what they can't read and go on, and if what they print is right: TLS 1.0
// and 1.1 sessions of curl give no line, openssl s_client over QUIC, whose stream and connection objects are no TLS connection, gives the lines of
// the TLS connection inside it as s_client writes them itself, and a TLS 1.3 session after them gives the four lines its server writes.
func TestKeylogSecretsNegative(state *testing.T) {
	stdout, logs, stop := startDecerterCommandLogs(state, []string{"Attached secrets uprobe"}, "keylog", "--uid", strconv.FormatUint(uint64(testUser.UID), 10))
	negativeCases := []struct {
		Name    string
		Version uint16
		Curl    string
	}{
		{Name: "tls1.0", Version: tls.VersionTLS10, Curl: "1.0"},
		{Name: "tls1.1", Version: tls.VersionTLS11, Curl: "1.1"},
	}
	oldKeyLog := &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}

	for _, negative := range negativeCases {
		state.Run(negative.Name, func(state *testing.T) {
			server := startServer(state, serverConfig{Certificate: &rsaCertificate, Version: negative.Version, KeyLog: oldKeyLog})
			// OpenSSL 3 allows TLS 1.0 and 1.1 only at security level 0
			output, err := runCurl(state.Context(), testUser, []string{"--insecure", "--pinnedpubkey", rsaCertificate.Pin, "--tlsv" + negative.Curl, "--tls-max", negative.Curl, "--ciphers", "DEFAULT:@SECLEVEL=0", server.URL + "old"})

			if err != nil {
				state.Skipf("curl of this host can't make a TLS %s session: %s", negative.Curl, err.Error())
			}

			request, receivedErr := server.received()

			if (output != "/old") || (receivedErr != nil) || (request.Version != negative.Version) {
				state.Fatalf("Test of the secrets uprobes failed, curl should get the answer over TLS %s, output: %q, request: %+v, error: %v", negative.Curl, output, request, receivedErr)
			}
		})
	}

	expected := []string{}

	state.Run("quic", func(state *testing.T) {
		expected = append(expected, exchangeQUIC(state)...)
	})

	newKeyLog := &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}
	server := startServer(state, serverConfig{Certificate: &rsaCertificate, KeyLog: newKeyLog})
	output, err := runCurl(state.Context(), testUser, []string{"--insecure", "--pinnedpubkey", rsaCertificate.Pin, "--tlsv1.3", server.URL + "new"})

	if (err != nil) || (output != "/new") {
		state.Fatalf("Test of the secrets uprobes failed, curl should get the answer over TLS 1.3, output: %q, error: %v", output, err)
	}

	err = stop()

	if err != nil {
		state.Fatalf("Could not stop decerter keylog, error: %s", err.Error())
	}

	expected = append(expected, keyLogLines(newKeyLog.String())...)
	decerterKeyLog := keyLogLines(stdout.String())
	slices.Sort(expected)
	slices.Sort(decerterKeyLog)

	if (len(keyLogLines(newKeyLog.String())) != 4) || !slices.Equal(decerterKeyLog, expected) {
		state.Errorf("Test of the secrets uprobes failed, decerter keylog should print the lines of the QUIC and the TLS 1.3 session, decerter: %q, expected: %q, logs: %s", decerterKeyLog, expected, logs.String())
		return
	}

	// the servers of the old versions wrote a CLIENT_RANDOM line each, decerter none
	for _, line := range keyLogLines(oldKeyLog.String()) {
		if slices.Contains(decerterKeyLog, line) {
			state.Errorf("Test of the secrets uprobes failed, decerter keylog should print nothing of TLS 1.0 and 1.1, line: %q", line)
			return
		}
	}
}

// build the QUIC server of assets/quic_server.c, run it as root and openssl s_client -quic as the test user, which sends a line and gets its echo;
// keyLog is what s_client writes into its key log, without EXPORTER_SECRET which decerter does not keep
// it skips when the host has no C compiler, no OpenSSL with the QUIC server API (3.5 or newer) or an openssl without -quic
func exchangeQUIC(state *testing.T) (keyLog []string) {
	directory := state.TempDir()
	serverPath := filepath.Join(directory, "quic_server")
	_, err := runCommand(state.Context(), "cc", "-std=gnu17", "-O2", "-Wall", "-Werror", "-o", serverPath, filepath.Join("assets", "quic_server.c"), "-l:libssl.so.3", "-l:libcrypto.so.3")

	if err != nil {
		state.Skipf("the QUIC server needs cc and OpenSSL 3.5 or newer with its QUIC server API: %s", err.Error())
	}

	ctx, cancel := context.WithTimeout(state.Context(), commandTimeout)
	defer cancel()
	server := exec.CommandContext(ctx, serverPath, filepath.Join("assets", "server_rsa.crt"), filepath.Join("assets", "server_rsa.key"))
	server.WaitDelay = time.Second
	serverOutput, err := server.StdoutPipe()

	if err != nil {
		state.Fatalf("Could not make the stdout of the QUIC server, error: %s", err.Error())
	}

	serverErrors := &strings.Builder{}
	server.Stderr = serverErrors
	err = server.Start()

	if err != nil {
		state.Fatalf("Could not start the QUIC server, error: %s", err.Error())
	}

	// the server waits for the client to close, which s_client never does on its own
	defer func() {
		cancel()

		if waitErr := server.Wait(); (waitErr != nil) && (ctx.Err() == nil) {
			state.Errorf("Test of the secrets uprobes failed, the QUIC server failed, error: %s: %s", waitErr.Error(), serverErrors.String())
		}
	}()

	port, err := bufio.NewReader(serverOutput).ReadString('\n')

	if err != nil {
		state.Fatalf("Could not read the port of the QUIC server, error: %s: %s", err.Error(), serverErrors.String())
	}

	// the key log of s_client goes into a directory of the test user, the test's own directory is root's
	keyLogDirectory, err := os.MkdirTemp("", "decerter-e2e-quic-")

	if err != nil {
		state.Fatalf("Could not make the key log directory, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if removeErr := os.RemoveAll(keyLogDirectory); removeErr != nil {
			state.Errorf("Could not remove %s, error: %s", keyLogDirectory, removeErr.Error())
		}
	})

	err = os.Chown(keyLogDirectory, int(testUser.UID), int(testUser.GID))

	if err != nil {
		state.Fatalf("Could not give the key log directory to the test user, error: %s", err.Error())
	}

	keyLogPath := filepath.Join(keyLogDirectory, "quic.log")
	client := exec.CommandContext(ctx, "openssl", "s_client", "-quic", "-alpn", "decerter", "-connect", "127.0.0.1:"+strings.TrimSpace(port), "-quiet", "-keylogfile", keyLogPath)
	client.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: testUser.UID, Gid: testUser.GID, Groups: []uint32{}, NoSetGroups: false}}
	client.Dir = "/"
	client.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	client.WaitDelay = time.Second
	clientErrors := &strings.Builder{}
	client.Stderr = clientErrors
	clientInput, err := client.StdinPipe()

	if err != nil {
		state.Fatalf("Could not make the stdin of openssl s_client, error: %s", err.Error())
	}

	clientOutput, err := client.StdoutPipe()

	if err != nil {
		state.Fatalf("Could not make the stdout of openssl s_client, error: %s", err.Error())
	}

	err = client.Start()

	if err != nil {
		state.Fatalf("Could not start openssl s_client, error: %s", err.Error())
	}

	// s_client stays until it is killed, its error then is the kill
	defer func() {
		cancel()

		if waitErr := client.Wait(); (waitErr != nil) && (ctx.Err() == nil) {
			state.Errorf("Test of the secrets uprobes failed, openssl s_client failed, error: %s: %s", waitErr.Error(), clientErrors.String())
		}
	}()

	_, err = io.WriteString(clientInput, "hello\n")

	if err != nil {
		state.Fatalf("Could not write to openssl s_client, error: %s", err.Error())
	}

	echo, err := bufio.NewReader(clientOutput).ReadString('\n')

	if (err != nil) || (echo != "echo hello\n") {
		// an openssl without QUIC support says so on stderr and leaves
		if strings.Contains(clientErrors.String(), "-quic") {
			state.Skipf("openssl s_client of this host has no -quic: %s", clientErrors.String())
		}

		state.Fatalf("Test of the secrets uprobes failed, openssl s_client should get the echo over QUIC, echo: %q, error: %v, client: %s, server: %s", echo, err, clientErrors.String(), serverErrors.String())
	}

	// the four TLS 1.3 secrets are written before the first stream data
	written, err := os.ReadFile(keyLogPath)

	if err != nil {
		state.Fatalf("Could not read the key log of openssl s_client, error: %s", err.Error())
	}

	for _, line := range keyLogLines(string(written)) {
		if !strings.HasPrefix(line, "EXPORTER_SECRET ") {
			keyLog = append(keyLog, line)
		}
	}

	if len(keyLog) != 4 {
		state.Fatalf("Test of the secrets uprobes failed, openssl s_client should write four key log lines, key log: %q", written)
	}

	return
}
