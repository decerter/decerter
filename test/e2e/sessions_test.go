// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/tlsrecord"
)

const (
	// the lines of the openssl s_client and s_server sessions, a number goes after each; the rules of sessionRuleRequests change them
	sessionClientLine   string = "client says hello"
	sessionClientEdited string = "CLIENT SAYS HELLO, EDITED BY DECERTER"
	sessionServerLine   string = "server says hello"
	sessionServerEdited string = "SERVER SAYS HELLO, EDITED BY DECERTER"
	// what s_server -trace writes for the extension, once for the ClientHello and once for the ServerHello that takes it
	etmTrace string = "encrypt_then_mac(22)"
	// what s_server -trace writes for a KeyUpdate message, sent or received
	keyUpdateTrace string = "KeyUpdate, Length=1"
	// s_client and s_server print this when the k or K command sent a KeyUpdate
	keyUpdateCommand string = "KEYUPDATE"
	// what decerter logs for a session the record layer can't take
	relayRawLog string = `"msg":"Could not intercept tls flow, relaying raw"`
)

// one TLS session between openssl s_client and s_server: Version is -tls1_2 or -tls1_3, Suite the only one both have (empty is the default), Certificate
// names the server's in assets, ClientArguments go to s_client
type opensslCase struct {
	Name            string
	Version         string
	Suite           string
	Certificate     string
	ClientArguments []string
}

var (
	// the AES-CBC suites of the record layer; OpenSSL takes encrypt-then-MAC for them, Go's crypto/tls of the cipher-suite matrix has none
	cbcSuites = []string{"ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA256", "ECDHE-ECDSA-AES128-SHA", "ECDHE-ECDSA-AES256-SHA", "ECDHE-ECDSA-AES128-SHA256", "AES128-SHA", "AES256-SHA", "AES128-SHA256"}
	// suites the host's OpenSSL has and the record layer does not: CBC with SHA-384 and AES256-SHA256, CCM, DHE, Camellia, and TLS 1.3 CCM
	unsupportedSuites = []string{"AES256-SHA256", "ECDHE-RSA-AES256-SHA384", "ECDHE-ECDSA-AES256-SHA384", "AES128-CCM", "ECDHE-ECDSA-AES128-CCM", "DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-CHACHA20-POLY1305", "CAMELLIA128-SHA256", "TLS_AES_128_CCM_SHA256"}
)

// Test if decerter run --intercept with rules of the API changes the lines of both directions between openssl s_client and s_server, OpenSSL at both ends:
// every AES-CBC suite with encrypt-then-MAC, which s_server's trace has to show, and one without; a TLS 1.2 and a TLS 1.3 session resumed by a second
// s_client; and a TLS 1.3 session with KeyUpdate messages of both sides, the client's second asking for the server's.
func TestOpenSSLSessionsPositive(state *testing.T) {
	startSessionDecerter(state)

	for _, suite := range cbcSuites {
		state.Run("encrypt-then-mac "+suite, func(state *testing.T) {
			state.Parallel()
			testCase := opensslSuiteCase(suite)
			testCase.ClientArguments = []string{"-nocommands"}
			testEncryptThenMAC(state, testCase, 2)
		})
	}

	state.Run("cbc without encrypt-then-mac", func(state *testing.T) {
		state.Parallel()
		testCase := opensslSuiteCase(cbcSuites[0])
		testCase.ClientArguments = []string{"-nocommands", "-no_etm"}
		testEncryptThenMAC(state, testCase, 0)
	})

	for _, testCase := range []opensslCase{{Name: "resumption tls1.2", Version: "-tls1_2", Suite: "ECDHE-RSA-AES128-SHA", Certificate: "server_rsa", ClientArguments: nil}, {Name: "resumption tls1.3", Version: "-tls1_3", Suite: "", Certificate: "server_rsa", ClientArguments: nil}} {
		state.Run(testCase.Name, func(state *testing.T) {
			state.Parallel()
			testResumption(state, testCase)
		})
	}

	state.Run("keyupdate tls1.3", func(state *testing.T) {
		state.Parallel()
		testKeyUpdate(state)
	})
}

// Test if the sessions of every suite in unsupportedSuites go on raw through decerter run --intercept: the lines of both directions arrive as they were sent,
// decerter logs that it relays the flow raw with the suite, and no rule changed anything.
func TestOpenSSLSessionsNegative(state *testing.T) {
	logs, client := startSessionDecerter(state)
	suites := []string{}

	for _, suite := range unsupportedSuites {
		state.Run(suite, func(state *testing.T) {
			testCase := opensslSuiteCase(suite)
			arguments := []string{"ciphers", "-s", "-tls1_2", suite}

			if testCase.Version == "-tls1_3" {
				arguments = []string{"ciphers", "-s", "-tls1_3", "-ciphersuites", suite}
			}

			if _, err := runCommand(state.Context(), "openssl", arguments...); err != nil {
				state.Skipf("the system OpenSSL has no %s: %s", suite, err.Error())
			}

			suites = append(suites, suite)
			server, sessionClient := startSession(state, testCase, 1)
			err := exchangeLines(sessionClient, server, sessionClientLine+" 1", sessionClientLine+" 1", sessionServerLine+" 1", sessionServerLine+" 1")
			err = errors.Join(err, sessionClient.finish())

			if err != nil {
				state.Errorf("Test of the unsupported suite %s failed, the lines should arrive as they were sent, error: %s", suite, err.Error())
			}
		})
	}

	// one relay line per session, each with the suite of its ServerHello
	relayed := 0

	for line := range strings.Lines(logs.String()) {
		if strings.Contains(line, relayRawLog) && strings.Contains(line, tlsrecord.ErrUnsupportedCipherSuite.Error()) {
			relayed++
		}
	}

	rules := v1.RuleList{}
	_, err := client.call(state.Context(), http.MethodGet, "/rules", nil, &rules)
	hits := uint64(0)

	for _, rule := range rules.Rules {
		hits += rule.Hits
	}

	if (err != nil) || (relayed != len(suites)) || (hits != 0) {
		state.Errorf("Test of the unsupported suites failed, decerter should relay the %d sessions of %v raw and change nothing, relayed: %d, rule hits: %d, error: %v, logs:\n%s", len(suites), suites, relayed, hits, err, logs.String())
	}
}

// decerter run --intercept selecting the test user with the rules of sessionRuleRequests, its logs and a client of its API
func startSessionDecerter(state *testing.T) (logs *lockedBuffer, client apiClient) {
	socket := filepath.Join(state.TempDir(), "api.sock")
	_, logs, _ = startDecerterCommandLogs(state, []string{"Redirecting flows"}, "run", "--uid", strconv.FormatUint(uint64(testUser.UID), 10), "--intercept", "--api-socket", socket)
	client = socketClient(socket)
	text := func(value string) (textValue v1.Value) {
		textValue = v1.Value{Type: v1.TextValueType, Value: value}
		return
	}
	addRules(state, client, []v1.RuleRequest{
		{Filter: "", Direction: v1.UpDirection, Layer: v1.TLSLayer, Find: text(sessionClientLine), Replace: text(sessionClientEdited)},
		{Filter: "", Direction: v1.DownDirection, Layer: v1.TLSLayer, Find: text(sessionServerLine), Replace: text(sessionServerEdited)},
	})
	return
}

// a session of one suite, TLS 1.2 or 1.3 by its name, the ECDSA certificate for an ECDSA suite
func opensslSuiteCase(suite string) (testCase opensslCase) {
	testCase = opensslCase{Name: suite, Version: "-tls1_2", Suite: suite, Certificate: "server_rsa", ClientArguments: nil}

	if strings.HasPrefix(suite, "TLS_") {
		testCase.Version = "-tls1_3"
	}

	if strings.Contains(suite, "-ECDSA-") {
		testCase.Certificate = "server_ecdsa"
	}

	return
}

// the server of the case for sessions sessions with its extra arguments, and the first client, the test user's
func startSession(state *testing.T, testCase opensslCase, sessions int, serverArguments ...string) (server opensslPeer, client opensslPeer) {
	server = startOpenSSLServer(state, false, testCase.Certificate, sessions, append(suiteArguments(testCase), serverArguments...)...)
	client = startOpenSSLClient(state, testUser, server, false, append(suiteArguments(testCase), testCase.ClientArguments...)...)
	return
}

// the version of the case, and its suite as the cipher list of TLS 1.2 or the suites of TLS 1.3
func suiteArguments(testCase opensslCase) (arguments []string) {
	arguments = []string{testCase.Version}

	switch {
	case testCase.Suite == "":
	case testCase.Version == "-tls1_3":
		arguments = append(arguments, "-ciphersuites", testCase.Suite)
	default:
		arguments = append(arguments, "-cipher", testCase.Suite)
	}

	return
}

// lines of both directions are edited, and s_server's trace has the encrypt_then_mac extension etmCount times: 2 when the ServerHello takes it, 0 when
// the client does not offer it
func testEncryptThenMAC(state *testing.T, testCase opensslCase, etmCount int) {
	tracePath := filepath.Join(state.TempDir(), "server.trace")
	server, client := startSession(state, testCase, 1, "-trace", "-msgfile", tracePath)
	err := exchangeLines(client, server, sessionClientLine+" 1", sessionClientEdited+" 1", sessionServerLine+" 1", sessionServerEdited+" 1")
	err = errors.Join(err, client.finish(), server.finish())
	trace, readErr := os.ReadFile(tracePath)

	if err = errors.Join(err, readErr); (err != nil) || (strings.Count(string(trace), etmTrace) != etmCount) {
		state.Errorf("Test of the CBC session failed, %s, both lines should be edited and the trace should have %s %d times, count: %d, error: %v", testCase.Name, etmTrace, etmCount, strings.Count(string(trace), etmTrace), err)
	}
}

// the first s_client keeps its session in a file, the second one resumes it; both sessions have their lines edited
func testResumption(state *testing.T, testCase opensslCase) {
	// the client runs as the test user and writes the session, the directories of TempDir are root's alone
	directory, err := os.MkdirTemp("", "decerter-session-")

	if err != nil {
		state.Fatalf("Could not make the session directory, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if removeErr := os.RemoveAll(directory); removeErr != nil {
			state.Errorf("Could not remove the session directory, error: %s", removeErr.Error())
		}
	})

	if err = errors.Join(os.Chmod(directory, 0o755), os.Chown(directory, int(testUser.UID), int(testUser.GID))); err != nil {
		state.Fatalf("Could not prepare the session directory, error: %s", err.Error())
	}

	sessionPath := filepath.Join(directory, "session.pem")

	testCase.ClientArguments = []string{"-nocommands", "-sess_out", sessionPath}
	server, client := startSession(state, testCase, 2)
	err = exchangeLines(client, server, sessionClientLine+" 1", sessionClientEdited+" 1", sessionServerLine+" 1", sessionServerEdited+" 1")
	err = errors.Join(err, client.finish())

	if (err != nil) || !strings.Contains(client.output.String(), "New, ") {
		state.Fatalf("Test of the resumption failed, %s, the first session should be new with its lines edited, error: %v, output:\n%s", testCase.Name, err, client.output.String())
	}

	resumed := startOpenSSLClient(state, testUser, server, false, append(suiteArguments(testCase), "-nocommands", "-sess_in", sessionPath)...)
	err = exchangeLines(resumed, server, sessionClientLine+" 2", sessionClientEdited+" 2", sessionServerLine+" 2", sessionServerEdited+" 2")
	err = errors.Join(err, resumed.finish())

	if (err != nil) || !strings.Contains(resumed.output.String(), "Reused, ") {
		state.Errorf("Test of the resumption failed, %s, the second session should be resumed with its lines edited, error: %v, output:\n%s", testCase.Name, err, resumed.output.String())
	}
}

// lines of both directions are edited before and after each KeyUpdate: the client's k, and the client's K, which asks the server for its own
func testKeyUpdate(state *testing.T) {
	tracePath := filepath.Join(state.TempDir(), "server.trace")
	server, client := startSession(state, opensslCase{Name: "keyupdate", Version: "-tls1_3", Suite: "", Certificate: "server_rsa", ClientArguments: nil}, 1, "-trace", "-msgfile", tracePath)
	err := exchangeLines(client, server, sessionClientLine+" 1", sessionClientEdited+" 1", sessionServerLine+" 1", sessionServerEdited+" 1")

	// a command has to be a line of its own, the next line waits until s_client printed KEYUPDATE for it; s_server takes the K's request when it
	// reads, so its next line goes after its own KeyUpdate
	for index, letter := range []string{"k", "K"} {
		if err != nil {
			break
		}

		taken := strings.Count(client.output.String(), keyUpdateCommand)
		err = client.send(letter)

		if (err == nil) && !client.waitCount(keyUpdateCommand, taken+1, commandTimeout) {
			err = fmt.Errorf("the %s command of the client was not taken, output:\n%s", letter, client.output.String())
		}

		if err == nil {
			number := strconv.Itoa(index + 2)
			err = exchangeLines(client, server, sessionClientLine+" "+number, sessionClientEdited+" "+number, sessionServerLine+" "+number, sessionServerEdited+" "+number)
		}
	}

	err = errors.Join(err, client.finish(), server.finish())
	trace, readErr := os.ReadFile(tracePath)

	// received k and K, sent the answer to K
	if err = errors.Join(err, readErr); (err != nil) || (strings.Count(string(trace), keyUpdateTrace) != 3) {
		state.Errorf("Test of the KeyUpdate failed, every line should be edited and the trace should have 3 KeyUpdate messages, count: %d, error: %v", strings.Count(string(trace), keyUpdateTrace), err)
	}
}
