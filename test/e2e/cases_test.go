// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/tlsrecord"
)

// one curl call against a fresh server: Suite is the OpenSSL name curl is pinned to, empty for curl's default
// Expected is what the server must see, a CipherSuite of 0 accepts any suite
type curlCase struct {
	Name     string
	Server   serverConfig
	Suite    string
	Expected receivedRequest
}

// one row of the table of supported cipher suites in eproxy's README
type suiteRow struct {
	IANA    string
	OpenSSL string
	ID      uint16
}

var (
	// the lines of the DTLS cases, none is part of another
	dtlsLine       = "dtls line from the client"
	dtlsEditedLine = "DTLS LINE EDITED BY DECERTER"
	dtlsGrowLine   = "dtls line that grows"
	dtlsGrownLine  = "DTLS LINE GROWN BY DECERTER:" + strings.Repeat(" grown", 400) + " END"
	// the line openssl s_server sends back
	dtlsServerLine       = "dtls line from the server"
	dtlsServerEditedLine = "DTLS SERVER LINE EDITED BY DECERTER"
	// the suites of the record layer that OpenSSL has for DTLS 1.2: every one of suiteRows but the TLS 1.3, 3DES and RC4 ones
	dtlsSuites = []string{
		"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA256",
		"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES128-SHA", "ECDHE-ECDSA-AES256-SHA", "ECDHE-ECDSA-AES128-SHA256",
		"AES128-GCM-SHA256", "AES256-GCM-SHA384", "AES128-SHA", "AES256-SHA", "AES128-SHA256",
	}
)

var (
	suiteRows = []suiteRow{
		{IANA: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", OpenSSL: "ECDHE-RSA-CHACHA20-POLY1305", ID: tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
		{IANA: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", OpenSSL: "ECDHE-ECDSA-CHACHA20-POLY1305", ID: tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305},
		{IANA: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", OpenSSL: "ECDHE-RSA-AES128-GCM-SHA256", ID: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		{IANA: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", OpenSSL: "ECDHE-ECDSA-AES128-GCM-SHA256", ID: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		{IANA: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", OpenSSL: "ECDHE-RSA-AES256-GCM-SHA384", ID: tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		{IANA: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", OpenSSL: "ECDHE-ECDSA-AES256-GCM-SHA384", ID: tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		{IANA: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", OpenSSL: "ECDHE-RSA-AES128-SHA256", ID: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256},
		{IANA: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", OpenSSL: "ECDHE-RSA-AES128-SHA", ID: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		{IANA: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", OpenSSL: "ECDHE-ECDSA-AES128-SHA256", ID: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256},
		{IANA: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", OpenSSL: "ECDHE-ECDSA-AES128-SHA", ID: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		{IANA: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", OpenSSL: "ECDHE-RSA-AES256-SHA", ID: tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
		{IANA: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", OpenSSL: "ECDHE-ECDSA-AES256-SHA", ID: tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		{IANA: "TLS_RSA_WITH_AES_128_GCM_SHA256", OpenSSL: "AES128-GCM-SHA256", ID: tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
		{IANA: "TLS_RSA_WITH_AES_256_GCM_SHA384", OpenSSL: "AES256-GCM-SHA384", ID: tls.TLS_RSA_WITH_AES_256_GCM_SHA384},
		{IANA: "TLS_RSA_WITH_AES_128_CBC_SHA256", OpenSSL: "AES128-SHA256", ID: tls.TLS_RSA_WITH_AES_128_CBC_SHA256},
		{IANA: "TLS_RSA_WITH_AES_128_CBC_SHA", OpenSSL: "AES128-SHA", ID: tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		{IANA: "TLS_RSA_WITH_AES_256_CBC_SHA", OpenSSL: "AES256-SHA", ID: tls.TLS_RSA_WITH_AES_256_CBC_SHA},
		{IANA: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", OpenSSL: "ECDHE-RSA-DES-CBC3-SHA", ID: tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
		{IANA: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", OpenSSL: "DES-CBC3-SHA", ID: tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
		{IANA: "TLS_RSA_WITH_RC4_128_SHA", OpenSSL: "RC4-SHA", ID: tls.TLS_RSA_WITH_RC4_128_SHA},
		{IANA: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", OpenSSL: "ECDHE-RSA-RC4-SHA", ID: tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
		{IANA: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", OpenSSL: "ECDHE-ECDSA-RC4-SHA", ID: tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
		{IANA: "TLS_AES_128_GCM_SHA256", OpenSSL: "TLS_AES_128_GCM_SHA256", ID: tls.TLS_AES_128_GCM_SHA256},
		{IANA: "TLS_CHACHA20_POLY1305_SHA256", OpenSSL: "TLS_CHACHA20_POLY1305_SHA256", ID: tls.TLS_CHACHA20_POLY1305_SHA256},
		{IANA: "TLS_AES_256_GCM_SHA384", OpenSSL: "TLS_AES_256_GCM_SHA384", ID: tls.TLS_AES_256_GCM_SHA384},
	}
)

// Test if the legacy GET / to GET /test rewrite reaches the server over plain HTTP/1.1, TLS 1.2 with RSA and ECDSA, and TLS 1.3.
func TestLegacyHTTP1Positive(state *testing.T) {
	startDecerter(state, InterceptDecerterMode, "", []intercept.Rule{getRule{}, newHeadersRule()})

	for _, positive := range legacyCases(false, "/test") {
		err := testCurl(state, testUser, positive)

		if err != nil {
			state.Errorf("Test of the legacy HTTP/1.1 rewrite failed, case: %s, error: %s", positive.Name, err.Error())
		}
	}
}

// Test if the legacy GET / to GET /test rewrite leaves the flows of an unselected user alone.
func TestLegacyHTTP1Negative(state *testing.T) {
	startDecerter(state, InterceptDecerterMode, "", []intercept.Rule{getRule{}, newHeadersRule()})

	for _, negative := range legacyCases(false, "/") {
		err := testCurl(state, otherUser, negative)

		if err != nil {
			state.Errorf("Test of the legacy HTTP/1.1 rewrite failed, case: %s, error: %s", negative.Name, err.Error())
		}
	}
}

// Test if the HTTP/2 HEADERS rewrite of :path / to /test reaches the server over h2c, TLS 1.2 with RSA and ECDSA, and TLS 1.3.
func TestLegacyHTTP2Positive(state *testing.T) {
	rule := newHeadersRule()
	startDecerter(state, InterceptDecerterMode, "", []intercept.Rule{getRule{}, rule})
	positiveCases := legacyCases(true, "/test")

	for _, positive := range positiveCases {
		err := testCurl(state, testUser, positive)

		if err != nil {
			state.Errorf("Test of the legacy HTTP/2 rewrite failed, case: %s, error: %s", positive.Name, err.Error())
		}
	}

	rewritten, spanned := rule.stats()
	state.Logf("HTTP/2 header blocks rewritten: %d, frames across messages: %d", rewritten, spanned)

	if rewritten != len(positiveCases) {
		state.Errorf("Test of the legacy HTTP/2 rewrite failed, rewritten should be %v, rewritten: %v", len(positiveCases), rewritten)
		return
	}
}

// Test if the HTTP/2 HEADERS rewrite leaves the flows of an unselected user alone.
func TestLegacyHTTP2Negative(state *testing.T) {
	rule := newHeadersRule()
	startDecerter(state, InterceptDecerterMode, "", []intercept.Rule{getRule{}, rule})

	for _, negative := range legacyCases(true, "/") {
		err := testCurl(state, otherUser, negative)

		if err != nil {
			state.Errorf("Test of the legacy HTTP/2 rewrite failed, case: %s, error: %s", negative.Name, err.Error())
		}
	}

	rewritten, _ := rule.stats()

	if rewritten != 0 {
		state.Errorf("Test of the legacy HTTP/2 rewrite failed, rewritten should be %v, rewritten: %v", 0, rewritten)
		return
	}
}

// Test if every cipher suite of eproxy's README is rewritten in both directions, a suite this host or decerter can't run is skipped with the reason: over HTTP/1.1
// curl asks for / twice on one connection, GET / becomes GET /test and the head of each request and answer grows past one record, so the later records of
// both directions go on with other sequence numbers, and the answer /test becomes /TEST; over HTTP/2 the HEADERS rewrite and the /TEST of the DATA frame.
func TestCipherSuitesPositive(state *testing.T) {
	startDecerter(state, InterceptDecerterMode, "", []intercept.Rule{getRule{}, newHeadersRule(), splitRule{}})

	for _, isHTTP2 := range []bool{false, true} {
		protocolName := "http1.1"

		if isHTTP2 {
			protocolName = "http2"
		}

		state.Run(protocolName, func(state *testing.T) {
			for _, row := range suiteRows {
				state.Run(row.OpenSSL, func(state *testing.T) {
					reason := skipReason(state.Context(), row)

					if reason != "" {
						state.Skip(reason)
					}

					positive := suiteCase(row, isHTTP2)
					err := testMatrixCurl(state, positive)

					if err != nil {
						state.Errorf("Test of the cipher suite %s failed, case: %s, error: %s", row.IANA, positive.Name, err.Error())
					}
				})
			}
		})
	}
}

// one DTLS 1.2 session: openssl s_client sends Line with Suite (empty is OpenSSL's default) and Arguments, the server has to print Expected; then the
// server sends dtlsServerLine and the client has to print ServerExpected; Certificate names the server's certificate in assets
type dtlsCase struct {
	Name           string
	Suite          string
	Certificate    string
	Arguments      []string
	Line           string
	Expected       string
	ServerExpected string
}

// Test if the DTLS rule changes the lines of both directions between openssl s_client and openssl s_server over DTLS 1.2 with every suite of the record
// layer OpenSSL has for DTLS: AES-GCM, ChaCha20-Poly1305 and AES-CBC, with and without encrypt-then-MAC, ECDHE and RSA key exchange, RSA and ECDSA
// certificates; and an edit that no longer fits one datagram. The sessions run at the same time.
func TestDTLSPositive(state *testing.T) {
	startDecerter(state, InterceptDecerterMode, "", []intercept.Rule{newDTLSRule()})
	testDTLSCases(state, testUser, dtlsCases(true))
}

// Test if the DTLS rule leaves the sessions of an unselected user alone.
func TestDTLSNegative(state *testing.T) {
	startDecerter(state, InterceptDecerterMode, "", []intercept.Rule{newDTLSRule()})
	testDTLSCases(state, otherUser, dtlsCases(false))
}

// each case as a parallel subtest, the originals of edited lines must not reach the peer
func testDTLSCases(state *testing.T, runAs account, testCases []dtlsCase) {
	for _, testCase := range testCases {
		state.Run(testCase.Name, func(state *testing.T) {
			// s_client takes half a second to leave a DTLS session
			state.Parallel()
			server := startOpenSSLServer(state, true, testCase.Certificate, 1)
			arguments := append([]string{"-nocommands"}, testCase.Arguments...)

			if testCase.Suite != "" {
				arguments = append(arguments, "-cipher", testCase.Suite)
			}

			client := startOpenSSLClient(state, runAs, server, true, arguments...)
			err := exchangeLines(client, server, testCase.Line, testCase.Expected, dtlsServerLine, testCase.ServerExpected)
			err = errors.Join(err, client.finish())

			if err != nil {
				state.Errorf("Test of the DTLS rewrite failed, case: %s, error: %s", testCase.Name, err.Error())
			}
		})
	}
}

// the client sends line and the server has to print expected, then the server sends serverLine and the client has to print serverExpected; the
// original of an edited line must not reach the peer
func exchangeLines(client opensslPeer, server opensslPeer, line string, expected string, serverLine string, serverExpected string) (err error) {
	err = client.send(line)

	if err != nil {
		return
	}

	output, found := server.waitFor(expected, commandTimeout)

	if !found || ((line != expected) && strings.Contains(output, line)) {
		err = fmt.Errorf("server should print %q and not %q, output:\n%s", expected, line, output)
		return
	}

	err = server.send(serverLine)

	if err != nil {
		return
	}

	output, found = client.waitFor(serverExpected, commandTimeout)

	if !found || ((serverLine != serverExpected) && strings.Contains(output, serverLine)) {
		err = fmt.Errorf("client should print %q and not %q, output:\n%s", serverExpected, serverLine, output)
		return
	}

	return
}

// the rule of the DTLS cases: the short line becomes another one, the long one grows past what a datagram of MinDatagramLength holds, so it goes on as
// several records; the server's line becomes another one too
func newDTLSRule() (rule dtlsRule) {
	rule = dtlsRule{replacements: map[string]string{dtlsLine: dtlsEditedLine, dtlsGrowLine: dtlsGrownLine, dtlsServerLine: dtlsServerEditedLine}}
	return
}

// the DTLS sessions of the tests, isEdited expects what the rule makes of the lines
func dtlsCases(isEdited bool) (cases []dtlsCase) {
	cases = []dtlsCase{
		{Name: "default suite", Suite: "", Certificate: "server_rsa", Arguments: nil, Line: dtlsLine, Expected: dtlsEditedLine},
		{Name: "grown past one datagram", Suite: "", Certificate: "server_rsa", Arguments: nil, Line: dtlsGrowLine, Expected: dtlsGrownLine},
		{Name: "cbc without encrypt-then-mac", Suite: "ECDHE-RSA-AES128-SHA", Certificate: "server_rsa", Arguments: []string{"-no_etm"}, Line: dtlsLine, Expected: dtlsEditedLine},
	}

	for _, suite := range dtlsSuites {
		certificate := "server_rsa"

		if strings.Contains(suite, "-ECDSA-") {
			certificate = "server_ecdsa"
		}

		cases = append(cases, dtlsCase{Name: suite, Suite: suite, Certificate: certificate, Arguments: nil, Line: dtlsLine, Expected: dtlsEditedLine})
	}

	for index := range cases {
		cases[index].ServerExpected = dtlsServerEditedLine

		if !isEdited {
			cases[index].Expected = cases[index].Line
			cases[index].ServerExpected = dtlsServerLine
		}
	}

	return
}

// the legacy calls of eproxy's tests: plain HTTP, TLS 1.2 with each certificate and TLS 1.3, all asking for /
func legacyCases(isHTTP2 bool, path string) (cases []curlCase) {
	proto := "HTTP/1.1"

	if isHTTP2 {
		proto = "HTTP/2.0"
	}

	cases = []curlCase{
		{
			Name:     "plain",
			Server:   serverConfig{Certificate: nil, Version: 0, CipherSuite: 0, HTTP2: isHTTP2},
			Suite:    "",
			Expected: receivedRequest{Path: path, Proto: proto, Version: 0, CipherSuite: 0},
		},
		{
			Name:     "tls1.2 rsa",
			Server:   serverConfig{Certificate: &rsaCertificate, Version: tls.VersionTLS12, CipherSuite: 0, HTTP2: isHTTP2},
			Suite:    "",
			Expected: receivedRequest{Path: path, Proto: proto, Version: tls.VersionTLS12, CipherSuite: 0},
		},
		{
			Name:     "tls1.2 ecdsa",
			Server:   serverConfig{Certificate: &ecdsaCertificate, Version: tls.VersionTLS12, CipherSuite: 0, HTTP2: isHTTP2},
			Suite:    "",
			Expected: receivedRequest{Path: path, Proto: proto, Version: tls.VersionTLS12, CipherSuite: 0},
		},
		{
			Name:     "tls1.3",
			Server:   serverConfig{Certificate: &rsaCertificate, Version: tls.VersionTLS13, CipherSuite: 0, HTTP2: isHTTP2},
			Suite:    "",
			Expected: receivedRequest{Path: path, Proto: proto, Version: tls.VersionTLS13, CipherSuite: 0},
		},
	}
	return
}

// a README row as a call: the server is pinned to the version and, for TLS 1.2, to the suite, curl to the suite; ECDSA suites get the ECDSA certificate
func suiteCase(row suiteRow, isHTTP2 bool) (testCase curlCase) {
	version := uint16(tls.VersionTLS12)
	serverSuite := row.ID
	proto := "HTTP/1.1"

	if !strings.Contains(row.IANA, "_WITH_") {
		version = tls.VersionTLS13
		serverSuite = 0
	}

	if isHTTP2 {
		proto = "HTTP/2.0"
	}

	certificate := &rsaCertificate

	if strings.Contains(row.IANA, "_ECDSA_") {
		certificate = &ecdsaCertificate
	}

	// the split rule grows only an HTTP/1.1 head
	grown := grownLength

	if isHTTP2 {
		grown = 0
	}

	testCase = curlCase{
		Name:     fmt.Sprintf("%s %s", strings.ToLower(proto), row.OpenSSL),
		Server:   serverConfig{Certificate: certificate, Version: version, CipherSuite: serverSuite, HTTP2: isHTTP2},
		Suite:    row.OpenSSL,
		Expected: receivedRequest{Path: "/test", Proto: proto, Version: version, CipherSuite: row.ID, Grown: grown},
	}
	return
}

// the README row of an OpenSSL name, it has to be in suiteRows
func rowByName(name string) (row *suiteRow) {
	row = &suiteRows[slices.IndexFunc(suiteRows, func(row suiteRow) (isRow bool) {
		isRow = (row.OpenSSL == name)
		return
	})]
	return
}

// why a README row can't run here, empty when it can: decerter's record layer, Go's crypto/tls and the system OpenSSL must all have the suite, every missing one is named
func skipReason(ctx context.Context, row suiteRow) (reason string) {
	var reasons []string

	if strings.HasPrefix(tlsrecord.CipherSuiteName(row.ID), "0x") {
		reasons = append(reasons, fmt.Sprintf("decerter's record layer (internal/tlsrecord) can't decrypt %s", row.IANA))
	}

	goSuites := slices.Concat(tls.CipherSuites(), tls.InsecureCipherSuites())

	if !slices.ContainsFunc(goSuites, func(suite *tls.CipherSuite) bool { return suite.ID == row.ID }) {
		reasons = append(reasons, fmt.Sprintf("Go's crypto/tls has no %s for the test server", row.IANA))
	}

	// the TLS 1.2 name is the cipher list, a TLS 1.3 name goes into -ciphersuites
	arguments := []string{"ciphers", "-s", "-tls1_2", row.OpenSSL}

	if !strings.Contains(row.IANA, "_WITH_") {
		arguments = []string{"ciphers", "-s", "-tls1_3", "-ciphersuites", row.OpenSSL}
	}

	_, err := runCommand(ctx, "openssl", arguments...)

	if err != nil {
		reasons = append(reasons, fmt.Sprintf("the system OpenSSL has no %s (%s)", row.OpenSSL, strings.ReplaceAll(err.Error(), "\n", " ")))
	}

	reason = strings.Join(reasons, "; ")
	return
}

// start the case's server, run curl as runAs and check what curl and the server saw; the server answers with the path it got
func testCurl(state *testing.T, runAs account, testCase curlCase) (err error) {
	server := startServer(state, testCase.Server)
	output, curlErr := runCurl(state.Context(), runAs, curlArguments(testCase, server.URL))

	if err = curlErr; err != nil {
		return
	}

	request, receivedErr := server.received()

	if err = receivedErr; err != nil {
		return
	}

	// a case without a pinned suite takes the one curl and the server agreed on
	if testCase.Expected.CipherSuite == 0 {
		request.CipherSuite = 0
	}

	if request != testCase.Expected {
		err = fmt.Errorf("server request return value was not %+v instead: %+v", testCase.Expected, request)
		return
	}

	if output != testCase.Expected.Path {
		err = fmt.Errorf("curl output return value was not %v instead: %v", testCase.Expected.Path, output)
		return
	}

	return
}

// testCurl for the rules of TestCipherSuitesPositive: HTTP/1.1 asks for / twice on one connection, the second request and answer go after a split
// record of each direction; curl prints the answer and the X-Decerter-Grown field the split rule gave it, and every request has to reach the server as expected
func testMatrixCurl(state *testing.T, testCase curlCase) (err error) {
	server := startServer(state, testCase.Server)
	arguments := curlArguments(testCase, server.URL)
	requests := 1
	expected := matrixAnswer

	if !testCase.Server.HTTP2 {
		requests = 2
		field := strings.Repeat(string(serverGrownByte), grownLength)
		arguments = append(arguments, server.URL, "--write-out", "%header{"+grownHeaderName+"}|%{num_connects}\n")
		expected = matrixAnswer + field + "|1\n" + matrixAnswer + field + "|0\n"
	}

	output, err := runCurl(state.Context(), testUser, arguments)

	if err != nil {
		return
	}

	for index := range requests {
		request, receivedErr := server.received()

		if err = receivedErr; err != nil {
			return
		}

		if request != testCase.Expected {
			err = fmt.Errorf("server request %d return value was not %+v instead: %+v", index+1, testCase.Expected, request)
			return
		}
	}

	if output != expected {
		err = fmt.Errorf("curl output return value was not %s instead: %s", shorten(expected), shorten(output))
		return
	}

	return
}

// text with every run of more than 16 equal bytes written as the byte and its count, so a grown header field fits an error message
func shorten(text string) (short string) {
	var builder strings.Builder

	for index := 0; index < len(text); {
		end := index

		for (end < len(text)) && (text[end] == text[index]) {
			end++
		}

		if end-index > 16 {
			fmt.Fprintf(&builder, "<%q x %d>", text[index], end-index)
		} else {
			builder.WriteString(text[index:end])
		}

		index = end
	}

	short = fmt.Sprintf("%q", builder.String())
	return
}

// curl's options for a case: the HTTP version, the server key for TLS, and the TLS version and suite the server is pinned to
func curlArguments(testCase curlCase, url string) (arguments []string) {
	config := testCase.Server

	switch {
	case config.HTTP2 && (config.Certificate == nil):
		arguments = append(arguments, "--http2-prior-knowledge")
	case config.HTTP2:
		arguments = append(arguments, "--http2")
	default:
		arguments = append(arguments, "--http1.1")
	}

	if config.Certificate != nil {
		arguments = append(arguments, "--insecure", "--pinnedpubkey", config.Certificate.Pin)
	}

	switch config.Version {
	case tls.VersionTLS12:
		arguments = append(arguments, "--tlsv1.2", "--tls-max", "1.2")

		if testCase.Suite != "" {
			arguments = append(arguments, "--ciphers", testCase.Suite)
		}
	case tls.VersionTLS13:
		arguments = append(arguments, "--tlsv1.3", "--tls-max", "1.3")

		if testCase.Suite != "" {
			arguments = append(arguments, "--tls13-ciphers", testCase.Suite)
		}
	}

	arguments = append(arguments, url)
	return
}
