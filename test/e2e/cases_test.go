// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"fmt"
	"testing"

	"github.com/decerter/decerter/internal/intercept"
)

// one curl call against a fresh server: Arguments come before the URL, Expected is the path the server must receive
type curlCase struct {
	Name      string
	Server    serverConfig
	Arguments []string
	Expected  receivedRequest
}

// Test if the legacy GET / to GET /test rewrite reaches the server.
func TestLegacyHTTP1Positive(state *testing.T) {
	startDecerter(state, InterceptDecerterMode, "", []intercept.Rule{getRule{}})
	positiveCases := []curlCase{
		{
			Name:      "plain",
			Server:    serverConfig{Certificate: nil, Version: 0, CipherSuite: 0, HTTP2: false},
			Arguments: []string{"--http1.1"},
			Expected:  receivedRequest{Path: "/test", Proto: "HTTP/1.1", Version: 0, CipherSuite: 0},
		},
	}

	for _, positive := range positiveCases {
		err := testCurl(state, testUser, positive)

		if err != nil {
			state.Errorf("Test of the legacy HTTP/1.1 rewrite failed, case: %s, error: %s", positive.Name, err.Error())
		}
	}
}

// start the case's server, run curl as runAs and check what curl and the server saw; the server answers with the path it got
func testCurl(state *testing.T, runAs account, testCase curlCase) (err error) {
	server := startServer(state, testCase.Server)
	output, curlErr := runCurl(state.Context(), runAs, append(testCase.Arguments, server.URL))

	if err = curlErr; err != nil {
		return
	}

	request, receivedErr := server.received()

	if err = receivedErr; err != nil {
		return
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
