// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/intercept"
)

const (
	// a second loopback address: the local 127.0.0.0/8 routes it, routePrefix lies between that and 127.0.0.1's local /32
	secondLoopback string = "127.0.0.2"
	routePrefix    string = "127.0.0.0/16"
	// the route sync waits 100 ms after a netlink event before it reads the routes again
	routeTimeout time.Duration = 5 * time.Second
	// curl's exit status when it can't connect
	curlConnectFailed int = 7
)

// Test if decerter redirects a destination by its longest route, as route_map's lookup per prefix length has to find it: 127.0.0.2 by the local
// 127.0.0.0/8, then not at all once an unreachable 127.0.0.0/16 is longer, and 127.0.0.1 by its local /32 either way. The kernel routes by the
// same prefixes, so curl to 127.0.0.2 then fails to connect (exit status 7); a redirect would have reached decerter's proxy instead, which accepts.
func TestRoutePositive(state *testing.T) {
	flags := testFlags()
	flags.DestinationCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	startFilteredDecerter(state, InterceptDecerterMode, "", []intercept.Rule{getRule{}}, flags, "")
	first := legacyCases(false, "/test")[0]
	second := first
	second.Server.Host = secondLoopback
	waitCurl(state, "127.0.0.2 by 127.0.0.0/8", second)
	// started before the route, which makes 127.0.0.2 unreachable for listen too
	server := startServer(state, second.Server)
	_, err := runCommand(state.Context(), "ip", "route", "add", "unreachable", routePrefix)

	if err != nil {
		state.Fatalf("Could not add the route, error: %s", err.Error())
	}

	state.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()

		if _, deleteErr := runCommand(ctx, "ip", "route", "del", "unreachable", routePrefix); deleteErr != nil {
			state.Errorf("Could not delete the route, error: %s", deleteErr.Error())
		}
	})

	deadline := time.Now().Add(routeTimeout)

	for {
		_, curlErr := runCurl(state.Context(), testUser, curlArguments(second, server.URL))
		exitErr, isExit := errors.AsType[*exec.ExitError](curlErr)

		if isExit && (exitErr.ExitCode() == curlConnectFailed) {
			break
		}

		if time.Now().After(deadline) {
			state.Fatalf("Test of the route lookup failed, curl to 127.0.0.2 should fail to connect under the unreachable %s instead of reaching the proxy, error: %v", routePrefix, curlErr)
		}

		time.Sleep(250 * time.Millisecond)
	}

	waitCurl(state, "127.0.0.1 by its local /32", first)
}

// testCurl until it passes or routeTimeout is over, the route sync of decerter follows a route change a little later
func waitCurl(state *testing.T, name string, testCase curlCase) {
	deadline := time.Now().Add(routeTimeout)

	for {
		err := testCurl(state, testUser, testCase)

		if err == nil {
			return
		}

		if time.Now().After(deadline) {
			state.Errorf("Test of the route lookup failed, case: %s, error: %s", name, err.Error())
			return
		}

		time.Sleep(250 * time.Millisecond)
	}
}
