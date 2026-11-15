// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	// documentation addresses (RFC 5737, RFC 3849) of the network namespace of the family test: no IPv4 route covers the first, the IPv6 default
	// route the second
	unroutedIPv4 string = "192.0.2.1:9"
	routedIPv6   string = "[2001:db8::1]:9"
	// what connect says without a route
	unreachableText string = "network is unreachable"
	// where ip netns keeps its namespaces
	netnsDirectory string = "/run/netns"
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

// Test if an IPv4 destination is never redirected by an IPv6 route: in a network namespace with an IPv6 default route and no IPv4 route but the
// loopback ones, connect to 192.0.2.1 fails with ENETUNREACH for tcp and udp with decerter as without it. IPv4 is kept IPv4-mapped in route_map, so
// the ::/0 key masks it to its own key and matched before the lookup was per family. 2001:db8::1, which the ::/0 route covers, is redirected
// to the proxy, which accepts.
func TestRouteFamilyNegative(state *testing.T) {
	namespace := addNetworkNamespace(state)
	_, err := runCommand(state.Context(), "ip", "-n", namespace, "-6", "route", "add", "default", "dev", "lo")

	if err != nil {
		state.Fatalf("Could not add the IPv6 default route, error: %s", err.Error())
	}

	clientPath := copyClient(state)
	before, err := runClientIn(state.Context(), namespace, testUser, clientPath, "connect", unroutedIPv4)

	if (err != nil) || (strings.Count(before, unreachableText) != 2) {
		state.Fatalf("Test of the route family failed, without decerter tcp and udp to %s should be unreachable, output: %q, error: %v", unroutedIPv4, before, err)
	}

	wrapper := []string{"nsenter", "--net=" + filepath.Join(netnsDirectory, namespace), "--"}
	_, _, logs, _ := startDecerterProcessTo(state, nil, wrapper, []string{"Redirecting flows"}, "run", "--uid", strconv.FormatUint(uint64(testUser.UID), 10), "--dst-cidr", "192.0.2.0/24", "--dst-cidr", "2001:db8::/32")
	deadline := time.Now().Add(routeTimeout)

	// the route sync has read the namespace's routes once the IPv6 destination is redirected
	for {
		routed, routedErr := runClientIn(state.Context(), namespace, testUser, clientPath, "connect", routedIPv6)

		if (routedErr == nil) && strings.HasPrefix(routed, "tcp connected\n") {
			break
		}

		if time.Now().After(deadline) {
			state.Fatalf("Test of the route family failed, %s should be redirected to the proxy under the IPv6 default route, output: %q, error: %v, logs:\n%s", routedIPv6, routed, routedErr, logs.String())
		}

		time.Sleep(250 * time.Millisecond)
	}

	after, err := runClientIn(state.Context(), namespace, testUser, clientPath, "connect", unroutedIPv4)

	if (err != nil) || (after != before) {
		state.Errorf("Test of the route family failed, with decerter tcp and udp to %s should be unreachable as without it, output should be %q, output: %q, error: %v", unroutedIPv4, before, after, err)
		return
	}
}

// a network namespace with lo up, deleted when the test ends
func addNetworkNamespace(state *testing.T) (namespace string) {
	namespace = fmt.Sprintf("decerter-e2e-%d", os.Getpid())
	_, err := runCommand(state.Context(), "ip", "netns", "add", namespace)

	if err != nil {
		state.Fatalf("Could not add the network namespace, error: %s", err.Error())
	}

	state.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()

		if _, deleteErr := runCommand(ctx, "ip", "netns", "del", namespace); deleteErr != nil {
			state.Errorf("Could not delete the network namespace, error: %s", deleteErr.Error())
		}
	})

	_, err = runCommand(state.Context(), "ip", "-n", namespace, "link", "set", "lo", "up")

	if err != nil {
		state.Fatalf("Could not set lo up in the network namespace, error: %s", err.Error())
	}

	return
}

// the Go client in a mode as runAs inside the network namespace: nsenter enters it as root, setpriv drops to the user
func runClientIn(ctx context.Context, namespace string, runAs account, path string, mode string, target string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	user := strconv.FormatUint(uint64(runAs.UID), 10)
	group := strconv.FormatUint(uint64(runAs.GID), 10)
	command := exec.CommandContext(commandCtx, "nsenter", "--net="+filepath.Join(netnsDirectory, namespace), "--", "setpriv", "--reuid="+user, "--regid="+group, "--clear-groups", "--", path, target)
	command.Dir = "/"
	command.Env = []string{clientCommandEnvironment + "=" + mode, "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.WaitDelay = time.Second
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	output = stdout.String()

	if err != nil {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return
}

// connect a tcp and a connected udp socket to target: "tcp connected" or the error of connect, the same for udp
func reportConnect(target string) (output string, err error) {
	builder := strings.Builder{}

	for _, network := range []string{"tcp", "udp"} {
		connection, dialErr := net.DialTimeout(network, target, 2*time.Second)

		if dialErr != nil {
			fmt.Fprintf(&builder, "%s %s\n", network, dialErr.Error())
			continue
		}

		fmt.Fprintf(&builder, "%s connected\n", network)
		err = errors.Join(err, connection.Close())
	}

	output = builder.String()
	return
}
