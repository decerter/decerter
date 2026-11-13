// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package cmd

import (
	"bytes"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/android"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/ui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Test if the flag parsers return with the expected output, several values in one flag and repeated flags add up.
func TestParseFlagsPositive(state *testing.T) {
	defer resetState(state)
	resetState(state)
	parsers := []struct {
		Parse func(value string) (err error)
		Value string
	}{
		{Parse: parseUIDs, Value: "1001, 1002"},
		{Parse: parseUIDs, Value: "0"},
		{Parse: parsePIDs, Value: "42,43"},
		{Parse: parsePackageNames, Value: "com.example.app, com.example.other"},
		{Parse: parsePackageNames, Value: "android"},
		{Parse: parseSetupPort, Value: "8080"},
		// a bare address is one host, a prefix with host bits set is masked
		{Parse: parseDestinationCIDRs, Value: "10.1.2.3, 10.1.2.3/8 ,2001:db8::1"},
		{Parse: parseDestinationCIDRs, Value: "2001:db8::/32"},
		{Parse: parseDestinationPorts, Value: "tcp/80, UDP/53, 443"},
		{Parse: parseFilter, Value: `proc.uid == 1001 && tls.sni contains "example"`},
		{Parse: parsePort, Value: "8080"},
		{Parse: parseIdleTimeout, Value: "1m30s"},
		{Parse: parseHoldTimeout, Value: "2m"},
		{Parse: parseSnaplen, Value: "1500"},
		{Parse: parseLogLevel, Value: "trace"},
		{Parse: parseUIAPISocket, Value: "127.0.0.1:8080"},
		{Parse: parseMCPAPISocket, Value: "@decerter-api"},
	}

	for _, parser := range parsers {
		err := parser.Parse(parser.Value)

		if err != nil {
			state.Fatalf("Test of the flag parsers failed, value %q, error: %s", parser.Value, err.Error())
		}
	}

	expected := redirect.Filter{
		UIDs:             []uint32{1001, 1002, 0},
		Tgids:            []uint32{42, 43},
		DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("10.1.2.3/32"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::1/128"), netip.MustParsePrefix("2001:db8::/32")},
		DestinationPorts: []redirect.DestinationPort{{Port: 80, IPProtocol: syscall.IPPROTO_TCP}, {Port: 53, IPProtocol: syscall.IPPROTO_UDP}, {Port: 443, IPProtocol: syscall.IPPROTO_TCP}, {Port: 443, IPProtocol: syscall.IPPROTO_UDP}},
		Comms:            nil,
	}

	if !reflect.DeepEqual(selection, expected) {
		state.Errorf("Test of the flag parsers failed, selection should be %+v, selection: %+v", expected, selection)
		return
	}

	if !reflect.DeepEqual(packageNames, []string{"com.example.app", "com.example.other", "android"}) || (setupOptions.Port != 8080) {
		state.Errorf("Test of the flag parsers failed, packages %q, setup port %d", packageNames, setupOptions.Port)
		return
	}

	if (scopeFilter == nil) || (scopeFilter.String() != `proc.uid == 1001 && tls.sni contains "example"`) || (proxyPort != 8080) || (udpIdleTimeout != 90*time.Second) || (holdTimeout != 2*time.Minute) || (snaplen != 1500) || !logger.Slog().Enabled(state.Context(), slog.LevelDebug-4) || (uiTarget != ui.Target{Network: ui.TCPNetwork, Address: "127.0.0.1:8080"}) || (mcpTarget != ui.Target{Network: ui.UnixNetwork, Address: "@decerter-api"}) {
		state.Errorf("Test of the flag parsers failed, filter %v, port %d, timeout %s, snaplen %d, ui api %s, mcp api %s", scopeFilter, proxyPort, udpIdleTimeout, snaplen, uiTarget, mcpTarget)
		return
	}
}

// Test if decerter returns with the expected errors for invalid flags, flags that exclude each other, a missing required flag and arguments, before a command runs.
func TestExecuteNegative(state *testing.T) {
	negativeCases := []struct {
		Args        []string
		Environment map[string]string
		Text        string
	}{
		{Args: []string{"run", "--uid", "1001", "--decrypt", "--intercept"}, Text: "if any flags in the group [decrypt intercept] are set none of the others can be"},
		// a flag from the environment counts for the groups too
		{Args: []string{"run", "--uid", "1001", "--intercept"}, Environment: map[string]string{"DECERTER_DECRYPT": "true"}, Text: "if any flags in the group [decrypt intercept] are set none of the others can be"},
		{Args: []string{"capture", "--uid", "1001"}, Text: `at least one of the flags in the group [write api-socket] is required`},
		{Args: []string{"run", "--uid", "1001", "extra"}, Text: `unknown command "extra" for "decerter run"`},
		{Args: []string{"android", "restore", "extra"}, Text: `unknown command "extra" for "decerter android restore"`},
		{Args: []string{"keylog", "--uid", "1001", "--dst-port", "443"}, Text: "unknown flag: --dst-port"},
		{Args: []string{"run", "--uid", "x"}, Text: `invalid argument "x" for "--uid" flag: invalid uid "x"`},
		{Args: []string{"run", "--uid", "4294967296"}, Text: `invalid uid "4294967296"`},
		{Args: []string{"run", "--pid", "1,0"}, Text: `invalid pid "0": must be positive`},
		{Args: []string{"run", "--uid", "1001", "--dst-cidr", "10.0.0.0/33"}, Text: `invalid destination cidr "10.0.0.0/33"`},
		{Args: []string{"run", "--uid", "1001", "--dst-cidr", "fe80::1%eth0"}, Text: `invalid destination cidr "fe80::1%eth0": zones are not supported`},
		{Args: []string{"run", "--uid", "1001", "--dst-cidr", "example.com"}, Text: `invalid destination cidr "example.com"`},
		{Args: []string{"run", "--uid", "1001", "--dst-port", "sctp/80"}, Text: `invalid destination port "sctp/80": protocol must be tcp or udp`},
		{Args: []string{"run", "--uid", "1001", "--dst-port", "0"}, Text: `invalid destination port "0": must be between 1 and 65535`},
		{Args: []string{"run", "--uid", "1001", "--dst-port", "tcp/70000"}, Text: `invalid destination port "tcp/70000"`},
		{Args: []string{"run", "--uid", "1001", "--port", "0"}, Text: `invalid port "0": must be between 1 and 65535`},
		{Args: []string{"run", "--uid", "1001", "--udp-idle-timeout", "0s"}, Text: `invalid udp idle timeout "0s": must be positive`},
		{Args: []string{"run", "--uid", "1001", "--udp-idle-timeout", "soon"}, Text: `invalid udp idle timeout "soon"`},
		{Args: []string{"run", "--uid", "1001", "--hold-timeout", "0s"}, Text: `invalid hold timeout "0s": must be positive and at most 1h0m0s`},
		{Args: []string{"run", "--uid", "1001", "--hold-timeout", "2h"}, Text: `invalid hold timeout "2h": must be positive and at most 1h0m0s`},
		{Args: []string{"run", "--uid", "1001", "--hold-timeout", "later"}, Text: `invalid hold timeout "later"`},
		{Args: []string{"capture", "-w", "out.pcapng", "--uid", "1001", "--snaplen", "262145"}, Text: `invalid snaplen "262145": must be between 1 and 262144`},
		// the parse error shows where in the filter it is, the way tshark does
		{Args: []string{"run", "--filter", `proc.comm = "curl"`}, Text: "invalid filter: column 11: syntax error: unexpected \"=\", equality is ==\nproc.comm = \"curl\"\n          ^"},
		{Args: []string{"--log-level", "loud", "run"}, Text: "invalid log level"},
		{Args: []string{"run"}, Environment: map[string]string{"DECERTER_UID": "abc"}, Text: `invalid environment variable DECERTER_UID: invalid argument "abc" for "--uid" flag: invalid uid "abc"`},
		{Args: []string{"ui", "--api-socket", "10.0.0.1:8080"}, Text: `invalid api socket: a tcp api address must be a loopback ip address`},
		{Args: []string{"ui", "--api-socket", ""}, Text: `invalid api socket: invalid api address "": empty`},
		{Args: []string{"ui", "extra"}, Text: `unknown command "extra" for "decerter ui"`},
		{Args: []string{"mcp", "--api-socket", "[::2]:8080"}, Text: `invalid api socket: a tcp api address must be a loopback ip address`},
		{Args: []string{"mcp", "extra"}, Text: `unknown command "extra" for "decerter mcp"`},
		{Args: []string{"run", "--package", "com.example.app,"}, Text: `invalid package name ""`},
		{Args: []string{"keylog", "--package", "com.example app"}, Text: `invalid package name "com.example app"`},
		// the tests run on Linux, where a package has no uid
		{Args: []string{"run", "--package", "com.example.app"}, Text: "--package needs Android"},
		{Args: []string{"capture", "-w", "-", "--package", "com.example.app"}, Text: "--package needs Android"},
		{Args: []string{"android", "setup", "--serial", "emulator-5554", "--avd", "decerter-a15"}, Text: "if any flags in the group [serial avd] are set none of the others can be"},
		{Args: []string{"android", "setup", "--remove", "--package", "com.example.app"}, Text: "if any flags in the group [remove package] are set none of the others can be"},
		{Args: []string{"android", "setup", "--port", "0"}, Text: `invalid port "0": must be between 1 and 65535`},
		{Args: []string{"android", "setup", "extra"}, Text: `unknown command "extra" for "decerter android setup"`},
	}

	for _, negative := range negativeCases {
		for name, value := range negative.Environment {
			state.Setenv(name, value)
		}

		_, err := execute(state, negative.Args)

		for name := range negative.Environment {
			state.Setenv(name, "")
		}

		if (err == nil) || !strings.Contains(err.Error(), negative.Text) {
			state.Errorf("Test of decerter %s failed, error should contain %q, error: %v", strings.Join(negative.Args, " "), negative.Text, err)
			return
		}
	}
}

// Test if decerter returns with the expected output for --version and the help pages, which run no command.
func TestExecutePositive(state *testing.T) {
	positiveCases := []struct {
		Args []string
		Text []string
	}{
		{Args: []string{"--version"}, Text: []string{"decerter ", "(commit "}},
		{Args: []string{"help", "filter"}, Text: []string{"subset of Wireshark's display filter language", "  proc.comm      string, flow, comm_map\n", "  tls.alpn       string, several values, clienthello\n"}},
		{Args: []string{"run", "--help"}, Text: []string{"--decrypt", "--udp-idle-timeout duration", "--api-socket path", "--hold-timeout duration", "--log-level level"}},
		{Args: []string{"capture", "--help"}, Text: []string{"-w, --write file", "--snaplen bytes", "--package name"}},
		{Args: []string{"android", "--help"}, Text: []string{"setup", "restore", "adb forward tcp:8080 localabstract:decerter-api", "/data/local/tmp/decerter.d"}},
		{Args: []string{"android", "setup", "--help"}, Text: []string{"--serial serial", "--avd avd", "--package name", "--binary path", "--port port", "--remove", "decerter android setup --avd decerter-a15 --package com.example.app"}},
		{Args: []string{"ui", "--help"}, Text: []string{"--api-socket address", "--open", "adb forward tcp:8080 localabstract:decerter-api"}},
		{Args: []string{"mcp", "--help"}, Text: []string{"--api-socket address", "--output-dir directory", "--allow-write", "claude mcp add decerter -- decerter mcp --allow-write", "<untrusted-traffic"}},
	}

	for _, positive := range positiveCases {
		output, err := execute(state, positive.Args)

		if err != nil {
			state.Errorf("Test of decerter %s failed, error: %s", strings.Join(positive.Args, " "), err.Error())
			return
		}

		for _, text := range positive.Text {
			if !strings.Contains(output, text) {
				state.Errorf("Test of decerter %s failed, output should contain %q, output: %q", strings.Join(positive.Args, " "), text, output)
				return
			}
		}
	}
}

// Test if decerter takes a flag from its environment variable, and the command line wins over it.
func TestApplyEnvironmentPositive(state *testing.T) {
	defer resetState(state)
	resetState(state)
	initConfig()
	command := &cobra.Command{}
	addProcessFlags(command.Flags())
	addScopeFlags(command.Flags())
	state.Setenv("DECERTER_UID", "1001,1002")
	state.Setenv("DECERTER_PID", "77")
	state.Setenv("DECERTER_DST_PORT", "udp/53")
	err := command.Flags().Set("pid", "42")

	if err != nil {
		state.Fatalf("Test of decerter's environment failed, cannot set flag, error: %s", err.Error())
	}

	err = applyEnvironment(command, nil)

	if err != nil {
		state.Errorf("Test of decerter's environment failed, error: %s", err.Error())
		return
	}

	expected := redirect.Filter{UIDs: []uint32{1001, 1002}, Tgids: []uint32{42}, DestinationCIDRs: nil, DestinationPorts: []redirect.DestinationPort{{Port: 53, IPProtocol: syscall.IPPROTO_UDP}}, Comms: nil}

	if !reflect.DeepEqual(selection, expected) {
		state.Errorf("Test of decerter's environment failed, selection should be %+v, selection: %+v", expected, selection)
		return
	}
}

// run decerter with the arguments, what it prints and its error; the flags and their variables are reset after it
func execute(state *testing.T, args []string) (output string, err error) {
	defer resetState(state)
	resetState(state)
	buffer := &bytes.Buffer{}
	rootCmd.SetArgs(args)
	rootCmd.SetOut(buffer)
	rootCmd.SetErr(buffer)
	err = rootCmd.Execute()
	output = buffer.String()
	return
}

// the commands and their flag variables are package globals, each case starts from the defaults
func resetState(state *testing.T) {
	selection = redirect.Filter{}
	packageNames = nil
	setupOptions = android.Options{}
	setupRemove = false
	scopeFilter = nil
	libssl = ""
	flowTable = false
	decrypt = false
	interceptFlows = false
	apiSocket = ""
	holdTimeout = defaultHoldTimeout
	proxyPort = defaultProxyPort
	udpIdleTimeout = 30 * time.Second
	capturePath = ""
	plaintext = false
	snaplen = capturebpf.MaxSnaplen
	uiTarget = ui.Target{}
	openBrowser = false
	mcpTarget = ui.Target{}
	allowWrite = false
	logger.ChangeLogLevel(slog.LevelInfo)
	commands := []*cobra.Command{rootCmd}

	for len(commands) > 0 {
		command := commands[0]
		commands = append(commands[1:], command.Commands()...)

		for _, flags := range []*pflag.FlagSet{command.Flags(), command.PersistentFlags()} {
			flags.VisitAll(func(flag *pflag.Flag) {
				flag.Changed = false

				// a func flag has no default to go back to, its variable is reset above
				if flag.Value.Type() == "func" {
					return
				}

				if setErr := flag.Value.Set(flag.DefValue); setErr != nil {
					state.Errorf("Test of decerter failed, cannot reset flag --%s, error: %s", flag.Name, setErr.Error())
				}
			})
		}
	}
}
