// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package cmd

import (
	"fmt"
	"strconv"
	"time"

	internal "github.com/decerter/decerter/pkg/internal/cmd"
	"github.com/spf13/cobra"
)

const (
	defaultProxyPort   uint16        = 15001
	defaultHoldTimeout time.Duration = 60 * time.Second
	// a message kept back for the rules of layer http blocks its direction of the flow while it comes, a client that waits for an answer to part of it
	// (Expect: 100-continue) waits this long
	defaultAssemblyTimeout time.Duration = 5 * time.Second
	// a held message blocks its direction of the flow, so a hold is never longer than this
	maxHoldTimeout time.Duration = time.Hour
)

var (
	proxyPort       uint16        = defaultProxyPort
	udpIdleTimeout  time.Duration = 30 * time.Second
	holdTimeout     time.Duration = defaultHoldTimeout
	assemblyTimeout time.Duration = defaultAssemblyTimeout
	decrypt         bool
	interceptFlows  bool
	apiSocket       string
	runCmd          = &cobra.Command{
		Use:   "run",
		Short: "Redirect the selected flows through decerter's proxy, optionally decrypting or intercepting them",
		Long: `Redirect the TCP and UDP flows of the selected processes through decerter's proxy on lo.
The cgroup hooks send connect() and sendmsg() of the selected sockets to the proxy port, the proxy dials the original
destination and relays, and getpeername() and recvmsg() still show the original server to the app.
Without --decrypt or --intercept every flow is relayed unchanged and logged with one line.

--decrypt reads the TLS records of the TCP flows and the DTLS 1.2 records of the UDP sessions with the secrets of the
libssl uprobe and prints the plaintext of their application data on stdout, escaped and at most 2048 bytes per record.
The flows are still relayed unchanged.

--intercept holds every TLS and DTLS 1.2 record, decrypts it, runs it through the intercept rules and encrypts it again
with the same session keys; plain TCP chunks and UDP datagrams run through the rules too. The only rule on the command
line is the identity rule, which changes nothing: every message is printed on stdout with a header line, its escaped text
and a hex dump, at most 2048 bytes, and a TLS flow or DTLS session ends with one line counting what happened to its records.

--api-socket serves the control API (HTTP under /api/v1, described by api/openapi.yaml) on a unix socket: the history
of the flows in scope with their decrypted or intercepted messages, a live event stream and a key log export. With
--intercept it also holds messages for editing, forwarding or dropping, and runs match-and-replace rules added over the
API after the identity rule. A socket file gets mode 0660 and the group decerter when that group exists, and is for root only
otherwise; an abstract socket (@name, the default on Android) lets root and, on Android, adb's shell user connect.
A held message that nobody decides goes on unchanged after --hold-timeout. A rule or hold of layer http needs whole HTTP messages:
a message it matches is kept back from its first byte until it is whole, and goes on as it came, with a note, when it is not whole
after --assembly-timeout.

The secrets come from OpenSSL's libssl on Linux (every 3.x and 4.x release, amd64 and arm64: libssl.so.3 and libssl.so.4 of the
linker cache and the libssl the selected processes map, so a container's own too), and on Android from Conscrypt's BoringSSL, the
BoringSSL in libflutter.so of the selected Flutter apps (Flutter 3.24.0 to 3.50.0, by the engine's Dart version) and the BoringSSL of
Chrome, Cronet and WebView (Chrome 124 to 160, by the Chrome version; Trichrome's library and the Chromium libraries the app's processes
map are found too). A process with another own TLS library, such as Go programs, or a Flutter or Chromium app of an unknown version, is
relayed without decryption, and so is a process that loads an OpenSSL of the linker cache decerter has no offsets for, which is a warning naming
the nearest known version while another OpenSSL is hooked (decerter stops when none is, and always for --libssl). QUIC is relayed without
decryption too; --block-quic makes it fail so the apps use TLS over TCP.`,
		Example: `  # the flows of the local user test (uid 1001), TLS decrypted
  sudo decerter run --uid 1001 --decrypt
  sudo -u test curl -s https://example.com/

  # only curl's flows to port 443, every record through the identity rule
  sudo decerter run --uid 1001 --intercept --filter 'proc.comm == "curl" && tcp.dstport == 443'

  # the control API: hold the test user's requests, list the flows
  sudo decerter run --uid 1001 --intercept --api-socket /run/decerter/api.sock
  sudo curl --unix-socket /run/decerter/api.sock -X PUT -d '{"enabled": true}' http://decerter/api/v1/intercept
  sudo curl --unix-socket /run/decerter/api.sock http://decerter/api/v1/flows

  # an Android app on the device after decerter android setup, selected by its package name
  adb shell -tt /data/local/tmp/decerter run --package com.example.app --decrypt`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			quiet(cmd)
			err = internal.Run(selection, packageNames, scopeFilter, proxyPort, udpIdleTimeout, blockQuic, flowTable, decrypt, interceptFlows, apiSocket, holdTimeout, assemblyTimeout, libssl, &logger)
			return
		},
	}
)

func init() {
	// the selection first, then what happens to the flows
	runCmd.Flags().SortFlags = false
	addProcessFlags(runCmd.Flags())
	addScopeFlags(runCmd.Flags())
	runCmd.Flags().BoolVar(&decrypt, "decrypt", false, "print the plaintext of the TLS and DTLS 1.2 records of the redirected flows, the flows are relayed unchanged (default is false)")
	runCmd.Flags().BoolVar(&interceptFlows, "intercept", false, "run every message of the redirected flows through the identity rule and print it, TLS and DTLS 1.2 records are decrypted and encrypted again (default is false)")
	runCmd.Flags().Func("port", "`port` of the TCP proxy listener and the UDP proxy socket on lo (default is 15001)", parsePort)
	runCmd.Flags().Func("udp-idle-timeout", "a UDP session ends after this `duration` without a datagram in either direction (default is 30s)", parseIdleTimeout)
	runCmd.Flags().StringVar(&apiSocket, "api-socket", "", "serve the control API on the unix socket at this `path`, @name is an abstract socket; the usual one is /run/decerter/api.sock on Linux and @decerter-api on Android (default is none)")
	runCmd.Flags().Func("hold-timeout", "a message held over the control API goes on unchanged when nobody forwards or drops it within this `duration`, at most 1h (default is 60s)", parseHoldTimeout)
	runCmd.Flags().Func("assembly-timeout", "an HTTP message kept back for the rules and holds of layer http goes on as it came when it is not whole within this `duration`, at most 1h (default is 5s)", parseAssemblyTimeout)
	addBlockQuicFlag(runCmd.Flags())
	addLibsslFlag(runCmd.Flags())
	addFlowTableFlag(runCmd.Flags())
	runCmd.MarkFlagsMutuallyExclusive("decrypt", "intercept")
	rootCmd.AddCommand(runCmd)
}

func parsePort(value string) (err error) {
	port, parseErr := strconv.ParseUint(value, 10, 16)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid port %q: %w", value, err)
		return
	}

	// the port is a load-time constant in the bpf programs, so it can't be picked by the kernel
	if port == 0 {
		err = fmt.Errorf("invalid port %q: must be between 1 and 65535", value)
		return
	}

	proxyPort = uint16(port)
	return
}

func parseIdleTimeout(value string) (err error) {
	timeout, parseErr := time.ParseDuration(value)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid udp idle timeout %q: %w", value, err)
		return
	}

	if timeout <= 0 {
		err = fmt.Errorf("invalid udp idle timeout %q: must be positive", value)
		return
	}

	udpIdleTimeout = timeout
	return
}

func parseHoldTimeout(value string) (err error) {
	timeout, parseErr := time.ParseDuration(value)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid hold timeout %q: %w", value, err)
		return
	}

	if (timeout <= 0) || (timeout > maxHoldTimeout) {
		err = fmt.Errorf("invalid hold timeout %q: must be positive and at most %s", value, maxHoldTimeout)
		return
	}

	holdTimeout = timeout
	return
}

func parseAssemblyTimeout(value string) (err error) {
	timeout, parseErr := time.ParseDuration(value)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid assembly timeout %q: %w", value, err)
		return
	}

	if (timeout <= 0) || (timeout > maxHoldTimeout) {
		err = fmt.Errorf("invalid assembly timeout %q: must be positive and at most %s", value, maxHoldTimeout)
		return
	}

	assemblyTimeout = timeout
	return
}
