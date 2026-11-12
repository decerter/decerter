// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"
	"strconv"
	"time"

	internal "github.com/decerter/decerter/pkg/internal/cmd"
	"github.com/spf13/cobra"
)

const (
	defaultProxyPort uint16 = 15001
)

var (
	proxyPort      uint16        = defaultProxyPort
	udpIdleTimeout time.Duration = 30 * time.Second
	decrypt        bool
	interceptFlows bool
	runCmd         = &cobra.Command{
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

The secrets come from OpenSSL 3's libssl on Linux (amd64 only) and Conscrypt's BoringSSL on Android. A process with its
own TLS library, such as Chrome, Cronet, Flutter or Go programs, is relayed without decryption.`,
		Example: `  # the flows of the local user test (uid 1001), TLS decrypted
  sudo decerter run --uid 1001 --decrypt
  sudo -u test curl -s https://example.com/

  # only curl's flows to port 443, every record through the identity rule
  sudo decerter run --uid 1001 --intercept --filter 'proc.comm == "curl" && tcp.dstport == 443'`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			quiet(cmd)
			err = internal.Run(selection, scopeFilter, proxyPort, udpIdleTimeout, flowTable, decrypt, interceptFlows, libssl, &logger)
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
