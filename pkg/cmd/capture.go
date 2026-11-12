// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"
	"strconv"

	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	internal "github.com/decerter/decerter/pkg/internal/cmd"
	"github.com/spf13/cobra"
)

var (
	capturePath string
	plaintext   bool
	snaplen     uint32 = capturebpf.MaxSnaplen
	captureCmd         = &cobra.Command{
		Use:   "capture -w <file>|-",
		Short: "Write the selected flows to pcapng with their TLS secrets, or decrypted, without redirecting them",
		Long: `Write the packets of the selected flows to a pcapng file, or with -w - as a live stream to stdout.
Nothing is redirected: the flows reach their servers directly and nothing in them is changed.

By default the file holds the packets as the kernel saw them, and before the first encrypted packet of a TLS or DTLS
session a Decryption Secrets Block with its secrets, so Wireshark and tshark decrypt it without a key log file.
With --plaintext the file holds synthesized packets with the decrypted payload instead: the TCP streams are put back in
order and the sessions decrypted, a flow keeps its addresses and ports and gets new sequence numbers, a flow that is not
TLS keeps its payload, and tcpdump and every other pcapng reader shows the plaintext.

The file holds secrets or plaintext, so it is created with mode 0600 and, under sudo, given to the user who ran sudo.
A live stream is flushed block by block. stdout must not be an interactive terminal (the raw pty of adb exec-out is fine),
the logs stay on stderr, and decerter stops when the reader goes away.`,
		Example: `  # packets and secrets of the local user test (uid 1001), tshark decrypts the file by itself
  sudo decerter capture --uid 1001 -w out.pcapng
  tshark -r out.pcapng -Y 'http or http2'

  # decrypted packets for tcpdump
  sudo decerter capture --uid 1001 -w out.pcapng --plaintext
  tcpdump -A -r out.pcapng

  # live into tshark, which needs dumpcap rights (group wireshark); -l prints each packet at once when its output is a pipe
  sudo decerter capture --uid 1001 -w - | tshark -l -i - -Y 'http or http2'`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			quiet(cmd)
			err = internal.Capture(selection, scopeFilter, capturePath, plaintext, snaplen, flowTable, libssl, defaultProxyPort, &logger)
			return
		},
	}
)

func init() {
	// the output first, then the selection and what is written
	captureCmd.Flags().SortFlags = false
	captureCmd.Flags().StringVarP(&capturePath, "write", "w", "", "write the capture to this pcapng `file`, - is a live stream to stdout (required)")
	addProcessFlags(captureCmd.Flags())
	addScopeFlags(captureCmd.Flags())
	captureCmd.Flags().BoolVar(&plaintext, "plaintext", false, "write synthesized packets with the decrypted payload instead of the captured packets and their secrets (default is false)")
	captureCmd.Flags().Func("snaplen", "copy at most this many `bytes` of a packet, counted from the IP header; a packet cut short can't be decrypted and is a gap in its TCP stream with --plaintext (default is 262144, the largest value)", parseSnaplen)
	addLibsslFlag(captureCmd.Flags())
	addFlowTableFlag(captureCmd.Flags())

	// a flag that is registered right above
	if err := captureCmd.MarkFlagRequired("write"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(captureCmd)
}

func parseSnaplen(value string) (err error) {
	length, parseErr := strconv.ParseUint(value, 10, 32)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid snaplen %q: %w", value, err)
		return
	}

	// the capture programs copy at most this much of a packet
	if (length == 0) || (length > uint64(capturebpf.MaxSnaplen)) {
		err = fmt.Errorf("invalid snaplen %q: must be between 1 and %d", value, capturebpf.MaxSnaplen)
		return
	}

	snaplen = uint32(length)
	return
}
