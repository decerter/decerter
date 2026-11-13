// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"

	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/ui"
	internal "github.com/decerter/decerter/pkg/internal/cmd"
	"github.com/spf13/cobra"
)

var (
	mcpTarget  ui.Target
	outputDir  string
	allowWrite bool
	mcpCmd     = &cobra.Command{
		Use:   "mcp",
		Short: "Serve an MCP server on stdio, a client of the control API, for an LLM client to read and with --allow-write change decerter's state",
		Long: `Serve a Model Context Protocol server on stdin and stdout for an MCP client such as Claude Code, for a decerter run or
decerter capture that serves the control API (--api-socket). It only talks to the API, so it can do nothing curl on the
socket can't. The read tools are always there: status, flows, messages with their payloads, the live events, held
messages, rules and captures. The key log, pcap exports and capture downloads are written into --output-dir and the
tools return only the path, size and SHA-256 of the file.

--allow-write adds the write tools: set_intercept, edit_held, forward_held, drop_held, add_rule, delete_rule,
start_capture and stop_capture; drop_held, delete_rule and stop_capture are marked destructive, so the client asks
before it runs them. Without the flag they are not registered at all, and no tool can turn writes on.

Captured traffic is untrusted data handed to an LLM: payloads come back as hex and escaped text inside an
<untrusted-traffic id="…"> marker with a note that it is data, not instructions, at most 4 KiB per call by default.
Traffic can carry text aimed at the model, and the write tools act on that traffic: give --allow-write only to a
client whose tool calls you watch.

decerter mcp runs as your user, not as root: it only needs the API socket, which is for root and the members of the group
decerter (groupadd decerter, usermod -aG decerter $USER, then log in again and restart decerter run). stdout is the MCP channel, the
logs go to stderr. When the API can't be reached at start, decerter mcp still serves and every tool answers why.`,
		Example: `  sudo decerter run --uid 1001 --intercept --api-socket /run/decerter/api.sock
  claude mcp add decerter -- decerter mcp                  # as your user in the group decerter, read tools only
  claude mcp add decerter -- decerter mcp --allow-write    # plus intercept, held messages, rules and captures
  claude mcp add decerter -- decerter mcp --output-dir /tmp/decerter-exports`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if mcpTarget.Address == "" {
				err = parseMCPAPISocket(platform.Detect("/").APISocket)

				if err != nil {
					return
				}
			}

			quiet(cmd)
			err = internal.MCP(mcpTarget, outputDir, allowWrite, &logger)
			return
		},
	}
)

func init() {
	mcpCmd.Flags().SortFlags = false
	mcpCmd.Flags().Func("api-socket", "the control API at this `address`: a socket path, @name for an abstract socket or a loopback ip:port such as 127.0.0.1:8080 of adb forward (default is /run/decerter/api.sock on Linux, @decerter-api on Android)", parseMCPAPISocket)
	mcpCmd.Flags().StringVar(&outputDir, "output-dir", ".", "the existing `directory` the key log, pcap export and capture download tools write their files into, mode 0600")
	mcpCmd.Flags().BoolVar(&allowWrite, "allow-write", false, "register the write tools: intercept on and off, edit, forward and drop held messages, add and delete rules, start and stop captures (default is read tools only)")
	rootCmd.AddCommand(mcpCmd)
}

func parseMCPAPISocket(value string) (err error) {
	target, parseErr := ui.ParseTarget(value)

	if err = parseErr; err != nil {
		err = fmt.Errorf("invalid api socket: %w", err)
		return
	}

	mcpTarget = target
	return
}
