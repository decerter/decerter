// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"
	"strings"

	"github.com/decerter/decerter/internal/filter"
	"github.com/spf13/cobra"
)

var (
	// a help topic: decerter help filter
	filterCmd = &cobra.Command{
		Use:   "filter",
		Short: "The --filter language of run and capture",
		Long: `--filter takes a subset of Wireshark's display filter language. It narrows --uid, --pid, --dst-cidr and --dst-port:
a flow is in scope when it passes those flags and the filter.

The filter needs a process: --uid or --pid, or a proc.uid or proc.pid term (== or in) in its top-level && chain.
A filter without one is refused before anything is attached, so it never selects every process of the machine.

The terms of the top-level && chain that the kernel can check go into its maps: proc.uid, proc.pid, proc.comm (exact,
at most 15 bytes), ip.dst, ipv6.dst, tcp.dstport and udp.dstport with == or in, also several of the same field joined
by ||. The flows they leave out are never redirected or recorded. The rest is decided once per flow: run mode relays a
flow out of scope unchanged, without decryption, rules or a flow line, and capture mode writes nothing of it. A tls
field waits for the ClientHello, which is read before any byte is changed or written.

Operators:
  == != === !== < <= > >= contains matches in {…} not in {…}
  eq ne lt le gt ge any_eq all_ne all_eq any_ne ~
  && || ! and or not ( )

matches is a Go RE2 regular expression that ignores case like Wireshark's, unless it starts with (?-i).
!= is true when every value differs: ip.addr != a is ip.src != a && ip.dst != a.
A comparison on a field the flow does not have is false, != and not in too.
Strings are in double quotes with Wireshark's escapes, or raw as r"…"; numbers are decimal or 0x; addresses can have
a CIDR prefix; sets are separated by commas or spaces and can hold number ranges a..b.
Not supported: slices, arithmetic, functions and bitwise operators.

Fields (type; where the value comes from: flow is the kernel's flow record, proc is /proc of the process, clienthello
the TLS ClientHello, http the HTTP/1 heads the HTTP layer read; the kernel map an == or in term on it goes into):
` + fieldsHelp() + `
In run mode ip.src is 127.0.0.1, the address the proxy sees.

The http fields are only known after a flow started, so --filter and the filter of a capture refuse them. They work
where the API filters what it has seen: the flow list and exports (a flow matches when any of its exchanges does: ==
is true for any value, != when every value differs), and the filters of rules and holds of layer http, where a request
has its method, target, Host and User-Agent and a response the fields of its request plus its status code.
http.request.uri is the request-target as sent, http.host the Host field.

Examples:
  sudo decerter run --uid 1001 --decrypt --filter 'proc.comm == "curl" && tls.sni contains "example"'
  sudo decerter capture -w out.pcapng --filter 'proc.uid == 1001 && tcp.dstport in {443 8443}'
  curl --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/flows?filter=http.request.method+==+"POST"'`,
	}
)

func init() {
	rootCmd.AddCommand(filterCmd)
}

// one line per field: name (type, source, kernel map)
func fieldsHelp() (help string) {
	var lines strings.Builder

	for _, info := range filter.Fields() {
		description := string(info.Type)

		if info.IsMulti {
			description += ", several values"
		}

		description += ", " + string(info.Source)

		if info.Pushdown != "" {
			description += ", " + info.Pushdown
		}

		fmt.Fprintf(&lines, "  %-19s %s\n", info.Name, description)
	}

	help = lines.String()
	return
}
