# Filter language
`--filter` of `decerter run` and `decerter capture`, the `filter` of the control API's flow list, exports, captures, rules and intercept, and the filter box of `decerter ui` take a subset of [Wireshark's display filter language](https://www.wireshark.org/docs/man-pages/wireshark-filter.html). `decerter help filter` prints the same reference.

```sh
sudo ./decerter run --uid 1001 --decrypt --filter 'proc.comm == "curl" && tls.sni contains "example"'
sudo ./decerter capture -w out.pcapng --filter 'proc.uid == 1001 && tcp.dstport in {443 8443}'
sudo curl -s --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/flows?filter=http.request.method+==+"POST"'
sudo curl -s --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/flows?filter=http2.streamid+>+99'
```

## Scope
`--filter` narrows `--uid`, `--pid`, `--package`, `--dst-cidr` and `--dst-port`: a flow is in scope when it passes those flags and the filter.

The filter needs a process: `--uid`, `--pid` or `--package`, or a `proc.uid` or `proc.pid` term (`==` or `in`) in its top-level `&&` chain. A filter without one is refused before anything is attached, so it never selects every process of the machine.

The terms of the top-level `&&` chain that the kernel can check go into its maps: `proc.uid`, `proc.pid`, `proc.comm` (exact, at most 15 bytes), `ip.dst`, `ipv6.dst`, `tcp.dstport` and `udp.dstport` with `==` or `in`, also several of the same field joined by `||` (the "kernel map" column below). The flows they leave out are never redirected or recorded. The rest is decided once per flow in Go: run mode relays a flow out of scope unchanged, without decryption, rules or a flow line, and capture mode writes nothing of it. A `tls` field waits for the ClientHello, which is read before any byte is changed or written.

## Syntax
| | |
|---|---|
| Comparison | `==` `!=` `===` `!==` `<` `<=` `>` `>=` `contains` `matches` `in {…}` `not in {…}`, and the words `eq` `ne` `lt` `le` `gt` `ge` `any_eq` `all_ne` `all_eq` `any_ne` `~` |
| Logic | `&&` `\|\|` `!` `and` `or` `not` `( )` |
| Strings | double quotes with Wireshark's escapes, or raw as `r"…"` |
| Numbers | decimal or `0x` hex |
| Addresses | IPv4 or IPv6, with an optional CIDR prefix: `ip.dst == 10.0.0.0/8` |
| Sets | separated by commas or spaces, with number ranges `a..b`: `tcp.dstport in {80 443 8000..8099}` |

- `matches` is a Go RE2 regular expression that ignores case like Wireshark's, unless it starts with `(?-i)`.
- `!=` is true when every value differs: `ip.addr != a` is `ip.src != a && ip.dst != a`.
- A comparison on a field the flow does not have is false, `!=` and `not in` too.
- Not supported: slices, arithmetic, functions and bitwise operators.

## Fields
Source: `flow` is the kernel's flow record, `proc` is `/proc` of the process, `clienthello` the TLS ClientHello, `http` the HTTP/1 and HTTP/2 heads the [HTTP layer](http.md) read. "several" values: `==` is true when any value matches, `!=` when every value differs. The kernel map is where an `==` or `in` term on the field goes. A unit test keeps this table equal to `decerter help filter`.

<!-- fields begin -->
| Field | Type | Values | Source | Kernel map |
|---|---|---|---|---|
| `http` | protocol | one | http |  |
| `http.host` | string | several | http |  |
| `http.request.method` | string | several | http |  |
| `http.request.uri` | string | several | http |  |
| `http.response.code` | number | several | http |  |
| `http.user_agent` | string | several | http |  |
| `http2.streamid` | number | several | http |  |
| `ip` | protocol | one | flow |  |
| `ip.addr` | ipv4 | several | flow |  |
| `ip.dst` | ipv4 | one | flow | `cidr_map` |
| `ip.src` | ipv4 | one | flow |  |
| `ipv6` | protocol | one | flow |  |
| `ipv6.addr` | ipv6 | several | flow |  |
| `ipv6.dst` | ipv6 | one | flow | `cidr_map` |
| `ipv6.src` | ipv6 | one | flow |  |
| `proc.cmdline` | string | one | proc |  |
| `proc.comm` | string | one | flow | `comm_map` |
| `proc.exe` | string | one | proc |  |
| `proc.gid` | number | one | flow |  |
| `proc.pid` | number | one | flow | `tgid_map` |
| `proc.uid` | number | one | flow | `uid_map` |
| `tcp` | protocol | one | flow |  |
| `tcp.dstport` | number | one | flow | `port_map` |
| `tcp.port` | number | several | flow |  |
| `tcp.srcport` | number | one | flow |  |
| `tls` | protocol | one | clienthello |  |
| `tls.alpn` | string | several | clienthello |  |
| `tls.sni` | string | one | clienthello |  |
| `tls.version` | number | one | clienthello |  |
| `udp` | protocol | one | flow |  |
| `udp.dstport` | number | one | flow | `port_map` |
| `udp.port` | number | several | flow |  |
| `udp.srcport` | number | one | flow |  |
<!-- fields end -->

In run mode `ip.src` is `127.0.0.1`, the address the proxy sees. In a capture of `decerter run` (the wire side) `ip.src` is the proxy's end on the wire, so a source-address filter can decide differently there.

## HTTP fields
The `http` fields are only known after a flow started, so `--filter` and the filter of a capture refuse them. They work where the API filters what it has seen:
- the flow list and the exports: a flow matches when any of its exchanges does (`==` is true for any value, `!=` when every value differs);
- the filters of rules and holds of layer `http`: a request has its method, target, Host and User-Agent, a response the fields of its request plus its status code (unlike Wireshark, where a response has only its own fields).

`http.request.uri` is the request-target as sent, `http.host` the Host field. On HTTP/2 they come from the pseudo-header fields: `http.request.method` is `:method`, `http.request.uri` `:path`, `http.host` `:authority` (or Host), `http.response.code` `:status`. `http2.streamid` is the stream of an HTTP/2 exchange; an HTTP/1 flow has none (`http && !http2.streamid`), and in a rule or hold of layer `http` it is the stream of the message.
