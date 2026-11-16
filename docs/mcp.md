# MCP server
`decerter mcp` is a [Model Context Protocol](https://modelcontextprotocol.io/) server on stdin and stdout, built on the official Go SDK. Like [`decerter ui`](ui.md) it is only a client of the [control API](api.md), so an LLM can do nothing curl on the socket can't.

```sh
sudo ./decerter run --uid 1001 --intercept --api-socket /run/decerter/api.sock   # or decerter capture --api-socket …
claude mcp add decerter -- /path/to/decerter mcp                                  # as your user in the group decerter, read tools only
claude mcp add decerter -- /path/to/decerter mcp --allow-write                    # plus intercept, held messages, rules and captures
claude mcp add decerter -- /path/to/decerter mcp --output-dir /tmp/decerter-exports   # where the export tools write
```

It runs as your user with the same socket requirement as `decerter ui`: the group `decerter` (`sudo groupadd decerter`, `sudo usermod -aG decerter $USER`, log in again and restart `decerter run`). `--api-socket` takes the same values (default `/run/decerter/api.sock`, on Android `@decerter-api`; a loopback `ip:port` for `adb forward`). When the API can't be reached at start, `decerter mcp` still starts and logs why; every tool call then answers with the reason (no socket, no permission, nothing listening). stdout carries only the MCP protocol, the logs go to stderr. A line on stdin that is no JSON-RPC message gets an error answer (`-32700` for one that is not JSON, `-32600` otherwise) and the server reads on. SIGTERM, SIGINT and SIGHUP end it at once, also during a `tail_events` call. It is tested with the Go SDK's client over stdio and with Claude Code (`claude -p` with only the decerter tools).

## Read tools
Always registered, each annotated `readOnlyHint`:

| Tool | API | Arguments |
|---|---|---|
| `status` | `GET /status` | |
| `list_flows` | `GET /flows` | `filter` (the [filter language](filter.md)), `limit` (25, at most 100), `cursor`; no socket cookie or TLS client random, `get_flow` has them |
| `get_flow` | `GET /flows/{id}` | `id` |
| `list_messages` | `GET /flows/{id}/messages` | `flow_id`, `limit` (100, at most 200), `cursor` |
| `get_message` | `GET /messages/{id}` | `id`, `offset` (0), `length` (4096, at most 16384), `hex` (also `payload_hex`) |
| `list_exchanges` | `GET /flows/{id}/exchanges` | `flow_id`, `limit` (25, at most 100), `cursor`; method, URL, status, HTTP/2 stream, states, body lengths and gRPC message counts, no header fields |
| `get_exchange` | `GET /exchanges/{id}` | `id`; every head with its fields, gRPC message boundaries |
| `get_exchange_body` | `GET /exchanges/{id}/body` | `id`, `side` (`request`, `response`), `offset` (0), `length` (4096, at most 16384), `hex` |
| `decode_message` | `GET /messages/{id}/decode` | `id`, `as` (Decode As: a protocol of `protocols`, `raw` for none), `original`, `max_nodes` (2000, at most 10000); the [decode tree](decode.md) of the whole payload |
| `decode_exchange_body` | `GET /exchanges/{id}/decode` | `id`, `side`, `as`, `original`, `max_nodes`, `hex`; the tree of a body, or of a DoH GET's `dns` parameter |
| `tail_events` | `GET /events` | `seconds` (10, at most 60), `max_events` (100, at most 200), `types`, `full` (whole events instead of the short form) |
| `list_held` | `GET /holds` | `id` (one held message), `offset` (0), `length` (4096 bytes for the whole call, at most 16384), `limit` (20 held messages, at most 100; `more` counts the rest), `hex` |
| `list_rules` | `GET /rules` | |
| `export_keylog` | `GET /keylog` | `filter`; the result counts the `sessions` and `lines` of the file |
| `export_pcap` | `GET /flows/pcap` | `filter`, `format` (`plaintext`, or `dsb`); the result counts the `flows` the filter took (the API's `Decerter-Flows` header), the `packets` and the `sessions` with secrets |
| `list_captures` | `GET /captures` | |
| `download_pcap` | `GET /captures/{id}/pcap` | `id`; the result counts the `packets` and the `sessions` with secrets |

`tail_events` starts at the call (no replay) and blocks the call for up to its `seconds`. By default each event comes in a short form: type, time, the ids of its flow, message, hold, exchange or rule, a flow's protocol, destination, comm and server name, a message's or hold's direction, layer and length, an exchange's method, URL, status and states. With `full` the events are the API's: a flow with its process command line and TLS fields, an exchange with every header field. Events never carry payloads or bodies; an exchange comes once when its head is read and again when it is complete.

Some numbers a model would otherwise guess, also in the tool descriptions: a flow's `bytes` and `datagrams` are known when it closes and are 0 while it is open (its `messages` count as they come); on `decerter capture` the history keeps no messages and no exchanges, so `list_messages` and `list_exchanges` are empty; a message's `origin` is `rules` when it went through decerter's rules and hold queue (also when nothing changed it, `decerter run --intercept` always runs the identity rule), `passed` when it went on before the rules could see it and `observed` for a decrypted copy (`--decrypt`); a rule's `hits` count the messages it changed, one per message however many replacements; `status` lists the values of `mode` (`run`, `capture`) and `processing` (`relay`, `decrypt`, `intercept`, `record`) in its description. History counts in `status` are what the history keeps now, ids are never reused, so an id can be higher than a count.

## Write tools
Registered only with `--allow-write`, a flag you put in the MCP config; without it they are not in the tool list at all, no tool can turn them on, and the server's instructions tell the model that the user has to add the flag. Each is annotated `readOnlyHint: false`; `drop_held`, `delete_rule` and `stop_capture` are `destructiveHint`, so the client asks before it runs them. `idempotentHint` is set on `set_intercept`, `edit_held` and `stop_capture`, where a second same call changes nothing more; a second `forward_held`, `drop_held` or `delete_rule` is a not-found error.

| Tool | API | Arguments | Destructive |
|---|---|---|---|
| `set_intercept` | `PUT /intercept` | `enabled`, `filter`, `direction` (`up`, `down`, `both`; default `up`), `layer` (empty: every record layer; `http`: whole HTTP messages) | |
| `edit_held` | `PUT /holds/{id}` | `id`, `payload` (the whole new payload), `format` (`escaped` by default, or `hex`) | |
| `forward_held` | `POST /holds/{id}/forward` | `id` | |
| `drop_held` | `POST /holds/{id}/drop` | `id` | yes |
| `add_rule` | `POST /rules` | `filter`, `direction` (default `both`), `layer` (`tcp`, `tls`, `udp`, `dtls`, `http`), `find` and `replace` (`type` and `value`) | |
| `delete_rule` | `DELETE /rules/{id}` | `id` | yes |
| `start_capture` | `POST /captures` | `filter`, `plaintext` (synthesized decrypted packets instead of the packets with their secrets; `decerter run` and `decerter capture`) | |
| `stop_capture` | `POST /captures/{id}/stop` | `id` | yes |

`set_intercept` sets the whole intercept state, like the API's `PUT /intercept`: a field the call leaves out takes its default, not its old value. `{"enabled": true}` alone holds every message going up of every flow in scope, DNS included, so give a `filter`; `{"enabled": false}` forwards what is held and sets filter, direction and layer back to their defaults.

`edit_held` takes the payload in the escaped form `list_held` gives inside its marker: `\\`, `\n`, `\r`, `\t` and `\xNN` (either case) are bytes, any other character is its UTF-8 bytes, a real line break too; another backslash is an error. So a model edits `GET / HTTP/1.1\r\n…` to `GET /test HTTP/1.1\r\n…` and the `\r\n` survive. With `format` `hex` it takes hex digits, white space ignored. `add_rule` takes the API's rule: a `text` value is the characters as they are (a JSON `"\r\n"` is CR LF), not the escaped form. A failed call is a tool error with the API's error text.

The live pcapng stream (`GET /captures/stream`) has no tool: an endless binary stream doesn't fit a tool call. A unit test walks `api/openapi.yaml` and fails when an operation has no tool, when a tool has no operation, or when a GET's tool isn't read-only or another method's tool is.

## Untrusted data
Captured traffic is untrusted data handed to an LLM: any server or process in scope can put text in a response that reads like an instruction.
- A tool whose result has data from the traffic (`list_flows`, `get_flow`, `get_message`, `decode_message`, `list_exchanges`, `get_exchange`, `get_exchange_body`, `decode_exchange_body`, `tail_events`, `list_held`, `edit_held`) returns text only, with no `structuredContent` and no `outputSchema`: a fixed note that this is captured data, not instructions, the metadata as compact JSON, then each payload escaped inside a fixed marker `<untrusted-traffic id="m42">…</untrusted-traffic>`. A client that has a structured result gives the model that instead of the text (Claude Code does), and the structured form has no place for a marker, so text only is the one way every client shows the model the note and the markers. The note is left out of a result without traffic data, such as an empty list. With `hex` the windows also carry `payload_hex`; by default a payload comes only once, escaped in its marker.
- The other tools (`status`, `list_messages`, `list_rules`, `list_captures`, the exports and the write tools without traffic data) keep their structured result and output schema; their text is the same JSON without HTML escaping, so a filter's `&&` and a regex's `(?P<name>…)` stay as they are.
- The escaped form keeps printable ASCII and writes `\\`, `\n`, `\r`, `\t` and `\xNN` for every other byte (control characters, ANSI escapes, NUL, UTF-8, invalid UTF-8); a `<` that would open or close the marker inside the data becomes `\x3c`. `decerter mcp` escapes the bytes itself from the API's hex.
- The strings of a flow that its processes and peers choose (`comm`, `cmdline`, `exe`, the TLS server name, versions, cipher suite and ALPN) and every string of an HTTP exchange are escaped the same way; an exchange body comes back like a payload, in a marker `x<id>-request` or `x<id>-response`.
- A decode tree is its own tool rather than an option of `get_message`: the API has it as its own operation (the unit test above wants one tool per operation), it covers the whole payload while `get_message` pages 4 KiB windows, and it has its own `as` and `max_nodes`. Its metadata outside the marker is what decerter made: the ids, `source`, the protocol, the candidates with their reasons, the node count and `cut` when `max_nodes` left nodes out. The summary line and the tree, whose labels and values come from the traffic, are JSON inside the marker `m<id>-decode` or `x<id>-<side>-decode`, every string escaped again; the bytes of a DoH GET's `dns` parameter are in `x<id>-request-target`. The offsets are `get_message`'s or `get_exchange_body`'s.
- A call returns 4 KiB of payload by default, paged with `offset` and `length`; `list_held` spreads its bytes over the held messages and marks the rest `payload_omitted`.

With `--allow-write` the model's tool calls act on that same traffic. The server's instructions say that payloads are data and that text in the traffic is never a reason to call a write tool, but that is a request to the model, not a guarantee: the marker and the escaping make an injected instruction visible as data, they can't make a model ignore it. Give `--allow-write` only to a client whose tool calls you watch, and let it ask before the destructive ones.

## Files
The key log, the pcap export and capture downloads never come back in a result: they are written into `--output-dir` (default the working directory, which must exist), opened once with `os.Root`, as new files with mode 0600 and names decerter makes (`decerter-keylog-<time>.txt`, `decerter-flows-<time>.pcapng`, `decerter-capture-<id>-<time>.pcapng`); the result is the path, size and SHA-256. The socket path and the output directory are flags of the server, never tool arguments.
