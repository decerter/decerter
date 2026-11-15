# Control API
`decerter run --api-socket` and `decerter capture --api-socket` serve HTTP on a unix socket under `/api/v1`. The contract is [api/openapi.yaml](../api/openapi.yaml) (OpenAPI 3.0.3, MIT licensed, so any client can be generated from it); a unit test checks the routes against it both ways and validates real responses. [`decerter ui`](ui.md), [`decerter mcp`](mcp.md) and the separate decerter-pro are clients of this API and can do nothing curl on the socket can't.

```sh
sudo ./decerter run --uid 1001 --intercept --api-socket /run/decerter/api.sock
api() { sudo curl -s --unix-socket /run/decerter/api.sock -H 'Content-Type: application/json' "$@"; }   # or curl without sudo as a member of the group decerter

api http://decerter/api/v1/status
api 'http://decerter/api/v1/flows?filter=tls.sni+contains+%22example%22'      # newest first, ?limit=&cursor= pages
api http://decerter/api/v1/flows/1/messages                                   # direction, length, edited; no payloads
api 'http://decerter/api/v1/messages/1?offset=0&length=4096'                  # payload as hex and escaped text
api -N http://decerter/api/v1/events                                          # server-sent events, no payloads
```

The host in the URL is `decerter`, `localhost` or a loopback address (with or without a port), and a request body needs `Content-Type: application/json`, which the `api` function above sends.

## Access
`--api-socket` takes a socket path or `@name` for an abstract socket. The usual ones are `/run/decerter/api.sock` on Linux and `@decerter-api` on Android. decerter serves the API only on a unix socket, its access control is the socket's mode and the peer credentials: a loopback `ip:port` such as `127.0.0.1:8080` is refused with an error (`decerter ui` and `decerter mcp` take one to dial the host side of `adb forward`), and a socket file in the current directory is written `./name`.

- **Socket file:** mode 0660 and the group `decerter` when that group exists (decerter doesn't create it: `sudo groupadd decerter`, `sudo usermod -aG decerter $USER`, log in again, restart decerter), mode 0600 for root alone otherwise, with a warning. decerter creates it under a temporary name and renames it, refuses a path that exists and is no socket or a socket another decerter serves, replaces a socket a killed decerter left, and removes it on exit.
- **Abstract socket:** it has no mode, so decerter checks the peer with `SO_PEERCRED`: root; on Android also adb's shell user (uid 2000); on Linux peers whose primary group is `decerter`.
- **Android:** `adb forward tcp:8080 localabstract:decerter-api` makes the API reachable on the host as `http://127.0.0.1:8080/api/v1/…`; adbd connects as root after `adb root` and as shell otherwise. adb forward's port is open to every local user of the workstation.
- **Browsers:** the API is for curl, scripts, `decerter ui` and `decerter mcp`, never for a web page. On the host side of `adb forward` every page in the workstation's browser could send to it, so it answers `403` to a request with an `Origin` or `Sec-Fetch-Site` header (only browsers send them; `decerter ui` drops them) and to a `Host` other than `decerter`, `localhost` or a loopback address (DNS rebinding: a page's own name resolved to 127.0.0.1), and `400` to a body that is not `application/json`, the type a page can't send without asking first.

## Operations
| Method and path | Operation | What |
|---|---|---|
| `GET /status` | getStatus | mode, version, intercept state, scope filter, history usage |
| `GET /flows` | listFlows | flows of the history, newest first; `filter`, `limit`, `cursor` |
| `GET /flows/{id}` | getFlow | one flow: process, addresses, TLS fields, counters |
| `GET /flows/{id}/messages` | listMessages | a flow's messages without payloads |
| `GET /messages/{id}` | getMessage | one message with a window of its payload (`offset`, `length`), as hex and escaped text, and the original when it was edited |
| `GET /flows/{id}/exchanges` | listExchanges | a flow's HTTP exchanges without bodies ([HTTP layer](http.md)) |
| `GET /exchanges/{id}` | getExchange | one exchange with its heads |
| `GET /exchanges/{id}/body` | getExchangeBody | a window of the request or response body |
| `GET /events` | streamEvents | server-sent events: flows opened and closed, messages, exchanges, holds, rules, intercept changes; no payloads |
| `PUT /intercept` | setIntercept | turn holding on or off, with a filter, a direction and a layer |
| `GET /holds` | listHolds | held messages with their payloads, or with `offset` and `length` a window of each |
| `PUT /holds/{id}` | editHold | replace a held message's payload |
| `POST /holds/{id}/forward` | forwardHold | let it go on |
| `POST /holds/{id}/drop` | dropHold | drop it |
| `GET /rules` | listRules | the API's match-and-replace rules in the order they run |
| `POST /rules` | addRule | add a rule |
| `DELETE /rules/{id}` | deleteRule | delete a rule |
| `GET /keylog` | exportKeylog | NSS key log of the TLS and DTLS sessions in the history |
| `GET /flows/pcap` | exportPcap | the history as pcapng: `format=plaintext` (synthesized packets) or `format=dsb` (captured packets with secrets) |
| `GET /captures` | listCaptures | the API's captures ([capture](capture.md#capture-api)) |
| `POST /captures` | startCapture | start one with its own filter and format |
| `POST /captures/{id}/stop` | stopCapture | stop it |
| `GET /captures/{id}/pcap` | downloadCapture | download a stopped one |
| `GET /captures/stream` | streamCapture | the live pcapng stream for Wireshark and tshark |

Errors are JSON `{"error": "…"}` with the HTTP status. A request that needs something the mode lacks answers 409: intercept, holds and rules without `--intercept` (and in capture mode), the key log without secrets, a download of a running capture.

## Holds and rules
```sh
# hold the client's requests, edit one and let it go
api -X PUT -d '{"enabled": true, "filter": "proc.comm == \"curl\""}' http://decerter/api/v1/intercept
api http://decerter/api/v1/holds                                              # held messages with their payloads
api -X PUT -d '{"payload": {"type": "text", "value": "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"}}' http://decerter/api/v1/holds/7
api -X POST http://decerter/api/v1/holds/7/forward                            # or /drop

# a match-and-replace rule for the next requests, and its removal
api -X POST -d '{"direction": "up", "find": {"type": "regex", "value": "GET /(\\S*) "}, "replace": {"type": "text", "value": "GET /test/$1 "}}' http://decerter/api/v1/rules
api -X DELETE http://decerter/api/v1/rules/1

api 'http://decerter/api/v1/keylog?filter=tls' > keys.log                     # NSS key log of the TLS sessions in the history
api -o flows.pcapng 'http://decerter/api/v1/flows/pcap?format=plaintext'      # the history as synthesized packets, edits as they went on
```

Holding and rules need `--intercept`. The rules of the code run first (the identity rule of `--intercept`), then the API rules in the order they were added, then the hold queue, so a held message shows what goes on the wire.

- A message is one TLS or DTLS record's application data, one read of a plain TCP stream, or one UDP datagram; with layer `http` it is a whole HTTP message ([HTTP layer](http.md)). A rule sees one message at a time, so a value split over two messages is not found by a record rule.
- A rule has a `filter` (the [filter language](filter.md)), a `direction` (`up` is client to server, `down` back, `both` the default), a `layer` (`tcp`, `tls`, `udp`, `dtls`, `http`; empty is every record layer) and `find` and `replace`, each `{"type": "text"|"hex"|"regex", "value": …}`. A `text` value is the characters as they are (a JSON `"\r\n"` is CR LF), `hex` is hex digits, `regex` is Go RE2 and `$1` in the replacement expands.
- `PUT /intercept` holds matching messages; the direction defaults to `up`. A held message blocks only its own direction of its own flow (each UDP client session has its own sender; on HTTP/2 only its stream). One that nobody decides goes on unchanged after `--hold-timeout` (60 s, at most 1 h). Turning intercept off lets every held message go on, and a flow that ends drops what it held.
- A dropped request is simply not sent: the client waits for an answer until its own timeout (on HTTP/2 both peers get `RST_STREAM` instead).
- An edited TLS record is sealed again with the session keys at the right sequence number; a payload over 2^14 bytes becomes several records.

## History
The history is in memory: at most 10000 flows, 200000 messages and 64 MiB of payload, 20000 messages and 1 MiB of payload per flow; the oldest flow goes first. It records the flows in scope in every mode, the decrypted records with `--decrypt` and every message through the rules with `--intercept`; plain relaying keeps no payloads. With the API every flow in scope is classified as TLS or not, so the proxy reads its first bytes before relaying it. Capture mode's history has flows but no messages. The history and the rules live only as long as decerter runs.

The event stream has no replay: a client that falls 256 events behind gets an `overflow` event and the stream ends.
