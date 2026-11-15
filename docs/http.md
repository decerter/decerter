# HTTP layer
With the [control API](api.md) on, `decerter run` reads HTTP/1.1 and HTTP/2 from the flows in scope: each request and its response is an exchange in the history, and rules and holds of layer `http` take whole HTTP messages instead of single records.

```sh
api() { sudo curl -s --unix-socket /run/decerter/api.sock -H 'Content-Type: application/json' "$@"; }

# the exchanges of a flow, one with its heads, a window of its response body without chunking
api 'http://decerter/api/v1/flows?filter=http.request.method+%3D%3D+%22POST%22'
api http://decerter/api/v1/flows/1/exchanges
api http://decerter/api/v1/exchanges/1
api 'http://decerter/api/v1/exchanges/1/body?side=response&offset=0&length=4096'
# HTTP/2: the flows with a stream above 99; the gRPC message boundaries of an exchange are in its heads, field grpc_messages
api 'http://decerter/api/v1/flows?filter=http2.streamid+%3E+99'

# hold whole HTTP requests, and a rule on whole responses (a word split over two chunks is found)
api -X PUT -d '{"enabled": true, "layer": "http", "filter": "http.request.method == \"POST\""}' http://decerter/api/v1/intercept
api -X POST -d '{"layer": "http", "direction": "down", "find": {"type": "text", "value": "world"}, "replace": {"type": "text", "value": "planet"}}' http://decerter/api/v1/rules
# HTTP/2: a request's head is ":method: GET\r\n:scheme: https\r\n:authority: example.com\r\n:path: /\r\n…\r\n\r\n", so :path is one line of it
api -X POST -d '{"layer": "http", "direction": "up", "find": {"type": "text", "value": ":path: /\r\n"}, "replace": {"type": "text", "value": ":path: /test\r\n"}}' http://decerter/api/v1/rules
```

Which flows are read: plain TCP with `--intercept`, decrypted TLS with `--intercept` or `--decrypt`. A TLS flow with ALPN `h2`, or a flow without ALPN whose client starts with the HTTP/2 connection preface (h2c with prior knowledge), is HTTP/2; ALPN `http/1.1` or none is HTTP/1. `--decrypt` without `--intercept` shows TLS exchanges but not plain HTTP ones. The [filter fields](filter.md#http-fields) `http.*` and `http2.streamid` match exchanges and messages of layer `http`.

## HTTP/1.1
decerter reads HTTP/1.1 (and 1.0) with its own incremental parser, which keeps every head as it came (`net/http` would change the case, order and merging of fields). Keep-alive, pipelining, Content-Length, chunked bodies with extensions and trailers, bodies delimited by the end of the stream, 1xx responses (100-continue) and responses without a body (HEAD, 204, 304) are followed. `101 Switching Protocols` and a `2xx` answer to CONNECT end the reading for the rest of the flow (a refused CONNECT, such as `407 Proxy Authentication Required`, is read on, so its retry on the same connection is seen too), and so does anything that is not HTTP/1 (another protocol, the HTTP/2 preface, a head over 64 KiB). An exchange has the heads with their fields in order and case and the bodies without chunk framing. Limits: 100000 exchanges and 32 MiB of heads and bodies, 10000 exchanges and 1 MiB per flow, counted apart from the message payloads; at most 16 interim (1xx) heads per exchange. A head the bytes have no room for keeps only its start line (no fields, no reason, the target cut to 256 bytes), so its exchange still shows the method, target and status, and the flow is marked truncated; gRPC message boundaries stop at the limit too.

## HTTP/2
HTTP/2 is read with `golang.org/x/net/http2`'s framer and HPACK decoder, one per direction, next to the relay. Frames are reassembled from records and reads of any size; header blocks with CONTINUATION, padding and priority are decoded in order, so the dynamic table stays in step, and the table size a peer allows in SETTINGS counts once the other peer acknowledges it. A server that speaks first, as Go's h2c server does, is read once the client's preface came.

Each stream is an exchange (`stream_id`): the pseudo-header fields give the method, the target (`:path`), the status and the URL (`:scheme`, `:authority`) and stay in the header list in the order they came; a header block after the body is the trailers; a 1xx before the response is an interim head; `PUSH_PROMISE` opens an exchange with the promised request (`promise_stream_id`); `RST_STREAM`, `GOAWAY` and the end of the connection end the open messages as incomplete with a note. A body whose `content-type` starts with `application/grpc` lists its length-prefixed messages in `grpc_messages` (offset, length, compressed flag; at most 1000, not decoded). At most 1000 streams of a flow are followed at once and heads keep 64 KiB of fields. A malformed frame, a frame over the receiver's `SETTINGS_MAX_FRAME_SIZE` or an HPACK error stops reading the flow, with a note on every open exchange; its bytes go on as they come and the relay is never touched.

## Rules and holds of layer http
They run after the record rules, which still see every record, on whole messages. A message is kept back from its first byte while such a rule or hold exists; once its head is there and nothing matches it, it goes on at once. A message that went through unchanged goes on byte for byte as it came.

**HTTP/1:** the message is the head as it came followed by the body without chunk framing, so a value split over records or chunks is found. An edited message keeps its head as written (no field is added, reordered or recased) with two fixes: every Content-Length gets the length of the new body, and a chunked body is sent as one chunk followed by the original trailers; a body on a message that had neither field gets a Content-Length. A response that has no body by its status or its request (HEAD, 1xx, 204, 304) goes on exactly as written: its Content-Length and Transfer-Encoding describe the representation, so neither is changed and no chunk is added. On TLS it is sealed again as records with the session keys, and the records after it keep their sequence numbers. A dropped request is not sent and its response slot goes to the next request.

**HTTP/2:** the message is one side of one stream, in this form: one `name: value` line per header field, the pseudo-header fields first in their order, then the other fields in theirs, lines ending in CR LF, a blank line, and the body (the payloads of its DATA frames joined, without padding). Trailers are not in the form; they go on as they came. A gRPC body is raw bytes with its 5-byte prefixes, which decerter does not recompute.
- A message whose head a rule or the hold queue takes is kept back on its stream until its END_STREAM; the other streams go on meanwhile, and a hold runs on its own. Only new streams the client opens after a held request wait for it, because a server has to see stream ids in increasing order.
- An edited message goes on with its head encoded again (names in lower case, `content-length` set to the new body's length) and its body in new DATA frames without padding; a head or body the edit did not change keeps its frames. A form that is no HTTP/2 message (no blank line, a line without a colon, a pseudo-header field after another field) lets the message go on as it came, with a note. A dropped message ends its stream with `RST_STREAM(CANCEL)` to each peer that knows it.
- **HPACK:** as long as every header block of a direction goes on as it came and in order, nothing is encoded again. The first block that does not (an edit, a drop, a block held while later ones go on) switches that direction to decerter's own encoder for the rest of the connection: a dynamic table size update to 0, then literals without indexing (static table and Huffman still used), so the receiver's table stays empty and any `SETTINGS_HEADER_TABLE_SIZE` is respected, at the cost of larger blocks. Blocks larger than the receiver's `SETTINGS_MAX_FRAME_SIZE` go on as HEADERS and CONTINUATION frames.
- **Flow control:** per direction and stream decerter counts the window the receiver granted and the difference between what the sender sent and what went on. The sender gets a WINDOW_UPDATE of its own at once for bytes the receiver will never count (a kept message's DATA, a shrunk body, dropped padding, a dropped message); when an edit sent more than the sender did, that much of the receiver's WINDOW_UPDATEs is held back. DATA never goes beyond the receiver's windows and is split at its `SETTINGS_MAX_FRAME_SIZE`. `RST_STREAM`, `GOAWAY`, `PING`, `SETTINGS` and `PRIORITY` go on as they came.

## Limits
- A body over 1 MiB, a message that is not whole within `--assembly-timeout` (5 s, at most 1 h; counted from its first byte, apart from `--hold-timeout`, which counts once the whole message is held), or one that a TLS alert or KeyUpdate interrupts goes on as it came, with a note in its exchange.
- A kept-back request with `Expect: 100-continue` waits for the client's own expect timeout (curl: 1 s) or `--assembly-timeout`, whichever comes first, since the server can't answer before it has the head.
- Bodies are not decompressed, so a rule doesn't find text in a gzip body.
- HTTP/2: a stream's window held back for a grown body is forgotten once both sides ended the stream; never-indexed fields are encoded again as literals without indexing; server push is passed on but its messages are not kept; a header block over 1 MiB can't be encoded again.
- Not read: h2c by `Upgrade: h2c` (the 101 ends the HTTP/1 reading), WebSocket, the inside of CONNECT tunnels, HTTP/3.
