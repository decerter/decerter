# Packet decoders
decerter decodes a message's payload, an HTTP body or the TLS handshake of a flow into a tree of fields, like the packet details pane of Wireshark: a DNS answer shows its header flags, its questions and its records with typed values instead of hex, a ClientHello its extensions and JA4. A decode runs only when it is asked for, over the [control API](api.md), in the [web UI](ui.md) and with the [MCP](mcp.md) tools `decode_message`, `decode_exchange_body` and `decode_flow`; the proxy never decodes anything on its own. The one thing it does on the hot path is copy the handshake records of TLS and DTLS flows, see [TLS handshake](#tls-handshake).

The decoders are decerter's own Go code written from the RFCs and the protocol specifications, with the standard library only (`crypto/x509` reads certificates); no code of Wireshark or of another dissector library is in decerter. `google.golang.org/protobuf/encoding/protowire` (BSD-3-Clause) is an oracle of the protobuf fuzz test only, it is not in the binary.

Protocols: DNS (over UDP, TCP, TLS, DTLS and HTTPS, mDNS and LLMNR), gRPC and gRPC-Web, Protocol Buffers without a schema, TLS and DTLS records and handshakes, and WebSocket.

## API
| Method and path | Operation | Bytes decoded |
|---|---|---|
| `GET /messages/{id}/decode` | decodeMessage | the message's payload, as `GET /messages/{id}` has it; `original=true` decodes what the peer sent when a rule or an edit changed it |
| `GET /exchanges/{id}/decode` | decodeExchangeBody | the body of one side (`side=request`, the default, or `response`) without its chunk framing, as `GET /exchanges/{id}/body` has it; `original=true` decodes the body before an edit of layer `http` |
| `GET /flows/{id}/decode` | decodeFlow | `part=handshake` (the default, the only part so far): the handshake records decerter kept of one direction (`direction=up`, the default, or `down`) of a TLS or DTLS flow; the bytes are in `data` |

All three take `as` (Decode As): a protocol of `protocols` in the answer, or `raw` for none. An unknown `as` is a 400. Without `as` decerter chooses. A payload that no decoder takes is not an error: it comes back as protocol `raw` with one `raw` node over its bytes.

```sh
sudo curl --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/messages/42/decode'
sudo curl --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/exchanges/7/decode?side=response&as=dns'
sudo curl --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/flows/3/decode?part=handshake&direction=down'
```

A DNS query of a UDP flow to port 53 (the tree is cut after the flags):

```json
{
  "message_id": 42,
  "source": "payload",
  "protocol": "dns",
  "summary": "Standard query 0xbeef A example.com",
  "length": 29,
  "total": 29,
  "truncated": false,
  "candidates": [
    {"protocol": "dns", "basis": "port", "reason": "udp port 53 is Domain Name System", "score": 100},
    {"protocol": "dns", "basis": "sniff", "reason": "the bytes read as Domain Name System", "score": 100}
  ],
  "tree": [
    {"name": "dns", "label": "Domain Name System (query)", "offset": 0, "length": 29, "children": [
      {"name": "dns.id", "label": "Transaction ID", "value": "0xbeef", "offset": 0, "length": 2},
      {"name": "dns.flags", "label": "Flags", "value": "0x0100 Standard query", "offset": 2, "length": 2, "children": [
        {"name": "dns.flags.response", "label": "Response", "value": "Message is a query", "offset": 2, "length": 2, "mask": 32768},
        {"name": "dns.flags.recdesired", "label": "Recursion desired", "value": "yes", "offset": 2, "length": 2, "mask": 256}
      ]},
      {"name": "dns.queries", "label": "Queries", "value": "1", "offset": 12, "length": 17, "children": [
        {"name": "dns.qry", "label": "example.com: type A, class IN", "offset": 12, "length": 17, "children": [
          {"name": "dns.qry.name", "label": "Name", "value": "example.com", "offset": 12, "length": 13},
          {"name": "dns.qry.type", "label": "Type", "value": "A (1)", "offset": 25, "length": 2},
          {"name": "dns.qry.class", "label": "Class", "value": "IN (1)", "offset": 27, "length": 2}
        ]}
      ]}
    ]}
  ],
  "protocols": ["dns", "raw"]
}
```

- `source` names the bytes that `offset` and `length` count in. `payload` is the message's payload, the same offsets as the `offset` of a `GET /messages/{id}` window. `body` is the exchange body, as in `GET /exchanges/{id}/body`. `target` is the bytes decerter took from the request target, because the request had no body (the `dns` parameter of a DoH GET). `handshake` is the handshake records of a flow's direction (`flow_id`, `direction`, and `cut` when a record did not fit). Those bytes are in `data` then, a payload window with hex and escaped text, and the offsets count from their first byte.
- A node has a filter-style `name` (`dns.qry.name`), a `label`, a `value` (empty for a branch), `offset` and `length`, a `mask` for a field smaller than its bytes (a flag bit), an `error` when that part is malformed or cut short, and `children`. The names follow Wireshark's where one exists, so they look familiar; they are not fields of [decerter's filter language](filter.md).
- `summary` is one line, like Wireshark's info column. `error` is set when the decoder failed (a panic, which decerter catches): the tree is then the raw node.
- `length` is the number of bytes decoded and `total` the payload's length. `truncated` is true when the input was cut at 1 MiB or the tree reached a limit; its last root is then a `decode.truncated` node that says which limit.

## How decerter chooses
The candidates are listed in this order, each with its reason. The first one with a score above 0 is taken. Sniffing alone needs a score of 50.
1. `override`: `as=` names the protocol. It is always taken, and the decoder then reports what doesn't fit as node errors.
2. `context`: something outside the bytes names the protocol. Examples are an HTTP body's `Content-Type` (`application/dns-message`, `application/grpc`, `application/x-protobuf`), the `dns` parameter of a GET, a TLS ALPN `dot`, the `Upgrade: websocket` of a 101 the flow's last exchange switched with (or the `:protocol` of an HTTP/2 extended CONNECT), and the handshake records of `GET /flows/{id}/decode`.
3. `port`: the flow's server port on its layer, such as udp 53, tcp 53, udp 5353 (mDNS), udp 5355 (LLMNR), tls 853, dtls 853 and tcp 443 (TLS records of a flow decerter only relays). HTTP bodies have no port candidate.
4. `sniff`: every decoder scores the bytes from 0 to 100, highest first.
5. `none`: nothing took the bytes, and the result is `raw`.

Protocol Buffers and WebSocket never win by sniffing alone (their scores stay below 50): bytes read cleanly as protobuf far too often, and a frame alone is not proof of WebSocket. `as=protobuf`, a content type or a WebSocket binary message takes protobuf.

A context or port candidate needs a sniff score above 0, so a port that carries something else (a TCP read that starts in the middle of a DNS message, for example) falls through to the next candidate instead of producing a tree full of errors.

## Framing
- A UDP datagram, the application data of one DTLS record and an HTTP body each hold one PDU.
- A TCP read and the application data of one TLS record are pieces of a stream. decerter doesn't reassemble streams yet: a decoder reads the PDUs that start in the message. DNS over TCP and TLS reads each message's 2-byte length. Several messages in one read become several roots. A message that goes on in the next read gets an error that says how many of its bytes are there.

## Limits
Every decode reads untrusted bytes, so each one is bounded:
- Input: at most 1 MiB. The rest is left out and the result is truncated.
- The tree: at most 10000 nodes, nesting 32 deep and 4 MiB of strings. Past a limit the tree stops growing.
- A value written as hex or base64 (a signature, unknown rdata) shows its first 256 bytes, but the node still spans the whole field. The summary is at most 512 bytes.
- DNS names: at most 32 compression pointers per name (a pointer loop is an error, not a hang) and 255 bytes on the wire. Reserved label types are an error.
- A panic in a decoder or a sniff function is recovered. It gives the raw tree and an `error`, and decerter logs a warning.
- Every string of the tree is escaped: printable ASCII stays as it is, and every other byte becomes `\xNN`. A DNS label also writes a dot, a space and a backslash inside the label as `\x2e`, `\x20` and `\\`. Text from the traffic, such as a TXT string, is escaped like the payloads: `\\`, `\n`, `\r`, `\t` and `\xNN`. `decerter mcp` escapes each string again and turns a `<` that would open or close its marker into `\x3c`.

- Inflating (gRPC gzip, WebSocket permessage-deflate) stops at 1 MiB with an error; text values show their first 1024 bytes; protobuf follows nested messages and groups 10 levels deep, deeper ones are bytes; a certificate shows at most 64 names of each kind.

Each decoder has a fuzz test, `go test -tags unit -run '^$' -fuzz '^FuzzDNS$' ./internal/decode` and the same with `FuzzProtobuf`, `FuzzGRPC`, `FuzzTLS`, `FuzzDTLS` and `FuzzWebSocket`: every context and `as` over a seed corpus, checking these limits. `FuzzDNS` also checks that the question and record counts agree with `golang.org/x/net/dns/dnsmessage`, `FuzzProtobuf` that the fields agree with `protowire`; both are used in tests only.

## DNS
- Transports: UDP 53, mDNS 5353 (the cache-flush and unicast-response bits of the class), LLMNR 5355, TCP 53 with the 2-byte length, DNS over TLS 853, DNS over DTLS 853, and DNS over HTTPS: an `application/dns-message` body of a POST or of a response, or the base64url `dns` parameter of a GET.
- The header with each flag and the opcode and rcode by name, then the questions, answers, authority and additional records.
- Names follow compression pointers. A name's node spans its bytes in the message, including its pointer.
- Typed records:
  - A, AAAA
  - NS, CNAME, PTR and DNAME
  - MX and KX
  - TXT and SPF, each string
  - HINFO
  - SOA, with durations as `300 (5m)`
  - SRV
  - CAA
  - SVCB and HTTPS with their parameters: mandatory, alpn, no-default-alpn, port, ipv4hint, ech, ipv6hint, dohpath, tls-supported-groups, and others as hex
  - OPT with the EDNS header (UDP payload size, extended rcode, version, DO bit) and its options: NSID, DAU/DHU/N3U, Client Subnet, Expire, Cookie, TCP keepalive, Padding, Extended DNS Error, and others as hex
  - DS and CDS, DNSKEY and CDNSKEY with their key tag, RRSIG with RFC 3339 times, NSEC with its type bitmap
- Other types are shown as hex. Each rdata is checked against its length.

## Protocol Buffers
Without a schema, like `protoc --decode_raw` (from protobuf.dev's encoding guide):
- Each field shows its number and wire type (the low 3 bits of the tag as a bit field when the tag has at most 4 bytes).
- VARINT: the value, as int64 when it is negative that way, as sint (zigzag) and, for 0 and 1, as bool.
- I64 and I32: the unsigned value, signed when negative, and as double or float.
- LEN: text that starts with a printable byte is a string; otherwise bytes that read as a message to their end are a nested message, then UTF-8 text a string, else bytes (hex). Groups (SGROUP to EGROUP) nest like messages.
- Taken by `as=protobuf`, a body with `Content-Type` `application/x-protobuf`, `application/protobuf`, `application/x-google-protobuf` or `application/vnd.google.protobuf`, a gRPC message and a WebSocket binary message.

## gRPC
- An HTTP/2 body (the exchange body the history keeps, with its 5-byte prefixes) of `application/grpc`, `application/grpc+proto` and other `+codec`s, and gRPC-Web `application/grpc-web[+codec]`; `application/grpc-web-text` is base64 and not taken. Without a content type, a body of prefixed messages to its end sniffs as gRPC.
- Each message is a root with its compressed flag and length, then its protobuf fields at body offsets (a `+json` or other codec as text or hex). A gRPC-Web trailers frame shows its header lines. A message cut short says how many of its bytes are there.
- A compressed message is inflated when the side's `grpc-encoding` is `gzip`; its fields all span the compressed bytes. Another encoding is shown as bytes with an error.
- The summary: `gRPC request /pkg.Service/Method, 2 messages`.

## TLS handshake
`decerter run --decrypt` and `--intercept` read the record layer of TLS and DTLS flows. As each record comes, the history copies the handshake, alert and change cipher spec records of the flow, nothing else; parsing happens only when `GET /flows/{id}/decode` asks:
- Each record is kept as a record header and its plaintext: a record decerter decrypted (the TLS 1.3 EncryptedExtensions, Certificate, CertificateVerify, Finished and NewSessionTicket, the TLS 1.2 Finished, alerts after the handshake) gets its inner content type and its plaintext length. DTLS records keep their 13-byte header; an encrypted DTLS record decerter could not decrypt is left out. Application data is never kept, it is in the messages.
- At most 16 KiB per direction (`MaxHandshakeBytes`); a record past that is cut and the direction is marked `cut`. The bytes count in the history's payload limits and go with the flow when it is evicted. `handshake_bytes` of a flow's `up` and `down` says how much was kept.
- `decerter capture` and plain relaying keep no handshake: their flows have no records decerter reads.

The tree:
- Records with content type, version and length (DTLS: epoch and sequence number). A handshake message over several TLS records is put together into a `tls.handshake.reassembled` root whose nodes span its pieces; DTLS fragments are shown as they are.
- ClientHello and ServerHello in full: version, random, session id, cipher suites by IANA name, compression, and the extensions server_name, max_fragment_length, status_request, supported_groups, ec_point_formats, signature_algorithms(_cert), ALPN, ALPS, padding, compress_certificate, record_size_limit, pre_shared_key, early_data, supported_versions, cookie, psk_key_exchange_modes, key_share (ClientHello, ServerHello and HelloRetryRequest forms), encrypted_client_hello (outer: config id, cipher suite, enc, payload) and renegotiation_info; others as hex. GREASE values are named.
- Fingerprints over the hello: JA3 and JA3S (the string and its MD5) and JA4 (FoxIO, BSD-3-Clause). JA4S and the other JA4+ fingerprints are not computed. They match tshark 4.4 on curl's hellos.
- HelloRetryRequest (by its random), HelloVerifyRequest, NewSessionTicket, EncryptedExtensions, Certificate (TLS 1.2 and 1.3 forms; each certificate read with `crypto/x509`: subject, issuer, serial number, validity in RFC 3339, algorithms, CA, and the DNS, IP, email and URI names, all spanning the certificate's DER), ServerKeyExchange (ECDHE named curve and point, signature), CertificateRequest, CertificateVerify, ClientKeyExchange, Finished, CertificateStatus and KeyUpdate.
- Alerts with level and description; after a change cipher spec of TLS 1.2 or on an encrypted DTLS epoch, records shown as encrypted.

The same decoder also takes TLS records as they go over tcp (a flow to port 443 that decerter only relays, or `as=tls`): the hellos and a TLS 1.2 server's certificate are plaintext there, the rest is encrypted.

## WebSocket
- The reads of a tcp or tls flow after an HTTP/1.1 `Upgrade: websocket` (the flow's last exchange is a 101 whose request came before the message; the read of the 101 can carry the first frames, its head is a `websocket.http_head` node), and the bodies of an HTTP/2 extended CONNECT whose `:protocol` is `websocket`.
- Each frame: FIN, RSV1-3, opcode, mask, payload length (with the 16- or 64-bit extended length), masking key, and the payload unmasked; close frames with their status code and reason, ping and pong.
- A text message as text; a binary one as the protocol its bytes sniff as (protobuf counts from its clean score), else hex. A message in several frames is put together into a `websocket.message` root after its last frame, control frames between them stay where they are.
- permessage-deflate (when the 101's `Sec-WebSocket-Extensions` has it): a message with RSV1 is inflated alone, at most 1 MiB; one that uses the window of earlier messages (context takeover) can't be inflated alone and gets an error that says so.
- Errors for what RFC 6455 forbids: a client frame without a mask or a server frame with one, reserved bits without an extension, reserved opcodes, a fragmented or long control frame, a continuation without its start, text that is not UTF-8.
- A frame that goes on in the next read says how many of its bytes are there; frames are not joined across reads.

## Web UI
The message view and the exchange view show the tree next to the bytes: a summary, the reason for the choice, and a "decode as" list. Clicking a node marks its bytes in the hex dump or the escaped text, and pages to them when they are outside the 4 KiB window. Clicking a byte selects the deepest node that has it and opens the branches above it. The "decode as" choice stays until it is set back to auto. A DoH GET shows the bytes of its `dns` parameter above the (empty) body. A TLS or DTLS flow with kept handshake records shows a Handshake pane under the flow's fields: client or server, its tree and all its bytes as a hex dump.

## Adding a protocol
A protocol is one new file in `internal/decode` whose `init()` calls `register(decoder{...})` with these fields:
- its name and title
- its ports per layer
- `hint`, the context reasons, such as a content type, an ALPN or an Upgrade header
- `sniff`, a score of the bytes
- `decode`, which adds nodes with `tree.add`, `tree.fail` and `tree.addSummary`
- `fromTarget` when a request target can carry the PDU

The registry, the choice order, the limits, `as=`, the API, the UI and both MCP tools pick a new protocol up with no other change. The planned ones are:
- STUN, RTP, DHCP, NTP, MQTT, RESP, SMTP, IMAP, POP3, PostgreSQL, MySQL, a BER walker and QUIC Initial

## Stream reassembly (planned)
A PDU that spans reads, such as a large DNS-over-TCP answer, a TLS handshake split over records, or a PostgreSQL or MySQL message, needs the bytes of more than one message. The plan, not built yet:
- `GET /flows/{id}/decode?part=stream&direction=up|down` joins the payloads of one direction of a TCP or TLS flow in order. A table maps each stream offset back to (message id, offset in that message).
- A stream decoder gets a `frame` function that tells a PDU's length from its first bytes (the 2-byte length of DNS, the 5-byte header of a TLS record, the 5-byte header of PostgreSQL). The framer walks the joined stream and decodes each whole PDU as a datagram.
- The tree's offsets stay stream offsets. The API adds the message spans of each root, so the UI can mark bytes across messages and page to the right message. The input, node and depth limits apply to the whole stream, and a PDU longer than the input limit gets an error.
- The per-message decode stays as it is. It is the view of one read, and it already shows where a PDU goes on.
