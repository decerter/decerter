# Packet decoders
decerter decodes a message's payload or an HTTP body into a tree of fields, like the packet details pane of Wireshark: a DNS answer shows its header flags, its questions and its records with typed values instead of hex. A decode runs only when it is asked for, over the [control API](api.md), in the [web UI](ui.md) and with the [MCP](mcp.md) tools `decode_message` and `decode_exchange_body`; the proxy never decodes anything on its own.

The decoders are decerter's own Go code written from the RFCs, with the standard library only; no code of Wireshark or of another dissector library is in decerter.

## API
| Method and path | Operation | Bytes decoded |
|---|---|---|
| `GET /messages/{id}/decode` | decodeMessage | the message's payload, as `GET /messages/{id}` has it; `original=true` decodes what the peer sent when a rule or an edit changed it |
| `GET /exchanges/{id}/decode` | decodeExchangeBody | the body of one side (`side=request`, the default, or `response`) without its chunk framing, as `GET /exchanges/{id}/body` has it; `original=true` decodes the body before an edit of layer `http` |

Both take `as` (Decode As): a protocol of `protocols` in the answer, or `raw` for none. An unknown `as` is a 400. Without `as` decerter chooses. A payload that no decoder takes is not an error: it comes back as protocol `raw` with one `raw` node over its bytes.

```sh
sudo curl --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/messages/42/decode'
sudo curl --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/exchanges/7/decode?side=response&as=dns'
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

- `source` names the bytes that `offset` and `length` count in. `payload` is the message's payload, the same offsets as the `offset` of a `GET /messages/{id}` window. `body` is the exchange body, as in `GET /exchanges/{id}/body`. `target` is the bytes decerter took from the request target, because the request had no body (the `dns` parameter of a DoH GET). Those bytes are in `data` then, a payload window with hex and escaped text, and the offsets count from their first byte.
- A node has a filter-style `name` (`dns.qry.name`), a `label`, a `value` (empty for a branch), `offset` and `length`, a `mask` for a field smaller than its bytes (a flag bit), an `error` when that part is malformed or cut short, and `children`. The names follow Wireshark's where one exists, so they look familiar; they are not fields of [decerter's filter language](filter.md).
- `summary` is one line, like Wireshark's info column. `error` is set when the decoder failed (a panic, which decerter catches): the tree is then the raw node.
- `length` is the number of bytes decoded and `total` the payload's length. `truncated` is true when the input was cut at 1 MiB or the tree reached a limit; its last root is then a `decode.truncated` node that says which limit.

## How decerter chooses
The candidates are listed in this order, each with its reason. The first one with a score above 0 is taken. Sniffing alone needs a score of 50.
1. `override`: `as=` names the protocol. It is always taken, and the decoder then reports what doesn't fit as node errors.
2. `context`: something outside the bytes names the protocol. Examples are an HTTP body's `Content-Type: application/dns-message`, the `dns` parameter of a GET, a TLS ALPN `dot` and, later, an `Upgrade` header.
3. `port`: the flow's server port on its layer, such as udp 53, tcp 53, udp 5353 (mDNS), udp 5355 (LLMNR), tls 853 and dtls 853. HTTP bodies have no port candidate.
4. `sniff`: every decoder scores the bytes from 0 to 100, highest first.
5. `none`: nothing took the bytes, and the result is `raw`.

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

The fuzz test `FuzzDNS` (`go test -tags unit -run '^$' -fuzz FuzzDNS ./internal/decode`) runs every context and both `as` values over a seed corpus and checks these limits. It also checks that the question and record counts agree with `golang.org/x/net/dns/dnsmessage`, which is used in tests only.

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

## Web UI
The message view and the exchange view show the tree next to the bytes: a summary, the reason for the choice, and a "decode as" list. Clicking a node marks its bytes in the hex dump or the escaped text, and pages to them when they are outside the 4 KiB window. Clicking a byte selects the deepest node that has it and opens the branches above it. The "decode as" choice stays until it is set back to auto. A DoH GET shows the bytes of its `dns` parameter above the (empty) body.

## Adding a protocol
A protocol is one new file in `internal/decode` whose `init()` calls `register(decoder{...})` with these fields:
- its name and title
- its ports per layer
- `hint`, the context reasons, such as a content type, an ALPN or an Upgrade header
- `sniff`, a score of the bytes
- `decode`, which adds nodes with `tree.add`, `tree.fail` and `tree.addSummary`
- `fromTarget` when a request target can carry the PDU

The registry, the choice order, the limits, `as=`, the API, the UI and both MCP tools pick a new protocol up with no other change. The planned ones are:
- gRPC and protobuf, the TLS handshake and WebSocket, keyed by content type, ALPN and Upgrade
- STUN, RTP, DHCP, NTP, MQTT, RESP, SMTP, IMAP, POP3, PostgreSQL, MySQL, a BER walker and QUIC Initial

## Stream reassembly (planned)
A PDU that spans reads, such as a large DNS-over-TCP answer, a TLS handshake split over records, or a PostgreSQL or MySQL message, needs the bytes of more than one message. The plan, not built yet:
- An endpoint `GET /flows/{id}/decode?direction=up|down` joins the payloads of one direction of a TCP or TLS flow in order. A table maps each stream offset back to (message id, offset in that message).
- A stream decoder gets a `frame` function that tells a PDU's length from its first bytes (the 2-byte length of DNS, the 5-byte header of a TLS record, the 5-byte header of PostgreSQL). The framer walks the joined stream and decodes each whole PDU as a datagram.
- The tree's offsets stay stream offsets. The API adds the message spans of each root, so the UI can mark bytes across messages and page to the right message. The input, node and depth limits apply to the whole stream, and a PDU longer than the input limit gets an error.
- The per-message decode stays as it is. It is the view of one read, and it already shows where a PDU goes on.
