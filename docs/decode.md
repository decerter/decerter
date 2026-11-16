# Packet decoders
decerter decodes a message's payload, an HTTP body or the TLS handshake of a flow into a tree of fields, like the packet details pane of Wireshark: a DNS answer shows its header flags, its questions and its records with typed values instead of hex, a ClientHello its extensions and JA4. A decode runs only when it is asked for, over the [control API](api.md), in the [web UI](ui.md) and with the [MCP](mcp.md) tools `decode_message`, `decode_exchange_body` and `decode_flow`; the proxy never decodes anything on its own. The one thing it does on the hot path is copy the handshake records of TLS and DTLS flows, see [TLS handshake](#tls-handshake).

The decoders are decerter's own Go code written from the RFCs and the protocol specifications, with the standard library only (`crypto/x509` reads certificates); no code of Wireshark or of another dissector library is in decerter. Some tests check the decoders against permissive pure-Go libraries, which are never in the binary:
- `google.golang.org/protobuf/encoding/protowire` (BSD-3-Clause) for protobuf;
- `golang.org/x/net/dns/dnsmessage` (BSD-3-Clause) for DNS;
- `github.com/pion/rtp` and `github.com/pion/rtcp` (MIT) for RTP and RTCP;
- `pgproto3` of `github.com/jackc/pgx/v5` (MIT) for PostgreSQL;
- the standard library's `encoding/asn1` for BER, LDAP and Kerberos.

STUN is checked against the test vectors of RFC 5769. MySQL, MQTT, RESP and the mail protocols are checked against handcrafted packets.

Protocols:
- DNS over UDP, TCP, TLS, DTLS and HTTPS, mDNS and LLMNR
- gRPC and gRPC-Web, Protocol Buffers without a schema
- TLS and DTLS records and handshakes, WebSocket
- STUN and TURN, RTP and RTCP, NTP, DHCP and DHCPv6
- MQTT 3.1.1 and 5.0, Redis RESP2 and RESP3, SMTP, IMAP and POP3
- PostgreSQL and MySQL
- a generic ASN.1 BER/DER walker, LDAP and Kerberos

A message is decoded alone, or one direction of a TCP flow is decoded as one stream: a PDU split over several reads (a large DNS answer, a Redis value, a PostgreSQL row) then decodes as one. See [Stream reassembly](#stream-reassembly).

## API
| Method and path | Operation | Bytes decoded |
|---|---|---|
| `GET /messages/{id}/decode` | decodeMessage | the message's payload, as `GET /messages/{id}` has it; `original=true` decodes what the peer sent when a rule or an edit changed it |
| `GET /exchanges/{id}/decode` | decodeExchangeBody | the body of one side (`side=request`, the default, or `response`) without its chunk framing, as `GET /exchanges/{id}/body` has it; `original=true` decodes the body before an edit of layer `http` |
| `GET /flows/{id}/decode` | decodeFlow | `part=handshake` (the default): the handshake records decerter kept of one direction (`direction=up`, the default, or `down`) of a TLS or DTLS flow; the bytes are in `data`. `part=stream`: the payloads of one direction of a TCP flow joined in order, at most 4 MiB, with `segments` that map stream offsets to messages; `original=true` joins what the peers sent, `offset` and `length` pick the window of `data` (`length=0` leaves it out) |

All three take `as` (Decode As): a protocol of `protocols` in the answer, or `raw` for none. An unknown `as` is a 400. Without `as` decerter chooses. A payload that no decoder takes is not an error: it comes back as protocol `raw` with one `raw` node over its bytes.

```sh
sudo curl --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/messages/42/decode'
sudo curl --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/exchanges/7/decode?side=response&as=dns'
sudo curl --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/flows/3/decode?part=handshake&direction=down'
sudo curl --unix-socket /run/decerter/api.sock 'http://decerter/api/v1/flows/5/decode?part=stream&direction=up&length=0'
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

- `source` names the bytes that `offset` and `length` count in. `payload` is the message's payload, the same offsets as the `offset` of a `GET /messages/{id}` window. `body` is the exchange body, as in `GET /exchanges/{id}/body`. `target` is the bytes decerter took from the request target, because the request had no body (the `dns` parameter of a DoH GET). `handshake` is the handshake records of a flow's direction (`flow_id`, `direction`, and `cut` when a record did not fit). `stream` is the joined payloads of a flow's direction (`flow_id`, `direction`, `segments`, and `cut` with a `note` when the stream stops early). For `handshake` and `stream` the bytes are in `data`, a payload window with hex and escaped text, and the offsets count from their first byte.
- A node has a filter-style `name` (`dns.qry.name`), a `label`, a `value` (empty for a branch), `offset` and `length`, a `mask` for a field smaller than its bytes (a flag bit), an `error` when that part is malformed or cut short, and `children`. The names follow Wireshark's where one exists, so they look familiar; they are not fields of [decerter's filter language](filter.md).
- `summary` is one line, like Wireshark's info column. `error` is set when the decoder failed (a panic, which decerter catches): the tree is then the raw node. It names the decoder and the runtime error (`index out of range [5] with length 3`), or only the type of any other panic value, since that value could carry text from the traffic.
- `length` is the number of bytes decoded and `total` the payload's length. `truncated` is true when the input was cut at 1 MiB or the tree reached a limit (nodes, depth, bytes of strings, or the bytes one decode inflates); its last root is then a `decode.truncated` node that names the limits.

## How decerter chooses
The candidates are listed in this order, each with its reason. A reason is in decerter's own words and carries no text from the traffic: a content type is named by decerter's media type (`content type application/grpc is gRPC`), never by the peer's header with its parameters. The first one with a score above 0 is taken. Sniffing alone needs a score of 50.
1. `override`: `as=` names the protocol. It is always taken, and the decoder then reports what doesn't fit as node errors.
2. `context`: something outside the bytes names the protocol. Examples are an HTTP body's `Content-Type` (`application/dns-message`, `application/grpc`, `application/x-protobuf`), the `dns` parameter of a GET, a TLS ALPN `dot`, the `Upgrade: websocket` of a 101 the flow's last exchange switched with (or the `:protocol` of an HTTP/2 extended CONNECT), and the handshake records of `GET /flows/{id}/decode`. The handshake records are always TLS or DTLS records, so for them only the `tls` or `dtls` context candidate is listed: the flow's ALPN (`mqtt`, `dot`, `imap`) and its port name what comes after the handshake, not the records.
3. `port`: the flow's server port on its layer, such as udp 53, tcp 53, udp 5353 (mDNS), udp 5355 (LLMNR), tls 853, dtls 853 and tcp 443 (TLS records of a flow decerter only relays). HTTP bodies have no port candidate.
4. `sniff`: every decoder scores the bytes from 0 to 100, highest first.
5. `none`: nothing took the bytes, and the result is `raw`.

Protocol Buffers and WebSocket never win by sniffing alone (their scores stay below 50): bytes read cleanly as protobuf far too often, and a frame alone is not proof of WebSocket. `as=protobuf`, a content type or a WebSocket binary message takes protobuf.

A context or port candidate needs a sniff score above 0, so a port that carries something else (a TCP read that starts in the middle of a DNS message, for example) falls through to the next candidate instead of producing a tree full of errors.

## Framing
- A UDP datagram, the application data of one DTLS record and an HTTP body each hold one PDU, or a few that frame back to back (an RTCP compound packet, coalesced STUN over a stream).
- A TCP read and the application data of one TLS record are pieces of a stream. A stream protocol has a `frame` function that gives a PDU's length from its first bytes:
  - DNS: the 2-byte length
  - MQTT: the remaining length
  - RESP: a value with all it nests
  - SMTP: a reply up to its last line, mail data up to the lone dot, a BDAT chunk
  - IMAP: a line with its literals
  - POP3: a multi-line response up to its dot
  - PostgreSQL: the type and length
  - MySQL: the 3-byte length
  - LDAP and Kerberos: the BER length (Kerberos over TCP: the 4-byte record mark)
  - STUN: the header, or a ChannelData message with its padding
- One loop walks the bytes with `frame` and decodes each whole PDU as a root, so several PDUs in one read become several roots. The protocol's state goes along from PDU to PDU: the MQTT version of CONNECT, the place in a MySQL result set, mail data after DATA.
- A PDU that goes on past the bytes is decoded as far as it goes and gets an error. In one read: "the message continues in the next read: 32 of its 102 bytes are here". In a joined stream: "the stream ends inside the message: …".
- After STARTTLS (SMTP, IMAP), STLS (POP3), an SSLRequest the server took (PostgreSQL, also after it refused a GSSENCRequest), an SSL request (MySQL; on the server's side a greeting that offers SSL) or the StartTLS extended operation (LDAP), the rest of the stream, once a TLS handshake record starts, is one `<protocol>.tls` root with the TLS records in it. decerter does not decrypt TLS that starts after plaintext.

## Limits
Every decode reads untrusted bytes, so each one is bounded:
- Input: at most 1 MiB, 4 MiB for a joined stream (`MaxStreamBytes`). The rest is left out and the result is truncated. Sniffing sees the first 128 KiB of a stream.
- The tree: at most 10000 nodes, nesting 32 deep and 4 MiB of strings. Every string a node gets counts, also a label or value a decoder writes after the node was added (a record's label with its rdata, a list of ALPN names), and errors too. Past a limit the tree stops growing.
- One string of a node (name, label, value or error) is at most 8 KiB; a longer one is cut before an escape it would split and ends with `...`.
- A value written as hex or base64 (a signature, unknown rdata) shows its first 256 bytes, but the node still spans the whole field. The summary is at most 32 lines (one per PDU), then `; N more`, and each line at most 512 bytes, cut the same way.
- DNS names: at most 32 compression pointers per name (a pointer loop is an error, not a hang) and 255 bytes on the wire. Reserved label types are an error.
- A size the traffic gives as text (an IMAP literal `{n}`, a RESP bulk length) or as a number is checked against the bytes left before any offset is computed from it: a size past them is a PDU cut short.
- A panic in a decoder or a sniff function is recovered. It gives the raw tree and an `error`, and decerter logs a warning.
- Every string of the tree is escaped: printable ASCII stays as it is, and every other byte becomes `\xNN`. A DNS label also writes a dot, a space and a backslash inside the label as `\x2e`, `\x20` and `\\`. Text from the traffic, such as a TXT string, is escaped like the payloads: `\\`, `\n`, `\r`, `\t` and `\xNN`. `decerter mcp` escapes each string again and turns a `<` that would open or close its marker into `\x3c`.

- Inflating (gRPC gzip, WebSocket permessage-deflate) stops at 1 MiB per message with an error, and at 4 MiB for all the messages of one decode (nested decodes count too): the message that reaches it gets the error and the result is truncated; text values show their first 1024 bytes; protobuf follows nested messages and groups 10 levels deep, deeper ones are bytes; a certificate shows at most 64 names of each kind.

Each decoder has a fuzz test, `go test -tags unit -run '^$' -fuzz '^FuzzDNS$' ./internal/decode`. The others are `FuzzProtobuf`, `FuzzGRPC`, `FuzzTLS`, `FuzzDTLS`, `FuzzWebSocket`, `FuzzSTUN`, `FuzzRTP` (RTP and RTCP), `FuzzNTP`, `FuzzDHCP` (both versions), `FuzzText` (MQTT, RESP, SMTP, IMAP, POP3), `FuzzDatabase` (PostgreSQL, MySQL) and `FuzzASN1` (BER, LDAP, Kerberos). Each runs every context and `as` over a seed corpus (a read and a joined stream each way for the stream protocols) and checks these limits (every string at most 8 KiB, all of them within 4 MiB, the summary within 32 lines of 512 bytes) and that every node lies inside the bytes. `FuzzDNS` also checks that the question and record counts agree with `golang.org/x/net/dns/dnsmessage`, `FuzzProtobuf` that the fields agree with `protowire`; both are used in tests only.

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
- Sniffing walks the message without building a tree: the header, the names, the questions, the records with their rdata inside the message, and the rdata of the types that are only names, numbers and addresses (A, AAAA, NS, CNAME, PTR, DNAME, MX, KX, SOA, SRV). A message whose structure reads to its end sniffs as 70 to 100; what only the decode finds wrong (a cookie's size, a DNSKEY's protocol) still shows as node errors.

## Protocol Buffers
Without a schema, like `protoc --decode_raw` (from protobuf.dev's encoding guide):
- Each field shows its number and wire type (the low 3 bits of the tag as a bit field when the tag has at most 4 bytes).
- VARINT: the value, as int64 when it is negative that way, as sint (zigzag) and, for 0 and 1, as bool.
- I64 and I32: the unsigned value, signed when negative, and as double or float.
- LEN: text that starts with a printable byte is a string; otherwise bytes that read as a message to their end are a nested message, then UTF-8 text a string, else bytes (hex). Groups (SGROUP to EGROUP) nest like messages. A field that breaks inside a group ends the message there, and an EGROUP with no open group (field 0 included) is an error.
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
- HelloRetryRequest (by its random, in TLS and in DTLS 1.3), HelloVerifyRequest, NewSessionTicket, EncryptedExtensions, Certificate (TLS 1.2 and 1.3 forms; each certificate read with `crypto/x509`: subject, issuer, serial number, validity in RFC 3339, algorithms, CA, and the DNS, IP, email and URI names, all spanning the certificate's DER), ServerKeyExchange (ECDHE named curve and point, signature), CertificateRequest, CertificateVerify, ClientKeyExchange, Finished, CertificateStatus and KeyUpdate.
- Alerts with level and description; after a change cipher spec of TLS 1.2 or on an encrypted DTLS epoch, records shown as encrypted.

The same decoder also takes TLS records as they go over tcp (a flow to port 443 that decerter only relays, or `as=tls`): the hellos and a TLS 1.2 server's certificate are plaintext there, the rest is encrypted.

## WebSocket
- The reads of a tcp or tls flow after an HTTP/1.1 `Upgrade: websocket` (the flow's last exchange is a 101 whose request came before the message; the read of the 101 can carry the first frames, its head is a `websocket.http_head` node), and the bodies of an HTTP/2 extended CONNECT whose `:protocol` is `websocket`.
- Each frame: FIN, RSV1-3, opcode, mask, payload length (with the 16- or 64-bit extended length), masking key, and the payload unmasked; close frames with their status code and reason, ping and pong.
- A text message as text; a binary one as the protocol its bytes sniff as (protobuf counts from its clean score, every other protocol needs the 50 of sniffing alone, so a msgpack or CBOR message is no RTP and a protobuf message no NTP), else hex. A message in several frames is put together into a `websocket.message` root after its last frame, control frames between them stay where they are. A continuation without its start, and what a message that never ended left, are not part of the next message.
- permessage-deflate (when the 101's `Sec-WebSocket-Extensions` has it): a message with RSV1 is inflated alone, at most 1 MiB; one that uses the window of earlier messages (context takeover) can't be inflated alone and gets an error that says so.
- Errors for what RFC 6455 forbids: a client frame without a mask or a server frame with one, reserved bits without an extension, reserved opcodes, a fragmented or long control frame, a continuation without its start, text that is not UTF-8.
- A frame that goes on in the next read says how many of its bytes are there; frames are not joined across reads.

## STUN and TURN
- STUN (RFC 8489) on udp and tcp 3478 and tls and dtls 5349, and by its magic cookie on any port (a sniff of 100). TURN (RFC 8656) methods and attributes, ICE (RFC 8445) and the NAT behaviour attributes of RFC 5780.
- The header with method and class, then each attribute:
  - (XOR-)MAPPED-ADDRESS, XOR-PEER-ADDRESS and XOR-RELAYED-ADDRESS decoded with the cookie and transaction ID
  - ERROR-CODE, USERNAME, REALM, NONCE and SOFTWARE as text, LIFETIME, REQUESTED-TRANSPORT and the address family
  - PRIORITY, USE-CANDIDATE and the ICE tie breakers
  - MESSAGE-INTEGRITY(-SHA256) as hex (decerter has no key to check it)
  - FINGERPRINT, checked against the CRC-32 of the message before it
- A TURN ChannelData message (channel 0x4000-0x4fff) shows its channel and length and decodes its data as what it sniffs as (DTLS, RTP). Over a stream the padding to 4 bytes is framed too.
- One port can carry STUN next to DTLS, RTP and RTCP (WebRTC). RFC 7983's first byte tells them apart: 0-3 STUN, 20-63 DTLS, 64-79 TURN channels, 128-191 RTP and RTCP. Each datagram goes to the decoder its first byte names.

## RTP and RTCP
- RTP (RFC 3550): version, padding, marker, payload type (static types of RFC 3551 by name), sequence number, timestamp, SSRC, the CSRCs, the RFC 8285 header extension with its one-byte or two-byte elements (another profile as bytes), the payload and the padding.
- RTCP: a compound packet is a root per packet. SR with its sender info, RR and the report blocks (fraction and cumulative lost, jitter, LSR, DLSR), SDES chunks and items, BYE with its reason, APP, and the RTPFB and PSFB feedback of RFC 4585 with the FCI as bytes; XR by name.
- RTP has no port and no magic number. Sniffing gives 40 for a header that adds up (below the 50 that sniffing alone needs) and 60 with an RFC 8285 extension. `as=rtp` takes the rest. A packet type of 200-223 in the second byte is RTCP (RFC 5761). An RTCP compound packet whose lengths add up to the datagram sniffs as 90.

## NTP
- NTPv1 to v4 (RFC 5905) on udp 123: leap indicator, version, mode, stratum, poll and precision as powers of two, root delay and dispersion in the short format, and the reference ID (a kiss code or a clock source for stratum 0 and 1, an address above).
- The four timestamps in RFC 3339. A timestamp below 1968 is taken as era 1 (2036 on), as RFC 4330 suggests.
- Extension fields (RFC 7822) and the MAC (key ID and digest). Control (mode 6) and private (mode 7) messages show their header and the rest as bytes.

## DHCP
- DHCPv4 (RFC 2131 and 2132) on udp 67 and 68, and by its magic cookie (100):
  - the BOOTP header with the client hardware address
  - each option, with typed values for the common ones: message type, addresses and address lists, lease and renewal times, hostname, domain, parameter request list, client identifier, classless static routes (RFC 3442)
  - others as hex; padding and End
- DHCPv6 (RFC 8415) on udp 546 and 547:
  - the message type and transaction ID
  - relay messages with their link and peer addresses, nested up to 8 deep
  - options: client and server DUIDs, IA_NA, IA_TA, IA_PD with their addresses and prefixes, the option request list, preference, elapsed time, status codes, DNS servers and domain lists

## MQTT
- MQTT 3.1.1 and 5.0 (OASIS) on tcp 1883 and tls 8883 (and TLS ALPN `mqtt`):
  - the fixed header with type and flags (DUP, QoS and retain for PUBLISH), and the remaining length
  - every control packet: CONNECT with its flags, keep alive, client id, will, user name and password; CONNACK, PUBLISH with topic, packet id and payload; the acks, SUBSCRIBE and SUBACK, UNSUBSCRIBE, PINGREQ, PINGRESP, DISCONNECT and AUTH
- The 5.0 properties are typed and reason codes are named. The version comes from the stream's CONNECT (or a CONNACK with properties). A read alone is taken as 3.1.1 until a CONNECT says otherwise.
- A CONNECT with the protocol name `MQTT` (or `MQIsdp`) sniffs as 100; other packets that frame up to the end only 15.

## Redis (RESP)
- RESP2 and RESP3 (the Redis protocol specification) on tcp 6379 and tls 6379 and 6380:
  - every type: simple strings, errors, integers, bulk strings, arrays, null, booleans, doubles, big numbers, bulk errors, verbatim strings, maps, sets, pushes and attributes
  - values nested 24 deep at most
  - inline commands
- A client's array of bulk strings is its command; the summary shows it with three arguments, each cut at 48 bytes: `Redis SET "key" "value"`.

## SMTP, IMAP and POP3
- SMTP (RFC 5321) on tcp 25 and 587 and tls 465 and 587: commands with their parameters, replies of several lines as one PDU, the mail data after DATA up to its lone dot with its header fields (RFC 5322), and BDAT chunks (RFC 3030).
- IMAP (RFC 9051) on tcp 143 and tls 993: tagged commands, untagged and tagged responses and continuations, with the literals `{n}` and `{n+}` kept inside their line.
- POP3 (RFC 1939) on tcp 110 and tls 995: commands, `+OK` and `-ERR`, and the responses of several lines up to their dot. A `+OK` line that ends a read is a whole response (a greeting, the answer to USER, PASS, DELE or QUIT); lines after it without their dot go on in the next read.
- Sniffing knows the greetings and the common commands. Any other line of text (an SMTP MAIL, RCPT or DATA, mail data, an IMAP tagged response, a `+` continuation, an APPEND) sniffs as 10: below the 50 that sniffing alone needs, enough for the port to take it.
- STARTTLS (RFC 3207, RFC 9051) and STLS (RFC 2595): the TLS records after them are a `smtp.tls`, `imap.tls` or `pop.tls` root.

## PostgreSQL
- The frontend/backend protocol 3.0 and 3.2 on tcp 5432 and tls 5432 (TLS ALPN `postgresql` of the direct TLS of PostgreSQL 17).
- The untyped first messages: StartupMessage with its parameters, SSLRequest, GSSENCRequest, CancelRequest. The server's one-byte answer: `S` (TLS follows), `G` (GSSAPI encryption follows, shown as encrypted data) or `N`. After an `N` another answer may follow, since libpq asks for GSSAPI encryption first and then for SSL.
- The typed messages of both sides:
  - Query, Parse, Bind (formats and parameter values, NULL), Execute, Describe, Close, Sync, Flush, Terminate, the password and SASL messages, copy
  - Authentication (the SASL mechanisms, the MD5 salt), BackendKeyData, ParameterStatus, ReadyForQuery with its status
  - RowDescription with each field, DataRow with each value, CommandComplete
  - ErrorResponse and NoticeResponse with their fields by name, NotificationResponse, NegotiateProtocolVersion
- The direction tells a client's `D` (Describe) from a server's `D` (DataRow).

## MySQL
- The client/server protocol (MySQL and MariaDB) on tcp 3306 and tls 3306:
  - the 3-byte length and the sequence id
  - the initial handshake v10 with version, thread id, salt, capabilities and auth plugin
  - the handshake response 41 with user, auth response, schema, plugin and connection attributes
  - the SSL request (TLS follows on both sides: the server's TLS records come after its greeting when it offers SSL), and the command packets (Query, Use Database, Prepare, Execute, Close, Ping, Quit and the others by name)
  - OK, ERR with its SQL state, EOF, auth switch and auth more data, LOCAL INFILE
- Text result sets: the column count, column definitions 41, and the rows with their length-encoded values, with or without EOF packets (CLIENT_DEPRECATE_EOF). The stream keeps its place in the result set from packet to packet. Inside the rows a value `def` is a value; outside them a packet that starts with the catalog `def` is a column definition.
- A read decoded alone has no stream before it. A row whose result set started in an earlier read isn't known as a row. It is shown as the packet its first byte looks like: a response, or auth more data for 0x01. The stream view has the whole result set.

## ASN.1 BER, LDAP and Kerberos
- A BER and DER walker (X.690):
  - the class, the constructed bit and the tag number (high tag numbers too)
  - definite lengths and indefinite ones with their end-of-contents octets
  - contents nested 24 deep and 10000 elements at most
  - universal types with their values: BOOLEAN, INTEGER of any size, ENUMERATED, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER in dotted form, the strings and times
  - other classes as `[APPLICATION n]`, `[n]` and `[PRIVATE n]`
  - an element whose identifier or length is wrong has an error and no contents; an indefinite element with a child cut short is a PDU that goes on (or ends with the stream), one with a broken child is no element
- `as=ber` shows any bytes as this generic TLV tree; sniffing gives it 25 at most, so it never wins alone.
- LDAP (RFC 4511) on tcp 389 and 3268, tls 636 and 3269, and CLDAP on udp 389:
  - the LDAPMessage with its message ID, the operation by name and the controls
  - the result code of a response, the DN of a bind, search, add, delete, modify, compare and search entry, and the name of an extended operation in the summary
  - StartTLS (`1.3.6.1.4.1.1466.20037`) switches both directions to TLS
  - LDAP has no indefinite lengths; one is an error
- Kerberos (RFC 4120) on udp and tcp 88: the message by its application tag (AS-REQ to KRB-ERROR) with its fields named by their context tags, the realm and the client and server principal names in the summary, and the KRB-ERROR codes by name. Over TCP each message has its 4-byte record mark.

## Web UI
- The message view and the exchange view show the tree next to the bytes: a summary, the reason for the choice, and a "decode as" list.
- Clicking a node marks its bytes in the hex dump or the escaped text, and pages to them when they are outside the 4 KiB window. Clicking a byte selects the deepest node that has it and opens the branches above it. The "decode as" choice stays until it is set back to auto.
- A DoH GET shows the bytes of its `dns` parameter above the (empty) body.
- A TLS or DTLS flow with kept handshake records shows a Handshake pane under the flow's fields: client or server, its tree and all its bytes as a hex dump.
- A TCP flow has a Stream pane (closed until opened) with client or server and "decode as". It shows the tree of the joined stream. A node opens the message that has its first byte and marks its bytes there; a node over several messages lists each one with its byte range, as buttons that open it.
- "Open in Wireshark (pcapng)" downloads the flow as `decerter-flow-<id>.pcapng`, see [Wireshark](#wireshark).

## Adding a protocol
A protocol is one new file in `internal/decode` whose `init()` calls `register(decoder{...})` with these fields:
- its name and title
- its ports per layer
- `hint`, the context reasons, such as a content type, an ALPN or an Upgrade header. A reason uses only decerter's words (its own constants, never a value from the context), and a new kind of reason needs a template in `reasonPattern` of `internal/mcp`, or `decerter mcp` withholds it; `TestReasonPatternPositive` checks that
- `sniff`, a score of the bytes
- `decode`, which adds nodes with `tree.add`, `tree.fail` and `tree.addSummary`
- `fromTarget` when a request target can carry the PDU
- for a stream protocol: `frame` (a PDU's length from its first bytes, 0 while it is cut short, -1 when the bytes are no PDU), `pdu` (one PDU as a root, with the `streamState` it shares with the PDUs before it), `unit` (its name in errors: message, packet, line, value) and `decode: framedDecode(name)`

The registry, the choice order, the limits, `as=`, the API, the stream view, the UI and the MCP tools pick a new protocol up with no other change. The cursor (`fieldsOf`, `number`, `little`, `cString`, `vector`, `opaque`) adds nodes that span their bytes and fails a node that runs past them. Planned: QUIC Initial, see [QUIC](#quic-initial-not-built).

## Stream reassembly
`GET /flows/{id}/decode?part=stream&direction=up|down` joins the payloads of one direction of a TCP flow in message order: the TLS-layer messages when the flow has any (the plaintext decerter decrypted), else the TCP reads. The decode then runs over the joined bytes with `Joined` set, so a PDU that spans reads is one root.
- `segments` maps the stream back to the messages: `{message_id, offset, length}`, one per message, in stream order. A node's `offset` is a stream offset. The segment that has it gives the message and the offset in that message. The UI uses this to open the message and mark the bytes.
- The stream stops at 4 MiB, or at the first message whose payload the history did not keep whole. `cut` is then true and `note` says where: "the stream is cut at 4194304 bytes, in message 812", "the history did not keep 1200 bytes of message 40, the stream stops there".
- `original=true` joins what the peers sent before a rule or an edit changed it. `offset` and `length` pick the window of the joined bytes in `data` (4 KiB by default, `length=0` for none).
- A UDP or DTLS flow is a 400: a datagram is one PDU, decode its message.
- The per-message decode stays as it is: the view of one read, which says where a PDU goes on.

A client's `SET` of a Redis value written in two reads (the tree cut after the first level):

```json
{
  "flow_id": 5,
  "direction": "up",
  "segments": [
    {"message_id": 12, "offset": 0, "length": 20},
    {"message_id": 13, "offset": 20, "length": 11}
  ],
  "source": "stream",
  "protocol": "resp",
  "summary": "Redis SET \"k\" \"hello\"",
  "length": 31,
  "total": 31,
  "truncated": false,
  "candidates": [
    {"protocol": "resp", "basis": "port", "reason": "tcp port 6379 is Redis Serialization Protocol", "score": 90},
    {"protocol": "resp", "basis": "sniff", "reason": "the bytes read as Redis Serialization Protocol", "score": 90}
  ],
  "tree": [
    {"name": "resp", "label": "Redis Serialization Protocol (Array)", "offset": 0, "length": 31, "children": [
      {"name": "resp.array", "label": "Array", "value": "Redis SET \"k\" \"hello\"", "offset": 0, "length": 31}
    ]}
  ]
}
```

The MCP tool `decode_flow` takes `part=stream` with the same `direction`, `as`, `original`, `offset` and `length`. Its metadata carries the `segments` and the `note`.

## Wireshark
"Open in Wireshark" is a download, never a link to Wireshark's code. `GET /flows/pcap?flow=<id>` returns one flow as `decerter-flow-<id>.pcapng`:
- With captures (`decerter capture`, or `decerter run` with its capture programs), the default format is `dsb`: the flow's packets with a Decryption Secrets Block for each TLS and DTLS session, so Wireshark and tshark decrypt it by themselves. UDP sessions of one app socket share an upstream socket, so their packets come together.
- Without captures it is `plaintext`: packets synthesized from the history, decrypted already.
- `format` and `filter` still apply. A flow the filter does not take is a 404.

The web UI links it from the flow view, and the MCP tool `export_pcap` takes `flow_id`. The e2e test opens the file with tshark and finds the decrypted HTTP request of that flow, and of no other.

### sharkd (design, not built)
Wireshark's own dissectors would add the protocols decerter does not decode. They are GPL-2.0-or-later, so decerter may only run them as a separate program the user installed, never link or ship them. The design for an optional host-only `--sharkd` mode:
- `decerter run --sharkd /usr/bin/sharkd` (off by default) starts `sharkd -` as a child process, as the user who started decerter and not as root, with a fixed environment and no access to the API socket.
- A decode request with `as=wireshark` writes the one-flow pcapng (the same as above) to a temporary file and sends sharkd its JSON-RPC calls: `load`, then `frames` and `frame` with `proto: true`. The answer's tree (`l` label, `f` filter name, `h`/`l` byte span) is mapped to `DecodeNode`s, with offsets moved from the frame to the message's payload.
- The answer goes through the same limits (10000 nodes, depth 32, 4 MiB of strings, a timeout) and the same escaping as decerter's own trees. sharkd's crashes and hangs are contained in the child, which decerter restarts.
- It is never in the API by default: `as=wireshark` is a 400 unless `--sharkd` was given, and `protocols` lists it only then. The MCP never starts it.
- The docs and the `--help` say that sharkd is GPL software the user installs, and that decerter only talks to it over a pipe.
- Not built in stage 50: the pcapng download already gives Wireshark everything, and a long-lived sharkd child needs its own lifecycle and sandbox work.

## QUIC Initial (not built)
A QUIC Initial packet is encrypted with keys anyone can derive from its Destination Connection ID (RFC 9001 5.2). Decoding the ClientHello inside needs:
- the long header (RFC 9000 17.2): version, the connection IDs, the token, the length, and the version's initial salt (v1 `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`, v2 of RFC 9369 its own, with its own labels)
- the client's initial secret from `crypto/hkdf` (HKDF-Extract of the DCID with the salt, then HKDF-Expand-Label "client in"), and from it "quic key", "quic iv" and "quic hp"
- header protection: AES-ECB of the 16-byte sample at offset pn+4 gives the mask for the first byte and the packet number length and value
- AES-128-GCM over the payload with the nonce from the IV and the packet number, the header as additional data
- the frames: PADDING, PING, ACK and CRYPTO. The CRYPTO frames are joined by their offsets, since a post-quantum ClientHello spans two Initial packets and two datagrams, so it needs the flow's datagrams joined like a stream.
- the stage 49 TLS handshake decoder over the joined CRYPTO data, and the server's Initial with the "server in" keys for the ServerHello

The test vectors are those of RFC 9001 Appendix A. Nothing of it is built. The risks are the two-datagram ClientHello (a per-message decode would show half of it) and the 0-RTT and Handshake packets that follow, which need TLS secrets decerter does not have for QUIC (its uprobes read TLS over TCP; QUIC is relayed undecrypted, see `--block-quic`).
