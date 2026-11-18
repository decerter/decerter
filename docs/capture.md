# Capture and key log
`decerter capture` writes the packets of the selected flows to pcapng without redirecting anything: the flows reach their servers directly and nothing in them is changed. `decerter keylog` prints only the TLS secrets.

```sh
# real packets plus a Decryption Secrets Block per TLS session: tshark decrypts without a key log file
sudo ./decerter capture --uid 1001 -w out.pcapng
tshark -r out.pcapng -Y 'http or http2'

# synthesized packets with the decrypted payload, for tcpdump and every other pcapng reader
sudo ./decerter capture --uid 1001 -w out.pcapng --plaintext
tcpdump -A -r out.pcapng

# live: the pcapng stream goes to stdout, the logs stay on stderr
sudo ./decerter capture --uid 1001 -w - | wireshark -k -i -
sudo ./decerter capture --uid 1001 -w - | tshark -l -i - -Y 'http or http2'

# the secrets only, in NSS key log format (SSLKEYLOGFILE)
sudo ./decerter keylog --uid 1001 > keys.log
```

## Formats
- **Default:** the packets as the kernel saw them, and before the first encrypted packet of a TLS or DTLS session a Decryption Secrets Block with its secrets (four lines for TLS 1.3, `CLIENT_RANDOM` for TLS 1.2 and DTLS 1.2), so Wireshark and tshark decrypt the file by themselves. A TLS flow is held until its secrets arrive: at most 10 s and 1 MiB per flow, 64 MiB in total; past that it is written without keys, with a warning. So the file is in time order within a flow, not across flows.
- **`--plaintext`:** synthesized packets with the decrypted payload. The TCP streams are put back in order (out-of-order data up to 8 MiB per direction), a flow keeps its addresses and ports and gets new sequence numbers and valid checksums, at most one MSS or one TLS record per packet, and the first decrypted packet of a session carries a comment with version, suite, SNI and ALPN. A flow that is not TLS keeps its payload. Bytes cut by `--snaplen`, or acknowledged by the peer but never seen, are a gap: the rest of that flow is written encrypted, with a comment saying why. UDP GSO super-datagrams are not split.
- **`-w -` (`--write -`):** the stream on stdout, flushed block by block. stdout must not be an interactive terminal (the raw pty of `adb exec-out` is fine), and decerter stops when the reader goes away.

The file holds secrets or plaintext: it is created with mode 0600 and, under sudo, given to the user who ran sudo. `--snaplen` limits the bytes copied per packet, counted from the IP header (default and maximum 262144). Packets between two selected local sockets appear twice.

For tshark: it reads `-i -` through dumpcap, so your user needs dumpcap's rights (on Debian the `wireshark` group); `-l` prints each packet at once when tshark's own output goes to a pipe; curl speaks HTTP/2 by default, hence `http or http2`. tshark was tested, the Wireshark GUI was not.

## Capture API
`decerter capture --api-socket` (with or without `-w`) serves the [control API](api.md) with captures that have their own filter (within `--filter`) and format:

```sh
sudo ./decerter capture --uid 1001 --api-socket /run/decerter/api.sock
api() { sudo curl -s --unix-socket /run/decerter/api.sock -H 'Content-Type: application/json' "$@"; }

api -X POST -d '{"filter": "tcp.dstport == 443"}' http://decerter/api/v1/captures    # {"plaintext": true} for decrypted packets
api http://decerter/api/v1/captures                                                  # id, filter, format, state, size
api -X POST http://decerter/api/v1/captures/1/stop
api -o capture.pcapng http://decerter/api/v1/captures/1/pcap                         # a running capture answers 409
tshark -r capture.pcapng -Y http

# the live stream, the same as -w - for as long as the client reads; ?filter= and ?plaintext=true work here too
api -N http://decerter/api/v1/captures/stream | sudo tshark -l -i - -Y 'http or http2'

# the packets decerter still keeps of the flows of the history (the latest 64 MiB), as captured with DSBs or decrypted
api -o flows.pcapng 'http://decerter/api/v1/flows/pcap?format=dsb&filter=tls'
```

One ring buffer reader feeds every writer: the `-w` file, each capture and each stream gets its own pcapng with its own section, filter and format. `--filter` is decided once per flow; a capture's filter narrows it further (one that matches nothing gives an empty capture, not an error). A writer that joins while flows are open first gets the packets decerter kept of them, so their TLS sessions are whole, with the DSB in front. Each writer has a queue of 16384 packets or 32 MiB: a file that falls behind loses packets and counts them (`dropped_packets`), a stream is cut off at a block boundary, and neither slows the others down.

The capture files are in the data directory, `/run/decerter/captures` on Linux and `/data/local/tmp/decerter.d/captures` on Android, owned by root with mode 0600; the API user downloads them through the socket. At most 16 captures are kept, 4 run at once, and all files together hold 1 GiB: a new capture or a growing file removes the oldest stopped capture, and a running capture that would go past the limit stops with a `reason`. The files are removed when decerter stops; a decerter killed with `kill -9` leaves them, and the next decerter with `--api-socket` removes them at start. There is no delete endpoint. pcapng answers use `application/x-pcapng`.

## Captures in run mode
The same operations work on `decerter run --api-socket`, where they record the wire side: the proxy's upstream sockets, after the rules and edits, with the real server address. The app's own sockets only talk to the proxy over loopback, and those packets are never copied.

```sh
sudo ./decerter run --uid 1001 --intercept --api-socket /run/decerter/api.sock
api -X POST -d '{"filter": "tls", "direction": "up", "layer": "tls", "find": {"type": "text", "value": "GET / "}, "replace": {"type": "text", "value": "GET /test "}}' http://decerter/api/v1/rules
api -N http://decerter/api/v1/captures/stream | sudo tshark -l -i - -Y http    # GET /test to the server's real address
```

The proxy writes each upstream socket's cookie into `upstream_map` with the cookie of the app's flow before it connects, and the capture programs (attached only with `--api-socket`) copy those packets under the app's flow, so the process fields and every filter work as in capture mode. The pcap export picks the packets of each flow of the history by its own upstream socket, so the UDP sessions of one unconnected app socket (one per destination, all with the app socket's cookie) are exported apart and a filter takes only the sessions it matches. The proxy seals edited records with the session's own keys, so the DSB decrypts the edits too. The app's side is in the history, and `GET /flows/pcap?format=plaintext` builds packets from the proxy's messages. In these captures `ip.src` is the proxy's end on the wire. UDP and DTLS upstream capture was not tested.

## Key log
`decerter keylog` attaches only the secrets uprobe and prints the secrets of the selected processes on stdout in NSS key log format, until stopped: four lines per TLS 1.3 session (both handshake and both application traffic secrets), one `CLIENT_RANDOM` line per TLS 1.2 or DTLS 1.2 session. The lines were checked byte for byte against `SSLKEYLOGFILE` of curl, `openssl s_client` and Python, against Chrome's own key log, and against a test server's.
