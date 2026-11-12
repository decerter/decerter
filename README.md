# decerter
eBPF-powered proxy that reads and rewrites live TCP/UDP/TLS traffic, with no CA certificate and no changes to the app.

decerter selects local processes by UID or PID. eBPF cgroup hooks send their sockets' `connect()` and `sendmsg()` to a proxy on `lo`, or only record the flows, and a uprobe on the TLS library reads the session secrets. So decerter can relay, decrypt, edit or capture the traffic of one user or one Android app while the app keeps talking to its real server with its real certificate.

Requires Linux ≥ 6.6.

## Current features
- `decerter run`: redirect the TCP and UDP flows of the selected processes through decerter's proxy. `--decrypt` prints the plaintext of TLS and DTLS 1.2 records; `--intercept` holds every record, decrypts it, runs it through the intercept rules and encrypts it again with the same session keys (the command line has the identity rule, which prints every message; other rules only come from Go code for now).
- `decerter capture -w <file>|-`: write the selected flows to pcapng without redirecting anything, with a Decryption Secrets Block per TLS session, so Wireshark and tshark decrypt the file by themselves; `--plaintext` writes synthesized decrypted packets for tcpdump and other tools; `-w -` streams live into Wireshark or tshark.
- `decerter keylog`: print the TLS secrets of the selected processes in NSS key log format (`SSLKEYLOGFILE`).
- `--filter`: a subset of Wireshark's display filter language over process, address, port and TLS ClientHello fields (`decerter help filter`); the parts the kernel can check go into BPF maps.
- TLS secrets from OpenSSL 3 (Linux, amd64) and from Conscrypt's BoringSSL (Android 15 and later); TLS 1.2, TLS 1.3 and DTLS 1.2.
- Android: rooted devices with a GKI kernel from android15-6.6 on; decerter shares netd's cgroup hooks while it runs and `decerter android restore` puts them back after a crash.

Planned, not built yet: a control API on a unix socket, a minimal web UI (`decerter ui`) and an MCP server (`decerter mcp`).

## Requirements
- Linux 6.6 or newer with BTF (`/sys/kernel/btf/vmlinux`) and cgroup v2 mounted at `/sys/fs/cgroup`.
- root: decerter loads and attaches BPF programs.
- TLS secrets on Linux: OpenSSL's `libssl.so.3` on amd64. The offsets are generated for OpenSSL 3.6.2; another version needs `make generate-openssl-offsets OPENSSL_VERSIONS=openssl-X.Y.Z` and a rebuild, and is refused with a clear error until then. Without the secrets uprobe (another architecture, or Android without Conscrypt) `run` and `capture` still work, without decryption.
- Android: Android 15 or newer with a GKI kernel android15-6.6 or newer, rooted. Only the x86_64 Android 15 emulator was tested; arm64 devices, Magisk and KernelSU are not verified.

## Build
```sh
make build          # ./decerter, static linux/amd64 binary
make build-arm64    # ./decerter-arm64, static linux/arm64 binary for Android devices
make verify-static  # builds both and checks that they are statically linked
make help           # every target
```

Building needs Go 1.26 or newer. The BPF objects are committed; regenerating them (`make generate-bpf-objects`) needs clang-21, llvm-strip-21 and `make generate-vmlinux` (bpftool).

Other targets: `make lint` (golangci-lint), `make test-unit`, `make test-e2e` (root, the local users `test` and `nobody`), `make license-check` (go-licenses on the dependencies plus an SPDX check of every source file), `make install-golangci-lint`, `make install-go-licenses`.

## Usage
```
$ decerter --help
decerter reads and rewrites the live TCP, UDP, TLS and DTLS traffic of selected local processes.
eBPF cgroup hooks pick the sockets of the selected processes and a uprobe on the TLS library reads their session secrets,
so there is no CA certificate to install, no proxy setting and no change to the app.

decerter runs as root on Linux 6.6 or newer with BTF, and on rooted Android 15 or newer (GKI android15-6.6 or newer).
Nothing is selected until --uid or --pid, or a proc.uid or proc.pid term of --filter, names a process.
Logs are JSON lines on stderr; stdout carries the output of the command.

Every flag can also be set with an environment variable DECERTER_<FLAG>, upper case with - as _, for example DECERTER_LOG_LEVEL=debug.
The command line wins over the environment, and sudo passes the variable on only with --preserve-env.

Usage:
  decerter [command]

Available Commands:
  android     Android helpers
  capture     Write the selected flows to pcapng with their TLS secrets, or decrypted, without redirecting them
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  keylog      Print the TLS secrets of the selected processes in NSS key log format
  run         Redirect the selected flows through decerter's proxy, optionally decrypting or intercepting them

Flags:
  -h, --help              help for decerter
      --log-level level   log level (default is info, valid values: trace, debug, info, warn, error)
  -v, --version           version for decerter

Additional help topics:
  decerter filter     The --filter language of run and capture

Use "decerter [command] --help" for more information about a command.
```

The examples select a separate local user `test` (UID 1001) and run the client as that user, so decerter never touches your own traffic. Nothing is selected without `--uid`, `--pid` or a `proc.uid` / `proc.pid` term in `--filter`.

### run
```sh
# relay and decrypt the test user's flows
sudo ./decerter run --uid 1001 --decrypt
sudo -u test curl -s https://example.com/

# every message through the identity rule, printed with a hex dump; only curl's flows to port 443
sudo ./decerter run --uid 1001 --intercept --filter 'proc.comm == "curl" && tcp.dstport == 443'

# narrow the selection with flags: only flows to these destination prefixes and ports
sudo ./decerter run --uid 1001 --dst-cidr 10.0.0.0/8,fd00::/8 --dst-port tcp/443,udp/53
```

The proxy listens on port 15001 of `lo` (`--port`), TCP and UDP; a UDP session ends after 30 s without a datagram (`--udp-idle-timeout`). `--flow-table` prints the kernel's flow table every 5 s for debugging.

### capture
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
```

tshark was tested with the live stream, the Wireshark GUI was not. The file holds secrets (or, with `--plaintext`, the plaintext): it is created with mode 0600 and, under sudo, owned by the user who ran sudo. With `-w -` stdout must not be an interactive terminal, and decerter stops when the reader goes away. For tshark: it reads `-i -` through dumpcap, so your user needs dumpcap's rights (on Debian the `wireshark` group); `-l` prints each packet at once when tshark's own output goes to a pipe; curl speaks HTTP/2 by default, hence `http or http2`. `--snaplen` limits the bytes copied per packet (default and maximum 262144).

### keylog
```sh
sudo ./decerter keylog --uid 1001 > keys.log
sudo -u test curl -s https://example.com/ > /dev/null
```

A TLS 1.3 session gets four lines (handshake and application traffic secrets of both sides), a TLS 1.2 or DTLS 1.2 session one `CLIENT_RANDOM` line.

## Android
decerter runs on rooted Android 15 or newer with a GKI kernel android15-6.6 or newer (android15-6.6, android16-6.12, android17-6.18). Every app has its own UID, so `--uid` selects one app. Only the x86_64 Android 15 emulator was tested, with `adb root`; real arm64 devices, Magisk and KernelSU are not verified.

```sh
make build                  # the x86_64 emulator; make build-arm64 builds decerter-arm64 for arm64 devices
adb root                    # the emulator's adbd as root; its su takes no -c, so decerter runs directly in adb shell
adb push decerter /data/local/tmp/decerter
adb shell pm list packages -U | grep <package>      # the app's uid, e.g. uid:10092

# run mode, stdout and the logs in the adb shell
adb shell /data/local/tmp/decerter run --uid 10092 --decrypt

# live capture into tshark or Wireshark on the host; adb exec-out shares one pty for stdout and stderr,
# so the logs have to go to a file on the device
adb exec-out sh -c '/data/local/tmp/decerter capture --uid 10092 -w - 2>/data/local/tmp/decerter.log' | tshark -l -i - -Y 'http or http2'

# after decerter was killed with SIGKILL: put netd's hooks back
adb shell /data/local/tmp/decerter android restore
```

netd holds most cgroup hooks exclusively. While decerter runs it attaches netd's programs again in shared mode next to its own and writes down what it changed in its data directory `/data/local/tmp/decerter.d` (the binary and its data directory need different names). On exit, also on SIGHUP when the adb shell closes, it puts netd's hooks back. After a SIGKILL they stay shared, and a netd restart then fails until `decerter android restore` ran; a decerter that starts over a leftover state file restores first by itself.

TLS secrets on Android come from Conscrypt's BoringSSL (`/apex/com.android.conscrypt/lib64/libssl.so`), so Java and Kotlin apps using the platform TLS stack are decrypted. Apps with their own statically linked TLS library (Chrome, Cronet, Flutter) are relayed and captured without secrets. An app's DNS is sent by netd as root, so it is not in the app's UID scope (`--uid 0` sees it).

## Limits worth knowing
- Only outgoing flows: sockets that `connect()` or `sendmsg()` in a selected process. Accepted (server-side) sockets are not redirected or captured, and the children of a `--pid` are not followed.
- `getsockname()` in the app still shows the loopback address in run mode. A destination that is routed but doesn't answer looks connected to the app until the proxy's 10 s dial timeout resets it.
- One unconnected UDP socket that sends a burst to two destinations before the proxy reads them can send both to the second one.
- TLS: TLS 1.2 and 1.3 with AES-GCM, ChaCha20-Poly1305, AES-CBC and 3DES suites (ECDHE and RSA key exchange) and DTLS 1.2; not DHE suites, ECDHE-RSA-AES256-SHA384, RC4, DTLS 1.0, renegotiation or 0-RTT. Processes that bundle their own TLS library (Chrome, Cronet, Flutter, Go programs) have no secrets for decerter.
- `--decrypt` drops back to plain relaying for a flow it can't keep up with (unthrottled loopback transfers); the relay itself is unaffected. `--intercept` ignores the peer's `record_size_limit` and `max_fragment_length`.
- Capture: a TLS flow is held until its secrets arrive (at most 10 s and 1 MiB per flow, 64 MiB in total; past that it is written without keys), so the file is in time order within a flow but not across flows. Packets between two selected local sockets appear twice. With `--plaintext` a gap (a truncated or lost packet) leaves the rest of that flow encrypted, and UDP GSO super-datagrams are not split.
- `--filter`: no slices, arithmetic, functions or bitwise operators.

## License
- The core (Go userspace, tools, tests) is licensed under the [GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`).
- The BPF C programs under `bpf/` are dual-licensed `GPL-2.0-only OR MIT`, matching their `SEC("license") = "Dual MIT/GPL"`.
- The vendored libbpf headers in `bpf/include/bpf/` keep their upstream license (`LGPL-2.1 OR BSD-2-Clause`).
- `internal/tlsrecord/cipher.go` and `internal/tlsrecord/keyschedule.go` contain code derived from `crypto/tls` of the Go standard library and keep the copyright notice of the Go authors (`AGPL-3.0-only AND BSD-3-Clause`, the BSD license is [internal/tlsrecord/LICENSE-Go.txt](internal/tlsrecord/LICENSE-Go.txt)).
- The dependencies are under MIT, BSD-3-Clause and Apache-2.0 licenses; `make license-check` fails on one that isn't on the allowed list, and `make license-report` lists them.
- Commercial licensing is available on request.
