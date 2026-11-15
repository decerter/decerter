# decerter
An eBPF intercepting proxy that reads and edits the live TCP, UDP, TLS and DTLS traffic of selected local processes, with no CA certificate and no change to the app.

decerter picks the sockets of one user, one process or one Android app with eBPF cgroup hooks and sends them through a proxy on `lo`, while a uprobe on the app's TLS library reads the session keys. With those keys decerter decrypts every TLS record and, when you edit one, encrypts it again with the same keys, so the app keeps talking to the real server over the real certificate. It runs as root on Linux 6.6 or newer and on rooted Android 15 or newer, and comes with a capture mode for Wireshark, a control API, a minimal web UI and an MCP server.

**Docs:** [filter language](docs/filter.md) · [control API](docs/api.md) · [HTTP layer](docs/http.md) · [capture](docs/capture.md) · [web UI](docs/ui.md) · [MCP](docs/mcp.md) · [Android](docs/android.md) · [building and testing](docs/development.md)

## Quickstart: Linux
Download `decerter_<version>_linux_amd64.tar.gz` (or `_arm64`) and `SHA256SUMS`, or build them with `make release` (see [building](docs/development.md)). decerter needs root, Linux 6.6 or newer with BTF, cgroup v2, and for decryption a program linked against OpenSSL 3's `libssl.so.3` or OpenSSL 4's `libssl.so.4`, such as curl on most distributions.

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf decerter_*_linux_amd64.tar.gz
cd decerter_*_linux_amd64/
./decerter --version
```

decerter selects nothing until you name a user, a process or an app. Use a second local user, so decerter never touches your own traffic; here it is `test` (`sudo useradd --create-home test` makes one).

```sh
# terminal 1: relay the flows of the user test and print their decrypted TLS records
sudo ./decerter run --uid "$(id -u test)" --decrypt
```
```sh
# terminal 2
sudo -u test curl -s https://example.com/ -o /dev/null
```

Terminal 1 shows one line per TLS session and the plaintext of every record, here curl's HTTP/2 request and the page:

```
tls pid=1466919 uid=1001 comm=curl [2606:4700:10::ac42:93f3]:443 client=[::1]:43304 version=TLS1.3 suite=TLS_AES_256_GCM_SHA384 sni="example.com" alpn="h2"
tls pid=1466919 uid=1001 comm=curl … direction=up sequence=0 length=101 shown=101
    PRI * HTTP/2.0\r\n
…
tls pid=1466919 uid=1001 comm=curl … direction=down sequence=3 length=586 shown=586
    \x00\x02A\x00\x00\x00\x00\x00\x01<!doctype html><html lang=en><head>…<title>Example Domain</title>…
```

Now edit the response. Stop decerter with Ctrl-C and start it with `--intercept` and the control API, then add a rule that replaces text in the server's HTTP responses:

```sh
# terminal 1
sudo ./decerter run --uid "$(id -u test)" --intercept --api-socket /run/decerter/api.sock
```
```sh
# terminal 2
sudo curl -s --unix-socket /run/decerter/api.sock -H 'Content-Type: application/json' -X POST -d '{"layer": "http", "direction": "down", "find": {"type": "text", "value": "Example Domain"}, "replace": {"type": "text", "value": "Edited by decerter"}}' http://decerter/api/v1/rules
sudo -u test curl -s https://example.com/ | grep -o '<title>.*</title>'
```
```
<title>Edited by decerter</title>
```

curl checked the server's real certificate; decerter sealed the changed HTTP/2 response with the session's own keys. Next: hold and edit requests by hand in [`decerter ui`](docs/ui.md), let an LLM drive decerter with [`decerter mcp`](docs/mcp.md), or write a pcapng that Wireshark decrypts by itself with [`decerter capture`](docs/capture.md).

## Quickstart: Android
On the Linux host (or an Apple Silicon Mac, below), with the Android SDK (platform-tools and the emulator, in `~/Android/Sdk` or `ANDROID_HOME`; setup takes the SDK's `adb` before one on `PATH`) and an AVD of the Google APIs x86_64 image of Android 15 (API 35), whose `adbd` can run as root:

```sh
sdkmanager "platform-tools" "emulator" "system-images;android-35;google_apis;x86_64"
avdmanager create avd --name decerter-a15 --package "system-images;android-35;google_apis;x86_64"
```

On an Apple Silicon Mac, take the `arm64-v8a` image in place of `x86_64` and build decerter from source there (there is no macOS release): `make build build-arm64` gives `./decerter` for macOS, which has only the host commands (`android setup`, `ui`, `mcp`, `help`), and `./decerter-arm64`, which setup pushes to the arm64 emulator. The commands below are the same with `./decerter`.

`decerter android setup` runs as your user, not as root. With `--avd` it boots the AVD without a window, pushes decerter to the emulator, checks that decerter can hook the app's TLS, forwards the control API to a host port and prints the commands to run (to watch the app, start the emulator with a window yourself, `emulator -avd decerter-a15`, and leave out `--avd`). Chrome is on every Google APIs image and brings its own BoringSSL:

```sh
tar -xzf decerter_*_linux_amd64.tar.gz
cd decerter_*_linux_amd64/
./decerter android setup --avd decerter-a15 --package com.android.chrome --port 8080
```
```
adb      /home/you/Android/Sdk/platform-tools/adb
boot     decerter-a15 as emulator-5554 without a window, its log is /tmp/decerter-emulator-2455380772.log
device   emulator-5554, sdk_gphone64_x86_64 (emulator)
android  15 (API level 35, userdebug build), x86_64, kernel 6.6.50-android15-8-g8adecb593e9b-ab12525588
root     adbd runs as root (adb root)
package  com.android.chrome, uid 10145
binary   /data/local/tmp/decerter, decerter v0.0.0-… (commit …), pushed from …/decerter_v0.0.0-…_linux_amd64/decerter
tls      Conscrypt offsets for Android 15 on x86_64
app      com.android.chrome: Chrome 124.0.6367.219 of com.google.android.trichromelibrary_636771938, BoringSSL offsets known, ssl_log_secret found through 7 key log labels in /data/app/…/TrichromeLibrary.apk!/lib/x86_64/libmonochrome_64.so
app      com.android.chrome: a Chromium app, it prefers QUIC, which decerter relays without decryption; --block-quic makes it use TLS over TCP
quic     com.android.chrome is a Chromium app, the device command gets --block-quic so it uses TLS over TCP, which decerter decrypts
chrome   wrote /data/local/tmp/chrome-command-line: _ --disable-fre --no-default-browser-check --no-first-run; Chrome reads it when it starts, setup --remove deletes it
api      adb forward tcp:8080 localabstract:decerter-api

Start decerter on the device, Ctrl-C stops it and puts netd's hooks back:
  /home/you/Android/Sdk/platform-tools/adb -s emulator-5554 shell -tt /data/local/tmp/decerter run --intercept --api-socket @decerter-api --package com.android.chrome --block-quic
Then the UI on this machine, in another terminal:
  ./decerter ui --api-socket 127.0.0.1:8080
Undo the setup with: ./decerter android setup --remove --serial emulator-5554
```

Run the printed command. Chrome prefers QUIC where a server offers it and decerter doesn't decrypt QUIC, so setup added `--block-quic`, which makes Chrome fall back to TLS over TCP; it also wrote Chrome's flags file without the first-run screens, which would hold the first page back.

```sh
# terminal 2: decerter on the emulator, Ctrl-C stops it, and so does closing this terminal
~/Android/Sdk/platform-tools/adb -s emulator-5554 shell -tt /data/local/tmp/decerter run --intercept --api-socket @decerter-api --package com.android.chrome --block-quic
```
```sh
# terminal 3: the UI on the host, open the URL it prints
./decerter ui --api-socket 127.0.0.1:8080
```
```sh
# terminal 4: open a page in Chrome
adb -s emulator-5554 shell am start -S -W -a android.intent.action.VIEW -d https://example.com/ com.android.chrome
curl -s 'http://127.0.0.1:8080/api/v1/flows?filter=tls.sni+contains+%22example%22'
```

The flow list in the UI (and the curl above) shows Chrome's TLS 1.3 flows to `example.com` with their decrypted HTTP/2 exchanges; the intercept switch holds the next request for editing. When you are done, stop decerter with Ctrl-C and undo the setup, which also deletes the flags file it wrote:

```sh
./decerter android setup --remove --serial emulator-5554
adb -s emulator-5554 emu kill
```

For an arm64 phone, put the arm64 binary next to the amd64 one, where setup looks for it: `tar -xzOf ../decerter_*_linux_arm64.tar.gz --wildcards '*/decerter' > decerter-arm64 && chmod +x decerter-arm64`. Real devices are experimental: only the x86_64 and arm64 emulators were tested. [docs/android.md](docs/android.md) covers `--package`, `decerter android tls`, Flutter, Chrome and Cronet apps, `decerter android restore` and the steps without setup.

## How it works
- **Selection:** cgroup v2 socket hooks (`connect4/6`, `sendmsg4/6`) check the calling process against BPF maps filled from `--uid`, `--pid`, `--package`, `--dst-cidr`, `--dst-port` and the kernel part of [`--filter`](docs/filter.md). Nothing is selected until a process is named.
- **Redirect:** a selected socket's destination is rewritten to decerter's proxy on `lo` (port 15001, one TCP listener and one UDP socket); `getpeername()` and `recvmsg()` still show the real server. The kernel builds every packet on both sides, so nothing rewrites checksums or sequence numbers, and no interface, VPN or iptables rule is added.
- **Keys:** a uprobe on the TLS library (OpenSSL 3 and 4 on Linux; Conscrypt, Flutter's and Chrome's BoringSSL on Android) copies the session secrets into a BPF map keyed by the ClientHello's random, the model of `SSLKEYLOGFILE`. The handshake goes on untouched.
- **Edit:** the proxy decrypts each record with those keys, runs it through the rules, the hold queue and the HTTP/1.1 and HTTP/2 layer, and seals it again with the same keys and the right sequence number.
- **Capture:** `decerter capture` redirects nothing; `cgroup_skb` programs copy the selected sockets' packets to a ring buffer, written as pcapng with a Decryption Secrets Block per session.
- On Android netd holds the cgroup hooks exclusively; decerter shares them while it runs and puts them back on exit.

The details are in the docs pages above and in `decerter <command> --help`.

## Why no CA
Most intercepting proxies terminate TLS with a certificate of their own CA, which the app has to trust. That needs a CA installed on the device, and apps that pin their certificate refuse it. decerter reads the keys of the app's own TLS session instead. Related tools, as of 2026-11, from their own documentation:

- **[mitmproxy](https://github.com/mitmproxy/mitmproxy)** (MIT): an intercepting proxy that decrypts traffic as long as the client trusts mitmproxy's CA, which signs certificates generated on the fly; pinned apps need modification ([certificates](https://docs.mitmproxy.org/stable/concepts/certificates/)). Its local capture mode on Linux redirects processes with eBPF and is supported on Linux 6.8 and above ([modes](https://docs.mitmproxy.org/stable/concepts/modes/)).
- **[HTTP Toolkit](https://github.com/httptoolkit/httptoolkit)** (open source, with a free and a paid Pro tier, [pricing](https://httptoolkit.com/pricing/)): an intercepting proxy with its own CA. On Android its app registers as a VPN; on rooted devices and emulators it installs the CA as a system certificate over ADB, and Frida can remove most certificate pinning ([Android guide](https://httptoolkit.com/docs/guides/android/)).
- **[PCAPdroid](https://github.com/emanuele-f/PCAPdroid)** (GPL-3.0): captures on Android without root by simulating a VPN; TLS decryption is done by mitmproxy in the PCAPdroid-mitm add-on, with a CA generated by PCAPdroid that must be trusted ([TLS decryption](https://emanuele-f.github.io/PCAPdroid/tls_decryption)). A pcapng with the secrets embedded comes with the purchasable pcapng feature ([paid features](https://emanuele-f.github.io/PCAPdroid/paid_features)).
- **[eCapture](https://github.com/gojue/ecapture)** (Apache-2.0): eBPF uprobes on TLS libraries capture plaintext and keys without a CA, written as text, a key log or pcapng. It reads traffic; it does not edit or redirect it.

What decerter adds: editing TLS traffic without a CA, by sealing changed records with the session's own keys; selection per UID (so per Android app) or PID; no VPN and no proxy setting; and apps that pin their certificate work unchanged when decerter supports their TLS library (see the matrix). The price is root and a kernel with eBPF, and a TLS library decerter knows.

## Support matrix
**tested**: run by `make test-e2e` / `make test-e2e-android` or by hand on the named target. **built, untested**: the code and offsets are there, no run on that target. **unsupported**: not handled; such traffic is relayed (and captured) without decryption.

| TLS library | Versions | Status |
|---|---|---|
| OpenSSL 3 (`libssl.so.3`), Linux amd64 | 3.6.2 (Debian forky); distribution builds 3.0.13 (Ubuntu 24.04), 3.5.7 (Debian 13), 3.5.7 (Parrot 7.4, `parrotsec/core`), 3.5.8 (AlmaLinux 10, FIPS), 3.5.9 (Fedora 45 `openssl3-libs`), 3.6.5 (Kali rolling 2026.3, `kalilinux/kali-rolling`), 3.6.5 (BlackArch on Arch, `blackarchlinux/blackarch`) | tested |
| OpenSSL 4 (`libssl.so.4`), Linux amd64 | 4.0.3 (Fedora 45's default, also next to `openssl3-libs` 3.5.9 with both hooked at once); 4.1.0 built from upstream source | tested |
| OpenSSL 3 and 4, Linux amd64 | every other release 3.0.0–3.6.5 and 4.0.0–4.1.0 (offsets generated from each release's source) | built, untested |
| OpenSSL 3 and 4, Linux arm64 | distribution builds on Debian 13 arm64 (2026-11-14): 3.0.13 (Ubuntu 24.04), 3.5.7 (Debian 13, the host and `debian:13`), 3.5.7 (Parrot), 3.5.8 (AlmaLinux 10), 3.6.5 (Kali rolling), 4.0.3 (Fedora 45) and 3.5.9 (Fedora 45 `openssl3-libs`) | tested |
| OpenSSL 3 and 4, Linux arm64 | every other release 3.0.0–3.6.5 and 4.0.0–4.1.0 | built, untested |
| OpenSSL 1.1, LibreSSL, GnuTLS, NSS, rustls, Go's `crypto/tls`, other statically linked TLS on Linux | | unsupported |
| Conscrypt (Android's platform TLS: Java and Kotlin apps) | Android 15, x86_64; Android 15, arm64 (emulator, 2026-11-14) | tested |
| Conscrypt | Android 16 and 17 offsets | built, untested |
| Flutter (`dart:io`'s BoringSSL in `libflutter.so`) | 3.35.7 and 3.50.0, x86_64; 3.35.7, arm64 (emulator, 2026-11-14) | tested |
| Flutter | 3.24.0–3.50.0 (74 releases, 38 Dart versions) | built, untested |
| Flutter | before 3.24.0; 32-bit apps | unsupported |
| Chrome (Trichrome) | 124.0.6367.219, x86_64 and arm64 (emulator, 2026-11-14) | tested |
| Chromium (ChromePublic snapshot) | 160.0.8161.0, x86_64 (snapshot 1744338) and arm64 (snapshot 1744436, 2026-11-14) | tested |
| Chrome, WebView, Cronet | release branches of milestones 124–160 and the listed builds 122.0.6238.4, 125.0.6383.0, 126.0.6452.4, 127.0.6493.0 | built, untested |
| Cronet bundled in apps | YouTube's Cronet 125.0.6383.0 is found and hooked, its key log lines were counted but not checked; Play services' Cronet 126.0.6452.4 is hooked, no traffic seen | built, untested |
| WebView in an app | maps Trichrome's library, so it is expected to work like Chrome | built, untested |
| Mainline Cronet (`HttpEngine`, tethering APEX) | uses the APEX's own `libssl.so` | unsupported |

| Protocol | Status |
|---|---|
| TCP and UDP relay, IPv4 and IPv6 | tested |
| TLS 1.2 and 1.3: AES-GCM, ChaCha20-Poly1305, AES-CBC (SHA-1, SHA-256), 3DES; ECDHE and RSA key exchange; KeyUpdate, resumption | tested (3DES only in unit tests, the host's OpenSSL has none) |
| TLS: DHE suites, `ECDHE-RSA-AES256-SHA384`, RC4, renegotiation, 0-RTT early data, kTLS | unsupported (kTLS not tried) |
| DTLS 1.2 (OpenSSL) | tested; a datagram that does not frame, a record of epoch 2 or more (renegotiation) and one that fails its MAC are dropped from the decryption and go on as they came, as an endpoint drops them |
| DTLS 1.0 and 1.3 | unsupported |
| HTTP/1.1 (and 1.0): view, rules, holds, edit with Content-Length and chunking fixed | tested |
| HTTP/2 over TLS (`h2`) and h2c with prior knowledge: view, rules, holds, edit with HPACK and flow control kept consistent | tested (curl, Go client and server); Chrome's HTTP/2 seen in the Android quickstart |
| gRPC over HTTP/2 | message boundaries listed, not decoded; edits are raw bytes |
| WebSocket, h2c by `Upgrade`, CONNECT tunnels | not read: the HTTP layer stops at `101` and at a `2xx` answer to CONNECT (a refused CONNECT is read on), the bytes still go through record rules |
| QUIC / HTTP/3 | unsupported: relayed without decryption; `--block-quic` makes clients fall back to TCP (tested) |
| STARTTLS | `decerter capture`: tested (SMTP); `decerter run`: not decrypted, TLS has to start with the client's first bytes |

| Platform | Status |
|---|---|
| Linux amd64, kernel 7.0.3 (Debian forky) | tested: every mode, `make test-e2e` |
| Linux kernel 6.6 | tested as the Android 15 emulators' kernels, 6.6.50 (x86_64) and 6.6.30 (arm64) (run, capture, keylog, API); every BPF object loads there; a desktop 6.6 kernel was not run |
| Linux before 6.6 | unsupported |
| Linux arm64, kernel 6.12 (Debian 13 in a Lima `vz` VM on an Apple Silicon Mac) | tested on 2026-11-14: `make test-unit` and `make test-e2e` (every mode, the distribution OpenSSL cases; BlackArch has no arm64 image) |
| Android 15 emulator, x86_64 (Google APIs image, userdebug, `adb root`) | tested: `make test-e2e-android` |
| Android 15 emulator, arm64-v8a (Google APIs image, kernel 6.6.30, on an Apple Silicon Mac) | tested on 2026-11-14: the Android e2e tests from the Mac (setup, `--package`, Conscrypt, Flutter, Chrome, ChromePublic, Cronet, `--block-quic`, restore) |
| macOS arm64 as the host of `decerter android setup` and `decerter ui` | tested on 2026-11-14 with the arm64 emulator |
| Android 16 and 17 (GKI android16-6.12, android17-6.18) | built, untested |
| Rooted arm64 phones (Magisk, KernelSU, `su`) | experimental: built, untested |
| Google Play images, Android before 15, 32-bit apps | unsupported |

## Commands
```
$ decerter --help
decerter reads and rewrites the live TCP, UDP, TLS and DTLS traffic of selected local processes.
eBPF cgroup hooks pick the sockets of the selected processes and a uprobe on the TLS library reads their session secrets,
so there is no CA certificate to install, no proxy setting and no change to the app.

decerter runs as root on Linux 6.6 or newer with BTF, and on rooted Android 15 or newer (GKI android15-6.6 or newer).
Nothing is selected until --uid or --pid, --package on Android, or a proc.uid or proc.pid term of --filter, names a process.
On Android, decerter android setup on the Linux or macOS host pushes decerter to the device and prints how to run it;
a decerter built for macOS (make build on a Mac) has only the host commands: android setup, ui, mcp and help.
Logs are JSON lines on stderr; stdout carries the output of the command.

Every flag can also be set with an environment variable DECERTER_<FLAG>, upper case with - as _, for example DECERTER_LOG_LEVEL=debug.
The command line wins over the environment, and sudo passes the variable on only with --preserve-env.

Usage:
  decerter [command]

Available Commands:
  android     Set decerter up on an Android device or emulator, and put netd's hooks back
  capture     Write the selected flows to pcapng with their TLS secrets, or decrypted, without redirecting them
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  keylog      Print the TLS secrets of the selected processes in NSS key log format
  mcp         Serve an MCP server on stdio, a client of the control API, for an LLM client to read and with --allow-write change decerter's state
  run         Redirect the selected flows through decerter's proxy, optionally decrypting or intercepting them
  ui          Serve the minimal web UI on 127.0.0.1, a client of the control API

Flags:
  -h, --help              help for decerter
      --log-level level   log level (default is info, valid values: trace, debug, info, warn, error)
  -v, --version           version for decerter

Additional help topics:
  decerter filter     The --filter language of run and capture

Use "decerter [command] --help" for more information about a command.
```

A few more, each with its page:

```sh
# every message through the identity rule, printed with a hex dump; only curl's flows to port 443
sudo ./decerter run --uid 1001 --intercept --filter 'proc.comm == "curl" && tcp.dstport == 443'
# a pcapng that tshark and Wireshark decrypt by themselves, or live into tshark (it reads through dumpcap, so your user needs dumpcap's rights, on Debian the group wireshark)
sudo ./decerter capture --uid 1001 -w out.pcapng
sudo ./decerter capture --uid 1001 -w - | tshark -l -i - -Y 'http or http2'
# the key log of the selected processes, for any tool that reads SSLKEYLOGFILE
sudo ./decerter keylog --uid 1001 > keys.log
```

`run` relays (`--decrypt` prints, `--intercept` edits), [`capture`](docs/capture.md) records without redirecting, `keylog` prints secrets, [`ui`](docs/ui.md) and [`mcp`](docs/mcp.md) are clients of the [control API](docs/api.md) and run as your user, [`android`](docs/android.md) sets up a device. The examples select the user `test`, UID 1001.

The proxy of `run` listens on port 15001 of `lo` (`--port`), TCP and UDP; a UDP session ends after 30 s without a datagram (`--udp-idle-timeout`). The secrets uprobe goes on the `libssl.so.3` and the `libssl.so.4` of the dynamic linker cache, both when the host has both, each with the offsets of its own version, and on every OpenSSL 3 or newer `libssl` the selected processes map (read from `/proc/<pid>/maps` at start and every 2 s and opened through `/proc/<pid>/root`), so a container's own OpenSSL is found too; with `--libssl` only the library it names (OpenSSL's `libcrypto` with the same suffix has to be next to it). An unknown version of `--libssl`'s OpenSSL stops decerter before anything is attached and names the nearest known version and `make generate-openssl-offsets`. A library of the linker cache with an unknown version is a warning with the same text while another OpenSSL is still hooked (the other soname of the linker cache, or one a selected process maps), and stops decerter when none is; the processes that load it are relayed without secrets. A library only a process maps with an unknown version is logged and that process is relayed without secrets. A host with neither soname and no selected process that maps one runs `run` and `capture` without TLS secrets, with a warning; `keylog` and a `--libssl` that does not exist stop decerter. `--flow-table` prints the kernel's flow table every 5 s for debugging. `--log-level` sets the JSON logs on stderr, and every flag can also come from an environment variable `DECERTER_<FLAG>`.

## Known limits
- Only outgoing flows: sockets that `connect()` or `sendmsg()` in a selected process. Accepted (server-side) sockets are not redirected or captured, and the children of a `--pid` are not followed.
- `getsockname()` in the app shows the loopback address in run mode. A destination that is routed but doesn't answer looks connected to the app until the proxy's 10 s dial timeout resets it.
- One unconnected UDP socket that sends a burst to two destinations before the proxy reads them can send both to the second one.
- A process whose TLS library decerter doesn't support (see the matrix), or a Flutter or Chromium app of a version not in decerter's tables, is relayed and captured without decryption; the log says why and names the `make` target that adds a version.
- A Chromium library found in a running process's mappings is hooked only once that process runs, so its first sessions before the next scan (every 2 s) have no secrets: start the app after decerter. The same holds on Linux for an OpenSSL that only a process started after decerter maps (a new container): its sessions in the first up to 2 s have no secrets, or give `--libssl`.
- `--decrypt` drops back to plain relaying for a flow it can't keep up with (unthrottled loopback transfers, about 400 MB/s); the relay is unaffected. `--intercept` ignores the peer's `record_size_limit` and `max_fragment_length`.
- A record rule sees one message at a time (a TLS record, one read, one datagram); layer `http` sees whole HTTP messages. HTTP bodies are not decompressed, bodies over 1 MiB go on unedited, and on HTTP/2 a held request also holds back the client's later new streams ([HTTP layer](docs/http.md)).
- Capture: a TLS flow is held until its secrets arrive (at most 10 s and 1 MiB per flow, 64 MiB in total), so the file is in time order within a flow but not across flows. Packets between two selected local sockets appear twice. A capture of `decerter run` holds the wire side, not the app's loopback packets.
- The history, rules and captures live in memory and in `/run/decerter` only while decerter runs; the event stream has no replay.
- `decerter mcp`: escaping and the untrusted-data marker make injected instructions visible as data; they can't make a model ignore them. Give `--allow-write` only to a client whose tool calls you watch.
- Android: decerter needs root and shares netd's cgroup hooks while it runs; after a `kill -9`, `decerter android restore` puts them back. An app's DNS is sent by netd as root and is not in the app's scope.
- Not verified: real phones, Magisk, KernelSU and setup's `su` path; Android 16 and 17; the Wireshark GUI (tshark was used); `decerter ui` in Firefox and editing an HTTP/2 hold in a browser; a real LLM client for `decerter mcp`; the socket's `decerter` group on a host that has the group; HTTP/2 holds on Android; server push, gRPC edits and `Expect: 100-continue` end to end; UDP and DTLS in run-mode captures; a ring buffer overrun; WebView in an app; musl distributions.

## License
- The core (Go code, tools, tests) is licensed under the [GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`).
- The BPF C programs under `bpf/` are dual-licensed `GPL-2.0-only OR MIT`, matching their `SEC("license") = "Dual MIT/GPL"`.
- The control API contract, [api/openapi.yaml](api/openapi.yaml), and its Go types, `api/types.go`, are `MIT`, so any client can be generated from them.
- The vendored libbpf headers in `bpf/include/bpf/` keep their upstream license (`LGPL-2.1 OR BSD-2-Clause`).
- `bpf/vmlinux.h` is bpftool's dump of the Linux kernel's types (`GPL-2.0-only`), only compiled into the BPF programs.
- `internal/tlsrecord/cipher.go` and `internal/tlsrecord/keyschedule.go` contain code derived from Go's `crypto/tls` and keep the Go authors' notice (`AGPL-3.0-only AND BSD-3-Clause`); the BSD license is `LICENSE-Go.txt` in the release tarball and `internal/tlsrecord/LICENSE-Go.txt` in the repository.
- The dependencies are under MIT, BSD-3-Clause and Apache-2.0; `make license-check` fails on one that isn't allowed, and each release tarball carries their license texts in `THIRD_PARTY_NOTICES`.
