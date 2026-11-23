# Web UI
`decerter ui` serves a small web page for the [control API](api.md) on `127.0.0.1`, run as your user:

```sh
sudo ./decerter run --uid 1001 --intercept --api-socket /run/decerter/api.sock
./decerter ui                     # as your user in the group decerter; prints http://127.0.0.1:<port>/?token=…
./decerter ui --open              # the same, and opens it with xdg-open (open on macOS)
```

The page (HTML, CSS and vanilla JS embedded in the binary, no build step):
- the flow list, live over the event stream, with a filter box in the [filter language](filter.md) and paging: live events and the first page keep at most their newest 1000 rows, the rows More read and the selected flow stay however many come (a busy decerter can leave a gap above the rows of More, which setting the filter again reads);
- a flow in parts that fold like the panes of Wireshark: the flow's fields, its messages, the message shown, its HTTP exchanges (HTTP/2 stream, method, URL, status, body lengths, edits and notes), the exchange shown, the handshake and the stream; the lists scroll in their own box, and the handshake and the stream start folded and are read only when opened, so the application data comes first;
- a message as escaped text or a hex dump, 4 KiB at a time, and as the peer sent it when it was changed; an exchange with its heads and a window of either body; a gRPC body with a line in front of each message;
- the [decode tree](decode.md) of a message or a body next to its bytes, with "decode as": a click on a node marks its bytes, a click on a byte selects its field; expand all and collapse all, and a branch opened or closed by hand stays so for that field in the next trees, like Wireshark;
- the TLS or DTLS handshake decerter kept of a flow, client or server, as a tree next to its bytes;
- the stream of a TCP flow, client or server: one direction joined and decoded, so a message split over reads decodes as one; a node opens the message with its first byte and marks its bytes, and lists every message it spans;
- "Open in Wireshark (pcapng)": the flow as a pcapng download, with its TLS secrets when decerter keeps packets;
- intercept on and off with a filter, a direction and the layer (every record layer, one of tcp, tls, udp and dtls, or whole HTTP messages);
- the held messages, to edit as escaped text (`\r`, `\n`, `\t`, `\\`, `\xNN`; line breaks are only layout) or as hex, and to forward or drop; the editor shows the decode tree of the held payload next to its hex dump (the first 16 KiB), of what goes on, so Save decodes an edit; the intercept pane widens while it edits.

The page is dark, with its fonts (Kode Mono, Inter, JetBrains Mono, OFL-1.1) and favicon embedded too, so it looks the same offline and loads nothing from another site.

There is no rules editor; rules are added with curl or a script. The full UI is the separate decerter-pro.

## Access
It needs only the API socket, which is for root and the group `decerter`: `sudo groupadd decerter`, `sudo usermod -aG decerter $USER`, log in again (or `newgrp decerter`) and restart `decerter run`, so the socket gets the group. Without that `decerter ui` stops at start and says so. `--api-socket` takes the same path as `decerter run` (default `/run/decerter/api.sock`), `@name` for an abstract socket, or a loopback `ip:port` such as the host side of `adb forward` (default on Android `@decerter-api`), which it then sends as the `Host` of its requests: over TCP the API takes no `Host: decerter`. adb forward accepts on the host even while nothing listens on the device; `decerter ui` then says that nothing is listening yet: start decerter on the device first.

## Security
It listens on `127.0.0.1` only, on a port the kernel picks, and prints a URL with a random 32-byte token. The first load sets the token as an `HttpOnly`, `SameSite=Strict` cookie and redirects, without the token, to a second random 32-byte path that the page and its API proxy are served under; the cookie's `Path` is that path. Browsers don't keep cookies apart by port, so with `Path=/` every other web server on `127.0.0.1` would get the token; with the random path a server on another port never sees it, as it can't know the path. Every request, the page and the API proxy alike, needs that cookie, the random path and the `Host` `127.0.0.1:<port>` (against DNS rebinding); a request that changes something also needs the page's `Origin`, and requests from other sites and other ports are refused; anything else gets `403`. The printed URL works as often as it is loaded; bookmark the page's address after the redirect, a load of `/` without the token is `403`. The page sends a strict Content-Security-Policy and shows traffic only as text nodes (a unit test fails on `innerHTML`, `eval` or inline script). `decerter ui` forwards only `/api/v1/…` to the socket, without the browser's cookie, `Origin`, `Referer`, `Authorization` and `Sec-Fetch-*`, so it can do nothing curl on the socket can't (the API refuses requests that carry `Origin` or `Sec-Fetch-Site`, see [the API](api.md#access)). `[::1]` is not served: one address is one origin and one cookie.

`--open` hands xdg-open (open on macOS) a URL with a one-time code in place of the token: command lines are readable by every local user, and a browser xdg-open starts keeps the URL in its own for its whole session. The code works for one first load within 5 minutes and is gone then; the token never goes into a command line.

Limits: the random path is in the address bar and the browser's history, and a page of another server on `127.0.0.1` still counts as the same site to the browser; the `Origin` and `Sec-Fetch-Site` checks keep such a page from changing anything. The held list shows the deadline with the browser's clock. Checked in headless Chromium; Firefox was not tried.
