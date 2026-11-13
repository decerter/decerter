# Web UI
`decerter ui` serves a small web page for the [control API](api.md) on `127.0.0.1`, run as your user:

```sh
sudo ./decerter run --uid 1001 --intercept --api-socket /run/decerter/api.sock
./decerter ui                     # as your user in the group decerter; prints http://127.0.0.1:<port>/?token=…
./decerter ui --open              # the same, and opens it with xdg-open
```

The page (HTML, CSS and vanilla JS embedded in the binary, no build step):
- the flow list, live over the event stream, with a filter box in the [filter language](filter.md) and paging;
- a flow with its messages and its HTTP exchanges (HTTP/2 stream, method, URL, status, body lengths, edits and notes);
- a message as escaped text or a hex dump, 4 KiB at a time, and as the peer sent it when it was changed; an exchange with its heads and a window of either body; a gRPC body with a line in front of each message;
- intercept on and off with a filter, a direction and the layer (records or whole HTTP messages);
- the held messages, to edit as escaped text (`\r`, `\n`, `\t`, `\\`, `\xNN`; line breaks are only layout) or as hex, and to forward or drop.

There is no rules editor; rules are added with curl or a script. The full UI is the separate decerter-pro.

## Access
It needs only the API socket, which is for root and the group `decerter`: `sudo groupadd decerter`, `sudo usermod -aG decerter $USER`, log in again (or `newgrp decerter`) and restart `decerter run`, so the socket gets the group. Without that `decerter ui` stops at start and says so. `--api-socket` takes the same path as `decerter run` (default `/run/decerter/api.sock`), `@name` for an abstract socket, or a loopback `ip:port` such as the host side of `adb forward` (default on Android `@decerter-api`).

## Security
It listens on `127.0.0.1` only, on a port the kernel picks, and prints a URL with a random 32-byte token. The first load sets the token as an `HttpOnly`, `SameSite=Strict` cookie and redirects to `/` without it. Every request, the page and the API proxy alike, needs that cookie and the `Host` `127.0.0.1:<port>` (against DNS rebinding); a request that changes something also needs the page's `Origin`, and requests from other sites are refused; anything else gets `403`. The page sends a strict Content-Security-Policy and shows traffic only as text nodes (a unit test fails on `innerHTML`, `eval` or inline script). `decerter ui` forwards only `/api/v1/…` to the socket, without the browser's cookie, `Origin`, `Referer` and `Authorization`, so it can do nothing curl on the socket can't. `[::1]` is not served: one address is one origin and one cookie.

Limits: cookies are not kept apart by port, so the token cookie also goes to any other web server on `127.0.0.1` the browser visits, and such a page counts as the same site; the `Origin` and `Sec-Fetch-Site` checks keep it from changing anything, but don't open pages of other local servers you don't trust while the UI runs. `--open` puts the URL with the token on xdg-open's command line while it runs. The held list shows the deadline with the browser's clock. Checked in headless Chromium; Firefox was not tried.
