# decerter
eBPF-powered proxy that reads and rewrites live TCP/UDP/TLS traffic, with no CA certificate and no changes to the app.

## License
- The core (Go userspace, tools, tests) is licensed under the [GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`).
- The BPF C programs under `bpf/` are dual-licensed `GPL-2.0-only OR MIT`, matching their `SEC("license") = "Dual MIT/GPL"`.
- The vendored libbpf headers in `bpf/include/bpf/` keep their upstream license (`LGPL-2.1 OR BSD-2-Clause`).
- `internal/tlsrecord/cipher.go` and `internal/tlsrecord/keyschedule.go` contain code derived from `crypto/tls` of the Go standard library and keep the copyright notice of the Go authors (`AGPL-3.0-only AND BSD-3-Clause`, the BSD license is [internal/tlsrecord/LICENSE-Go.txt](internal/tlsrecord/LICENSE-Go.txt)).
- Commercial licensing is available on request.
