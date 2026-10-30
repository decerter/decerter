# decerter
eBPF-powered proxy that reads and rewrites live TCP/UDP/TLS traffic, with no CA certificate and no changes to the app.

## License
- The core (Go userspace, tools, tests) is licensed under the [GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`).
- The BPF C programs under `bpf/` are dual-licensed `GPL-2.0-only OR MIT`, matching their `SEC("license") = "Dual MIT/GPL"`.
- The vendored libbpf headers in `bpf/include/bpf/` keep their upstream license (`LGPL-2.1 OR BSD-2-Clause`).
- Commercial licensing is available on request.
