{{- /* SPDX-License-Identifier: AGPL-3.0-only */ -}}
{{- /* the go-licenses report template of make release, see tools/release/release.sh; a module whose license file has two licenses comes twice in a row */ -}}
Third-party notices of the decerter binary

decerter is licensed under the GNU Affero General Public License v3.0 only (LICENSE). Its BPF programs are
GPL-2.0-only OR MIT. The binary also contains the Go modules below, each under the license whose full text
follows its name, and the Go standard library and runtime, under the BSD-3-Clause license in LICENSE-Go.txt,
which also covers the parts of internal/tlsrecord derived from Go's crypto/tls.
{{ $previous := "" }}{{ range . }}{{ if eq .Name $previous }}
{{ .Name }} {{ .Version }} is also under {{ .LicenseName }}, the text is the one above.
{{ else }}
================================================================================
{{ .Name }} {{ .Version }}
License: {{ .LicenseName }}
================================================================================

{{ .LicenseText }}
{{ end }}{{ $previous = .Name }}{{ end -}}
