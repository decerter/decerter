# Building and testing
Building needs Go 1.26 or newer. The BPF objects and the offset tables are committed, so a build needs no clang and no kernel headers.

```sh
make build          # ./decerter, static linux/amd64 binary
make build-arm64    # ./decerter-arm64, static linux/arm64 binary for Android devices
make verify-static  # builds both and checks that they are statically linked
make help           # every target
```

## Versions and releases
`decerter --version` prints the version, the commit, the commit time and the Go version:

```
decerter v0.0.0-52-g463e4fc (commit 463e4fc, date 2026-11-13T22:41:14Z, go1.26.2 linux/amd64)
```

The version comes from `tools/release/version.sh`, set with `-ldflags -X` by `make build` and `make release`: on a tag the form of `git describe --tags` (`v0.1.0`, or `v0.1.0-3-gabc1234` three commits after it); before the first tag `v0.0.0-<n>-g<hash>`, where `n` is the number of commits since the root commit; `-dirty` when a tracked file has uncommitted changes. A plain `go build` or `go install` gets Go's own module version instead (`v0.0.0-<time>-<hash>` before a tag). The date is the commit time, so one commit builds the same binary.

`make release` builds the release into `dist/`:

```
dist/decerter_<version>_linux_amd64.tar.gz
dist/decerter_<version>_linux_arm64.tar.gz
dist/SHA256SUMS
```

Each tarball has one directory `decerter_<version>_linux_<arch>/` with the static binary `decerter` (`-trimpath`, `-buildvcs=false`, no build id), `LICENSE`, `LICENSE-Go.txt` (the BSD license of the Go standard library and of the code in `internal/tlsrecord` derived from `crypto/tls`), `README.md`, `docs/`, `api/openapi.yaml` and `THIRD_PARTY_NOTICES`: the full license texts of the Go modules in that architecture's binary, from `go-licenses report` with `tools/release/notices.tpl`. The tarballs are reproducible from one commit with one Go toolchain: sorted entries, owner and group 0, every mtime the commit time, fixed modes, gzip without a name or time stamp. `make release` refuses a work tree with changes or untracked files unless `ALLOW_DIRTY=1`; it tags, pushes and publishes nothing. It needs `go-licenses` (`make install-go-licenses`) and `file`.

## Static analysis and tests
```sh
make lint            # golangci-lint (make install-golangci-lint)
make license-check   # go-licenses on the dependencies of both architectures plus the SPDX line of every source file
make license-report  # the dependencies with their licenses
make test-unit       # unit tests with the race detector
make test-e2e        # e2e tests on this host, as root
make test-e2e-android
```

- `make test-unit` includes tests that keep the docs honest: the `decerter --help` dump in the README, the field table of [filter.md](filter.md) and a check that every flag of every command is named in the README or `docs/`.
- `make test-e2e` runs decerter in-process with sudo and needs the local users `test` (selected) and `nobody` (not selected); it refuses to run when a test user has UID 0 or 1000. curl runs as those users, the Go test servers as root. The distribution OpenSSL cases need docker, a C compiler and the images `ubuntu:24.04`, `debian:13`, `fedora` and `almalinux:10`, and are skipped without them.
- `make test-e2e-android` runs decerter only on the emulator, never on the host: a running x86_64 emulator, or `decerter android setup` boots the AVD `decerter-a15` (`system-images;android-35;google_apis;x86_64`) from `ANDROID_SDK_ROOT` or `~/Android/Sdk` as the cold setup case and stops it again. It needs a JDK and the SDK's d8 for the Conscrypt test client and tshark. The Flutter cases build the app of `test/android/flutter` with each Flutter SDK in `DECERTER_E2E_FLUTTER` (colon separated, default every `~/.cache/decerter-flutter/<version>/flutter`) as the user who ran sudo, cached in `~/.cache/decerter-flutter/e2e`, and are skipped without an SDK. The Chrome cases use the image's Chrome and YouTube; the ChromePublic cases the x86_64 `ChromePublic.apk` of a Chromium snapshot in `DECERTER_E2E_CHROMIUM` (default the newest `~/.cache/decerter-chromium/snapshot-AndroidDesktop_x64-*/chrome-android-desktop/apks/ChromePublic.apk`) and are skipped without it.

## BPF objects
Regenerating the BPF objects (`make generate-bpf-objects`) needs clang-21, llvm-strip-21 and `make generate-vmlinux` (bpftool, the host's BTF). `make generate-libbpf-headers` vendors the libbpf headers; `make generate-vmlinux-arm64` writes the arm64 header from the BTF of the device adb is connected to.

## TLS offsets
decerter reads the TLS secrets from library structures whose offsets change between releases. The tables are generated from the libraries' sources; nothing is run for the other architecture.

- **OpenSSL:** `make generate-openssl-offsets` (`OPENSSL_VERSIONS=all`, the default, or tags like `OPENSSL_VERSIONS="openssl-3.6.2"`) takes every final 3.x release tag of github.com/openssl/openssl, downloads each release tarball once into `~/.cache/decerter-openssl` (`OPENSSL_CACHE`), checks it against the published SHA-256, compiles `tools/offsetgen/openssl_offset.c` against the release's own `ssl/ssl_local.h` with clang for `linux-x86_64` and `linux-aarch64`, and rewrites `internal/tls/openssl/offsets_gen.go` as version ranges per architecture. arm64 needs the aarch64 glibc headers (`ARM64_SYSROOT`, default `/usr/aarch64-linux-gnu`, Debian's `libc6-dev-arm64-cross`). About 2.5 minutes with the tarballs cached. A version the table doesn't have is refused at start with the nearest known version and this command.
- **Conscrypt:** `make generate-boringssl-offsets` (`BORINGSSL_RELEASES="15 16 17"`) compiles `tools/offsetgen/boringssl_offset.cc` against the `android1X-release` branches with the NDK's clang (`ANDROID_NDK`, default the newest in `~/Android/Sdk/ndk`).
- **Flutter:** `make generate-flutter-offsets` (`FLUTTER_VERSIONS=all`, every stable tag from `FLUTTER_MIN_VERSION`, 3.24.0; or a list like `FLUTTER_VERSIONS="3.35.7 3.50.0"`) reads per release the engine, its `DEPS`, the Dart version and the BoringSSL revision the engine pins, fetches each revision once into `~/.cache/decerter-boringssl` (`BORINGSSL_CACHE`), probes it for x86_64 and arm64 and rewrites `internal/tls/boringssl/flutter_offsets_gen.go`. No Flutter SDK is needed; about a minute with the revisions cached.
- **Chrome, WebView, Cronet:** `make generate-chrome-offsets` (`CHROME_VERSIONS="branches"` plus the listed builds, see the Makefile; `CHROME_MIN_MILESTONE`, 124) takes the release tags of chromium/src with `git ls-remote`, picks per milestone its release branch, reads `boringssl_revision` from the `DEPS` of the branch's tags through gitiles (bisecting where it changes), probes each revision like the Flutter generator and rewrites `internal/tls/boringssl/chromium_offsets_gen.go`. A version that is not on a release branch is added by name, `CHROME_VERSIONS="branches 161.0.8200.3"`, or with its chromium/src commit, `CHROME_VERSIONS="branches 160.0.8161.0@20d5177b437511f9931e078aa4d3ed2ed43cc1c0"`. DEPS files are cached in `~/.cache/decerter-chromium/deps` (`CHROMIUM_CACHE`); about 2.5 minutes cold, 20 s cached.

Then rebuild and run `make test-e2e` (OpenSSL) or `make test-e2e-android` (the others).
