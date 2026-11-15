# Building and testing
Building needs Go 1.26 or newer; `go.mod` names `toolchain go1.26.2`, so an older Go 1.26 downloads go1.26.2 (`GOTOOLCHAIN=auto`, the default) and a release built anywhere has the same checksums. The BPF objects and the offset tables are committed, so a build needs no clang and no kernel headers.

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
make coverage        # test coverage of the unit tests, COVERAGE_E2E=1 adds the e2e tests, COVERAGE_ANDROID=1 the Android e2e tests
```

- `make test-unit` includes tests that keep the docs honest: the `decerter --help` dump in the README, the field table of [filter.md](filter.md) and a check that every flag of every command is named in the README or `docs/`.
- `make test-e2e` runs decerter in-process with sudo and needs the local users `test` (selected) and `nobody` (not selected); it refuses to run when a test user has UID 0 or 1000. curl runs as those users, the Go test servers as root. The distribution OpenSSL cases need docker, a C compiler and the images `ubuntu:24.04`, `debian:13`, `fedora` (OpenSSL 4; the test builds `decerter-e2e/fedora-openssl3` from it for OpenSSL 3), `almalinux:10`, `kalilinux/kali-rolling`, `parrotsec/core` and `blackarchlinux/blackarch` (amd64 only), and skip an image that is missing. Each image's default OpenSSL is checked three ways: its libraries copied to the host with `--libssl`, a client inside the container with `--libssl /proc/<pid>/root/…`, and the same client without `--libssl`, found through the maps of a selected process. The route family case makes a network namespace with `ip netns` and enters it with `nsenter` and `setpriv` (util-linux), the socket mark case reads the upstream socket with `ss`, and the QUIC key log case builds `test/e2e/assets/quic_server.c` against the host's `libssl.so.3` and talks to it with `openssl s_client -quic`; it skips without a C compiler, OpenSSL 3.5 or newer (the QUIC server API) or an `openssl` with `-quic`.
- `make test-e2e-android` runs decerter only on the emulator, never on the host: a running x86_64 or arm64 emulator, or `decerter android setup` boots the AVD `decerter-a15` (`system-images;android-35;google_apis;x86_64`, `arm64-v8a` on an Apple Silicon Mac) from `ANDROID_SDK_ROOT` or `~/Android/Sdk` as the cold setup case and stops it again. It needs a JDK and the SDK's d8 for the Conscrypt test client and tshark. The Flutter cases build the app of `test/android/flutter` with each Flutter SDK in `DECERTER_E2E_FLUTTER` (colon separated, default every `~/.cache/decerter-flutter/<version>/flutter`) as the user who ran sudo, cached in `~/.cache/decerter-flutter/e2e`, and are skipped without an SDK. The Chrome cases use the image's Chrome and YouTube; the ChromePublic cases the `ChromePublic.apk` of a Chromium snapshot for the emulator's ABI in `DECERTER_E2E_CHROMIUM` (default the newest `~/.cache/decerter-chromium/snapshot-AndroidDesktop_x64-*/chrome-android-desktop/apks/ChromePublic.apk`, `snapshot-Android_Arm64-*/chrome-android/apks/ChromePublic.apk` on an arm64 host) and are skipped without it. The tests build decerter for the host and decerter and the test client for both emulator ABIs, and push the ones of the emulator's `ro.product.cpu.abi`. When the emulator drops off adb (`device offline`), every later case skips and the run fails with one message saying so.
- On an Apple Silicon Mac: `make build` builds a macOS decerter with only the host commands (`android setup`, `ui`, `mcp`, `help`); the Android tests run against the arm64 emulator with the Android SDK for macOS, a JDK (`JAVA_HOME`, which the tests pass on to apksigner and Gradle) and tshark; macOS's sudo drops `PATH`, `JAVA_HOME` and `ANDROID_HOME`, so the 2026-11-14 run built the test binary (`go test -c -tags e2e_android ./test/android`) and ran it with `sudo env PATH=… JAVA_HOME=… ANDROID_HOME=…`. `make test-unit` and `make test-e2e` need Linux: run them in an arm64 Linux VM (the 2026-11-14 run used Lima with the `vz` driver and Debian 13, kernel 6.12, BTF and cgroup v2).

### Coverage
`make coverage` (`tools/coverage/coverage.sh`) runs the unit tests with the race detector and `-coverpkg` over the whole module, so a test counts for every package it runs, and writes into `coverage/` (`COVERAGE_DIR`, gitignored):

```
coverage/packages.txt    statements and percentage per package: unit, e2e, android and all together
coverage/functions.txt   go tool cover -func, every function with its percentage
coverage/coverage.html   go tool cover -html, the source with the lines no test ran
coverage/unit.out        the profiles of go test, e2e.out and e2e-children.out with the e2e tests, android.out with the Android e2e tests
coverage/merged.out      the profiles together, without the code that is not hand-written
```

`COVERAGE_E2E=1 make coverage` runs the e2e tests too, with sudo as `make test-e2e` does. They run decerter in the test process, so their profile has the production packages; the cases that run the test binary as decerter (`decerter mcp`, the distribution OpenSSL cases, the capture that is stopped) write their counters into `DECERTER_E2E_COVERDIR`, which the script sets and merges. `tools/coverage/coverage.sh e2e` runs only the e2e tests and merges the profiles of an earlier run of the other suites; a profile from before a source file changed counts that file's statements twice, so run every suite again for numbers to keep.

`COVERAGE_ANDROID=1 make coverage` runs the Android e2e tests too, with sudo and the emulator as `make test-e2e-android` does. With `DECERTER_E2E_COVERDIR` set the tests build decerter with `go build -cover` for the host and the emulator: the host's decerter (`decerter android setup`, `decerter ui`) writes its counters into that directory, the ones on the emulator into `/data/local/tmp/decerter-e2e-cover`, which the tests pull and remove at the end, and the script turns both into `android.out`. A decerter that `decerter android setup` or a printed command line starts on the device has no `GOCOVERDIR`: it is not counted and prints `warning: GOCOVERDIR not set, no coverage data emitted` when it exits. A decerter that is killed instead of stopped writes no counters either.

`COVERAGE_MIN=85 make coverage` fails when the total (the last column of the `total` line, merged) is below 85 %; the `coverage` job of `ci.yml` runs the unit tests with that floor (88.8 % on 2026-11-15).

Left out of the numbers: the bpf2go output (`*_bpfel.go`, `*_bpfeb.go`), the generated offset tables (`*_gen.go`), `cmd/decerter` (its `main` only calls `cmd.Execute`) and the helpers under `test/`. The BPF C programs have no Go coverage; the e2e tests cover them, the redirect and capture paths in `test/e2e/redirect_test.go`. Without `COVERAGE_ANDROID=1` the Android e2e tests are not in the numbers, so `app/boringssl.go`, the netd hook sharing of `internal/attach` and what `internal/android` does over adb count only as far as the unit tests reach them.

## BPF objects
The BPF objects are built from the committed `bpf/vmlinux.h`, bpftool's dump of the dev box's kernel types (7.0.3), so every build sees the same kernel types; CO-RE relocates them to the running kernel when decerter loads. Regenerating them needs clang-21 and llvm-strip-21:

```sh
make generate-bpf-objects  # the bpf2go output in internal/bpf, commit it with the C change
make check-bpf-objects     # regenerates and checks that the committed output is what the sources build
```

`make check-bpf-objects` (`tools/bpfdrift/check.sh`) compares the bpf2go Go files byte for byte and the objects by content with `tools/bpfdrift`: programs with their source lines, function info and CO-RE relocations, maps, variables and the BTF types. A plain `cmp` doesn't work, because clang orders the BTF types and strings of one source differently when it builds from another path. An object that is the same by content gets its committed bytes back, so only real changes stay in the work tree. `make generate-vmlinux` (bpftool, the host's BTF) rewrites `bpf/vmlinux.h`; a new header changes the objects and is committed like a C change. `make generate-libbpf-headers` vendors the libbpf headers; `make generate-vmlinux-arm64` writes the arm64 header from the BTF of the device adb is connected to (gitignored, nothing builds from it yet).

## TLS offsets
decerter reads the TLS secrets from library structures whose offsets change between releases. The tables are generated from the libraries' sources; nothing is run for the other architecture.

- **OpenSSL:** `make generate-openssl-offsets` (`OPENSSL_VERSIONS=all`, the default, or tags like `OPENSSL_VERSIONS="openssl-3.6.2"`) takes every final 3.x and 4.x release tag of github.com/openssl/openssl, downloads each release tarball once into `~/.cache/decerter-openssl` (`OPENSSL_CACHE`), checks it against the published SHA-256, compiles `tools/offsetgen/openssl_offset.c` against the release's own `ssl/ssl_local.h` with clang for `linux-x86_64` and `linux-aarch64`, and rewrites `internal/tls/openssl/offsets_gen.go` as version ranges per architecture. OpenSSL 4 (`libssl.so.4`) kept the field names of 3.2 and later, so the one probe reads both; 4.0 has the 3.5 layout, 4.1 moved the fields from `s3` on. A new major whose fields are renamed needs its own branch in the probe. arm64 needs the aarch64 glibc headers (`ARM64_SYSROOT`, default `/usr/aarch64-linux-gnu`, Debian's `libc6-dev-arm64-cross`). About 2.5 minutes with the tarballs cached. A version the table doesn't have is named at start with the nearest known version and this command: refused for `--libssl`, and for the linker cache when no other OpenSSL is hooked, a warning otherwise.
- **Conscrypt:** `make generate-boringssl-offsets` (`BORINGSSL_RELEASES="15 16 17"`) compiles `tools/offsetgen/boringssl_offset.cc` against the `android1X-release` branches with the NDK's clang (`ANDROID_NDK`, default the newest in `~/Android/Sdk/ndk`). In all three BoringSSL modes a probe that does not compile, a probe without the offsets and a DEPS without a BoringSSL revision stop the run, and the generated file is left as it was; `tools/offsetgen/scripttest` runs the script with a fake clang.
- **Flutter:** `make generate-flutter-offsets` (`FLUTTER_VERSIONS=all`, every stable tag from `FLUTTER_MIN_VERSION`, 3.24.0; or a list like `FLUTTER_VERSIONS="3.35.7 3.50.0"`) reads per release the engine, its `DEPS`, the Dart version and the BoringSSL revision the engine pins, fetches each revision once into `~/.cache/decerter-boringssl` (`BORINGSSL_CACHE`), probes it for x86_64 and arm64 and rewrites `internal/tls/boringssl/flutter_offsets_gen.go`. No Flutter SDK is needed; about a minute with the revisions cached.
- **Chrome, WebView, Cronet:** `make generate-chrome-offsets` (`CHROME_VERSIONS="branches"`; `CHROME_MIN_MILESTONE`, 124) takes the release tags of chromium/src with `git ls-remote`, picks per milestone its release branch, reads `boringssl_revision` from the `DEPS` of the branch's tags through gitiles (bisecting where it changes), probes each revision like the Flutter generator and rewrites `internal/tls/boringssl/chromium_offsets_gen.go`: the milestone table, keyed by branch and patch ranges. Builds that are on no release branch are a list of their own, `CHROME_BUILDS` (the Cronet builds of the `decerter-a15` image and the ChromePublic snapshot of the Android e2e tests, see the Makefile), each keyed by its exact version and looked up before the milestone table: a version by name, `CHROME_BUILDS="… 161.0.8200.3"`, or with its chromium/src commit, `160.0.8161.0@20d5177b437511f9931e078aa4d3ed2ed43cc1c0`. DEPS files are cached in `~/.cache/decerter-chromium/deps` (`CHROMIUM_CACHE`); about 2.5 minutes cold, 20 s cached.

Then rebuild and run `make test-e2e` (OpenSSL) or `make test-e2e-android` (the others).

## pre-commit
`.pre-commit-config.yaml` runs, on the files of a commit: trailing whitespace, end of file, `check-yaml` and `check-merge-conflict` from pre-commit-hooks (pinned by commit), then local hooks for gofmt, `make vet`, `make lint`, `tools/licensecheck/spdx.sh` and the docs drift tests of `pkg/cmd` (`-tags unit`). The generated and vendored files (`bpf/vmlinux.h`, `bpf/include/bpf/`, the bpf2go output, the test certificates) are left out. The local hooks need Go and the pinned golangci-lint (`make install-golangci-lint`).

```sh
pipx install pre-commit      # or: uv tool install pre-commit
pre-commit install           # run the hooks on every git commit
pre-commit run --all-files   # every file of the tree, as the pre-commit workflow does
```

## CI
GitHub Actions in `.github/workflows/`. Every action is pinned to a full commit SHA with its version in a comment, every workflow starts with `permissions: {}` and gives each job only what it needs, and only `GITHUB_TOKEN` is used, no other secret. A newer push to a pull request cancels its older run. Go comes from `go.mod` through `actions/setup-go`, which takes its `toolchain go1.26.2` line, so CI builds with the same Go as the dev box (cached).

| Workflow | When | Job | Runner | What |
|---|---|---|---|---|
| `ci.yml` | pull request, push to `main` | `lint` | amd64 | `make lint` with the golangci-lint the Makefile pins (`go install`) |
| | | `unit` | amd64, arm64 | `make test-unit` |
| | | `coverage` | amd64 | `make coverage COVERAGE_MIN=85`: the unit tests' coverage, fails below 85 %; `packages.txt`, `functions.txt` and `coverage.html` are the run's artifact `coverage` (30 days) |
| | | `license` | amd64 | `make install-go-licenses`, `make license-check` |
| | | `build` | amd64, arm64 | `make build build-arm64 verify-static`, `./decerter --version` (the runner's architecture); on amd64 also `go build` and `go vet` for macOS arm64 |
| | | `bpf-drift` | amd64 | clang-21 and llvm-21 from apt.llvm.org (Ubuntu 24.04 has no clang-21; the signing key is pinned by SHA-256), `make check-bpf-objects` |
| | | `e2e-linux` | amd64, arm64 | the e2e tests as root, see below |
| `pre-commit.yml` | pull request | `pre-commit` | amd64 | `pre-commit run --all-files` |
| `android.yml` | Mondays 03:17 UTC, by hand | `e2e-android` | x86_64, arm64 | the Android e2e tests on an emulator of the runner, see below |
| `release.yml` | push of a `v*` tag | `release` | amd64 | `make release`, provenance, the GitHub release, see [Releasing](#releasing) |

The amd64 jobs run on `ubuntu-24.04`, the arm64 ones on `ubuntu-24.04-arm`. The arm64 runners are free for public repositories; a private repository needs a GitHub Team or Enterprise plan for them, otherwise the arm64 jobs wait for a runner that never comes.

- **e2e-linux** does what `make test-e2e` needs: it fails with a clear message when the kernel is older than 6.6, has no `/sys/kernel/btf/vmlinux` or `/sys/fs/cgroup` isn't cgroup v2; installs tshark, tcpdump and socat (curl with HTTP/2, wget, openssl, a C compiler and docker are on the runner image); creates the user `test` with the first free UID from 1001 on, because the runner user usually has 1001 already (the tests look `test` and `nobody` up by name and refuse UID 0 and 1000); pulls `ubuntu:24.04`, `debian:13`, `fedora`, `almalinux:10`, `kalilinux/kali-rolling`, `parrotsec/core` and, on amd64 only, `blackarchlinux/blackarch` (published for amd64 only, its case skips on arm64 with that reason) in the runner's architecture for the distro OpenSSL cases, which skip an image that is missing; then builds the test binary as the runner user and runs it with sudo in `test/e2e`, which is what `sudo go test` does without root writing to the runner's Go caches.
- **e2e-android** (x86_64) gives the runner user `/dev/kvm` with a udev rule and fails without it, installs the SDK into `~/Android/Sdk` (cmdline-tools pinned by SHA-256; platform-tools, emulator, build-tools 35.0.0, NDK 30.0.16248370 and `system-images;android-35;google_apis;x86_64`), creates the AVD `decerter-a15`, clones Flutter 3.35.7 for the Flutter cases and downloads the ChromePublic of Chromium snapshot 1744338 (pinned by SHA-256) for the ChromePublic cases, both cached, and runs the tests with sudo; `decerter android setup` boots the AVD as the cold setup case. The arm64 job (`system-images;android-35;google_apis;arm64-v8a`) first checks for `/dev/kvm` and for an emulator build for Linux arm64 hosts, which the SDK doesn't have as of 2026-11 (only Linux x64, macOS and Windows), and skips with a notice when either is missing, so the job doesn't fail the workflow; the Android tests themselves pass on an arm64 emulator on an Apple Silicon Mac.

Checked locally: `actionlint` and `zizmor` on every workflow, and `act` (nektos/act with the `catthehacker/ubuntu:act-24.04` image) for the `lint`, `unit`, `license`, `build` and `bpf-drift` jobs of `ci.yml`:

```sh
actionlint
uvx zizmor --offline .github/workflows/
act push -W .github/workflows/ci.yml -j bpf-drift -P ubuntu-24.04=catthehacker/ubuntu:act-24.04
act push -W .github/workflows/ci.yml -j unit --matrix runner:ubuntu-24.04 -P ubuntu-24.04=catthehacker/ubuntu:act-24.04
```

act can't run `e2e-linux` (it needs root on a real kernel, act's job runs in a container) or `e2e-android` (KVM), and on an x86_64 host none of the arm64 jobs.

## Releasing
A release is a pushed tag. On a clean `main` that CI passed:

```sh
./tools/release/version.sh            # v0.0.0-<n>-g<hash> before the first tag
git tag -a v0.1.0 -m "decerter v0.1.0"    # the message becomes the release notes
git push origin v0.1.0
```

`release.yml` checks out the full history, refuses to release when the tag isn't what `tools/release/version.sh` prints for its commit (such as a second `v*` tag on the same commit that `git describe` prefers), runs `make release`, attests the build provenance of both tarballs with `actions/attest-build-provenance` and creates the GitHub release with `gh release create`: both tarballs and `SHA256SUMS`, titled `decerter <tag>`, the notes from the tag message without its signature, or generated by GitHub for a lightweight tag or an empty message. A tag with a `-` (`v0.2.0-rc1`) becomes a pre-release. It needs `contents: write`, `id-token: write` and `attestations: write`, nothing else. The tarballs are reproducible for one commit and one Go toolchain; CI builds with the Go of `go.mod`, so a local `make release` with another Go patch release gives other checksums. Check a downloaded tarball with:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify decerter_v0.1.0_linux_amd64.tar.gz --repo decerter/decerter
```

## GitHub settings
These are settings of the repository on GitHub, nothing in the tree sets them:

- **Rulesets:** a ruleset for `main` that requires the checks of `ci.yml` and `pre-commit.yml` (`lint`, `unit (ubuntu-24.04)`, `license`, `build (ubuntu-24.04)`, `bpf-drift`, `e2e-linux (ubuntu-24.04)`, `pre-commit`, plus `unit (ubuntu-24.04-arm)` and `build (ubuntu-24.04-arm)` once the arm64 runners are available to the repository) and blocks force pushes, and a tag ruleset for `v*` so only you can create release tags.
- **Actions:** Settings → Actions → General: workflow permissions read-only by default (the workflows ask for what they need), and the policy that actions must be pinned to a full commit SHA.
