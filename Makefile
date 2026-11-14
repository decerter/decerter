# SPDX-License-Identifier: AGPL-3.0-only

.DEFAULT_GOAL := help

# Build Default Variables
# the tag git describe finds, or v0.0.0-<commits since the root commit>-g<hash> before the first tag, -dirty with uncommitted changes (tools/release/version.sh)
VERSION ?= $(shell ./tools/release/version.sh)
GITCOMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null)
# the commit time, not the time of the build, so one commit builds the same binary
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null)
BUILDDATE ?= $(shell TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
# make release refuses a dirty work tree unless this is 1
ALLOW_DIRTY ?= 0
LDFLAGS ?= -s -w -buildid= -X github.com/decerter/decerter/api.buildVersion=$(VERSION) -X github.com/decerter/decerter/api.gitCommit=$(GITCOMMIT) -X github.com/decerter/decerter/api.buildDate=$(BUILDDATE)
VMLINUX ?= ./bpf/vmlinux.h
VMLINUX_ARM64 ?= ./bpf/vmlinux-arm64.h
BPFTOOL ?= bpftool
ADB ?= adb
BPF_CFLAGS ?=
CLANG ?= clang-21
LLVM_STRIP ?= llvm-strip-21
LIBBPF_VERSION ?= v1.8.0
LIBBPF_HEADERS ?= bpf_helpers.h bpf_helper_defs.h bpf_endian.h bpf_tracing.h bpf_core_read.h
OPENSSL_VERSIONS ?= all
# empty: the script's defaults (~/.cache/decerter-openssl, /usr/aarch64-linux-gnu, the host headers for amd64)
OPENSSL_CACHE ?=
ARM64_SYSROOT ?=
AMD64_SYSROOT ?=
BORINGSSL_RELEASES ?= 15 16 17
# Flutter stable releases whose engine's BoringSSL gets offsets: all is every x.y.z tag from FLUTTER_MIN_VERSION on
FLUTTER_VERSIONS ?= all
FLUTTER_MIN_VERSION ?= 3.24.0
# the milestone table of the Chromium offsets: branches is the release branch of every milestone from CHROME_MIN_MILESTONE on with all its tags
CHROME_VERSIONS ?= branches
# Chromium builds of no release branch, kept apart from the milestone table, one version each: the Cronet builds of the decerter-a15 image (GoogleTTS,
# YouTube, Play services, the Google app) are trunk builds of their own, and 160.0.8161.0@20d5177… is the ChromePublic snapshot the Android e2e tests install
CHROME_BUILDS ?= 122.0.6238.4 125.0.6383.0 126.0.6452.4 127.0.6493.0 160.0.8161.0@20d5177b437511f9931e078aa4d3ed2ed43cc1c0
CHROME_MIN_MILESTONE ?= 124
# empty: the script's default ~/.cache/decerter-boringssl, one shallow checkout per BoringSSL revision
BORINGSSL_CACHE ?=
# empty: the script's default ~/.cache/decerter-chromium/deps, the boringssl_revision of each Chromium tag read
CHROMIUM_CACHE ?=
# the Flutter SDKs the Android e2e tests build their Flutter app with, colon separated
empty :=
space := $(empty) $(empty)
DECERTER_E2E_FLUTTER ?= $(subst $(space),:,$(wildcard $(HOME)/.cache/decerter-flutter/*/flutter))
# the ChromePublic apk of a Chromium snapshot for the ChromePublic cases, default the newest one unpacked in ~/.cache/decerter-chromium for the emulator of
# this host: the x86_64 one (AndroidDesktop_x64) on an x86_64 host, the arm64 one (Android_Arm64) on an arm64 host such as an Apple Silicon Mac
CHROMIUM_SNAPSHOTS := $(if $(filter arm64 aarch64,$(shell uname -m)),snapshot-Android_Arm64-*/chrome-android,snapshot-AndroidDesktop_x64-*/chrome-android-desktop)
DECERTER_E2E_CHROMIUM ?= $(lastword $(sort $(wildcard $(HOME)/.cache/decerter-chromium/$(CHROMIUM_SNAPSHOTS)/apks/ChromePublic.apk)))
# the newest NDK of the SDK, the BoringSSL probe is compiled for x86_64 and aarch64 Android with its clang
ANDROID_NDK ?= $(lastword $(sort $(wildcard $(HOME)/Android/Sdk/ndk/*)))
# licenses a dependency may have, each of them can be combined with AGPL-3.0-only; any other one needs a look first
ALLOWED_LICENSES ?= Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MIT,MPL-2.0

# Tools Default Version
GOLANGCI_LINT_VERSION ?= v2.12.2
GO_LICENSES_VERSION ?= v2.0.1

# bpf2go reads the compiler from the environment, the go:generate lines stay compiler independent
export BPF2GO_CC := $(CLANG)
export BPF2GO_STRIP := $(LLVM_STRIP)

### General ###
.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "}; /[[:space:]]##[[:space:]]/ {printf "    \033[34m%-28s\033[0m %s\n", $$1, $$2}; /### [a-zA-Z ]+ ###/ {printf "\033[1m%s\033[0m\n", substr($$1, 5, length($$1) - 8)}' $(MAKEFILE_LIST)

### Tools ###
.PHONY: install-golangci-lint
install-golangci-lint: ## Install golangci-lint binary
	curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b $$(go env GOPATH)/bin $(GOLANGCI_LINT_VERSION)

.PHONY: install-go-licenses
install-go-licenses: ## Install go-licenses
	go install github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)

### Generate Files ###
.PHONY: generate-vmlinux
generate-vmlinux: ## Generate vmlinux.h, location can be changed with VMLINUX variable, default is ./bpf/vmlinux.h
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX}

# the BTF is read as the adb shell user first (adb root, or a device where shell may read it), then through su -c (Magisk, KernelSU)
# bpftool checks what exec-out gave, a cat that failed leaves an error message instead of BTF
.PHONY: generate-vmlinux-arm64
generate-vmlinux-arm64: ## Generate vmlinux.h for the arm64 uprobe build from the BTF of the device adb is connected to, location can be changed with VMLINUX_ARM64 variable, default is ./bpf/vmlinux-arm64.h
	@arch="$$($(ADB) shell uname -m | tr -d '\r')"; \
	[ "$$arch" = aarch64 ] || echo "warning: the device is $$arch, not aarch64, the header is not for arm64" >&2; \
	{ $(ADB) exec-out cat /sys/kernel/btf/vmlinux > ${VMLINUX_ARM64}.btf && $(BPFTOOL) btf dump file ${VMLINUX_ARM64}.btf format c > ${VMLINUX_ARM64}.tmp 2>/dev/null; } || \
	{ $(ADB) exec-out su -c 'cat /sys/kernel/btf/vmlinux' > ${VMLINUX_ARM64}.btf && $(BPFTOOL) btf dump file ${VMLINUX_ARM64}.btf format c > ${VMLINUX_ARM64}.tmp; } && \
	mv ${VMLINUX_ARM64}.tmp ${VMLINUX_ARM64} && echo "wrote ${VMLINUX_ARM64} from the BTF of $$($(ADB) shell uname -r | tr -d '\r') $$arch"; \
	status=$$?; rm -f ${VMLINUX_ARM64}.btf ${VMLINUX_ARM64}.tmp; exit $$status

.PHONY: generate-libbpf-headers
generate-libbpf-headers: ## Vendor libbpf headers of LIBBPF_VERSION into bpf/include/bpf
	rm -rf bpf/include/bpf && mkdir -p bpf/include/bpf
	curl -sSfL https://github.com/libbpf/libbpf/archive/refs/tags/$(LIBBPF_VERSION).tar.gz | tar -xz -C bpf/include/bpf --strip-components=2 $(addprefix libbpf-$(LIBBPF_VERSION:v%=%)/src/,$(LIBBPF_HEADERS))

.PHONY: generate-bpf-redirect-objects
generate-bpf-redirect-objects: ## Generate bpf redirect object files
	BPF_CFLAGS="$(BPF_CFLAGS)" go generate ./internal/bpf/redirect

.PHONY: generate-bpf-secrets-objects
generate-bpf-secrets-objects: ## Generate bpf secrets object files
	BPF_CFLAGS="$(BPF_CFLAGS)" go generate ./internal/bpf/secrets

.PHONY: generate-bpf-capture-objects
generate-bpf-capture-objects: ## Generate bpf capture object files
	BPF_CFLAGS="$(BPF_CFLAGS)" go generate ./internal/bpf/capture

.PHONY: generate-bpf-objects
generate-bpf-objects: generate-bpf-redirect-objects generate-bpf-secrets-objects generate-bpf-capture-objects ## Generate all bpf object files

# clang orders the BTF of one source differently per build path, so the objects are compared by content (tools/bpfdrift)
.PHONY: check-bpf-objects
check-bpf-objects: ## Check that the committed bpf2go output is what generate-bpf-objects builds from the committed sources and bpf/vmlinux.h: the Go files byte for byte, the objects by content
	./tools/bpfdrift/check.sh

.PHONY: generate-openssl-offsets
generate-openssl-offsets: ## Generate OpenSSL struct offsets of amd64 and arm64 for OPENSSL_VERSIONS (default is all, every 3.x and 4.x release, or tags like openssl-3.6.2), tarballs are cached in OPENSSL_CACHE (default is ~/.cache/decerter-openssl), arm64 needs the aarch64 glibc headers in ARM64_SYSROOT (default is /usr/aarch64-linux-gnu)
	tmp="$$(mktemp)"; \
	OPENSSL_CACHE="$(OPENSSL_CACHE)" ARM64_SYSROOT="$(ARM64_SYSROOT)" AMD64_SYSROOT="$(AMD64_SYSROOT)" CLANG="$(CLANG)" ./tools/offsetgen/offsetgen.sh $(OPENSSL_VERSIONS) > "$$tmp" && gofmt -w "$$tmp" && mv "$$tmp" internal/tls/openssl/offsets_gen.go || { rm -f "$$tmp"; exit 1; }

# the offsets are read from the probe's assembly, nothing is run, so both architectures come from one host
.PHONY: generate-boringssl-offsets
generate-boringssl-offsets: ## Generate BoringSSL offsets of Conscrypt for the Android BORINGSSL_RELEASES (default is 15 16 17) with the NDK in ANDROID_NDK (default is the newest in ~/Android/Sdk/ndk)
	tmp="$$(mktemp)"; \
	ANDROID_NDK="$(ANDROID_NDK)" ./tools/offsetgen/boringssl.sh conscrypt $(BORINGSSL_RELEASES) > "$$tmp" && gofmt -w "$$tmp" && mv "$$tmp" internal/tls/boringssl/offsets_gen.go || { rm -f "$$tmp"; exit 1; }

# no signature is generated: decerter finds ssl_log_secret in a stripped libflutter.so through the call sites of its key log labels, the same way for every engine
.PHONY: generate-flutter-offsets
generate-flutter-offsets: ## Generate BoringSSL offsets of the Flutter engine (dart:io's TLS) for FLUTTER_VERSIONS (default is all, every stable release from FLUTTER_MIN_VERSION, default 3.24.0, or releases like 3.35.7), keyed by the engine's Dart version, with the NDK in ANDROID_NDK; BoringSSL checkouts are cached in BORINGSSL_CACHE (default is ~/.cache/decerter-boringssl)
	tmp="$$(mktemp)"; \
	ANDROID_NDK="$(ANDROID_NDK)" FLUTTER_MIN_VERSION="$(FLUTTER_MIN_VERSION)" BORINGSSL_CACHE="$(BORINGSSL_CACHE)" ./tools/offsetgen/boringssl.sh flutter $(FLUTTER_VERSIONS) > "$$tmp" && gofmt -w "$$tmp" && mv "$$tmp" internal/tls/boringssl/flutter_offsets_gen.go || { rm -f "$$tmp"; exit 1; }

# the same finder for Chrome, WebView and Cronet; their BoringSSL revision comes from chromium/src's DEPS through gitiles, no Chromium checkout
.PHONY: generate-chrome-offsets
generate-chrome-offsets: ## Generate BoringSSL offsets of Chrome, WebView and Cronet for CHROME_VERSIONS (default is branches, every milestone's release branch from CHROME_MIN_MILESTONE, default 124, keyed by branch and patch) and the builds of no release branch in CHROME_BUILDS (default is the image's Cronet and the e2e snapshot; versions like 161.0.8200.3, version@commit for a snapshot), kept apart and keyed by their version, with the NDK in ANDROID_NDK; DEPS answers are cached in CHROMIUM_CACHE (default is ~/.cache/decerter-chromium/deps), BoringSSL checkouts in BORINGSSL_CACHE
	tmp="$$(mktemp)"; \
	ANDROID_NDK="$(ANDROID_NDK)" CHROME_MIN_MILESTONE="$(CHROME_MIN_MILESTONE)" BORINGSSL_CACHE="$(BORINGSSL_CACHE)" CHROMIUM_CACHE="$(CHROMIUM_CACHE)" ./tools/offsetgen/boringssl.sh chrome $(CHROME_VERSIONS) $(CHROME_BUILDS) > "$$tmp" && gofmt -w "$$tmp" && mv "$$tmp" internal/tls/boringssl/chromium_offsets_gen.go || { rm -f "$$tmp"; exit 1; }

.PHONY: generate
generate: generate-vmlinux generate-bpf-objects ## Generate vmlinux.h and bpf object files

### Static Analysis ###
.PHONY: fix
fix: ## Run go fix modernizers
	go fix -tags=unit,e2e,e2e_android ./...

.PHONY: vet
vet: ## Run go vet
	go vet -tags=unit,e2e,e2e_android ./...

.PHONY: lint
lint: ## Run golangci-lint
	$$(go env GOPATH)/bin/golangci-lint run --build-tags unit,e2e,e2e_android ./...

# the dependencies of both architectures; test-only dependencies are not shipped and not checked
.PHONY: license-check
license-check: ## Check that the dependencies have AGPL-compatible licenses (ALLOWED_LICENSES) and every source file has its SPDX line
	for arch in amd64 arm64; do \
		GOOS=linux GOARCH=$$arch $$(go env GOPATH)/bin/go-licenses check ./... --ignore github.com/decerter/decerter --allowed_licenses=$(ALLOWED_LICENSES) || exit 1; \
	done
	./tools/licensecheck/spdx.sh

.PHONY: license-report
license-report: ## List the dependencies with their licenses
	$$(go env GOPATH)/bin/go-licenses report ./... --ignore github.com/decerter/decerter

### Test ###
.PHONY: test-unit
test-unit: ## Run unit tests with the race detector
	CGO_ENABLED=1 go test -race -count=1 -tags=unit ./...

# root loads the bpf programs; curl runs as the local user test, which decerter selects, and as nobody, which it doesn't
.PHONY: test-e2e
test-e2e: ## Run the e2e tests with sudo, needs root and the local users test and nobody
	sudo go test -tags=e2e -count=1 ./test/e2e/

# decerter runs on the emulator, never on the host: the tests use a running x86_64 or arm64 emulator, or decerter android setup boots the AVD decerter-a15 (system-images;android-35;google_apis;x86_64,
# arm64-v8a on an Apple Silicon Mac, google_apis because its adbd may run as root) from ANDROID_SDK_ROOT or ~/Android/Sdk as the cold setup case, and they stop it again; the tests build
# decerter for the host (Linux or macOS, it runs setup and ui) and decerter and the client for the emulator's ABI; javac (a JDK) and the SDK's d8 build the Conscrypt client, tshark reads the live capture
# the Flutter test app is built as your user with each SDK of decerter_E2E_FLUTTER (colon separated), cached in ~/.cache/decerter-flutter/e2e; the first build of an SDK takes minutes
.PHONY: test-e2e-android
test-e2e-android: ## Run the Android e2e tests on the emulator with sudo, needs the Android SDK with the emulator and the AVD decerter-a15, a JDK and tshark; the Flutter cases need DECERTER_E2E_FLUTTER (default is every ~/.cache/decerter-flutter/*/flutter), the ChromePublic cases DECERTER_E2E_CHROMIUM
	sudo DECERTER_E2E_FLUTTER="$(DECERTER_E2E_FLUTTER)" DECERTER_E2E_CHROMIUM="$(DECERTER_E2E_CHROMIUM)" go test -tags=e2e_android -count=1 -timeout 60m ./test/android/

### Build ###
.PHONY: build
build: ## Run static go build from the committed bpf objects
	CGO_ENABLED=0 go build -trimpath -tags netgo,osusergo -ldflags="$(LDFLAGS)" -o decerter ./cmd/decerter

.PHONY: build-arm64
build-arm64: ## Run static go build for linux/arm64 from the committed bpf objects, the binary for Android devices is decerter-arm64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -tags netgo,osusergo -ldflags="$(LDFLAGS)" -o decerter-arm64 ./cmd/decerter

.PHONY: verify-static
verify-static: build build-arm64 ## Check that both binaries are statically linked
	file decerter | grep -q 'statically linked'
	file decerter-arm64 | grep -q 'statically linked'

# one tarball per architecture with the binary, the licenses, the third-party notices of go-licenses and the docs, see tools/release/release.sh
.PHONY: release
release: ## Build the static linux/amd64 and linux/arm64 release tarballs and their SHA256SUMS into dist/, versioned by git describe; refused on a dirty work tree unless ALLOW_DIRTY=1, nothing is tagged or published
	VERSION="$(VERSION)" LDFLAGS="$(LDFLAGS)" SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)" ALLOW_DIRTY="$(ALLOW_DIRTY)" GO_LICENSES="$$(go env GOPATH)/bin/go-licenses" DIST=dist ./tools/release/release.sh

.PHONY: build-debug
build-debug: ## Run go build with race condition detection (dynamic, never shipped)
	CGO_ENABLED=1 go build -race -o decerter-debug ./cmd/decerter

.PHONY: run
run: build ## Run decerter with sudo, the command and its flags go in ARGS, for example ARGS="run --uid 1001 --decrypt"
	sudo ./decerter $(ARGS)
