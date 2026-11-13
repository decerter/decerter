# SPDX-License-Identifier: AGPL-3.0-only

.DEFAULT_GOAL := help

# Build Default Variables
VERSION ?= development
GITCOMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILDDATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
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
OPENSSL_VERSIONS ?= openssl-3.6.2
BORINGSSL_RELEASES ?= 15 16 17
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

.PHONY: generate-openssl-offsets
generate-openssl-offsets: ## Generate OpenSSL struct offsets for OPENSSL_VERSIONS (default is openssl-3.6.2)
	tmp="$$(mktemp)"; \
	./tools/offsetgen/offsetgen.sh $(OPENSSL_VERSIONS) > "$$tmp" && gofmt -w "$$tmp" && mv "$$tmp" internal/tls/openssl/offsets_gen.go || { rm -f "$$tmp"; exit 1; }

# the offsets are read from the probe's assembly, nothing is run, so both architectures come from one host
.PHONY: generate-boringssl-offsets
generate-boringssl-offsets: ## Generate BoringSSL offsets of Conscrypt for the Android BORINGSSL_RELEASES (default is 15 16 17) with the NDK in ANDROID_NDK (default is the newest in ~/Android/Sdk/ndk)
	tmp="$$(mktemp)"; \
	ANDROID_NDK="$(ANDROID_NDK)" ./tools/offsetgen/boringssl.sh $(BORINGSSL_RELEASES) > "$$tmp" && gofmt -w "$$tmp" && mv "$$tmp" internal/tls/boringssl/offsets_gen.go || { rm -f "$$tmp"; exit 1; }

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

# decerter runs on the emulator, never on the host: the tests use a running x86_64 emulator or boot the AVD decerter-a15 (system-images;android-35;google_apis;x86_64,
# google_apis because its adbd may run as root) from ANDROID_SDK_ROOT or ~/Android/Sdk, and stop it again; javac (a JDK) and the SDK's d8 build the Conscrypt client, tshark reads the live capture
.PHONY: test-e2e-android
test-e2e-android: ## Run the Android e2e tests on the emulator with sudo, needs the Android SDK with the emulator and the AVD decerter-a15, a JDK and tshark
	sudo go test -tags=e2e_android -count=1 ./test/android/

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

.PHONY: build-debug
build-debug: ## Run go build with race condition detection (dynamic, never shipped)
	CGO_ENABLED=1 go build -race -o decerter-debug ./cmd/decerter

.PHONY: run
run: build ## Run decerter with sudo, the command and its flags go in ARGS, for example ARGS="run --uid 1001 --decrypt"
	sudo ./decerter $(ARGS)
