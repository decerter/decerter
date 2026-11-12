# SPDX-License-Identifier: AGPL-3.0-only

.DEFAULT_GOAL := help

# Build Default Variables
VMLINUX ?= ./bpf/vmlinux.h
BPF_CFLAGS ?=
CLANG ?= clang-21
LLVM_STRIP ?= llvm-strip-21
LIBBPF_VERSION ?= v1.8.0
LIBBPF_HEADERS ?= bpf_helpers.h bpf_helper_defs.h bpf_endian.h bpf_tracing.h bpf_core_read.h
OPENSSL_VERSIONS ?= openssl-3.6.2

# bpf2go reads the compiler from the environment, the go:generate lines stay compiler independent
export BPF2GO_CC := $(CLANG)
export BPF2GO_STRIP := $(LLVM_STRIP)

### General ###
.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "}; /[[:space:]]##[[:space:]]/ {printf "    \033[34m%-28s\033[0m %s\n", $$1, $$2}; /### [a-zA-Z ]+ ###/ {printf "\033[1m%s\033[0m\n", substr($$1, 5, length($$1) - 8)}' $(MAKEFILE_LIST)

### Generate Files ###
.PHONY: generate-vmlinux
generate-vmlinux: ## Generate vmlinux.h, location can be changed with VMLINUX variable, default is ./bpf/vmlinux.h
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX}

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

.PHONY: generate
generate: generate-vmlinux generate-bpf-objects ## Generate vmlinux.h and bpf object files

### Build ###
.PHONY: build
build: ## Run static go build from the committed bpf objects
	CGO_ENABLED=0 go build -trimpath -tags netgo,osusergo -ldflags="-s -w -buildid=" -o decerter .

.PHONY: build-arm64
build-arm64: ## Run static go build for linux/arm64 from the committed bpf objects, the binary for Android devices is decerter-arm64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -tags netgo,osusergo -ldflags="-s -w -buildid=" -o decerter-arm64 .

.PHONY: run
run: build ## Run decerter with sudo
	sudo ./decerter $(ARGS)
