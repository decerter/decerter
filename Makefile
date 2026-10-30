# SPDX-License-Identifier: AGPL-3.0-only

.DEFAULT_GOAL := help

# Build Default Variables
LIBBPF_VERSION ?= v1.8.0
LIBBPF_HEADERS ?= bpf_helpers.h bpf_helper_defs.h bpf_endian.h bpf_tracing.h bpf_core_read.h

### General ###
.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "}; /[[:space:]]##[[:space:]]/ {printf "    \033[34m%-28s\033[0m %s\n", $$1, $$2}; /### [a-zA-Z ]+ ###/ {printf "\033[1m%s\033[0m\n", substr($$1, 5, length($$1) - 8)}' $(MAKEFILE_LIST)

### Generate Files ###
.PHONY: generate-libbpf-headers
generate-libbpf-headers: ## Vendor libbpf headers of LIBBPF_VERSION into bpf/include/bpf
	rm -rf bpf/include/bpf && mkdir -p bpf/include/bpf
	curl -sSfL https://github.com/libbpf/libbpf/archive/refs/tags/$(LIBBPF_VERSION).tar.gz | tar -xz -C bpf/include/bpf --strip-components=2 $(addprefix libbpf-$(LIBBPF_VERSION:v%=%)/src/,$(LIBBPF_HEADERS))
