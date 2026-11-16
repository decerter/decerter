# SPDX-License-Identifier: AGPL-3.0-only

# The OpenSSL 4.1.0 image of the distro e2e tests (openssl_test.go): libssl.so.4 and libcrypto.so.4 of the upstream
# release tarball, checked against its published SHA-256, on Debian 13 in /usr/local/lib. Only the libraries are
# built and kept, the test client links them. The tests build it as decerter-e2e/openssl-4.1.0:<first 12 hex digits of
# the SHA-256 of this file> when it is missing, CI keeps it in its cache under the same name.
FROM debian:13 AS build
ARG OPENSSL_VERSION=4.1.0
ARG OPENSSL_SHA256=50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd
RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends ca-certificates curl gcc libc6-dev make perl \
	&& rm -rf /var/lib/apt/lists/*
RUN curl -sSfL --retry 3 -o /tmp/openssl.tar.gz "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
	&& echo "${OPENSSL_SHA256}  /tmp/openssl.tar.gz" | sha256sum --check --strict \
	&& mkdir /tmp/openssl \
	&& tar -xzf /tmp/openssl.tar.gz -C /tmp/openssl --strip-components=1 \
	&& cd /tmp/openssl \
	&& ./Configure --prefix=/usr/local --libdir=lib --openssldir=/usr/local/ssl shared no-tests no-docs \
	&& make -j"$(nproc)" build_libs

FROM debian:13
COPY --from=build /tmp/openssl/libssl.so.4 /tmp/openssl/libcrypto.so.4 /usr/local/lib/
RUN ldconfig
