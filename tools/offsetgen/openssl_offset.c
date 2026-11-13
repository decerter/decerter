// SPDX-License-Identifier: AGPL-3.0-only

// Compiled (never linked or run) inside an OpenSSL 3.x source tree after
// `make build_generated`, once per architecture with clang --target, so the
// layout is the one that release has on that architecture. offsetgen.sh reads
// the constants from the assembly. Offsets come from the release's own internal
// headers so they match exactly how that version is laid out.
// From OpenSSL 3.2 on the TLS state lives in SSL_CONNECTION and the SSL *
// handed out by the public API points at its embedded ssl_st base, whose type
// field tells a TLS connection from the QUIC objects; ssl_connection is the
// delta to subtract from that SSL * to reach the SSL_CONNECTION. Up to 3.1 the
// SSL * is the connection itself and has no type field (there is no QUIC).
#include <stddef.h>

#include "ssl/ssl_local.h"

#if (OPENSSL_VERSION_MAJOR == 3) && (OPENSSL_VERSION_MINOR < 2)
typedef SSL SSL_CONNECTION;

const unsigned long decerter_offset_has_type = 0;
const unsigned long decerter_offset_type = 0;
const unsigned long decerter_offset_ssl_connection = 0;
#else
const unsigned long decerter_offset_has_type = 1;
const unsigned long decerter_offset_type = offsetof(SSL_CONNECTION, ssl.type);
const unsigned long decerter_offset_ssl_connection = offsetof(SSL_CONNECTION, ssl);
#endif

// the release the headers belong to, offsetgen.sh checks it against the tarball
const unsigned long decerter_offset_version_major = OPENSSL_VERSION_MAJOR;
const unsigned long decerter_offset_version_minor = OPENSSL_VERSION_MINOR;
const unsigned long decerter_offset_version_patch = OPENSSL_VERSION_PATCH;

const unsigned long decerter_offset_version = offsetof(SSL_CONNECTION, version);
const unsigned long decerter_offset_client_random = offsetof(SSL_CONNECTION, s3.client_random);
const unsigned long decerter_offset_session = offsetof(SSL_CONNECTION, session);
const unsigned long decerter_offset_master_key = offsetof(SSL_SESSION, master_key);
const unsigned long decerter_offset_master_key_length = offsetof(SSL_SESSION, master_key_length);
const unsigned long decerter_offset_client_app_traffic_secret = offsetof(SSL_CONNECTION, client_app_traffic_secret);
const unsigned long decerter_offset_server_app_traffic_secret = offsetof(SSL_CONNECTION, server_app_traffic_secret);
const unsigned long decerter_offset_handshake_secret = offsetof(SSL_CONNECTION, handshake_secret);
const unsigned long decerter_offset_handshake_traffic_hash = offsetof(SSL_CONNECTION, handshake_traffic_hash);
const unsigned long decerter_offset_session_cipher = offsetof(SSL_SESSION, cipher);
const unsigned long decerter_offset_cipher_id = offsetof(SSL_CIPHER, id);
