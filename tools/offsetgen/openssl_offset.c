// SPDX-License-Identifier: AGPL-3.0-only

// Compiled inside an OpenSSL source tree after `make build_generated`, prints one
// Go map entry for internal/tls/openssl/offsets_gen.go. Offsets come from the
// release's own internal headers so they match exactly how that version is laid
// out. For OpenSSL >= 3.2 the TLS state lives in SSL_CONNECTION and the SSL *
// handed out by the public API points at its embedded ssl_st base; SSLConnection
// is the delta to subtract from that SSL * to reach the SSL_CONNECTION.
#include <stddef.h>
#include <stdio.h>

#include "ssl/ssl_local.h"

int main(void)
{
	printf("\t\"%d.%d.%d\": {\n", OPENSSL_VERSION_MAJOR, OPENSSL_VERSION_MINOR, OPENSSL_VERSION_PATCH);
	printf("\t\tType:                   0x%zx,\n", offsetof(SSL_CONNECTION, ssl.type));
	printf("\t\tVersion:                0x%zx,\n", offsetof(SSL_CONNECTION, version));
	printf("\t\tClientRandom:           0x%zx,\n", offsetof(SSL_CONNECTION, s3.client_random));
	printf("\t\tSession:                0x%zx,\n", offsetof(SSL_CONNECTION, session));
	printf("\t\tMasterKey:              0x%zx,\n", offsetof(SSL_SESSION, master_key));
	printf("\t\tMasterKeyLength:        0x%zx,\n", offsetof(SSL_SESSION, master_key_length));
	printf("\t\tClientAppTrafficSecret: 0x%zx,\n", offsetof(SSL_CONNECTION, client_app_traffic_secret));
	printf("\t\tServerAppTrafficSecret: 0x%zx,\n", offsetof(SSL_CONNECTION, server_app_traffic_secret));
	printf("\t\tHandshakeSecret:        0x%zx,\n", offsetof(SSL_CONNECTION, handshake_secret));
	printf("\t\tHandshakeTrafficHash:   0x%zx,\n", offsetof(SSL_CONNECTION, handshake_traffic_hash));
	printf("\t\tSessionCipher:          0x%zx,\n", offsetof(SSL_SESSION, cipher));
	printf("\t\tCipherId:               0x%zx,\n", offsetof(SSL_CIPHER, id));
	printf("\t\tSSLConnection:          0x%zx,\n", offsetof(SSL_CONNECTION, ssl));
	printf("\t},\n");

	return 0;
}
