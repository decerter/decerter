// SPDX-License-Identifier: AGPL-3.0-only

// Test-only QUIC server of the secrets e2e test (secrets_test.go): openssl s_client -quic
// talks to it, so a selected process drives OpenSSL's QUIC connection object through the
// functions the secrets uprobe hooks. It needs OpenSSL 3.5 or newer (the QUIC server API)
// and declares the few functions it calls instead of including the OpenSSL headers.
// usage: quic_server <certificate> <key>; it listens on 127.0.0.1 with a port the kernel
// picks, prints the port, takes one connection with one stream, answers what it reads first
// with "echo <data>", ends its side of the stream and leaves when the client closes.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;

const SSL_METHOD *OSSL_QUIC_server_method(void);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx, int (*callback)(SSL *ssl, const unsigned char **out, unsigned char *out_length, const unsigned char *in, unsigned int in_length, void *argument), void *argument);
SSL *SSL_new_listener(SSL_CTX *ctx, uint64_t flags);
int SSL_set_fd(SSL *ssl, int fd);
int SSL_listen(SSL *ssl);
SSL *SSL_accept_connection(SSL *ssl, uint64_t flags);
SSL *SSL_accept_stream(SSL *ssl, uint64_t flags);
int SSL_read_ex(SSL *ssl, void *buffer, size_t length, size_t *read);
int SSL_write_ex(SSL *ssl, const void *buffer, size_t length, size_t *written);
int SSL_stream_conclude(SSL *ssl, uint64_t flags);
int SSL_shutdown(SSL *ssl);
void SSL_free(SSL *ssl);
void SSL_CTX_free(SSL_CTX *ctx);
void ERR_print_errors_fp(FILE *file);

#define SSL_FILETYPE_PEM 1
#define SSL_TLSEXT_ERR_OK 0

// the client's first protocol, s_client -quic needs one
static int select_protocol(SSL *ssl, const unsigned char **out, unsigned char *out_length, const unsigned char *in, unsigned int in_length, void *argument)
{
	(void)ssl;
	(void)argument;

	if ((in_length < 2) || (in[0] == 0) || (in[0] >= in_length))
	{
		return 3;
	}

	*out = in + 1;
	*out_length = in[0];

	return SSL_TLSEXT_ERR_OK;
}

static int fail(const char *what)
{
	fprintf(stderr, "quic_server: %s failed\n", what);
	ERR_print_errors_fp(stderr);

	return 1;
}

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		fprintf(stderr, "usage: quic_server <certificate> <key>\n");

		return 2;
	}

	SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());

	if (!ctx)
	{
		return fail("SSL_CTX_new");
	}

	if ((SSL_CTX_use_certificate_chain_file(ctx, argv[1]) != 1) || (SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) != 1))
	{
		return fail("loading the certificate");
	}

	SSL_CTX_set_alpn_select_cb(ctx, select_protocol, NULL);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in address = {0};
	socklen_t address_length = sizeof(address);
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if ((fd < 0) || (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) || (getsockname(fd, (struct sockaddr *)&address, &address_length) != 0))
	{
		perror("quic_server: socket");

		return 1;
	}

	SSL *listener = SSL_new_listener(ctx, 0);

	if ((!listener) || (SSL_set_fd(listener, fd) != 1) || (SSL_listen(listener) != 1))
	{
		return fail("SSL_listen");
	}

	printf("%d\n", ntohs(address.sin_port));
	fflush(stdout);
	SSL *connection = SSL_accept_connection(listener, 0);

	if (!connection)
	{
		return fail("SSL_accept_connection");
	}

	SSL *stream = SSL_accept_stream(connection, 0);

	if (!stream)
	{
		return fail("SSL_accept_stream");
	}

	char buffer[4096];
	size_t length = 0;

	size_t written = 0;

	if (SSL_read_ex(stream, buffer, sizeof(buffer), &length) != 1)
	{
		return fail("SSL_read_ex");
	}

	if ((SSL_write_ex(stream, "echo ", 5, &written) != 1) || (SSL_write_ex(stream, buffer, length, &written) != 1) || (SSL_stream_conclude(stream, 0) != 1))
	{
		return fail("SSL_write_ex");
	}

	// the client reads the answer and the end of the stream before the connection closes
	while (SSL_read_ex(stream, buffer, sizeof(buffer), &length) == 1)
	{
	}

	SSL_free(stream);
	SSL_shutdown(connection);
	SSL_free(connection);
	SSL_free(listener);
	SSL_CTX_free(ctx);
	close(fd);

	return 0;
}
