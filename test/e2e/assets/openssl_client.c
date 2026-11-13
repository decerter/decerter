// SPDX-License-Identifier: AGPL-3.0-only

// Test-only TLS client of the distro e2e test (openssl_test.go): it links the
// libssl.so.3 the dynamic linker finds (LD_LIBRARY_PATH, or the container's
// own), so one binary runs against every OpenSSL 3.x. It declares the few
// functions it calls instead of including the OpenSSL headers, all of them
// exist since 3.0.0, and writes its key log to SSLKEYLOGFILE through the key
// log callback like curl does. usage: openssl_client <ip> <port> <1.2|1.3> <path>
// sends GET <path>, prints the response and leaves after the server closes.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;

const SSL_METHOD *TLS_client_method(void);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
long SSL_CTX_ctrl(SSL_CTX *ctx, int command, long larg, void *parg);
void SSL_CTX_set_keylog_callback(SSL_CTX *ctx, void (*callback)(const SSL *ssl, const char *line));
SSL *SSL_new(SSL_CTX *ctx);
int SSL_set_fd(SSL *ssl, int fd);
int SSL_connect(SSL *ssl);
int SSL_write(SSL *ssl, const void *buffer, int length);
int SSL_read(SSL *ssl, void *buffer, int length);
int SSL_shutdown(SSL *ssl);
void SSL_free(SSL *ssl);
void SSL_CTX_free(SSL_CTX *ctx);
void ERR_print_errors_fp(FILE *file);

// SSL_CTX_set_min_proto_version and SSL_CTX_set_max_proto_version are macros over SSL_CTX_ctrl
#define SSL_CTRL_SET_MIN_PROTO_VERSION 123
#define SSL_CTRL_SET_MAX_PROTO_VERSION 124
#define TLS1_2_VERSION 0x0303
#define TLS1_3_VERSION 0x0304

static FILE *key_log = NULL;

static void write_key_log(const SSL *ssl, const char *line)
{
	(void)ssl;
	fprintf(key_log, "%s\n", line);
	fflush(key_log);
}

static int fail(const char *what)
{
	fprintf(stderr, "openssl_client: %s failed\n", what);
	ERR_print_errors_fp(stderr);

	return 1;
}

int main(int argc, char **argv)
{
	if (argc != 5)
	{
		fprintf(stderr, "usage: openssl_client <ip> <port> <1.2|1.3> <path>\n");

		return 2;
	}

	long version = (strcmp(argv[3], "1.2") == 0) ? TLS1_2_VERSION : TLS1_3_VERSION;
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

	if (!ctx)
	{
		return fail("SSL_CTX_new");
	}

	SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL);
	SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL);
	const char *key_log_path = getenv("SSLKEYLOGFILE");

	if (key_log_path && key_log_path[0])
	{
		key_log = fopen(key_log_path, "a");

		if (!key_log)
		{
			return fail("open SSLKEYLOGFILE");
		}

		SSL_CTX_set_keylog_callback(ctx, write_key_log);
	}

	struct sockaddr_in address = {};
	address.sin_family = AF_INET;
	address.sin_port = htons((uint16_t)atoi(argv[2]));
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if ((fd < 0) || (inet_pton(AF_INET, argv[1], &address.sin_addr) != 1) || connect(fd, (struct sockaddr *)&address, sizeof(address)))
	{
		return fail("connect");
	}

	SSL *ssl = SSL_new(ctx);

	if ((!ssl) || (SSL_set_fd(ssl, fd) != 1) || (SSL_connect(ssl) != 1))
	{
		return fail("SSL_connect");
	}

	char request[512];
	int length = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", argv[4], argv[1]);

	if ((length <= 0) || (length >= (int)sizeof(request)) || (SSL_write(ssl, request, length) != length))
	{
		return fail("SSL_write");
	}

	char response[4096];
	int read_length = 0;

	while ((read_length = SSL_read(ssl, response, sizeof(response))) > 0)
	{
		fwrite(response, 1, (size_t)read_length, stdout);
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(fd);

	return 0;
}
