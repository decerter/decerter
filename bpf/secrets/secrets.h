// SPDX-License-Identifier: GPL-2.0-only OR MIT

#include "shared.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

//check return values
#define OK					0
#define NOK					1

//TLS sizes, SECRET_SIZE is EVP_MAX_MD_SIZE, the field holds the suite hash length (32 or 48), Go trims it
#define SSL3_RANDOM_SIZE	32
#define MASTER_KEY_SIZE		48
#define SECRET_SIZE			64

//SSL_CONNECTION.version values
#define TLS1_2_VERSION		0x0303
#define TLS1_3_VERSION		0x0304

//SSL object type, only a TLS connection has this layout, QUIC objects reach the same functions with another one
#define SSL_TYPE_SSL_CONNECTION	0

char __license[] SEC("license") = "Dual MIT/GPL";

//Value: tgid of decerter, decerter does not use libssl so it is never read, excluded for parity with the redirect, set from Go before load
volatile const uint32_t own_tgid = 0;

//Value: offsetof(ssl_st, type), the SSL object type, read before the other offsets to skip QUIC objects, set from Go before load
volatile const uint64_t type_offset = 0;

//Value: delta from the SSL * the public API hands out to the SSL_CONNECTION, subtracted first, 0 for OpenSSL >= 3.2, set from Go before load
volatile const uint64_t ssl_connection_offset = 0;

//Value: offsetof(SSL_CONNECTION, version), set from Go before load
volatile const uint64_t version_offset = 0;

//Value: offsetof(SSL_CONNECTION, s3.client_random), set from Go before load
volatile const uint64_t client_random_offset = 0;

//Value: offsetof(SSL_CONNECTION, session), set from Go before load
volatile const uint64_t session_offset = 0;

//Value: offsetof(SSL_SESSION, master_key), set from Go before load
volatile const uint64_t master_key_offset = 0;

//Value: offsetof(SSL_SESSION, master_key_length), set from Go before load
volatile const uint64_t master_key_length_offset = 0;

//Value: offsetof(SSL_SESSION, cipher), the negotiated SSL_CIPHER pointer, set from Go before load
volatile const uint64_t session_cipher_offset = 0;

//Value: offsetof(SSL_CIPHER, id), the cipher id whose low 16 bits select the hash length, set from Go before load
volatile const uint64_t cipher_id_offset = 0;

//Value: offsetof(SSL_CONNECTION, client_app_traffic_secret), set from Go before load
volatile const uint64_t client_app_traffic_secret_offset = 0;

//Value: offsetof(SSL_CONNECTION, server_app_traffic_secret), set from Go before load
volatile const uint64_t server_app_traffic_secret_offset = 0;

//Value: offsetof(SSL_CONNECTION, handshake_secret), Go derives the handshake traffic secrets from it, set from Go before load
volatile const uint64_t handshake_secret_offset = 0;

//Value: offsetof(SSL_CONNECTION, handshake_traffic_hash), the transcript hash the handshake traffic secrets bind to, set from Go before load
volatile const uint64_t handshake_traffic_hash_offset = 0;

//client_random of a TLS session, the key of secrets_map
struct client_random {
	uint8_t value[SSL3_RANDOM_SIZE];
};

//Raw secret fields read from the SSL_CONNECTION, Go trims the TLS 1.3 secrets to the hash length and derives the handshake traffic secrets
//tls_version: 0x0303 (TLS 1.2) or 0x0304 (TLS 1.3), cipher_id: SSL_CIPHER.id, master_key_length: used only to gate TLS 1.2
struct tls_secrets {
	uint32_t tls_version;
	uint32_t cipher_id;
	uint64_t master_key_length;
	uint8_t client_random[SSL3_RANDOM_SIZE];
	uint8_t master_key[MASTER_KEY_SIZE];
	uint8_t client_app_traffic_secret[SECRET_SIZE];
	uint8_t server_app_traffic_secret[SECRET_SIZE];
	uint8_t handshake_secret[SECRET_SIZE];
	uint8_t handshake_traffic_hash[SECRET_SIZE];
};

//Key: client_random of the TLS session, Value: secrets to decrypt and re-encrypt its records, LRU so entries never grow without bound
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, struct client_random);
	__type(value, struct tls_secrets);
} secrets_map SEC(".maps");

//Key: ringbuf, Value: struct tls_secrets, one record the first time a session's secrets are complete, drained by keylog mode
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} secrets_event_map SEC(".maps");

//Key: pid_tgid, Value: the SSL * stashed at function entry so the matching uretprobe can read the connection, LRU so a thread that dies inside a call can't fill it
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, uint64_t);
	__type(value, uint64_t);
} ssl_map SEC(".maps");

//Check if the process is selected: its uid is in uid_map or its tgid in tgid_map, with both maps empty no process is selected, decerter itself never is
bool is_selected_process(uint32_t tgid, uint32_t uid)
{
	if (tgid == own_tgid)
	{
		return false;
	}

	if (bpf_map_lookup_elem(&uid_map, &uid))
	{
		return true;
	}

	if (bpf_map_lookup_elem(&tgid_map, &tgid))
	{
		return true;
	}

	return false;
}

//OR every byte of a secret buffer, a complete secret is never all zero, static inline because a global function may not take a raw byte pointer
static __always_inline bool buffer_nonzero(const uint8_t *buffer, uint32_t length)
{
	uint8_t result = 0;

	for (uint32_t index = 0; index < length; index++)
	{
		result |= buffer[index];
	}

	return result != 0;
}

//Check if the version appropriate secret is present: TLS 1.3 needs both application traffic secrets, TLS 1.2 a 48 byte master key, this filters the not yet complete handshakes
bool secrets_complete(struct tls_secrets *secrets)
{
	if (!secrets)
	{
		return false;
	}

	switch (secrets->tls_version)
	{
	case TLS1_3_VERSION:
		return buffer_nonzero(secrets->client_app_traffic_secret, SECRET_SIZE) && buffer_nonzero(secrets->server_app_traffic_secret, SECRET_SIZE);
	case TLS1_2_VERSION:
		return (secrets->master_key_length == MASTER_KEY_SIZE) && buffer_nonzero(secrets->master_key, MASTER_KEY_SIZE);
	default:
		return false;
	}
}

//Read the secrets of an SSL_CONNECTION, the address is a user space pointer so it is passed as a scalar, best effort reads do not fail the whole read
uint16_t read_secrets(uint64_t ssl_address, struct tls_secrets *secrets)
{
	if ((!ssl_address) || (!secrets))
	{
		return NOK;
	}

	uint64_t session_address = 0;
	uint64_t cipher_address = 0;

	if (bpf_probe_read_user(&secrets->tls_version, sizeof(secrets->tls_version), (void *)(ssl_address + version_offset)))
	{
		return NOK;
	}

	if (bpf_probe_read_user(&secrets->client_random, sizeof(secrets->client_random), (void *)(ssl_address + client_random_offset)))
	{
		return NOK;
	}

	if (bpf_probe_read_user(&session_address, sizeof(session_address), (void *)(ssl_address + session_offset)))
	{
		return NOK;
	}

	//TLS 1.3 application and handshake secrets live in the connection
	bpf_probe_read_user(&secrets->client_app_traffic_secret, sizeof(secrets->client_app_traffic_secret), (void *)(ssl_address + client_app_traffic_secret_offset));
	bpf_probe_read_user(&secrets->server_app_traffic_secret, sizeof(secrets->server_app_traffic_secret), (void *)(ssl_address + server_app_traffic_secret_offset));
	bpf_probe_read_user(&secrets->handshake_secret, sizeof(secrets->handshake_secret), (void *)(ssl_address + handshake_secret_offset));
	bpf_probe_read_user(&secrets->handshake_traffic_hash, sizeof(secrets->handshake_traffic_hash), (void *)(ssl_address + handshake_traffic_hash_offset));

	//the TLS 1.2 master key and the negotiated cipher live in the session
	if (session_address)
	{
		bpf_probe_read_user(&secrets->master_key, sizeof(secrets->master_key), (void *)(session_address + master_key_offset));
		bpf_probe_read_user(&secrets->master_key_length, sizeof(secrets->master_key_length), (void *)(session_address + master_key_length_offset));

		if ((!bpf_probe_read_user(&cipher_address, sizeof(cipher_address), (void *)(session_address + session_cipher_offset))) && cipher_address)
		{
			bpf_probe_read_user(&secrets->cipher_id, sizeof(secrets->cipher_id), (void *)(cipher_address + cipher_id_offset));
		}
	}

	return OK;
}

//Push the new secrets to userspace once, keylog mode prints them and the proxy looks them up in secrets_map
void notify_secrets(struct tls_secrets *secrets)
{
	if (!secrets)
	{
		return;
	}

	struct tls_secrets *event = bpf_ringbuf_reserve(&secrets_event_map, sizeof(struct tls_secrets), 0);

	if (!event)
	{
		return;
	}

	*event = *secrets;

	bpf_ringbuf_submit(event, 0);
}
