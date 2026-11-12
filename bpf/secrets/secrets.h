// SPDX-License-Identifier: GPL-2.0-only OR MIT

#include "shared.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

//check return values, LAYOUT: the BoringSSL version read does not fit the label, the offsets do not match this libssl
#define OK					0
#define NOK					1
#define LAYOUT				2

//TLS sizes, SECRET_SIZE is EVP_MAX_MD_SIZE, the field holds the suite hash length (32 or 48), Go trims it
#define SSL3_RANDOM_SIZE	32
#define MASTER_KEY_SIZE		48
#define SECRET_SIZE			64

//SSL_CONNECTION.version values, DTLS 1.2 keeps its secrets like TLS 1.2: the master key in the session
#define TLS1_2_VERSION		0x0303
#define TLS1_3_VERSION		0x0304
#define DTLS1_2_VERSION		0xFEFD

//SSL object type, only a TLS connection has this layout, QUIC objects reach the same functions with another one
#define SSL_TYPE_SSL_CONNECTION	0

//BoringSSL: TLS 1.0 and 1.1 log CLIENT_RANDOM too, Go refuses them like it refuses them for OpenSSL
#define TLS1_VERSION		0x0301

//BoringSSL ssl_log_secret labels decerter keeps, one bit each in tls_secrets.secret_mask, the label buffer holds the longest one with its NUL
#define LABEL_SIZE						32
#define CLIENT_RANDOM_BIT				1
#define CLIENT_HANDSHAKE_SECRET_BIT		2
#define SERVER_HANDSHAKE_SECRET_BIT		4
#define CLIENT_TRAFFIC_SECRET_BIT		8
#define SERVER_TRAFFIC_SECRET_BIT		16
#define TLS1_3_SECRET_BITS				30

//TLS 1.3 secret lengths, the hash length of the suite: SHA-256 or SHA-384
#define SHA256_LENGTH		32
#define SHA384_LENGTH		48

//arm64 uprobe context: the arm64 UAPI register layout (arch/arm64/include/uapi/asm/ptrace.h) PT_REGS_* reads, the x86 vmlinux.h has no arm64 types and the uprobe needs no other
#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
};
#endif

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

//Value: BoringSSL offsetof(ssl_st, version), or offsetof(SSL3_STATE, version) from Android 16 on, the negotiated version checks the layout, set from Go before load
volatile const uint64_t boringssl_version_offset = 0;

//Value: BoringSSL 1 if boringssl_version_offset is inside SSL3_STATE, 0 if inside ssl_st, set from Go before load
volatile const uint32_t boringssl_version_in_s3 = 0;

//Value: BoringSSL offsetof(ssl_st, s3), the SSL3_STATE pointer, set from Go before load
volatile const uint64_t boringssl_s3_offset = 0;

//Value: BoringSSL offsetof(SSL3_STATE, client_random), set from Go before load
volatile const uint64_t boringssl_client_random_offset = 0;

//client_random of a TLS session, the key of secrets_map
struct client_random {
	uint8_t value[SSL3_RANDOM_SIZE];
};

//Secrets of one TLS session, Go trims the TLS 1.3 secrets to the hash length
//OpenSSL: the raw fields read from the SSL_CONNECTION, Go takes the hash length from cipher_id and derives the handshake traffic secrets from handshake_secret and handshake_traffic_hash
//BoringSSL: the secrets ssl_log_secret was called with, secret_length is the TLS 1.3 hash length it passed and the handshake traffic secrets come as they are, cipher_id, handshake_secret and handshake_traffic_hash stay zero
//tls_version: 0x0303 (TLS 1.2), 0x0304 (TLS 1.3) or 0xFEFD (DTLS 1.2), cipher_id: SSL_CIPHER.id, master_key_length: used only to gate TLS 1.2 and DTLS 1.2
//secret_length: 0 for OpenSSL, secret_mask: the ssl_log_secret labels seen so far, *_BIT
struct tls_secrets {
	uint32_t tls_version;
	uint32_t cipher_id;
	uint64_t master_key_length;
	uint32_t secret_length;
	uint32_t secret_mask;
	uint8_t client_random[SSL3_RANDOM_SIZE];
	uint8_t master_key[MASTER_KEY_SIZE];
	uint8_t client_app_traffic_secret[SECRET_SIZE];
	uint8_t server_app_traffic_secret[SECRET_SIZE];
	uint8_t handshake_secret[SECRET_SIZE];
	uint8_t handshake_traffic_hash[SECRET_SIZE];
	uint8_t client_handshake_traffic_secret[SECRET_SIZE];
	uint8_t server_handshake_traffic_secret[SECRET_SIZE];
};

//BoringSSL calls that did not fit the offsets, read by Go to report a Conscrypt APEX with another layout
//count: rejected calls, tls_version: the version read last, secret_bit: its label, secret_length: its secret length
struct layout_error {
	uint32_t count;
	uint32_t tls_version;
	uint32_t secret_bit;
	uint32_t secret_length;
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

//Key: 0, Value: scratch tls_secrets, too large for the BPF stack
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, struct tls_secrets);
} secrets_scratch_map SEC(".maps");

//Key: client_random of a BoringSSL TLS 1.3 session, Value: the secrets ssl_log_secret passed so far, moved to secrets_map when all four are there, LRU so an aborted handshake can't fill it
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct client_random);
	__type(value, struct tls_secrets);
} partial_secrets_map SEC(".maps");

//Key: 0, Value: BoringSSL calls whose version did not fit the label, Go reports a layout that does not match the offsets
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, struct layout_error);
} layout_error_map SEC(".maps");

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

//Check if the version appropriate secret is present: TLS 1.3 needs both application traffic secrets, TLS 1.2 and DTLS 1.2 a 48 byte master key, this filters the not yet complete handshakes
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
	case DTLS1_2_VERSION:
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
//a global function has to return a scalar on 6.6
uint16_t notify_secrets(struct tls_secrets *secrets)
{
	if (!secrets)
	{
		return NOK;
	}

	struct tls_secrets *event = bpf_ringbuf_reserve(&secrets_event_map, sizeof(struct tls_secrets), 0);

	if (!event)
	{
		return NOK;
	}

	*event = *secrets;

	bpf_ringbuf_submit(event, 0);

	return OK;
}

//Store complete secrets by client_random and push them to userspace, every later call of the session gets here too and BPF_NOEXIST lets only the first one write, so keylog mode gets each session once
uint16_t store_complete_secrets(struct tls_secrets *secrets)
{
	if (!secrets)
	{
		return NOK;
	}

	if (bpf_map_update_elem(&secrets_map, &secrets->client_random, secrets, BPF_NOEXIST))
	{
		return NOK;
	}

	return notify_secrets(secrets);
}

//NUL terminated ssl_log_secret label
struct label {
	char value[LABEL_SIZE];
};

//Compare a label with an expected one including its NUL, static inline because a global function may not take a raw byte pointer
static __always_inline bool label_equal(const char *label, const char *expected, uint32_t size)
{
	for (uint32_t index = 0; index < size; index++)
	{
		if (label[index] != expected[index])
		{
			return false;
		}
	}

	return true;
}

//Map an ssl_log_secret label to its bit, 0 for the labels decerter does not keep (CLIENT_EARLY_TRAFFIC_SECRET, EXPORTER_SECRET)
uint32_t label_bit(struct label *label)
{
	if (!label)
	{
		return 0;
	}

	if (label_equal(label->value, "CLIENT_RANDOM", sizeof("CLIENT_RANDOM")))
	{
		return CLIENT_RANDOM_BIT;
	}

	if (label_equal(label->value, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", sizeof("CLIENT_HANDSHAKE_TRAFFIC_SECRET")))
	{
		return CLIENT_HANDSHAKE_SECRET_BIT;
	}

	if (label_equal(label->value, "SERVER_HANDSHAKE_TRAFFIC_SECRET", sizeof("SERVER_HANDSHAKE_TRAFFIC_SECRET")))
	{
		return SERVER_HANDSHAKE_SECRET_BIT;
	}

	if (label_equal(label->value, "CLIENT_TRAFFIC_SECRET_0", sizeof("CLIENT_TRAFFIC_SECRET_0")))
	{
		return CLIENT_TRAFFIC_SECRET_BIT;
	}

	if (label_equal(label->value, "SERVER_TRAFFIC_SECRET_0", sizeof("SERVER_TRAFFIC_SECRET_0")))
	{
		return SERVER_TRAFFIC_SECRET_BIT;
	}

	return 0;
}

//Read the version and the client_random of a BoringSSL ssl_st and check them against the label, a mismatch means the offsets don't fit this libssl
//TLS 1.3 labels need version 0x0304 and a 32 or 48 byte secret, CLIENT_RANDOM 0x0301 to 0x0303 or DTLS 1.2 and a 48 byte master secret
uint16_t read_boringssl_session(uint64_t ssl_address, uint32_t secret_bit, uint64_t secret_length, struct tls_secrets *secrets)
{
	if ((!ssl_address) || (!secrets))
	{
		return NOK;
	}

	uint64_t s3_address = 0;
	uint16_t version = 0;

	//ssl_st is mapped while BoringSSL works on it, a failed read means the s3 offset points somewhere else
	if (bpf_probe_read_user(&s3_address, sizeof(s3_address), (void *)(ssl_address + boringssl_s3_offset)) || (!s3_address))
	{
		return LAYOUT;
	}

	uint64_t version_address = boringssl_version_in_s3 ? s3_address : ssl_address;

	if (bpf_probe_read_user(&version, sizeof(version), (void *)(version_address + boringssl_version_offset)))
	{
		return LAYOUT;
	}

	secrets->tls_version = version;

	if (bpf_probe_read_user(&secrets->client_random, sizeof(secrets->client_random), (void *)(s3_address + boringssl_client_random_offset)))
	{
		return LAYOUT;
	}

	switch (secret_bit)
	{
	case CLIENT_RANDOM_BIT:
		if (((version < TLS1_VERSION) || (version > TLS1_2_VERSION)) && (version != DTLS1_2_VERSION))
		{
			return LAYOUT;
		}

		if (secret_length != MASTER_KEY_SIZE)
		{
			return LAYOUT;
		}

		return OK;
	default:
		if ((version != TLS1_3_VERSION) || ((secret_length != SHA256_LENGTH) && (secret_length != SHA384_LENGTH)))
		{
			return LAYOUT;
		}

		return OK;
	}
}

//Count a BoringSSL call that did not fit the offsets and keep what was read, Go reports it once
uint16_t report_layout_error(uint32_t tls_version, uint32_t secret_bit, uint64_t secret_length)
{
	uint32_t key = 0;
	struct layout_error *error = bpf_map_lookup_elem(&layout_error_map, &key);

	if (!error)
	{
		return NOK;
	}

	error->tls_version = tls_version;
	error->secret_bit = secret_bit;
	error->secret_length = secret_length;
	__sync_fetch_and_add(&error->count, 1);

	return OK;
}

//Add one TLS 1.3 secret to the partial entry of its session, the four secrets move to secrets_map together when the last one is there
//BoringSSL logs the handshake traffic secrets after the ServerHello and the application traffic secrets after the server Finished, both before the first application data record
uint16_t add_tls13_secret(struct tls_secrets *secrets, uint32_t secret_bit, uint64_t secret_address, uint64_t secret_length)
{
	if ((!secrets) || (!secret_address))
	{
		return NOK;
	}

	//read_boringssl_session allows 32 or 48 bytes only, the bound is for the verifier
	if (secret_length > SECRET_SIZE)
	{
		return NOK;
	}

	struct tls_secrets *partial = bpf_map_lookup_elem(&partial_secrets_map, &secrets->client_random);

	if (!partial)
	{
		bpf_map_update_elem(&partial_secrets_map, &secrets->client_random, secrets, BPF_NOEXIST);
		partial = bpf_map_lookup_elem(&partial_secrets_map, &secrets->client_random);
	}

	if (!partial)
	{
		return NOK;
	}

	long read_result = 0;

	switch (secret_bit)
	{
	case CLIENT_HANDSHAKE_SECRET_BIT:
		read_result = bpf_probe_read_user(partial->client_handshake_traffic_secret, secret_length, (void *)secret_address);
		break;
	case SERVER_HANDSHAKE_SECRET_BIT:
		read_result = bpf_probe_read_user(partial->server_handshake_traffic_secret, secret_length, (void *)secret_address);
		break;
	case CLIENT_TRAFFIC_SECRET_BIT:
		read_result = bpf_probe_read_user(partial->client_app_traffic_secret, secret_length, (void *)secret_address);
		break;
	case SERVER_TRAFFIC_SECRET_BIT:
		read_result = bpf_probe_read_user(partial->server_app_traffic_secret, secret_length, (void *)secret_address);
		break;
	default:
		return NOK;
	}

	if (read_result)
	{
		return NOK;
	}

	partial->secret_length = secret_length;
	partial->secret_mask |= secret_bit;

	if ((partial->secret_mask & TLS1_3_SECRET_BITS) != TLS1_3_SECRET_BITS)
	{
		return OK;
	}

	uint16_t status = store_complete_secrets(partial);

	bpf_map_delete_elem(&partial_secrets_map, &secrets->client_random);

	return status;
}
