// SPDX-License-Identifier: GPL-2.0-only OR MIT

//go:build ignore

#include "secrets.h"

//Stash the SSL * at function entry so the matching uretprobe can read the complete secrets: int SSL_do_handshake/SSL_read/SSL_write/SSL_read_ex/SSL_write_ex(SSL *ssl, ...)
//One program attached to every entry, a thread is in only one of these calls at a time so a single stash keyed by pid_tgid is enough
SEC("uprobe/ssl")
int stash_ssl(struct pt_regs *ctx)
{
	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	uint32_t uid = bpf_get_current_uid_gid();

	//every process on the host enters libssl, read nothing for a process that is not selected
	if (!is_selected_process(pid_tgid >> 32, uid))
	{
		return 0;
	}

	uint64_t ssl_address = PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&ssl_map, &pid_tgid, &ssl_address, BPF_ANY);

	return 0;
}

//Store the session secrets by client_random when they are complete, at the return of the entry functions the handshake has finished and the secrets are in place
SEC("uretprobe/ssl")
int store_secrets(struct pt_regs *ctx)
{
	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	uint64_t *stashed = bpf_map_lookup_elem(&ssl_map, &pid_tgid);

	//not a selected process, or no entry was stashed for this return
	if (!stashed)
	{
		return 0;
	}

	uint64_t ssl_address = *stashed - ssl_connection_offset;

	bpf_map_delete_elem(&ssl_map, &pid_tgid);

	//a QUIC SSL object reaches the same functions with a different layout, reading it at these offsets would be garbage; up to OpenSSL 3.1 there is no QUIC and no type field
	if (has_type)
	{
		int32_t type = 0;

		if (bpf_probe_read_user(&type, sizeof(type), (void *)(ssl_address + type_offset)) || (type != SSL_TYPE_SSL_CONNECTION))
		{
			return 0;
		}
	}

	uint32_t key = 0;
	struct tls_secrets *secrets = bpf_map_lookup_elem(&secrets_scratch_map, &key);

	if (!secrets)
	{
		return 0;
	}

	__builtin_memset(secrets, 0, sizeof(*secrets));

	switch (read_secrets(ssl_address, secrets))
	{
	case OK:
		if (secrets_complete(secrets))
		{
			store_complete_secrets(secrets);
		}

		return 0;
	default:
		return 0;
	}
}

//Collect the secrets BoringSSL logs: bool bssl::ssl_log_secret(const SSL *ssl, const char *label, Span<const uint8_t> secret), the Span comes in two registers (data, size)
//BoringSSL calls it for every secret and only then checks for a key log callback, so the entry fires without one, and at entry the secret is complete
//one program for every BoringSSL library, the attach cookie is the index of the library's offsets in boringssl_layout_map
SEC("uprobe/ssl_log_secret")
int log_secret(struct pt_regs *ctx)
{
	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	uint32_t uid = bpf_get_current_uid_gid();

	//every app enters Conscrypt's libssl, read nothing for a process that is not selected
	if (!is_selected_process(pid_tgid >> 32, uid))
	{
		return 0;
	}

	struct label label = {};

	if (bpf_probe_read_user_str(label.value, sizeof(label.value), (void *)PT_REGS_PARM2(ctx)) < 0)
	{
		return 0;
	}

	uint32_t secret_bit = label_bit(&label);

	//a label decerter does not keep
	if (!secret_bit)
	{
		return 0;
	}

	uint32_t layout_index = bpf_get_attach_cookie(ctx);
	struct boringssl_layout *layout = bpf_map_lookup_elem(&boringssl_layout_map, &layout_index);

	if (!layout)
	{
		return 0;
	}

	uint32_t key = 0;
	struct tls_secrets *secrets = bpf_map_lookup_elem(&secrets_scratch_map, &key);

	if (!secrets)
	{
		return 0;
	}

	__builtin_memset(secrets, 0, sizeof(*secrets));

	uint64_t ssl_address = PT_REGS_PARM1(ctx);
	uint64_t secret_address = PT_REGS_PARM3(ctx);
	uint64_t secret_length = PT_REGS_PARM4(ctx);

	switch (read_boringssl_session(ssl_address, layout, secret_bit, secret_length, secrets))
	{
	case OK:
		break;
	case LAYOUT:
		report_layout_error(layout_index, secrets->tls_version, secret_bit, secret_length);
		return 0;
	default:
		return 0;
	}

	switch (secret_bit)
	{
	case CLIENT_RANDOM_BIT:
		//TLS 1.2 has one secret, the master secret, logged by ssl_send_finished for full and resumed handshakes
		if (bpf_probe_read_user(secrets->master_key, sizeof(secrets->master_key), (void *)secret_address))
		{
			return 0;
		}

		secrets->master_key_length = MASTER_KEY_SIZE;
		secrets->secret_mask = CLIENT_RANDOM_BIT;
		store_complete_secrets(secrets);

		return 0;
	default:
		add_tls13_secret(secrets, secret_bit, secret_address, secret_length);

		return 0;
	}
}
