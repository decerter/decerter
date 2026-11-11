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

	//a QUIC SSL object reaches the same functions with a different layout, reading it at these offsets would be garbage
	int32_t type = 0;

	if (bpf_probe_read_user(&type, sizeof(type), (void *)(ssl_address + type_offset)) || (type != SSL_TYPE_SSL_CONNECTION))
	{
		return 0;
	}

	struct tls_secrets secrets = {};

	switch (read_secrets(ssl_address, &secrets))
	{
	case OK:
		//every later call of the session gets here too, BPF_NOEXIST lets only the first one write, so keylog mode gets each session once
		if (secrets_complete(&secrets) && (bpf_map_update_elem(&secrets_map, &secrets.client_random, &secrets, BPF_NOEXIST) == 0))
		{
			notify_secrets(&secrets);
		}

		return 0;
	default:
		return 0;
	}
}
