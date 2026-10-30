// SPDX-License-Identifier: GPL-2.0-only OR MIT

//go:build ignore

#include "redirect.h"

//Count IPv4 connect calls per uid, the connection is always allowed
SEC("cgroup/connect4")
int count_connect4(struct bpf_sock_addr *ctx)
{
	switch (count_connect())
	{
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}
