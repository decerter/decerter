// SPDX-License-Identifier: GPL-2.0-only OR MIT

//go:build ignore

#include "redirect.h"

//Record the original destination of TCP and connected UDP IPv4 sockets, the connection is always allowed
SEC("cgroup/connect4")
int redirect_connect4(struct bpf_sock_addr *ctx)
{
	switch (record_flow4(ctx))
	{
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Record the original destination of TCP and connected UDP IPv6 sockets, the connection is always allowed
SEC("cgroup/connect6")
int redirect_connect6(struct bpf_sock_addr *ctx)
{
	switch (record_flow6(ctx))
	{
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Record the original destination of unconnected UDP IPv4 sends, the datagram is always allowed
SEC("cgroup/sendmsg4")
int redirect_sendmsg4(struct bpf_sock_addr *ctx)
{
	switch (record_flow4(ctx))
	{
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Record the original destination of unconnected UDP IPv6 sends, the datagram is always allowed
SEC("cgroup/sendmsg6")
int redirect_sendmsg6(struct bpf_sock_addr *ctx)
{
	switch (record_flow6(ctx))
	{
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}
