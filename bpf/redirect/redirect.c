// SPDX-License-Identifier: GPL-2.0-only OR MIT

//go:build ignore

#include "redirect.h"

//Record in scope TCP and connected UDP IPv4 flows and redirect them to the proxy, the connect is allowed unless block_quic rejects it
SEC("cgroup/connect4")
int redirect_connect4(struct bpf_sock_addr *ctx)
{
	switch (record_flow4(ctx))
	{
	case REDIRECT:
		redirect_to_proxy4(ctx);

		return SOCK_ALLOW;
	case BLOCK:
		return SOCK_REJECT;
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Record in scope TCP and connected UDP IPv6 flows and redirect them to the proxy, the connect is allowed unless block_quic rejects it
SEC("cgroup/connect6")
int redirect_connect6(struct bpf_sock_addr *ctx)
{
	switch (record_flow6(ctx))
	{
	case REDIRECT:
		redirect_to_proxy6(ctx);

		return SOCK_ALLOW;
	case BLOCK:
		return SOCK_REJECT;
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Record the original destination of in scope unconnected UDP IPv4 sends and redirect them to the proxy, the datagram is allowed unless block_quic rejects it
SEC("cgroup/sendmsg4")
int redirect_sendmsg4(struct bpf_sock_addr *ctx)
{
	switch (record_flow4(ctx))
	{
	case REDIRECT:
		redirect_to_proxy4(ctx);

		return SOCK_ALLOW;
	case BLOCK:
		return SOCK_REJECT;
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Record the original destination of in scope unconnected UDP IPv6 sends and redirect them to the proxy, the datagram is allowed unless block_quic rejects it
SEC("cgroup/sendmsg6")
int redirect_sendmsg6(struct bpf_sock_addr *ctx)
{
	switch (record_flow6(ctx))
	{
	case REDIRECT:
		redirect_to_proxy6(ctx);

		return SOCK_ALLOW;
	case BLOCK:
		return SOCK_REJECT;
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Map the client endpoint of redirected TCP sockets to their cookie and remove both entries when the socket closes, in capture mode mark the flow of a recorded socket released when it closes
SEC("sockops")
int client_sockops(struct bpf_sock_ops *skops)
{
	switch (skops->op)
	{
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		watch_flow(skops);

		return SOCK_ALLOW;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		save_client(skops);

		return SOCK_ALLOW;
	case BPF_SOCK_OPS_STATE_CB:
		forget_flow(skops);

		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Show the original IPv4 destination instead of the proxy to the application
SEC("cgroup/getpeername4")
int restore_getpeername4(struct bpf_sock_addr *ctx)
{
	switch (restore_destination4(ctx))
	{
	case REDIRECT:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Show the original IPv6 destination instead of the proxy to the application
SEC("cgroup/getpeername6")
int restore_getpeername6(struct bpf_sock_addr *ctx)
{
	switch (restore_destination6(ctx))
	{
	case REDIRECT:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Show the original IPv4 server instead of the proxy as the source of a received datagram
SEC("cgroup/recvmsg4")
int restore_recvmsg4(struct bpf_sock_addr *ctx)
{
	switch (restore_destination4(ctx))
	{
	case REDIRECT:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Show the original IPv6 server instead of the proxy as the source of a received datagram
SEC("cgroup/recvmsg6")
int restore_recvmsg6(struct bpf_sock_addr *ctx)
{
	switch (restore_destination6(ctx))
	{
	case REDIRECT:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Map the client endpoint of redirected UDP sockets to their cookie from the first datagram to the proxy, the socket is bound by then, every packet passes
SEC("cgroup_skb/egress")
int learn_udp_client(struct __sk_buff *skb)
{
	switch (save_udp_client(skb))
	{
	case OK:
		return SKB_PASS;
	default:
		return SKB_PASS;
	}
}

//Remove the flow of a closed recorded only socket at once and mark a redirected UDP flow released for Go to remove later, redirected TCP is left to sockops at TCP_CLOSE
//In capture mode mark every flow released but the one of an open TCP connection, which is left to sockops at TCP_CLOSE
SEC("cgroup/sock_release")
int forget_released_socket(struct bpf_sock *sk)
{
	switch (release_flow(sk))
	{
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}
