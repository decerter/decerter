// SPDX-License-Identifier: GPL-2.0-only OR MIT

//go:build ignore

#include "redirect.h"

//Record TCP and connected UDP IPv4 sockets of in scope processes and redirect them to the proxy, always allowed
SEC("cgroup/connect4")
int redirect_connect4(struct bpf_sock_addr *ctx)
{
	switch (record_flow4(ctx))
	{
	case REDIRECT:
		redirect_to_proxy4(ctx);

		return SOCK_ALLOW;
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Record TCP and connected UDP IPv6 sockets of in scope processes and redirect them to the proxy, always allowed
SEC("cgroup/connect6")
int redirect_connect6(struct bpf_sock_addr *ctx)
{
	switch (record_flow6(ctx))
	{
	case REDIRECT:
		redirect_to_proxy6(ctx);

		return SOCK_ALLOW;
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Record the original destination of unconnected UDP IPv4 sends and redirect them to the proxy, the datagram is always allowed
SEC("cgroup/sendmsg4")
int redirect_sendmsg4(struct bpf_sock_addr *ctx)
{
	switch (record_flow4(ctx))
	{
	case REDIRECT:
		redirect_to_proxy4(ctx);

		return SOCK_ALLOW;
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Record the original destination of unconnected UDP IPv6 sends and redirect them to the proxy, the datagram is always allowed
SEC("cgroup/sendmsg6")
int redirect_sendmsg6(struct bpf_sock_addr *ctx)
{
	switch (record_flow6(ctx))
	{
	case REDIRECT:
		redirect_to_proxy6(ctx);

		return SOCK_ALLOW;
	case OK:
		return SOCK_ALLOW;
	default:
		return SOCK_ALLOW;
	}
}

//Map the client endpoint of redirected TCP sockets to their cookie and remove both entries when the socket closes
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
	switch (restore_peer4(ctx))
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
	switch (restore_peer6(ctx))
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
	switch (restore_source4(ctx))
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
	switch (restore_source6(ctx))
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

//Remove the map entries of a closed socket that sockops doesn't remove: recorded only flows and redirected UDP, which has no TCP_CLOSE state callback
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
