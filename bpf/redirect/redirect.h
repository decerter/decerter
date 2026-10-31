// SPDX-License-Identifier: GPL-2.0-only OR MIT

#include "shared.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

//cgroup sock_addr return values
#define SOCK_REJECT		0
#define SOCK_ALLOW		1

//check return values
#define OK				0
#define NOK				1
#define REDIRECT		2

//second word of an IPv4-mapped IPv6 address (::ffff:0:0/96)
#define IPV4_MAPPED		0x0000FFFF

char __license[] SEC("license") = "Dual MIT/GPL";

//Value: tgid of decerter, its own connections are never recorded, set from Go before load
volatile const uint32_t proxy_tgid = 0;

//Key: socket cookie, Value: original destination + process of the socket
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, uint64_t);
	__type(value, struct flow);
} flow_map SEC(".maps");

//Check if the calling process is in scope and fill the protocol, port and process of the flow
uint16_t check_flow(struct bpf_sock_addr *ctx, struct flow *flow)
{
	if ((!ctx) || (!flow))
	{
		return NOK;
	}

	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	uint32_t tgid = pid_tgid >> 32;
	uint32_t uid = bpf_get_current_uid_gid();

	if (tgid == proxy_tgid)
	{
		return OK;
	}

	if (!bpf_map_lookup_elem(&uid_map, &uid))
	{
		return OK;
	}

	flow->tgid = tgid;
	flow->uid = uid;
	flow->cgroup_id = bpf_get_current_cgroup_id();
	flow->ip_protocol = ctx->protocol;
	flow->port = bpf_ntohs(ctx->user_port);

	return REDIRECT;
}

//Save the flow under the socket cookie
uint16_t save_flow(struct bpf_sock_addr *ctx, struct flow *flow)
{
	if ((!ctx) || (!flow))
	{
		return NOK;
	}

	uint64_t cookie = bpf_get_socket_cookie(ctx);

	if (bpf_map_update_elem(&flow_map, &cookie, flow, BPF_ANY) != 0)
	{
#ifdef DEBUG
		bpf_printk("sock_addr === save_flow flow_map update failed");
#endif

		return NOK;
	}

	return OK;
}

//Record the IPv4 destination of an in scope process IPv4-mapped in flow_map
uint16_t record_flow4(struct bpf_sock_addr *ctx)
{
	if (!ctx)
	{
		return NOK;
	}

	struct flow flow = {};

	switch (check_flow(ctx, &flow))
	{
	case REDIRECT:
		break;
	case OK:
		return OK;
	default:
		return NOK;
	}

	//user_ip4 is only readable from the IPv4 attach types, so it can't be read in check_flow
	flow.ip[0] = 0;
	flow.ip[1] = 0;
	flow.ip[2] = bpf_htonl(IPV4_MAPPED);
	flow.ip[3] = ctx->user_ip4;

	return save_flow(ctx, &flow);
}

//Record the IPv6 destination of an in scope process in flow_map
uint16_t record_flow6(struct bpf_sock_addr *ctx)
{
	if (!ctx)
	{
		return NOK;
	}

	struct flow flow = {};

	switch (check_flow(ctx, &flow))
	{
	case REDIRECT:
		break;
	case OK:
		return OK;
	default:
		return NOK;
	}

	//user_ip6 is only readable from the IPv6 attach types, so it can't be read in check_flow
	flow.ip[0] = ctx->user_ip6[0];
	flow.ip[1] = ctx->user_ip6[1];
	flow.ip[2] = ctx->user_ip6[2];
	flow.ip[3] = ctx->user_ip6[3];

	return save_flow(ctx, &flow);
}
