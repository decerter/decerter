// SPDX-License-Identifier: GPL-2.0-only OR MIT

#include "shared.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

//cgroup sock_addr and sockops return values
#define SOCK_REJECT		0
#define SOCK_ALLOW		1

//socket address families missing from vmlinux.h
#define AF_INET			2
#define AF_INET6		10

//check return values
#define OK				0
#define NOK				1
#define REDIRECT		2

//second word of an IPv4-mapped IPv6 address (::ffff:0:0/96)
#define IPV4_MAPPED		0x0000FFFF

//loopback addresses in host byte order: 127.0.0.1 and the last word of ::1
#define LOOPBACK4		0x7F000001
#define LOOPBACK6		0x00000001

char __license[] SEC("license") = "Dual MIT/GPL";

//Value: tgid of decerter, its own connections are never recorded or redirected, set from Go before load
volatile const uint32_t proxy_tgid = 0;

//Value: port of the TCP proxy listener on lo in host byte order, set from Go before load
volatile const uint16_t tcp_proxy_port = 0;

//Key: socket cookie, Value: original destination + process of the socket
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, uint64_t);
	__type(value, struct flow);
} flow_map SEC(".maps");

//Key: destination prefix of a route, Value: 1 for routes the kernel can send on, 0 for blackhole, unreachable and prohibit routes, mirrored from the routing tables by Go
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65535);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct prefix_key);
	__type(value, uint8_t);
} route_map SEC(".maps");

//Key: client endpoint of a redirected TCP connection: IP address + layer 4 port + IP protocol, Value: socket cookie
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, struct endpoint);
	__type(value, uint64_t);
} client_map SEC(".maps");

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

	//comm of the thread group leader like /proc/<tgid>/comm, read here so a process that exits before the proxy accepts keeps its name
	//bpf_get_current_comm would give the name of the calling thread, it is only the fallback if the read fails
	struct task_struct *task = bpf_get_current_task_btf();

	if (BPF_CORE_READ_STR_INTO(&flow->comm, task, group_leader, comm) < 0)
	{
		bpf_get_current_comm(&flow->comm, sizeof(flow->comm));
	}

	return REDIRECT;
}

//Check if the kernel has a route to the original destination of the flow
bool has_route(struct flow *flow)
{
	if (!flow)
	{
		return false;
	}

	struct prefix_key key = {
		.prefixlen = 128,
		.ip = {flow->ip[0], flow->ip[1], flow->ip[2], flow->ip[3]}
	};
	uint8_t *routable = bpf_map_lookup_elem(&route_map, &key);

	return (routable) && (*routable == 1);
}

//Save the flow under the socket cookie, REDIRECT if the destination has to be rewritten to the proxy
uint16_t save_flow(struct bpf_sock_addr *ctx, struct flow *flow)
{
	if ((!ctx) || (!flow))
	{
		return NOK;
	}

	//only TCP goes to the proxy for now, connected UDP is just recorded
	//without a route the connect has to fail with ENETUNREACH like without decerter, so happy eyeballs falls back to the other family
	flow->redirected = (flow->ip_protocol == IPPROTO_TCP) && has_route(flow);
	uint64_t cookie = bpf_get_socket_cookie(ctx);

	if (bpf_map_update_elem(&flow_map, &cookie, flow, BPF_ANY) != 0)
	{
#ifdef DEBUG
		bpf_printk("sock_addr === save_flow flow_map update failed");
#endif

		return NOK;
	}

	if (flow->redirected)
	{
		return REDIRECT;
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

//Rewrite the IPv4 destination to the TCP proxy on 127.0.0.1
uint16_t redirect_to_proxy4(struct bpf_sock_addr *ctx)
{
	if (!ctx)
	{
		return NOK;
	}

	ctx->user_ip4 = bpf_htonl(LOOPBACK4);
	ctx->user_port = bpf_htons(tcp_proxy_port);

	return OK;
}

//Rewrite the IPv6 destination to the TCP proxy on ::1
uint16_t redirect_to_proxy6(struct bpf_sock_addr *ctx)
{
	if (!ctx)
	{
		return NOK;
	}

	ctx->user_ip6[0] = 0;
	ctx->user_ip6[1] = 0;
	ctx->user_ip6[2] = 0;
	ctx->user_ip6[3] = bpf_htonl(LOOPBACK6);
	ctx->user_port = bpf_htons(tcp_proxy_port);

	return OK;
}

//Fill the IPv4 client endpoint IPv4-mapped, local_port is host byte order (remote_port would be network byte order)
__noinline uint16_t client_endpoint4(struct bpf_sock_ops *skops, struct endpoint *endpoint)
{
	if ((!skops) || (!endpoint))
	{
		return NOK;
	}

	endpoint->ip[0] = 0;
	endpoint->ip[1] = 0;
	endpoint->ip[2] = bpf_htonl(IPV4_MAPPED);
	endpoint->ip[3] = skops->local_ip4;
	endpoint->port = skops->local_port;
	endpoint->ip_protocol = IPPROTO_TCP;
	endpoint->padding = 0;

	return OK;
}

//Fill the IPv6 client endpoint, local_port is host byte order (remote_port would be network byte order)
__noinline uint16_t client_endpoint6(struct bpf_sock_ops *skops, struct endpoint *endpoint)
{
	if ((!skops) || (!endpoint))
	{
		return NOK;
	}

	endpoint->ip[0] = skops->local_ip6[0];
	endpoint->ip[1] = skops->local_ip6[1];
	endpoint->ip[2] = skops->local_ip6[2];
	endpoint->ip[3] = skops->local_ip6[3];
	endpoint->port = skops->local_port;
	endpoint->ip_protocol = IPPROTO_TCP;
	endpoint->padding = 0;

	return OK;
}

//Fill the client endpoint of a TCP socket by its address family
uint16_t client_endpoint(struct bpf_sock_ops *skops, struct endpoint *endpoint)
{
	if ((!skops) || (!endpoint))
	{
		return NOK;
	}

	//separate __noinline helpers: inlined, clang merges the local_ip4 / local_ip6[3] / local_port loads of both cases into one load through a modified ctx pointer, which the verifier rejects
	switch (skops->family)
	{
	case AF_INET:
		return client_endpoint4(skops, endpoint);
	case AF_INET6:
		return client_endpoint6(skops, endpoint);
	default:
		return NOK;
	}
}

//Get state callbacks for a redirected socket, so its map entries can be removed when it closes
uint16_t watch_flow(struct bpf_sock_ops *skops)
{
	if (!skops)
	{
		return NOK;
	}

	uint64_t cookie = bpf_get_socket_cookie(skops);
	struct flow *flow = bpf_map_lookup_elem(&flow_map, &cookie);

	if ((!flow) || (!flow->redirected))
	{
		return OK;
	}

	if (bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG) != 0)
	{
#ifdef DEBUG
		bpf_printk("sockops === watch_flow state callback flag set failed");
#endif

		return NOK;
	}

	return OK;
}

//Map the client endpoint of an established redirected connection to its socket cookie
uint16_t save_client(struct bpf_sock_ops *skops)
{
	if (!skops)
	{
		return NOK;
	}

	uint64_t cookie = bpf_get_socket_cookie(skops);
	struct flow *flow = bpf_map_lookup_elem(&flow_map, &cookie);

	if ((!flow) || (!flow->redirected))
	{
		return OK;
	}

	struct endpoint endpoint = {};

	if (client_endpoint(skops, &endpoint) != OK)
	{
		return NOK;
	}

	if (bpf_map_update_elem(&client_map, &endpoint, &cookie, BPF_ANY) != 0)
	{
#ifdef DEBUG
		bpf_printk("sockops === save_client client_map update failed");
#endif

		return NOK;
	}

	return OK;
}

//Remove the flow_map and client_map entries of a redirected socket that reached TCP_CLOSE
uint16_t forget_flow(struct bpf_sock_ops *skops)
{
	if (!skops)
	{
		return NOK;
	}

	//args[0] is the old state, args[1] the new state
	if (skops->args[1] != BPF_TCP_CLOSE)
	{
		return OK;
	}

	uint64_t cookie = bpf_get_socket_cookie(skops);
	struct endpoint endpoint = {};

	//a connection refused in SYN_SENT has no client_map entry, so a failed delete is fine
	if (client_endpoint(skops, &endpoint) == OK)
	{
		bpf_map_delete_elem(&client_map, &endpoint);
	}

	bpf_map_delete_elem(&flow_map, &cookie);

	return OK;
}

//Restore the original IPv4 destination of a redirected socket as its peer
uint16_t restore_peer4(struct bpf_sock_addr *ctx)
{
	if (!ctx)
	{
		return NOK;
	}

	uint64_t cookie = bpf_get_socket_cookie(ctx);
	struct flow *flow = bpf_map_lookup_elem(&flow_map, &cookie);

	if ((!flow) || (!flow->redirected))
	{
		return OK;
	}

	ctx->user_ip4 = flow->ip[3];
	ctx->user_port = bpf_htons(flow->port);

	return REDIRECT;
}

//Restore the original IPv6 destination of a redirected socket as its peer
uint16_t restore_peer6(struct bpf_sock_addr *ctx)
{
	if (!ctx)
	{
		return NOK;
	}

	uint64_t cookie = bpf_get_socket_cookie(ctx);
	struct flow *flow = bpf_map_lookup_elem(&flow_map, &cookie);

	if ((!flow) || (!flow->redirected))
	{
		return OK;
	}

	ctx->user_ip6[0] = flow->ip[0];
	ctx->user_ip6[1] = flow->ip[1];
	ctx->user_ip6[2] = flow->ip[2];
	ctx->user_ip6[3] = flow->ip[3];
	ctx->user_port = bpf_htons(flow->port);

	return REDIRECT;
}
