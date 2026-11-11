// SPDX-License-Identifier: GPL-2.0-only OR MIT

#include "shared.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

//cgroup sock_addr, sock and sockops return values
#define SOCK_REJECT		0
#define SOCK_ALLOW		1

//cgroup_skb return values
#define SKB_DROP		0
#define SKB_PASS		1

//socket address families missing from vmlinux.h
#define AF_INET			2
#define AF_INET6		10

//ethernet protocols of skb->protocol missing from vmlinux.h
#define ETH_P_IP		0x0800
#define ETH_P_IPV6		0x86DD

//check return values
#define OK				0
#define NOK				1
#define REDIRECT		2

//prefix length of a full address in an LPM_TRIE lookup key, IPv4 is stored IPv4-mapped
#define ADDRESS_BITS	128

//second word of an IPv4-mapped IPv6 address (::ffff:0:0/96)
#define IPV4_MAPPED		0x0000FFFF

//loopback addresses in host byte order: 127.0.0.1 and the last word of ::1
#define LOOPBACK4		0x7F000001
#define LOOPBACK6		0x00000001

//IPv4 multicast (224.0.0.0/4) and limited broadcast, IPv6 multicast (ff00::/8) in host byte order
#define MULTICAST4_MASK	0xF0000000
#define MULTICAST4		0xE0000000
#define BROADCAST4		0xFFFFFFFF
#define MULTICAST6_MASK	0xFF000000
#define MULTICAST6		0xFF000000

char __license[] SEC("license") = "Dual MIT/GPL";

//Value: tgid of decerter, its own connections are never recorded or redirected, set from Go before load
volatile const uint32_t proxy_tgid = 0;

//Value: port of the TCP listener and the UDP socket of the proxy on lo in host byte order, set from Go before load
volatile const uint16_t proxy_port = 0;

//source and destination of a UDP packet, IPv4 stored IPv4-mapped like in struct endpoint
struct packet_info {
	struct endpoint source;
	struct endpoint destination;
};

//cidr_filter: 1 if the destination address has to match cidr_map, 0 if every address passes
//port_filter: 1 if the destination port + IP protocol has to match port_map, 0 if every port passes
struct filter_config {
	uint8_t cidr_filter;
	uint8_t port_filter;
	uint16_t padding;
};

//port: destination port in host byte order, ip_protocol: IPPROTO_TCP or IPPROTO_UDP
struct port_key {
	uint16_t port;
	uint8_t ip_protocol;
	uint8_t padding;
};

//Key: socket cookie, Value: original destination + process of the socket, only flows that passed the process and destination filters are here
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

//Key: 0, Value: which destination filters are set, a program can't ask if cidr_map or port_map is empty and an unset filter has to pass everything, written by Go after the sets
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, struct filter_config);
} filter_map SEC(".maps");

//Key: destination prefix of the CIDR filter, IPv4 stored IPv4-mapped like in route_map, Value: 1, only read while filter_config.cidr_filter is set
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65535);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct prefix_key);
	__type(value, uint8_t);
} cidr_map SEC(".maps");

//Key: destination port + IP protocol of the port filter, Value: 1, only read while filter_config.port_filter is set
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct port_key);
	__type(value, uint8_t);
} port_map SEC(".maps");

//Key: client endpoint of a redirected TCP connection or UDP socket: IP address + layer 4 port + IP protocol, Value: socket cookie
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, struct endpoint);
	__type(value, uint64_t);
} client_map SEC(".maps");

//Check if the process is selected: its uid is in uid_map or its tgid in tgid_map, decerter itself never is
bool is_selected_process(uint32_t tgid, uint32_t uid)
{
	if (tgid == proxy_tgid)
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

//Check if the destination of the flow passes the port and the CIDR filter, a filter that is not set passes everything
bool is_selected_destination(struct flow *flow)
{
	if (!flow)
	{
		return false;
	}

	uint32_t index = 0;
	struct filter_config *filter_config = bpf_map_lookup_elem(&filter_map, &index);

	//the only slot of an ARRAY map is always there
	if (!filter_config)
	{
		return false;
	}

	if (filter_config->port_filter)
	{
		struct port_key key = {
			.port = flow->port,
			.ip_protocol = flow->ip_protocol,
			.padding = 0
		};

		if (!bpf_map_lookup_elem(&port_map, &key))
		{
			return false;
		}
	}

	if (filter_config->cidr_filter)
	{
		struct prefix_key key = {
			.prefixlen = ADDRESS_BITS,
			.ip = {flow->ip[0], flow->ip[1], flow->ip[2], flow->ip[3]}
		};

		if (!bpf_map_lookup_elem(&cidr_map, &key))
		{
			return false;
		}
	}

	return true;
}

//Check if the flow is in scope: a selected process and a destination that passes the filters, and fill its protocol, port and process, its destination address is already filled
uint16_t check_flow(struct bpf_sock_addr *ctx, struct flow *flow)
{
	if ((!ctx) || (!flow))
	{
		return NOK;
	}

	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	uint32_t tgid = pid_tgid >> 32;
	uint32_t uid = bpf_get_current_uid_gid();

	//most connects and sends of the system leave here
	if (!is_selected_process(tgid, uid))
	{
		return OK;
	}

	flow->ip_protocol = ctx->protocol;
	flow->port = bpf_ntohs(ctx->user_port);

	//a socket with a flow of an earlier destination keeps it, restore_destination4/6 only touch the proxy address
	if (!is_selected_destination(flow))
	{
		return OK;
	}

	flow->tgid = tgid;
	flow->uid = uid;
	flow->cgroup_id = bpf_get_current_cgroup_id();

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
		.prefixlen = ADDRESS_BITS,
		.ip = {flow->ip[0], flow->ip[1], flow->ip[2], flow->ip[3]}
	};
	uint8_t *routable = bpf_map_lookup_elem(&route_map, &key);

	return (routable) && (*routable == 1);
}

//Check if the original destination of the flow is a unicast address, a multicast or broadcast send can't be relayed by one upstream socket
bool is_unicast(struct flow *flow)
{
	if (!flow)
	{
		return false;
	}

	if ((flow->ip[0] == 0) && (flow->ip[1] == 0) && (flow->ip[2] == bpf_htonl(IPV4_MAPPED)))
	{
		uint32_t address = bpf_ntohl(flow->ip[3]);

		return ((address & MULTICAST4_MASK) != MULTICAST4) && (address != BROADCAST4);
	}

	return (bpf_ntohl(flow->ip[0]) & MULTICAST6_MASK) != MULTICAST6;
}

//Save the flow under the socket cookie, REDIRECT if the destination has to be rewritten to the proxy
uint16_t save_flow(struct bpf_sock_addr *ctx, struct flow *flow)
{
	if ((!ctx) || (!flow))
	{
		return NOK;
	}

	//without a route the connect or send has to fail with ENETUNREACH like without decerter, so happy eyeballs falls back to the other family
	flow->redirected = ((flow->ip_protocol == IPPROTO_TCP) || (flow->ip_protocol == IPPROTO_UDP)) && has_route(flow) && is_unicast(flow);
	uint64_t cookie = bpf_get_socket_cookie(ctx);
	struct flow *saved_flow = bpf_map_lookup_elem(&flow_map, &cookie);

	//an unconnected UDP socket gets here for every datagram: update in place and keep the client endpoint learned from its first datagram
	if (saved_flow)
	{
		flow->client = saved_flow->client;
		*saved_flow = *flow;
	}
	else if (bpf_map_update_elem(&flow_map, &cookie, flow, BPF_ANY) != 0)
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

//Record the flow if it is in scope, its destination address is already filled, REDIRECT if the destination has to be rewritten to the proxy
uint16_t record_flow(struct bpf_sock_addr *ctx, struct flow *flow)
{
	if ((!ctx) || (!flow))
	{
		return NOK;
	}

	switch (check_flow(ctx, flow))
	{
	case REDIRECT:
		return save_flow(ctx, flow);
	case OK:
		return OK;
	default:
		return NOK;
	}
}

//Record the flow to an IPv4 destination, stored IPv4-mapped
uint16_t record_flow4(struct bpf_sock_addr *ctx)
{
	if (!ctx)
	{
		return NOK;
	}

	//user_ip4 is only readable from the IPv4 attach types, so the address is filled here and everything else in record_flow
	struct flow flow = {};

	flow.ip[0] = 0;
	flow.ip[1] = 0;
	flow.ip[2] = bpf_htonl(IPV4_MAPPED);
	flow.ip[3] = ctx->user_ip4;

	return record_flow(ctx, &flow);
}

//Record the flow to an IPv6 destination
uint16_t record_flow6(struct bpf_sock_addr *ctx)
{
	if (!ctx)
	{
		return NOK;
	}

	//user_ip6 is only readable from the IPv6 attach types, so the address is filled here and everything else in record_flow
	struct flow flow = {};

	flow.ip[0] = ctx->user_ip6[0];
	flow.ip[1] = ctx->user_ip6[1];
	flow.ip[2] = ctx->user_ip6[2];
	flow.ip[3] = ctx->user_ip6[3];

	return record_flow(ctx, &flow);
}

//Rewrite the IPv4 destination to the proxy on 127.0.0.1, the TCP listener and the UDP socket share the port
uint16_t redirect_to_proxy4(struct bpf_sock_addr *ctx)
{
	if (!ctx)
	{
		return NOK;
	}

	ctx->user_ip4 = bpf_htonl(LOOPBACK4);
	ctx->user_port = bpf_htons(proxy_port);

	return OK;
}

//Rewrite the IPv6 destination to the proxy on ::1, the TCP listener and the UDP socket share the port
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
	ctx->user_port = bpf_htons(proxy_port);

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

//Check if the endpoint is the proxy: 127.0.0.1 (stored IPv4-mapped, also how a dual-stack IPv6 socket sees it) or ::1 on proxy_port
bool is_proxy_endpoint(struct endpoint *endpoint)
{
	if (!endpoint)
	{
		return false;
	}

	if ((endpoint->port != proxy_port) || (endpoint->ip[0] != 0) || (endpoint->ip[1] != 0))
	{
		return false;
	}

	if (endpoint->ip[2] == bpf_htonl(IPV4_MAPPED))
	{
		return endpoint->ip[3] == bpf_htonl(LOOPBACK4);
	}

	return (endpoint->ip[2] == 0) && (endpoint->ip[3] == bpf_htonl(LOOPBACK6));
}

//Fill the ports and the IP protocol of the source and destination from the UDP header at l4_offset
uint16_t parse_udp_ports(struct __sk_buff *skb, uint32_t l4_offset, struct packet_info *packet)
{
	if ((!skb) || (!packet))
	{
		return NOK;
	}

	struct udphdr udph = {};

	if (bpf_skb_load_bytes(skb, l4_offset, &udph, sizeof(struct udphdr)) != 0)
	{
		return NOK;
	}

	packet->source.port = bpf_ntohs(udph.source);
	packet->source.ip_protocol = IPPROTO_UDP;
	packet->source.padding = 0;
	packet->destination.port = bpf_ntohs(udph.dest);
	packet->destination.ip_protocol = IPPROTO_UDP;
	packet->destination.padding = 0;

	return OK;
}

//Fill the source and destination of an IPv4 UDP packet, cgroup_skb data starts at the IP header
__noinline uint16_t parse_packet4(struct __sk_buff *skb, struct packet_info *packet)
{
	if ((!skb) || (!packet))
	{
		return NOK;
	}

	struct iphdr iph = {};

	if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr)) != 0)
	{
		return NOK;
	}

	//egress runs before fragmentation, so the UDP header follows the IP header and its options
	if ((iph.protocol != IPPROTO_UDP) || (iph.ihl < 5))
	{
		return NOK;
	}

	packet->source.ip[0] = 0;
	packet->source.ip[1] = 0;
	packet->source.ip[2] = bpf_htonl(IPV4_MAPPED);
	packet->source.ip[3] = iph.saddr;
	packet->destination.ip[0] = 0;
	packet->destination.ip[1] = 0;
	packet->destination.ip[2] = bpf_htonl(IPV4_MAPPED);
	packet->destination.ip[3] = iph.daddr;

	return parse_udp_ports(skb, iph.ihl * 4, packet);
}

//Fill the source and destination of an IPv6 UDP packet, cgroup_skb data starts at the IP header
__noinline uint16_t parse_packet6(struct __sk_buff *skb, struct packet_info *packet)
{
	if ((!skb) || (!packet))
	{
		return NOK;
	}

	struct ipv6hdr iph = {};

	if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct ipv6hdr)) != 0)
	{
		return NOK;
	}

	//extension headers are not followed, a UDP socket only adds them with IPV6_HOPOPTS / IPV6_DSTOPTS / IPV6_RTHDR, such a client is not learned
	if (iph.nexthdr != IPPROTO_UDP)
	{
		return NOK;
	}

	packet->source.ip[0] = iph.saddr.in6_u.u6_addr32[0];
	packet->source.ip[1] = iph.saddr.in6_u.u6_addr32[1];
	packet->source.ip[2] = iph.saddr.in6_u.u6_addr32[2];
	packet->source.ip[3] = iph.saddr.in6_u.u6_addr32[3];
	packet->destination.ip[0] = iph.daddr.in6_u.u6_addr32[0];
	packet->destination.ip[1] = iph.daddr.in6_u.u6_addr32[1];
	packet->destination.ip[2] = iph.daddr.in6_u.u6_addr32[2];
	packet->destination.ip[3] = iph.daddr.in6_u.u6_addr32[3];

	return parse_udp_ports(skb, sizeof(struct ipv6hdr), packet);
}

//Fill the source and destination of a UDP packet by its IP version, NOK for anything else
uint16_t parse_packet(struct __sk_buff *skb, struct packet_info *packet)
{
	if ((!skb) || (!packet))
	{
		return NOK;
	}

	switch (bpf_ntohs(skb->protocol))
	{
	case ETH_P_IP:
		return parse_packet4(skb, packet);
	case ETH_P_IPV6:
		return parse_packet6(skb, packet);
	default:
		return NOK;
	}
}

//Check if two endpoints are equal
bool same_endpoint(struct endpoint *first, struct endpoint *second)
{
	if ((!first) || (!second))
	{
		return false;
	}

	return (first->ip[0] == second->ip[0]) && (first->ip[1] == second->ip[1]) && (first->ip[2] == second->ip[2]) && (first->ip[3] == second->ip[3]) && (first->port == second->port) && (first->ip_protocol == second->ip_protocol);
}

//Map the source endpoint of a datagram from a redirected UDP socket to the proxy to the socket cookie
uint16_t save_udp_client(struct __sk_buff *skb)
{
	if (!skb)
	{
		return NOK;
	}

	struct packet_info packet = {};

	if (parse_packet(skb, &packet) != OK)
	{
		return OK;
	}

	//every other packet leaves here without a map lookup
	if (!is_proxy_endpoint(&packet.destination))
	{
		return OK;
	}

	uint64_t cookie = bpf_get_socket_cookie(skb);
	struct flow *flow = bpf_map_lookup_elem(&flow_map, &cookie);

	if ((!flow) || (!flow->redirected) || (flow->ip_protocol != IPPROTO_UDP))
	{
		return OK;
	}

	//the source endpoint only changes when a dual-stack socket sends over the other IP version, the old client_map entry is left to LRU then
	if (same_endpoint(&flow->client, &packet.source))
	{
		return OK;
	}

	if (bpf_map_update_elem(&client_map, &packet.source, &cookie, BPF_ANY) != 0)
	{
#ifdef DEBUG
		bpf_printk("egress === save_udp_client client_map update failed");
#endif

		return NOK;
	}

	flow->client = packet.source;

	return OK;
}

//Remove the flow of a released socket: recorded only at once, redirected UDP is only marked released because datagrams it sent can still wait in the proxy socket, Go removes it later
uint16_t release_flow(struct bpf_sock *sk)
{
	if (!sk)
	{
		return NOK;
	}

	uint64_t cookie = bpf_get_socket_cookie(sk);
	struct flow *flow = bpf_map_lookup_elem(&flow_map, &cookie);

	//every socket of the system gets here, only the recorded ones go further
	if (!flow)
	{
		return OK;
	}

	//nothing looks a recorded but not redirected flow up after the close
	if (!flow->redirected)
	{
		bpf_map_delete_elem(&flow_map, &cookie);

		return OK;
	}

	//a redirected TCP flow is removed by sockops at TCP_CLOSE, the proxy may not have accepted it yet
	if (sk->protocol != IPPROTO_UDP)
	{
		return OK;
	}

	//no bpf_timer: its callback panics kernels with kCFI (Android 15, 6.6), Go removes the flow_map and client_map entries a grace time after released_ns
	flow->released_ns = bpf_ktime_get_ns();

	return OK;
}

//Replace the proxy address with the original IPv4 destination of a redirected socket: its peer in getpeername, the source of a datagram in recvmsg
uint16_t restore_destination4(struct bpf_sock_addr *ctx)
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

	struct endpoint reported = {
		.ip = {0, 0, bpf_htonl(IPV4_MAPPED), ctx->user_ip4},
		.port = bpf_ntohs(ctx->user_port),
		.ip_protocol = flow->ip_protocol,
		.padding = 0
	};

	//every other address is real: another sender of an unconnected socket, or the peer of a socket that was connected again to a destination that is not redirected
	if (!is_proxy_endpoint(&reported))
	{
		return OK;
	}

	ctx->user_ip4 = flow->ip[3];
	ctx->user_port = bpf_htons(flow->port);

	return REDIRECT;
}

//Replace the proxy address with the original IPv6 destination of a redirected socket: its peer in getpeername, the source of a datagram in recvmsg, IPv4 on a dual-stack socket is IPv4-mapped
uint16_t restore_destination6(struct bpf_sock_addr *ctx)
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

	struct endpoint reported = {
		.ip = {ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3]},
		.port = bpf_ntohs(ctx->user_port),
		.ip_protocol = flow->ip_protocol,
		.padding = 0
	};

	//every other address is real: another sender of an unconnected socket, or the peer of a socket that was connected again to a destination that is not redirected
	if (!is_proxy_endpoint(&reported))
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
