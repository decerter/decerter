// SPDX-License-Identifier: GPL-2.0-only OR MIT

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

//Key: uid of an inspected user, Value: 1, a process is selected if its uid is here or its tgid in tgid_map, with both maps empty no process is selected
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, uint32_t);
	__type(value, uint8_t);
} uid_map SEC(".maps");

//Key: tgid of an inspected process, Value: 1, selects single processes next to uid_map, a child gets its own tgid and is not followed
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, uint32_t);
	__type(value, uint8_t);
} tgid_map SEC(".maps");

//ip: network byte order, IPv4 stored IPv4-mapped (::ffff:a.b.c.d), port: host byte order
struct endpoint {
	uint32_t ip[4];
	uint16_t port;
	uint8_t ip_protocol;
	uint8_t padding;
};

//LPM_TRIE key, prefixlen: bits of ip that have to match, IPv4 stored IPv4-mapped with prefixlen + 96, ip: network byte order
struct prefix_key {
	uint32_t prefixlen;
	uint32_t ip[4];
};

//ip: original destination in network byte order, IPv4 stored IPv4-mapped (::ffff:a.b.c.d), port: host byte order
//redirected: 1 if the destination was rewritten to the proxy, 0 if the flow is only recorded
//comm: name of the process (thread group leader) at connect/sendmsg time, NUL terminated
//client: source endpoint of a redirected UDP socket as the proxy sees it, learned from its first datagram to the proxy, zero for TCP (sockops keeps it in client_map only)
//mark: SO_MARK of the socket at connect/sendmsg time, on Android netd's fwmark that selects the network, the proxy sets it on its upstream socket, 0 when the socket has none
//released_ns: bpf_ktime_get_ns() (CLOCK_MONOTONIC) when a redirected UDP socket was released, in capture mode when any recorded socket was released or reached TCP_CLOSE, 0 while it is open, Go removes the flow a grace time later
struct flow {
	uint32_t ip[4];
	uint16_t port;
	uint8_t ip_protocol;
	uint8_t redirected;
	uint32_t tgid;
	uint32_t uid;
	uint32_t mark;
	uint64_t cgroup_id;
	char comm[TASK_COMM_LEN];
	struct endpoint client;
	uint32_t pad32_end;
	uint64_t released_ns;
};

//Key: socket cookie, Value: original destination + process of the socket, only flows that passed the process and destination filters are here
//only an object that defines SHARED_FLOW_MAP before the include gets the map: the redirect object owns it and the capture object shares it through MapReplacements, the secrets object reads no flow
#ifdef SHARED_FLOW_MAP
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, uint64_t);
	__type(value, struct flow);
} flow_map SEC(".maps");
#endif
