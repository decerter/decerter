// SPDX-License-Identifier: GPL-2.0-only OR MIT

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

//Key: uid of an inspected user, Value: 1, an empty map matches no process
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, uint32_t);
	__type(value, uint8_t);
} uid_map SEC(".maps");

//ip: network byte order, IPv4 stored IPv4-mapped (::ffff:a.b.c.d), port: host byte order
struct endpoint {
	uint32_t ip[4];
	uint16_t port;
	uint8_t ip_protocol;
	uint8_t padding;
};

//ip: original destination in network byte order, IPv4 stored IPv4-mapped (::ffff:a.b.c.d), port: host byte order
struct flow {
	uint32_t ip[4];
	uint16_t port;
	uint8_t ip_protocol;
	uint8_t padding;
	uint32_t tgid;
	uint32_t uid;
	uint32_t pad32;
	uint64_t cgroup_id;
};
