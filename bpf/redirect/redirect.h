// SPDX-License-Identifier: GPL-2.0-only OR MIT

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

//cgroup sock_addr return values
#define SOCK_REJECT		0
#define SOCK_ALLOW		1

//check return values
#define OK				0
#define NOK				1

char __license[] SEC("license") = "Dual MIT/GPL";

//Key: uid of the connecting process, Value: number of connect calls
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65535);
	__type(key, uint32_t);
	__type(value, uint64_t);
} counter_map SEC(".maps");

//Increment the connect counter of the current uid
uint16_t count_connect(void)
{
	uint32_t uid = bpf_get_current_uid_gid();
	uint64_t *count = bpf_map_lookup_elem(&counter_map, &uid);

	if (count)
	{
		__sync_fetch_and_add(count, 1);

		return OK;
	}

	uint64_t first_count = 1;

	if (bpf_map_update_elem(&counter_map, &uid, &first_count, BPF_NOEXIST) != 0)
	{
		return NOK;
	}

	return OK;
}
