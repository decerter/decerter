// SPDX-License-Identifier: GPL-2.0-only OR MIT

//the capture object shares the flow_map of the redirect object
#define SHARED_FLOW_MAP

#include "shared.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

//cgroup_skb return values
#define SKB_DROP		0
#define SKB_PASS		1

//check return values
#define OK				0
#define NOK				1

//direction of a packet as its socket sees it
#define EGRESS			0
#define INGRESS			1

//the packet bytes are copied in chunks of a size the verifier knows, MAX_CHUNKS chunks are the largest packet a record can hold
#define CHUNK_SIZE		256
#define MAX_CHUNKS		1024
#define MAX_SNAPLEN		(CHUNK_SIZE * MAX_CHUNKS)

char __license[] SEC("license") = "Dual MIT/GPL";

//Value: most bytes of a packet that are copied, counted from the IP header, at most MAX_SNAPLEN, set from Go before load
volatile const uint32_t snaplen = 0;

//start of a packet_map record, captured_length bytes of the packet follow it
//cookie: socket cookie, the key of flow_map
//timestamp_ns: bpf_ktime_get_boot_ns() (CLOCK_BOOTTIME) when the program saw the packet
//length: bytes of the packet from the IP header on, a GSO or GRO packet is one packet with its whole length
//captured_length: bytes that follow the header, length cut to snaplen
//direction: EGRESS or INGRESS
struct packet_header {
	uint64_t cookie;
	uint64_t timestamp_ns;
	uint32_t length;
	uint32_t captured_length;
	uint8_t direction;
	uint8_t padding[7];
};

//Key: ringbuf, Value: struct packet_header and the packet bytes behind it, one record of its own size per packet of a recorded socket, read by the capture writer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 25);
	__type(value, struct packet_header);
} packet_map SEC(".maps");

//Key: 0, Value: packets of recorded sockets that were not copied because packet_map was full, per CPU, the capture writer adds them up
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, uint64_t);
} drop_map SEC(".maps");

//Count a packet that found no room in packet_map
uint16_t count_drop(void)
{
	uint32_t index = 0;
	uint64_t *dropped = bpf_map_lookup_elem(&drop_map, &index);

	//the only slot of an ARRAY map is always there
	if (!dropped)
	{
		return NOK;
	}

	*dropped += 1;

	return OK;
}

//Copy the packet of a recorded socket into packet_map: the header and the first snaplen bytes from the IP header on, cgroup_skb data starts there
uint16_t capture_packet(struct __sk_buff *skb, uint8_t direction)
{
	if (!skb)
	{
		return NOK;
	}

	uint64_t cookie = bpf_get_socket_cookie(skb);

	//every packet of every socket of the system gets here, only the ones of recorded sockets go further
	if (!bpf_map_lookup_elem(&flow_map, &cookie))
	{
		return OK;
	}

	struct packet_header header = {
		.cookie = cookie,
		.timestamp_ns = bpf_ktime_get_boot_ns(),
		.length = skb->len,
		.captured_length = skb->len,
		.direction = direction,
		.padding = {0, 0, 0, 0, 0, 0, 0}
	};

	if (header.captured_length > snaplen)
	{
		header.captured_length = snaplen;
	}

	if (header.captured_length > MAX_SNAPLEN)
	{
		header.captured_length = MAX_SNAPLEN;
	}

	//the record is reserved at the size of this packet, a small packet does not pay for the snaplen
	struct bpf_dynptr record;

	//the verifier wants a failed reserve discarded too
	if (bpf_ringbuf_reserve_dynptr(&packet_map, sizeof(struct packet_header) + header.captured_length, 0, &record) != 0)
	{
		bpf_ringbuf_discard_dynptr(&record, 0);
		count_drop();

#ifdef DEBUG
		bpf_printk("skb === capture_packet packet_map is full, packet dropped");
#endif

		return NOK;
	}

	if (bpf_dynptr_write(&record, 0, &header, sizeof(struct packet_header), 0) != 0)
	{
		bpf_ringbuf_discard_dynptr(&record, 0);

#ifdef DEBUG
		bpf_printk("skb === capture_packet header write failed");
#endif

		return NOK;
	}

	//whole chunks go from the packet straight into the record: a slice of the record has to have a constant size
	int index = 0;

	bpf_for(index, 0, MAX_CHUNKS)
	{
		uint32_t offset = index * CHUNK_SIZE;

		if (offset + CHUNK_SIZE > header.captured_length)
		{
			break;
		}

		void *chunk = bpf_dynptr_data(&record, sizeof(struct packet_header) + offset, CHUNK_SIZE);

		if ((!chunk) || (bpf_skb_load_bytes(skb, offset, chunk, CHUNK_SIZE) != 0))
		{
			bpf_ringbuf_discard_dynptr(&record, 0);

#ifdef DEBUG
			bpf_printk("skb === capture_packet chunk copy failed");
#endif

			return NOK;
		}
	}

	//the rest is shorter than a chunk and its length is only known at run time, so it goes through the stack
	uint32_t rest_length = header.captured_length % CHUNK_SIZE;

	if (rest_length > 0)
	{
		uint8_t rest[CHUNK_SIZE];
		uint32_t offset = header.captured_length - rest_length;

		//bpf_skb_load_bytes takes no length that can be zero, and the verifier of 6.6 does not learn from the check above that rest_length is at least 1
		//so the same value is built in a way that shows its bounds, the barrier keeps clang from folding it back
		rest_length -= 1;
		barrier_var(rest_length);
		rest_length &= CHUNK_SIZE - 1;
		rest_length += 1;

		if ((bpf_skb_load_bytes(skb, offset, rest, rest_length) != 0) || (bpf_dynptr_write(&record, sizeof(struct packet_header) + offset, rest, rest_length, 0) != 0))
		{
			bpf_ringbuf_discard_dynptr(&record, 0);

#ifdef DEBUG
			bpf_printk("skb === capture_packet rest copy failed");
#endif

			return NOK;
		}
	}

	bpf_ringbuf_submit_dynptr(&record, 0);

	return OK;
}
