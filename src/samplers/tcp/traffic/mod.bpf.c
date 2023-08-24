// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
// Copyright (c) 2023 The Rezolus Authors

// NOTICE: this file is based off `tcptop.bpf.c` from the BCC project
// <https://github.com/iovisor/bcc/> and has been modified for use within
// Rezolus.

// This BPF program probes TCP send and receive paths to get the number of
// segments and bytes transmitted as well as the size distributions.

#include <vmlinux.h>
#include "../../../common/bpf/histogram.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* Taken from kernel include/linux/socket.h. */
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/

#define TCP_RX_BYTES 0
#define TCP_TX_BYTES 1
#define TCP_RX_SEGMENTS 2
#define TCP_TX_SEGMENTS 3

#define MAX_TRACEABLE_CPU 32
#define TCP_TRACE_INDEX_BYTES 0
#define TCP_TRACE_SIZE (0x100000)
#define TCP_TRACE_INDEX_MASK (0xfffff)

// counters
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 8192); // good for up to 1024 cores w/ 8 counters
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 7424);
} rx_size SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 7424);
} tx_size SEC(".maps");

// tcp_trace_index, one 4K page, max 64 CPUs with 64 bytes per CPU pointing to the tail of the ring buffer
// 8 * cpuid + TCP_TRACE_INDEX_BYTES is the head of the ring buffer
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 512); 
} tcp_trace_index SEC(".maps");

// 256 MB size buffer: 32 CPUs, each CPU has 1M 8-byte elements
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 33554432);
} tcp_trace SEC(".maps");

static int probe_ip(bool receiving, struct sock *sk, size_t size)
{
	u16 family;
	u64 *cnt;
	u32 idx;
  u32 sk_portpair;
  u64 sk_addrpair;
  //u32 sk_hash;
  u32 cpuid;
  u64 now;
  u32 trace_idx;
  u32 timestamp_idx;
  u32 event_head_idx;
  u32 event_payload_idx;
  u64 *trace_offset;
  u64 *timestamp;
  // [bit 63]: 1 receiving, 0 sending
  // [bit 62 - 32]: low 31 bits of the nanosecond timestamp
  // [bit 31 - 0]: sk_hash
  u64 event;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);

	/* drop */
	if (family != AF_INET && family != AF_INET6) {
		return 0;
	}

  //sk_hash = BPF_CORE_READ(sk, __sk_common.skc_hash);
  sk_portpair = BPF_CORE_READ(sk, __sk_common.skc_portpair);
  sk_addrpair = BPF_CORE_READ(sk, __sk_common.skc_addrpair);
  cpuid = bpf_get_smp_processor_id();
  if (cpuid < MAX_TRACEABLE_CPU) {
    now = bpf_ktime_get_ns();
    trace_idx = 8 * bpf_get_smp_processor_id() + TCP_TRACE_INDEX_BYTES;  
    timestamp_idx = trace_idx + 1; 
    trace_offset = bpf_map_lookup_elem(&tcp_trace_index, &trace_idx); 
    timestamp = bpf_map_lookup_elem(&tcp_trace_index, &timestamp_idx);
    if ((trace_offset != NULL) && (timestamp != NULL)) {
      if (receiving)
        event = ((now | 0x80000000) << 32) | sk_portpair;
      else
        event = ((now & 0x7fffffff) << 32) | sk_portpair;    
      event_head_idx = cpuid * TCP_TRACE_SIZE + ((*trace_offset) & TCP_TRACE_INDEX_MASK);
      event_payload_idx = event_head_idx + 1;
      
      if (bpf_map_update_elem(&tcp_trace, &event_head_idx, &event, BPF_ANY) == 0) {
        *trace_offset += 1;
      }
      if (bpf_map_update_elem(&tcp_trace, &event_payload_idx, &sk_addrpair, BPF_ANY) == 0) {
        *trace_offset += 1;
      }
      //*trace_offset += 2;
      *timestamp = now;
    }
  }


	if (receiving) {
		idx = 8 * bpf_get_smp_processor_id() + TCP_RX_BYTES;
		cnt = bpf_map_lookup_elem(&counters, &idx);

		if (cnt) {
			__sync_fetch_and_add(cnt, (u64) size);
		}

		idx = value_to_index((u64) size);
		cnt = bpf_map_lookup_elem(&rx_size, &idx);

		if (cnt) {
			__sync_fetch_and_add(cnt, 1);
		}

		idx = 8 * bpf_get_smp_processor_id() + TCP_RX_SEGMENTS;
		cnt = bpf_map_lookup_elem(&counters, &idx);

		if (cnt) {
			__sync_fetch_and_add(cnt, 1);
		}
	} else {
		idx = 8 * bpf_get_smp_processor_id() + TCP_TX_BYTES;
		cnt = bpf_map_lookup_elem(&counters, &idx);

		if (cnt) {
			__sync_fetch_and_add(cnt, (u64) size);
		}

		idx = value_to_index((u64) size);
		cnt = bpf_map_lookup_elem(&tx_size, &idx);

		if (cnt) {
			__sync_fetch_and_add(cnt, 1);
		}

		idx = 8 * bpf_get_smp_processor_id() + TCP_TX_SEGMENTS;
		cnt = bpf_map_lookup_elem(&counters, &idx);

		if (cnt) {
			__sync_fetch_and_add(cnt, 1);
		}
	}

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	return probe_ip(false, sk, size);
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0) {
		return 0;
	}

	return probe_ip(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";