#ifndef __NAT64_TABLE_TUPLE_H
#define __NAT64_TABLE_TUPLE_H

#include <linux/in.h>
#include <string.h>
#include <bpf/bpf_endian.h>


#include "nat64_ipaddr.h"

struct nat64_table_tuple {
	__u8 version; // IP version (IPv4 or IPv6)
	__u8 protocol; // Protocol (TCP/UDP)
	__be16 src_port; // Source port
	__be16 dst_port; // Destination port
	union {
		struct {
			__u32 src_ip; // IPv4 source address
			__u32 dst_ip; // IPv4 destination address
		} v4;
		struct {
			union ipv6_addr src_ip6; // IPv6 source address
			union ipv6_addr dst_ip6; // IPv6 destination address
		} v6;
	} addr;
} __attribute__((aligned(4)));

struct nat64_table_value {
	union {
		__be16 nat64_port;
		__be16 original_port;
	} port;
	union {
		__u32 nat64_v4_addr;
		__u8 original_ip6[16];
	} addr;
	__u64 last_seen;
} __attribute__((aligned(4)));


#endif /* __NAT64_TABLE_TUPLE_H */
