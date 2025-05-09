// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0


#ifndef NAT64_TABLE_TUPLE_H
#define NAT64_TABLE_TUPLE_H

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
	__u16 tcp_state;
	__u16 timeout_value;
	__u64 last_seen;
	struct bpf_spin_lock item_semaphore;
} __attribute__((aligned(4)));


static __always_inline void
nat64_fill_reverse_key(enum nat64_flow_direction direction, const struct nat64_table_tuple *key, const struct nat64_table_value *value,
								struct nat64_table_tuple *reverse_key)
{
	if (direction == NAT64_FLOW_DIRECTION_OUTGOING) {
		reverse_key->version = NAT64_IP_VERSION_V4; // IPv4
		reverse_key->addr.v4.src_ip = key->addr.v6.dst_ip6.u6_addr32[3]; // Last 4 bytes of IPv6 dst
		reverse_key->addr.v4.dst_ip = value->addr.nat64_v4_addr;
		if (key->protocol == IPPROTO_TCP || key->protocol == IPPROTO_UDP) {
			reverse_key->protocol = key->protocol;
			reverse_key->src_port = key->dst_port; // Swap src and dst
			reverse_key->dst_port = value->port.nat64_port;
		} else {
			reverse_key->protocol = IPPROTO_ICMP;
			reverse_key->src_port = ICMP_ECHOREPLY;
			reverse_key->dst_port = value->port.nat64_port;
		}

	} else {
		reverse_key->version = NAT64_IP_VERSION_V6; // IPv6
		memcpy(&reverse_key->addr.v6.src_ip6, &value->addr.original_ip6, NAT64_IPV6_ADDR_LENGTH);
		memcpy(&reverse_key->addr.v6.dst_ip6.u6_addr8, &nat64_ipv6_prefix, 12);
		memcpy(&reverse_key->addr.v6.dst_ip6.u6_addr32[3], &key->addr.v4.src_ip, 4);
		if (key->protocol == IPPROTO_TCP || key->protocol == IPPROTO_UDP) {
			reverse_key->protocol = key->protocol;
			reverse_key->src_port = value->port.original_port; // Swap src and dst
			reverse_key->dst_port = key->src_port;
		} else {
			reverse_key->protocol = IPPROTO_ICMPV6;
			reverse_key->src_port = bpf_htons(ICMPV6_ECHO_REQUEST);
			reverse_key->dst_port = key->src_port;
		}

	}
}

#endif /* NAT64_TABLE_TUPLE_H */
