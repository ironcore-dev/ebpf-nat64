// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0


#ifndef NAT64_COMMON_H
#define NAT64_COMMON_H

#include <bpf/bpf_endian.h>

#include "nat64_ipaddr.h"

#define NAT64_OK 0
#define NAT64_ERROR (-1)
#define NAT64_IGNORE 1

#define NAT64_FAILED(RET) \
	((RET) < 0)

#define NAT64_ATTACH_IFACE_MAX_CNT 4 //Please use 4,8,16,32, etc.
#define NAT64_ADDR_PORT_POOL_SIZE 3
#define NAT64_MAX_PORT_PER_ADDR 16384 // (65535-49152)
#define NAT64_MAX_ADDR_PORT_IN_USE (NAT64_ADDR_PORT_POOL_SIZE * NAT64_MAX_PORT_PER_ADDR)
#define NAT64_FLOW_HANDLE_CAPACITY (16384 * 5)

#define NAT64_ASSIGNMENT_LIVENESS_IN_SEC 10
#define NAT64_TEST_MODE_ASSIGNMENT_LIVENESS_IN_SEC 3
#define NAT64_ASSIGNMENT_LIVENESS_TCP_ESTABLISHED_IN_SEC 86400 //(24 * 60 * 60)
#define NAT64_SEC_TO_NANO(SEC) (1000ULL * 1000ULL * 1000ULL * SEC)

// sizeof(nat64_ipv6_new_flow_event) * NAT64_ATTACH_IFACE_MAX_CNT.
// max 1 new pending flow needs to request NAT addr-port assighment.
#define NAT64_MAX_PENDING_NEW_FLOW_ON_IFACE 4
#define NAT64_NEW_FLOW_EVENT_RINGBUFFER_SIZE \
		(sizeof(struct nat64_ipv6_new_flow_event) * NAT64_ATTACH_IFACE_MAX_CNT * NAT64_MAX_PENDING_NEW_FLOW_ON_IFACE)

#define NAT64_PORT_MAX_RANDOM_RETRY 1

#define NAT64_ADDR_PORT_ASSIGNMENT_FETCH_RETRY 10

#define NAT64_KERNEL_CONFIG_MAP_KEY 0


// Define pkt forwarding mode
#define NAT64_PKT_FORWARDING_MODE_KERNEL	0
#define NAT64_PKT_FORWARDING_MODE_TX		1
#define NAT64_PKT_FORWARDING_MODE_REDIRECT	2

#define NAT64_V6_V4_HDR_LENGTH_DIFF ((int)(sizeof(struct ipv6hdr) - sizeof(struct iphdr)))
#define NAT64_EHT_IPv6_ICMPv6_HDR_LEN ((int)(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr)))

enum nat64_ip_version {
	NAT64_IP_VERSION_NON,
	NAT64_IP_VERSION_V4,
	NAT64_IP_VERSION_V6,
};

enum nat64_flow_direction {
	NAT64_FLOW_DIRECTION_OUTGOING,
	NAT64_FLOW_DIRECTION_INCOMING,
};

struct nat64_ipv6_new_flow_event {
	__u32 iface_index;
};

struct nat64_kernel_config {
	__u8 log_level;
	__u8 enable_icmp_icmp6_cksum_recalc;
	__u8 enable_tcp_udp_cksum_recalc;
	__u8 test_mode;
	__u8 forwarding_mode;
};


#endif /* __NAT64_COMMON_H */
