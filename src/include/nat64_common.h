#ifndef __NAT64_COMMON_H
#define __NAT64_COMMON_H

#include <stdlib.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>

#include "nat64_addr_port_assignment.h"
#include "nat64_table_tuple.h"

#define NAT64_OK 0
#define NAT64_ERROR (-1)

#define NAT64_FAILED(RET) \
	((RET) < 0)

#define NAT64_ATTACH_IFACE_MAX_CNT 4 //Please use 4,8,16,32, etc.
#define NAT64_ADDR_PORT_POOL_SIZE 3
#define NAT64_MAX_PORT_PER_ADDR 16384 // (65535-49152)
#define NAT64_MAX_ADDR_PORT_IN_USE (NAT64_ADDR_PORT_POOL_SIZE * NAT64_MAX_PORT_PER_ADDR)
#define NAT64_IPV6_ADDR_LENGTH 16
#define NAT64_FLOW_HANDLE_CAPACITY 8192

// sizeof(nat64_ipv6_new_flow_event) * NAT64_ATTACH_IFACE_MAX_CNT.
// max 1 new pending flow needs to request NAT addr-port assighment.
#define NAT64_MAX_PENDING_NEW_FLOW_ON_IFACE 4
#define NAT64_NEW_FLOW_EVENT_RINGBUFFER_SIZE \
		(sizeof(struct nat64_ipv6_new_flow_event) * NAT64_ATTACH_IFACE_MAX_CNT * NAT64_MAX_PENDING_NEW_FLOW_ON_IFACE)

#define NAT64_PORT_MAX_RANDOM_RETRY 1

#define NAT64_ADDR_PORT_ASSIGNMENT_FETCH_RETRY 3


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


#endif /* __NAT64_COMMON_H */
