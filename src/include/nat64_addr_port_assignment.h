#ifndef NAT64_ADDR_PORT_ASSIGNMENT_H
#define NAT64_ADDR_PORT_ASSIGNMENT_H


#include <bpf/bpf_endian.h>
#include <string.h>

#include <linux/bpf.h>

#define NAT64_ADDR_PORT_ASSIGNMENT_POOL_SIZE 16

struct nat64_address_ports_range {
	__u32 addr;
	__u16 port_range[2];
};

struct nat64_address_port_item {
	__u8 used;
	__u16 nat_port;
	__u32 nat_addr;
};

struct nat64_address_port_assignment {
	struct bpf_spin_lock item_semaphore;
	// increasing the number of this items could enhance the capability of peak flow handling
	struct nat64_address_port_item address_port_item[NAT64_ADDR_PORT_ASSIGNMENT_POOL_SIZE];
};

#endif /* __NAT64_ADDR_PORT_ASSIGNMENT_H */
