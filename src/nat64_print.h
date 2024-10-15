#ifndef __NAT64_PRINT_H
#define __NAT64_PRINT_H	

#include "nat64_table_tuple.h"

#ifdef NAT64_KERN_PROG

#include <bpf/bpf_helpers.h>
#define NAT64_PRINT(MESSAGE, ...) bpf_printk(MESSAGE, ##__VA_ARGS__)

#else

#define NAT64_PRINT(MESSAGE, ...) printf(MESSAGE, ##__VA_ARGS__)

#endif




static __always_inline void print_addr_bytes(const struct nat64_table_tuple *tuple)
{
	if (!tuple) {
		NAT64_PRINT("Error: Null pointer passed to print_addr_bytes");
		return;
	}

	if (tuple->version == 1) {
		// IPv4
		NAT64_PRINT("IPv4 src: %u.%u.%u.%u \n",
			(tuple->addr.v4.src_ip >> 24) & 0xFF,
			(tuple->addr.v4.src_ip >> 16) & 0xFF,
			(tuple->addr.v4.src_ip >> 8) & 0xFF,
			tuple->addr.v4.src_ip & 0xFF);
		
		NAT64_PRINT("IPv4 dst: %u.%u.%u.%u \n",
			(tuple->addr.v4.dst_ip >> 24) & 0xFF,
			(tuple->addr.v4.dst_ip >> 16) & 0xFF,
			(tuple->addr.v4.dst_ip >> 8) & 0xFF,
			tuple->addr.v4.dst_ip & 0xFF);
	} else if (tuple->version == 2) {
		// IPv6 (print in parts)
		NAT64_PRINT("IPv6 src part 1: %02x%02x:%02x%02x:%02x%02x:%02x%02x \n",
			tuple->addr.v6.src_ip6.u6_addr8[0], tuple->addr.v6.src_ip6.u6_addr8[1],
			tuple->addr.v6.src_ip6.u6_addr8[2], tuple->addr.v6.src_ip6.u6_addr8[3],
			tuple->addr.v6.src_ip6.u6_addr8[4], tuple->addr.v6.src_ip6.u6_addr8[5],
			tuple->addr.v6.src_ip6.u6_addr8[6], tuple->addr.v6.src_ip6.u6_addr8[7]);
		NAT64_PRINT("IPv6 src part 2: %02x%02x:%02x%02x:%02x%02x:%02x%02x \n",
			tuple->addr.v6.src_ip6.u6_addr8[8], tuple->addr.v6.src_ip6.u6_addr8[9],
			tuple->addr.v6.src_ip6.u6_addr8[10], tuple->addr.v6.src_ip6.u6_addr8[11],
			tuple->addr.v6.src_ip6.u6_addr8[12], tuple->addr.v6.src_ip6.u6_addr8[13],
			tuple->addr.v6.src_ip6.u6_addr8[14], tuple->addr.v6.src_ip6.u6_addr8[15]);

		NAT64_PRINT("IPv6 dst part 1: %02x%02x:%02x%02x:%02x%02x:%02x%02x \n",
			tuple->addr.v6.dst_ip6.u6_addr8[0], tuple->addr.v6.dst_ip6.u6_addr8[1],
			tuple->addr.v6.dst_ip6.u6_addr8[2], tuple->addr.v6.dst_ip6.u6_addr8[3],
			tuple->addr.v6.dst_ip6.u6_addr8[4], tuple->addr.v6.dst_ip6.u6_addr8[5],
			tuple->addr.v6.dst_ip6.u6_addr8[6], tuple->addr.v6.dst_ip6.u6_addr8[7]);
		NAT64_PRINT("IPv6 dst part 2: %02x%02x:%02x%02x:%02x%02x:%02x%02x \n",
			tuple->addr.v6.dst_ip6.u6_addr8[8], tuple->addr.v6.dst_ip6.u6_addr8[9],
			tuple->addr.v6.dst_ip6.u6_addr8[10], tuple->addr.v6.dst_ip6.u6_addr8[11],
			tuple->addr.v6.dst_ip6.u6_addr8[12], tuple->addr.v6.dst_ip6.u6_addr8[13],
			tuple->addr.v6.dst_ip6.u6_addr8[14], tuple->addr.v6.dst_ip6.u6_addr8[15]);
	} else {
		NAT64_PRINT("Error: Unknown IP version %d", tuple->version);
	}

	NAT64_PRINT("Protocol: %u, Src Port: %u, Dst Port: %u \n",
		tuple->protocol, bpf_ntohs(tuple->src_port), bpf_ntohs(tuple->dst_port));
}

#endif /* __NAT64_PRINT_H */
