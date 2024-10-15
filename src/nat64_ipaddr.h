#ifndef __NAT64_IPADDR_H
#define __NAT64_IPADDR_H

#include <stdlib.h>
#include <stdbool.h>
#include <linux/in.h>
#include <linux/in6.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>


union ipv6_addr {
	__u8 u6_addr8[16];
	__be16 u6_addr16[8];
	__be32 u6_addr32[4];
	struct {
		__be64	_prefix;
		__be64	_suffix;
	};
};

const union ipv6_addr nat64_ipv6_prefix = {
	.u6_addr8 = { 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
const union ipv6_addr nat64_ipv6_mask = {
	.u6_addr8 = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 }
};

__attribute__((__always_inline__)) static inline bool
masked_ipv6_match(const union ipv6_addr *l, const union ipv6_addr *r, const union ipv6_addr *mask)
{
	return (l->_prefix & mask->_prefix) == (r->_prefix & mask->_prefix)
		&& (l->_suffix & mask->_suffix) == (r->_suffix & mask->_suffix);
}

__attribute__((__always_inline__)) static inline int
is_nat64_ipv6_address(struct ipv6hdr *ipv6)
{
	const union ipv6_addr *ipv6_dst_addr = (union ipv6_addr *)(&ipv6->daddr);

	return masked_ipv6_match(ipv6_dst_addr, &nat64_ipv6_prefix, &nat64_ipv6_mask);
}


#endif
