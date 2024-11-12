#ifndef NAT64_IPV6_ADDR_CHECK_H
#define NAT64_IPV6_ADDR_CHECK_H

#include "../include/nat64_ipaddr.h"

const union ipv6_addr nat64_ipv6_prefix = {
	.u6_addr8 = { 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
const union ipv6_addr nat64_ipv6_mask = {
	.u6_addr8 = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 }
};


static __always_inline bool
masked_ipv6_match(const union ipv6_addr *l, const union ipv6_addr *r, const union ipv6_addr *mask)
{
	return (l->_prefix & mask->_prefix) == (r->_prefix & mask->_prefix)
		&& (l->_suffix & mask->_suffix) == (r->_suffix & mask->_suffix);
}

static __always_inline int
is_nat64_ipv6_address(struct ipv6hdr *ipv6)
{
	const union ipv6_addr *ipv6_dst_addr = (union ipv6_addr *)(&ipv6->daddr);

	return masked_ipv6_match(ipv6_dst_addr, &nat64_ipv6_prefix, &nat64_ipv6_mask);
}


#endif
