// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0


#ifndef NAT64_IPADDR_H
#define NAT64_IPADDR_H

#include <stdlib.h>
#include <stdbool.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>

#define NAT64_IPV6_ADDR_LENGTH 16

union ipv6_addr {
	__u8 u6_addr8[16];
	__be16 u6_addr16[8];
	__be32 u6_addr32[4];
	struct {
		__be64	_prefix;
		__be64	_suffix;
	};
};

extern const union ipv6_addr nat64_ipv6_prefix; 
extern const union ipv6_addr nat64_ipv6_mask; 

#endif
