#ifndef __NAT64_KERN_H
#define __NAT64_KERN_H

#include <linux/in.h>

#include "nat64_common.h"

#define assert_len(target, end)  \
	if ((void *)(target + 1) > end) \
		return NAT64_ERROR;

#define NAT64_KERN_PROG

#include "nat64_checksum.h"
#include "nat64_table_tuple.h"
#include "nat64_print.h"
#include "nat64_modify_hdr.h"


#define NAT64_V6_V4_HDR_LENGTH_DIFF ((int)(sizeof(struct ipv6hdr) - sizeof(struct iphdr)))
#define NAT64_ICMP_HDR_MAX_LENGTH 128 //bytes



#endif
