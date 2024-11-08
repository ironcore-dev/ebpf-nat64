#ifndef __NAT64_KERN_H
#define __NAT64_KERN_H

#include <linux/in.h>

#include "nat64_common.h"
#include "nat64_kern_config.h"
#include "nat64_kern_log.h"

#define assert_len(target, end)  \
	if ((void *)(target + 1) > end) { \
		NAT64_LOG_ERROR("Invalid packet length"); \
		return NAT64_ERROR; \
	} \

#define NAT64_KERN_PROG

#include "include/nat64_table_tuple.h"

#include "nat64_checksum.h"
#include "nat64_modify_hdr.h"
#include "nat64_ipv6_addr_check.h"
#include "nat64_flow_handling.h"

#define NAT64_ICMP_HDR_MAX_LENGTH 128 //bytes


#endif
