// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0



#ifndef NAT64_KERN_H
#define NAT64_KERN_H

#include "nat64_common.h"
#include "nat64_kern_config.h"
#include "nat64_kern_log.h"


#define NAT64_KERN_PROG

#include "include/nat64_table_tuple.h"

#include "nat64_checksum.h"
#include "nat64_modify_hdr.h"
#include "nat64_ipv6_addr_check.h"
#include "nat64_flow_handling.h"
#include "nat64_tcp_state_tracking.h"
#include "nat64_exporter.h"

#define NAT64_ICMP_HDR_MAX_LENGTH 128 //bytes


#endif
