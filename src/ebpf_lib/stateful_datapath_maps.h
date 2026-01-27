// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef STATEFUL_DATAPATH_MAPS_H
#define STATEFUL_DATAPATH_MAPS_H

#include <linux/bpf.h>
#include "nat64_table_tuple.h"
#include "nat64_addr_port_assignment.h"
#include "nat64_common.h"

// Stateful BPF Maps

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // IPv4 address
	__type(value, struct nat64_address_ports_range);
	__uint(max_entries, NAT64_ADDR_PORT_POOL_SIZE);
} nat64_addr_port_range_map SEC(".maps"); // only used by userspace prog

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct nat64_address_port_item);
	__type(value, __u8);
	__uint(max_entries, NAT64_MAX_ADDR_PORT_IN_USE);
} nat64_alloc_map SEC(".maps");

#endif // STATEFUL_DATAPATH_MAPS_H
