// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef STATELESS_DATAPATH_MAPS_H
#define STATELESS_DATAPATH_MAPS_H

#include <linux/bpf.h>

// Stateless BPF Maps
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, union ipv6_addr);
	__type(value, __u32);
	__uint(max_entries, 5); // Adjust size as needed
} nat64_stateless_v6_v4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, union ipv6_addr);
	__uint(max_entries, 5); // Adjust size as needed
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat64_stateless_v4_v6_map SEC(".maps");

#endif // STATELESS_DATAPATH_MAPS_H
