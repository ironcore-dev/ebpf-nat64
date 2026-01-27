// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0



#ifndef NAT64_CONFIG_H
#define NAT64_CONFIG_H


#include <bpf/bpf_helpers.h>

#include "nat64_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct nat64_kernel_config);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat64_kernel_config_map SEC(".maps");

static bool __is_config_loaded = false;
static bool __is_test_mode = false;
static int __forwarding_mode = NAT64_PKT_FORWARDING_MODE_KERNEL;
static bool __is_icmp_icmp6_cksum_recalc_enabled = false;
static bool __is_tcp_udp_cksum_recalc_enabled = false;

__u8 __log_level = 0;

static __always_inline void load_kernel_config()
{

	if (!__is_config_loaded) {
		__u16 key = NAT64_KERNEL_CONFIG_MAP_KEY;
		struct nat64_kernel_config *config = bpf_map_lookup_elem(&nat64_kernel_config_map, &key);

		if (config) {
			__log_level = config->log_level;

			__is_icmp_icmp6_cksum_recalc_enabled = config->enable_icmp_icmp6_cksum_recalc;
			__is_tcp_udp_cksum_recalc_enabled = config->enable_tcp_udp_cksum_recalc;
			__is_test_mode = config->test_mode;
			__forwarding_mode = config->forwarding_mode;
			__is_config_loaded = true;
		}
	}
}


#endif
