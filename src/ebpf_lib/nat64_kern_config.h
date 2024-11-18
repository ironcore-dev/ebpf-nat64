#ifndef NAT64_CONFIG_H
#define NAT64_CONFIG_H


#include <bpf/bpf_helpers.h>

#include "nat64_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct nat64_kernel_config);
	__uint(max_entries, 1);
} nat64_kernel_config_map SEC(".maps");


static bool __is_config_loaded = false;

__u8 __log_level = 0;

static __always_inline void load_kernel_config()
{

	if (!__is_config_loaded) {
		__u16 key = NAT64_KERNEL_CONFIG_MAP_KEY;
		struct nat64_kernel_config *config = bpf_map_lookup_elem(&nat64_kernel_config_map, &key);

		if (config) {
			__log_level = config->log_level;
			__is_config_loaded = true;
		}
	}
}


#endif
