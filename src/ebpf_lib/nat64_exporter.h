#ifndef NAT64_EXPORTER_H
#define NAT64_EXPORTER_H


#include "nat64_exporter_stats.h"


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct nat64_exporter_stats);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat64_stats_map SEC(".maps");

#define NAT64_EXPORTER_STATS_FIELD_INCREMENT(name) \
	static __always_inline int nat64_exporter_increment_##name(void) \
	{ \
		struct nat64_exporter_stats *stats; \
		struct nat64_exporter_stats init_val = {0}; \
		__u32 key = 0; \
		stats = bpf_map_lookup_elem(&nat64_stats_map, &key); \
		if (!stats) { \
			init_val.name = 1; \
			bpf_map_update_elem(&nat64_stats_map, &key, &init_val, BPF_NOEXIST); \
		} \
		if (stats && stats->name) \
			__sync_fetch_and_add(&stats->name, 1); \
		else \
			return NAT64_ERROR; \
		return NAT64_OK; \
	}

NAT64_EXPORTER_STATS_FIELD_INCREMENT(drop_pkts);;
NAT64_EXPORTER_STATS_FIELD_INCREMENT(drop_flows);;
NAT64_EXPORTER_STATS_FIELD_INCREMENT(accepted_flows);;

#endif
