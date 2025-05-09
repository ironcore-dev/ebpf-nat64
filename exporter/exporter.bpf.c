// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

#include "nat64_exporter_stats.h"

__s64 bpf_map_sum_elem_count(struct bpf_map *map) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct nat64_exporter_stats);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat64_stats_map SEC(".maps");


static __always_inline  int is_not_same_string(const char *cs, const char *ct, int size)
{
	int len = 0;
	unsigned char c1, c2;

	for (len = 0; len < size; len++) {
		c1 = *cs++;
		c2 = *ct++;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
	}
	return 0;
}

SEC("iter/bpf_map_elem")
int dump_exporter_stats_map(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct bpf_map *map = ctx->map;
	__u32 *key = ctx->key;
	const struct nat64_exporter_stats *stats = (const struct nat64_exporter_stats *)ctx->value;

	if (!map || !key || !stats
		|| is_not_same_string(map->name, "nat64_stats_map", 16))
		return 0; // Skip if the data is invalid or not target map

	BPF_SEQ_PRINTF(seq, "map_id=%4u map_name=%-16s drop_pkts=%10llu drop_flows=%10llu accepted_flows=%10lld \n",
						map->id, map->name,
						stats->drop_pkts, stats->drop_flows, stats->accepted_flows);

	return 0;
}

SEC("iter/bpf_map")
int dump_nat64_map_fullness(struct bpf_iter__bpf_map *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct bpf_map *map = ctx->map;

	if (!map)
		return 0;

	if (!is_not_same_string(map->name, "nat64_v6_v4_map", 16) ||
		!is_not_same_string(map->name, "nat64_v4_v6_map", 16) ||
		!is_not_same_string(map->name, "nat64_alloc_map", 16)) {
		BPF_SEQ_PRINTF(seq, "map_id=%4u map_name=%-16s max_entries=%10d curr_elements=%10lld\n", map->id, map->name,
					map->max_entries, bpf_map_sum_elem_count(map));
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
