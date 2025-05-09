// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0



#ifndef NAT64_PROFILE_H
#define NAT64_PROFILE_H

#include "bpf_helpers.h"
#include <linux/types.h>

struct timing_stats {
	__u64 sum;
	__u64 sum_squares;
	__u32 count;
};

/*
 * Usage:
 * include "nat64_profile.h" in the file that has the function you want to profile
 *
 * CREATE_STATS(STATS_NAME) // put this in the file that has the function you want to profile
 * START_TIMER(STATS_NAME) // put this at the beginning of the function you want to profile
 * END_TIMER(STATS_NAME, MAX_COUNTER) // put this at the end of the function you want to profile
 * MAX_COUNTER is the maximum number of times the function can be called before the stats are printed
 *
 * Example:
 * CREATE_STATS(nat64_lookup);
 * START_TIMER(nat64_lookup);
 * END_TIMER(nat64_lookup, 100)
 *
 * to print the stats, run `cat /sys/kernel/debug/tracing/trace_pipe`
 */

#define CREATE_STATS(STATS_NAME) static struct timing_stats stats_##STATS_NAME = {0}

#define START_TIMER(STATS_NAME) __u64 start_time_##STATS_NAME = bpf_ktime_get_ns()
#define END_TIMER(STATS_NAME, MAX_COUNTER) update_stats(&(stats_##STATS_NAME), (bpf_ktime_get_ns() - start_time_##STATS_NAME), #STATS_NAME, MAX_COUNTER)


static __always_inline __u64 bpf_sqrt(__u64 x)
{
	if (x == 0)
		return 0;

	__u64 result = x;
	__u64 last;

	// Simple Newton's method, limited iterations for BPF
	#pragma unroll
	for (int i = 0; i < 8; i++) {
		last = result;
		result = (result + x / result) >> 1;
		if (result >= last)
			break;
	}
	return result;
}

static __always_inline void update_stats(struct timing_stats *stats, __u64 duration, const char *operation, __u32 max_count)
{
	stats->sum += duration;
	stats->sum_squares += duration * duration;
	stats->count++;

	if (stats->count == max_count) {
		__u64 avg = stats->sum / max_count;
		__u64 variance = (stats->sum_squares / max_count) - (avg * avg);
		__u64 stddev = bpf_sqrt(variance);

		bpf_printk("%s stats: avg=%llu ns, stddev=%llu ns", operation, avg, stddev);

		// Reset stats
		stats->sum = 0;
		stats->sum_squares = 0;
		stats->count = 0;
	}
}
#endif
