#ifndef NAT64_EXPORTER_STATS_H
#define NAT64_EXPORTER_STATS_H

#include <bpf/bpf_helpers.h>

#define NAT64_EXPORTER_STATS_FIELD(name) \
	__u64 name

struct nat64_exporter_stats {
	NAT64_EXPORTER_STATS_FIELD(drop_pkts);
	NAT64_EXPORTER_STATS_FIELD(drop_flows);
	NAT64_EXPORTER_STATS_FIELD(accepted_flows);
};


#endif
