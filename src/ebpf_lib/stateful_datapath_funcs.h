// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef STATEFUL_DATAPATH_FUNCS_H
#define STATEFUL_DATAPATH_FUNCS_H

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>

#include <bpf/bpf_helpers.h>

#include "nat64_kern.h"
#include "nat64_kern_log.h"
#include "nat64_table_tuple.h"
#include "nat64_addr_port_assignment.h"
#include "nat64_modify_hdr.h"
#include "nat64_checksum.h"
#include "nat64_exporter.h"
#include "nat64_icmp_error_handling.h"
#include "nat64_ipv6_addr_check.h"

#include "stateful_datapath_maps.h"

// Stateful BPF Functions
static __always_inline int
stateful_process_ipv6_pkt(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ipv6_hdr = (struct ipv6hdr *)nxt_ptr;
	assert_len(ipv6_hdr, data_end);

	struct nat64_table_value new_flow_value = {0};

	if (!is_nat64_ipv6_address(ipv6_hdr))
		return NAT64_IGNORE;

	struct nat64_table_tuple flow_sig = {0};
	struct nat64_table_value *flow_value = NULL;
	int ret;

	ret = fill_flow_signature(&flow_sig, data_end, NAT64_IP_VERSION_V6, (void *)ipv6_hdr, ipv6_hdr->nexthdr, (void *)(ipv6_hdr + 1));
	if (NAT64_FAILED(ret))
		return NAT64_ERROR;

	NAT64_LOG_DEBUG("Filled an IPv6 flow signature", NAT64_LOG_L4_PROTOCOL(flow_sig.protocol),
											NAT64_LOG_SRC_IPV6(flow_sig.addr.v6.src_ip6.u6_addr8),
											NAT64_LOG_DST_IPV6(flow_sig.addr.v6.dst_ip6.u6_addr8),
											NAT64_LOG_L4_PROTO_SRC_PORT(bpf_ntohs(flow_sig.src_port)),
											NAT64_LOG_L4_PROTO_DST_PORT(bpf_ntohs(flow_sig.dst_port)));

	flow_value = bpf_map_lookup_elem(&nat64_v6_v4_map, &flow_sig);

	if (!flow_value) {
		flow_value = &new_flow_value;
		flow_value->last_seen = bpf_ktime_get_ns();
		if (__is_test_mode)
			flow_value->timeout_value = NAT64_TEST_MODE_ASSIGNMENT_LIVENESS_IN_SEC;
		else
			flow_value->timeout_value = NAT64_ASSIGNMENT_LIVENESS_IN_SEC;
		ret = process_nat64_new_outgoing_ipv6_flow(ctx->ingress_ifindex, &flow_sig, flow_value);
		if (NAT64_FAILED(ret)) {
			NAT64_LOG_ERROR("Failed to fetch an assigned nat64 addr and port");
			nat64_exporter_increment_drop_flows();
			return NAT64_ERROR;
		}
		nat64_exporter_increment_accepted_flows();
	}

	// Update the last seen timestamp
	flow_value->last_seen = bpf_ktime_get_ns();

	// process tcp state
	if (flow_sig.protocol == IPPROTO_TCP)
		nat64_process_tcp_state(NAT64_FLOW_DIRECTION_OUTGOING, data_end,
								(const struct nat64_table_tuple *)&flow_sig, flow_value, (const struct tcphdr *)(ipv6_hdr + 1));

	ret = convert_v6_pkt_to_v4_pkt(ctx, flow_value, eth, ipv6_hdr);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to convert v6 pkt to v4 pkt");
		NAT64_ERROR;
	}

	return NAT64_OK;
}


static __always_inline int
stateful_process_ipv4_pkt(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ipv4_hdr = (struct iphdr *)nxt_ptr;
	assert_len(ipv4_hdr, data_end);

	struct nat64_table_tuple flow_sig = {0};
	struct nat64_table_value *flow_value;
	int ret;

	// Fill the flow signature
	ret = fill_flow_signature(&flow_sig, data_end, NAT64_IP_VERSION_V4, ipv4_hdr, ipv4_hdr->protocol, (void *)(ipv4_hdr + 1));
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to fill flow signature for IPv4 packet");
		return NAT64_ERROR;
	}

	// Lookup the flow in the NAT64 v4->v6 map
	flow_value = bpf_map_lookup_elem(&nat64_v4_v6_map, &flow_sig);
	if (!flow_value)
		return NAT64_IGNORE;

	NAT64_LOG_DEBUG("Filled an IPv4 flow signature", NAT64_LOG_L4_PROTOCOL(flow_sig.protocol),
		NAT64_LOG_SRC_IPV4(flow_sig.addr.v4.src_ip),
		NAT64_LOG_DST_IPV4(flow_sig.addr.v4.dst_ip),
		NAT64_LOG_L4_PROTO_SRC_PORT(bpf_ntohs(flow_sig.src_port)),
		NAT64_LOG_L4_PROTO_DST_PORT(bpf_ntohs(flow_sig.dst_port)));

	// Update the last seen timestamp
	flow_value->last_seen = bpf_ktime_get_ns();

	if (flow_sig.protocol == IPPROTO_TCP)
		nat64_process_tcp_state(NAT64_FLOW_DIRECTION_INCOMING, data_end,
								(const struct nat64_table_tuple *)&flow_sig, flow_value, (const struct tcphdr *)(ipv4_hdr + 1));

	// Convert the IPv4 packet to IPv6
	ret = convert_v4_pkt_to_v6_pkt(ctx, flow_value, eth, ipv4_hdr);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to convert IPv4 packet to IPv6");
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

#endif // STATEFUL_DATAPATH_FUNCS_H
