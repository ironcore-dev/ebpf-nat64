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
} nat64_alloc_map SEC(".maps"); // only used by userspace prog

static __always_inline int
process_ipv6_pkt(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth)
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
process_ipv4_pkt(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth)
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
	if (!flow_value) {
		NAT64_LOG_INFO("No NAT64 mapping found for incoming IPv4 packet. Pass.");
		return NAT64_IGNORE;
	}

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


static __always_inline int nat64_send_packet(struct xdp_md *ctx) {
	struct bpf_fib_lookup fib_params = {};
	int ret;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	// Determine the protocol (IPv4 or IPv6)
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip_hdr = (struct iphdr *)(eth + 1);
		if ((void *)(ip_hdr + 1) > data_end)
			return XDP_DROP;

		// Fill in the FIB lookup parameters for IPv4
		fib_params.family = AF_INET;
		fib_params.ipv4_src = ip_hdr->saddr;
		fib_params.ipv4_dst = ip_hdr->daddr;
		fib_params.tos = ip_hdr->tos;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6_hdr = (struct ipv6hdr *)(eth + 1);
		if ((void *)(ipv6_hdr + 1) > data_end)
			return XDP_DROP;

		// Fill in the FIB lookup parameters for IPv6
		fib_params.family = AF_INET6;
		__builtin_memcpy(fib_params.ipv6_src, ipv6_hdr->saddr.s6_addr, sizeof(fib_params.ipv6_src));
		__builtin_memcpy(fib_params.ipv6_dst, ipv6_hdr->daddr.s6_addr, sizeof(fib_params.ipv6_dst));
		fib_params.flowinfo = ipv6_hdr->flow_lbl[0] << 16 | ipv6_hdr->flow_lbl[1] << 8 | ipv6_hdr->flow_lbl[2];
	} else {
		// Unsupported protocol
		NAT64_LOG_ERROR("Unsupported l3 protocol, cannot send", NAT64_LOG_L3_PROTOCOL(bpf_ntohs(eth->h_proto)));
		return XDP_DROP;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	// Perform the FIB lookup
	ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
		// Drop the packet if FIB lookup fails
		NAT64_LOG_ERROR("FIB lookup failed", NAT64_LOG_ERRNO(ret), NAT64_LOG_IFACE_INDEX(ctx->ingress_ifindex));
		return XDP_DROP;
	}

	// Update Ethernet header with resolved MAC addresses
	__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

	if (__forwarding_mode == NAT64_PKT_FORWARDING_MODE_TX)
		return XDP_TX;
	else
		return bpf_redirect(fib_params.ifindex, 0);
}

static __always_inline int
nat64_process_l2(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int ret;

	struct ethhdr *eth = data;
	if ((void *)(eth+1) > data_end)
		return XDP_DROP;

	// only process IPv4 and IPv6 packets, ignore other types
	if(eth->h_proto == bpf_htons(ETH_P_IP))
		ret = process_ipv4_pkt(ctx, eth + 1, eth);
	else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		ret = process_ipv6_pkt(ctx, eth + 1, eth);
		if (NAT64_FAILED(ret))
			nat64_exporter_increment_drop_pkts();
	} else {
		ret = NAT64_IGNORE;
	}

	if (NAT64_FAILED(ret))
		return XDP_DROP;
	else if (ret == NAT64_IGNORE)
		return XDP_PASS;
	else {
		if (__forwarding_mode == NAT64_PKT_FORWARDING_MODE_KERNEL)
			return XDP_PASS;
		else 
			return nat64_send_packet(ctx);
	}
}

SEC("xdp.frags")
int xdp_nat64_frags(struct xdp_md *ctx)
{
	load_kernel_config();
	return nat64_process_l2(ctx);
}

SEC("xdp")
int xdp_nat64(struct xdp_md *ctx)
{
	load_kernel_config();
	return nat64_process_l2(ctx);
}

char __license[] SEC("license") = "GPL";
