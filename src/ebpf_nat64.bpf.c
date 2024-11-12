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



// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, __u32); // Interface index
// 	__type(value, __u64); // Packet count
// 	__uint(max_entries, NAT64_ATTACH_IFACE_MAX_CNT);
// 	__uint(pinning, LIBBPF_PIN_BY_NAME);
// } iface_packet_count_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // IPv4 address
	__type(value, struct nat64_address_ports_range);
	__uint(max_entries, NAT64_ADDR_PORT_POOL_SIZE);
} nat64_address_port_range_map SEC(".maps"); // only used by userspace prog


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct nat64_address_port_item);
	__type(value, __u8);
	__uint(max_entries, NAT64_MAX_ADDR_PORT_IN_USE);
} nat64_address_port_in_use_map SEC(".maps"); // only used by userspace prog


// Function to update the packet count for the given interface index
// static inline void update_packet_count(__u32 iface_index) {
// 	__u64 *count, initial_count = 0;

// 	// Look up the current count for the interface index
// 	count = bpf_map_lookup_elem(&iface_packet_count_map, &iface_index);
// 	if (count) {
// 		// If found, increment the count
// 		__sync_fetch_and_add(count, 1);
// 	} else {
// 		// If not found, create a new entry with initial count
// 		bpf_map_update_elem(&iface_packet_count_map, &iface_index, &initial_count, BPF_ANY);
// 	}
// }

static __u8 flag;

static __always_inline int
process_ipv6_pkt(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ipv6_hdr = (struct ipv6hdr *)nxt_ptr;
	assert_len(ipv6_hdr, data_end);

	struct nat64_table_value new_flow_value = {0};

	if (!is_nat64_ipv6_address(ipv6_hdr))
		return NAT64_OK;

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
		flow_value->timeout_value = NAT64_ASSIGNMENT_LIVENESS_IN_SEC;
		ret = process_nat64_new_outgoing_ipv6_flow(ctx->ingress_ifindex, &flow_sig, flow_value);
		if (NAT64_FAILED(ret)) {
			NAT64_LOG_ERROR("Failed to fetch an assigned nat64 addr and port");
			return NAT64_ERROR;
		}
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
		return NAT64_OK;
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


static __always_inline int
nat64_parse_l2(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 iface_index = ctx->ingress_ifindex; // Get the interface index from the context

	struct ethhdr *eth = data;
	assert_len(eth, data_end);

	// Update the packet count for the interface
	// update_packet_count(iface_index);
	
	if(eth->h_proto == bpf_htons(ETH_P_IP))
		return process_ipv4_pkt(ctx, eth + 1, eth);

	if(eth->h_proto == bpf_htons(ETH_P_IPV6))
		return process_ipv6_pkt(ctx, eth + 1, eth);

	return NAT64_OK;
}

SEC("xdp")
int xdp_nat64(struct xdp_md *ctx)
{
	load_kernel_config();
	if (NAT64_FAILED(nat64_parse_l2(ctx)))
		return XDP_DROP;
	else
		return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
