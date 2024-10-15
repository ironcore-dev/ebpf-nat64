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
	__type(key, struct nat64_table_tuple);
	__type(value, struct nat64_table_value);
	__uint(max_entries, NAT64_FLOW_HANDLE_CAPACITY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat64_v4_v6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct nat64_table_tuple);
	__type(value, struct nat64_table_value);
	__uint(max_entries, NAT64_FLOW_HANDLE_CAPACITY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat64_v6_v4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // Interface index
	__type(value, __u64); // Packet count
	__uint(max_entries, NAT64_ATTACH_IFACE_MAX_CNT);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} iface_packet_count_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct nat64_address_port_assignment);
	__uint(max_entries, NAT64_ATTACH_IFACE_MAX_CNT);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat64_address_assignment_map SEC(".maps");

struct {
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, NAT64_NEW_FLOW_EVENT_RINGBUFFER_SIZE);
} nat64_new_flow_event_rb SEC (".maps") /* placed in maps section */;

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
} nat64_address_port_in_use_map SEC(".maps");


// Function to update the packet count for the given interface index
static inline void update_packet_count(__u32 iface_index) {
	__u64 *count, initial_count = 0;

	// Look up the current count for the interface index
	count = bpf_map_lookup_elem(&iface_packet_count_map, &iface_index);
	if (count) {
		// If found, increment the count
		__sync_fetch_and_add(count, 1);
	} else {
		// If not found, create a new entry with initial count
		bpf_map_update_elem(&iface_packet_count_map, &iface_index, &initial_count, BPF_ANY);
	}
}

__attribute__((__always_inline__)) static inline int
send_new_flow_event(__u32 iface_index)
{
	struct nat64_ipv6_new_flow_event *event;

	event = bpf_ringbuf_reserve(&nat64_new_flow_event_rb, sizeof(struct nat64_ipv6_new_flow_event), 0);
	if (!event) {
		//bpf_printk("Failed to reserve an event from nat64_new_flow_event_rb");
		return NAT64_ERROR;
	}
	event->iface_index = iface_index;

	bpf_ringbuf_submit(event, 0);
	return NAT64_OK;
}

__attribute__((__always_inline__)) static inline int
fill_flow_signature(struct nat64_table_tuple *flow_sig, void *data_end,
					__u8 ip_version, void *ip_hdr, 
					__u8 nxt_hdr, void *nxt_ptr)
{
	flow_sig->version = ip_version;
	flow_sig->protocol = nxt_hdr;

	switch (ip_version) {
		case NAT64_IP_VERSION_V4: {
			struct iphdr *ipv4 = (struct iphdr *)ip_hdr;
			flow_sig->addr.v4.src_ip = ipv4->saddr;
			flow_sig->addr.v4.dst_ip = ipv4->daddr;
			break;
		}
		case NAT64_IP_VERSION_V6: {
			struct ipv6hdr *ipv6 = (struct ipv6hdr *)ip_hdr;
			// ipv6_hdr->daddr.in6_u.u6_addr32
			memcpy(flow_sig->addr.v6.src_ip6.u6_addr32, &ipv6->saddr.in6_u.u6_addr32, sizeof(flow_sig->addr.v6.src_ip6));
			memcpy(flow_sig->addr.v6.dst_ip6.u6_addr32, &ipv6->daddr.in6_u.u6_addr32, sizeof(flow_sig->addr.v6.dst_ip6));
			break;
		}
		default:
			//bpf_printk("Only support IPv4 or IPv6 packets");
			return NAT64_ERROR; // Invalid IP version
	}

	if (nxt_hdr == IPPROTO_TCP) {
		struct tcphdr *tcp_hdr = (struct tcphdr *)nxt_ptr;
		assert_len(tcp_hdr, data_end);
		flow_sig->src_port = tcp_hdr->source;
		flow_sig->dst_port = tcp_hdr->dest;
	} else if (nxt_hdr == IPPROTO_UDP) {
		struct udphdr *udp_hdr = (struct udphdr *)nxt_ptr;
		assert_len(udp_hdr, data_end);
		flow_sig->src_port = udp_hdr->source;
		flow_sig->dst_port = udp_hdr->dest;
	} else if (nxt_hdr == IPPROTO_ICMPV6){
		struct icmp6hdr *icmp6_hdr = (struct icmp6hdr *)nxt_ptr;
		assert_len(icmp6_hdr, data_end);
		// For ICMP, we use type and identifier as "ports"
		flow_sig->src_port = (__be16)icmp6_hdr->icmp6_type;
		flow_sig->dst_port = icmp6_hdr->icmp6_dataun.u_echo.identifier;
	} else if (nxt_hdr == IPPROTO_ICMP){
		struct icmphdr *icmp_hdr = (struct icmphdr *)nxt_ptr;
		assert_len(icmp_hdr, data_end);

		if (icmp_hdr->type != ICMP_ECHO && icmp_hdr->type != ICMP_ECHOREPLY) {
			//bpf_printk("Does not support other icmp type.");
			return NAT64_ERROR;
		}
		flow_sig->src_port = (__be16)icmp_hdr->type;
		flow_sig->dst_port = icmp_hdr->un.echo.id;
	} else {
		return NAT64_ERROR; 
	}

	//bpf_printk("Flow Signature: version=%d, protocol=%d, src_port=%d, dst_port=%d, src_ip=%pI4, dst_ip=%pI4",
			//   flow_sig->version, flow_sig->protocol, flow_sig->src_port, flow_sig->dst_port,
			//   flow_sig->addr.v4.src_ip, flow_sig->addr.v4.dst_ip);
	//print_addr_bytes(flow_sig);

	return NAT64_OK; // Success
}

__attribute__((__always_inline__)) static inline int
store_nat64_flow_records(const struct nat64_table_tuple *outgoing_flow_sig,
				const struct nat64_table_value *outgoing_flow_value)
{
	int ret;
	struct nat64_table_tuple incoming_flow_sig = {0};
	struct nat64_table_value incoming_flow_value = {0};

	// Store outgoing (v6 to v4) flow in nat64_v6_v4_map
	// ret = bpf_map_update_elem(&nat64_v6_v4_map, outgoing_flow_sig, outgoing_flow_value, BPF_NOEXIST | BPF_F_LOCK);
	ret = bpf_map_update_elem(&nat64_v6_v4_map, outgoing_flow_sig, outgoing_flow_value, BPF_NOEXIST);
	if (ret < 0) {
		//bpf_printk("Failed to store outgoing flow in nat64_v6_v4_map: %d\n", ret);
		return NAT64_ERROR;
	}

	// Prepare incoming (v4 to v6) flow signature
	incoming_flow_sig.version = NAT64_IP_VERSION_V4; // IPv4
	incoming_flow_sig.addr.v4.src_ip = outgoing_flow_sig->addr.v6.dst_ip6.u6_addr32[3]; // Last 4 bytes of IPv6 dst
	incoming_flow_sig.addr.v4.dst_ip = outgoing_flow_value->addr.nat64_v4_addr;
	if (outgoing_flow_sig->protocol == IPPROTO_TCP || outgoing_flow_sig->protocol == IPPROTO_UDP) {
		incoming_flow_sig.protocol = outgoing_flow_sig->protocol;
		incoming_flow_sig.src_port = outgoing_flow_sig->dst_port; // Swap src and dst
		incoming_flow_sig.dst_port = outgoing_flow_value->port.nat64_port;
	
		incoming_flow_value.port.original_port = outgoing_flow_sig->src_port;
	} else {
		incoming_flow_sig.protocol = IPPROTO_ICMP;
		incoming_flow_sig.src_port = ICMP_ECHOREPLY;
		incoming_flow_sig.dst_port = outgoing_flow_value->port.nat64_port;

		incoming_flow_value.port.original_port = outgoing_flow_sig->dst_port; // icmpv6's identifier is stored in dst_port
	}

	// Prepare incoming (v4 to v6) flow value
	__builtin_memcpy(incoming_flow_value.addr.original_ip6, outgoing_flow_sig->addr.v6.src_ip6.u6_addr8, NAT64_IPV6_ADDR_LENGTH);
	incoming_flow_value.last_seen = outgoing_flow_value->last_seen;

	//bpf_printk("Created incoming flow signature (reversion): version=%u, protocol=%u, src_port=%u, dst_port=%u, src_ip=%pI4, dst_ip=%pI4",
			//    incoming_flow_sig.version, incoming_flow_sig.protocol, incoming_flow_sig.src_port, incoming_flow_sig.dst_port,
			//    &incoming_flow_sig.addr.v4.src_ip, &incoming_flow_sig.addr.v4.dst_ip);
	//print_addr_bytes(&incoming_flow_sig);

	// Store incoming (v4 to v6) flow in nat64_v4_v6_map
	// ret = bpf_map_update_elem(&nat64_v4_v6_map, &incoming_flow_sig, &incoming_flow_value, BPF_NOEXIST | BPF_F_LOCK);
	ret = bpf_map_update_elem(&nat64_v4_v6_map, &incoming_flow_sig, &incoming_flow_value, BPF_NOEXIST);
	if (NAT64_FAILED(ret)) {
		//bpf_printk("Failed to store incoming flow in nat64_v4_v6_map: %d\n", ret);
		// If this fails, we should remove the entry we just added to nat64_v6_v4_map
		bpf_map_delete_elem(&nat64_v6_v4_map, outgoing_flow_sig);
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

__attribute__((__always_inline__)) static inline int
fetch_nat64_addr_and_port(__u32 iface_index,
							const struct nat64_table_tuple *outgoing_flow_sig, struct nat64_table_value *outgoing_flow_value)
{
	struct nat64_address_port_assignment *assignment;
	struct nat64_address_port_item *item;

	int ret;
	
	bool new_flow_event_sent = false;
	bool succeed = false;

	for (int i = 0; i < NAT64_ADDR_PORT_ASSIGNMENT_FETCH_RETRY; i++) {
		// Lookup the assignment for the given interface
		assignment = bpf_map_lookup_elem(&nat64_address_assignment_map, &iface_index);
		if (!assignment) {
			//bpf_printk("No NAT64 address assignment found for interface %d\n", iface_index);
			return NAT64_ERROR;
		}
		// Acquire the spinlock
		bpf_spin_lock(&assignment->item_semaphore);
		if (assignment->address_port_item.used) {
			// Release the spinlock
			bpf_spin_unlock(&assignment->item_semaphore);
			if (!new_flow_event_sent) {
				ret = send_new_flow_event(iface_index);
				if (NAT64_FAILED(ret)) {
					//bpf_printk("Failed to send a new flow event");
					return NAT64_ERROR;
				}
				new_flow_event_sent = true;
			}
			continue;
		}
		item = &assignment->address_port_item;

		// Assign the NAT64 address and port
		outgoing_flow_value->addr.nat64_v4_addr = item->nat_addr;
		outgoing_flow_value->port.nat64_port = bpf_htons(item->nat_port);
		item->used = 1;
		// Release the spinlock
		bpf_spin_unlock(&assignment->item_semaphore);

		//bpf_printk("Test outgoing_flow_value->addr.nat64_v4_addr %u \n", outgoing_flow_value->addr.nat64_v4_addr);

		ret = send_new_flow_event(iface_index);
		if (NAT64_FAILED(ret)) {
			//bpf_printk("Failed to send a new flow event");
			return NAT64_ERROR;
		}

		//bpf_printk("Allocated NAT64 address %u and port %u for interface %d\n", 
				// item->nat_addr, item->nat_port, iface_index);

		ret = store_nat64_flow_records(outgoing_flow_sig, outgoing_flow_value);
		if (NAT64_FAILED(ret)) {
			//bpf_printk("Failed to store nat64 flow records");
			return NAT64_ERROR;
		} // best to stay here? but does it lock the semaphore too long?

		succeed = true;
	}

	if (!succeed) {
		//bpf_printk("Failed to get an unused nat address/port assignment");
		return NAT64_ERROR;
	}

	
	return NAT64_OK;
}

__attribute__((__always_inline__)) static inline int
convert_v6_pkt_to_v4_pkt(struct xdp_md *ctx, const struct nat64_table_value *flow_value,
						struct ethhdr *eth_hdr, struct ipv6hdr *ipv6_hdr)
{
	int ret;
	__u8 nxt_hdr_type;
	struct ipv6hdr ipv6_tmp = {0};

	struct ethhdr tmp_eth = {0};
	memcpy(&tmp_eth, eth_hdr, ETH_HLEN);
	tmp_eth.h_proto = bpf_htons(ETH_P_IP);

	nxt_hdr_type = ipv6_hdr->nexthdr;

	//bpf_printk("value of new IP src %u ", flow_value->addr.nat64_v4_addr);

	struct iphdr tmp_ipv4 = {
		.version = 4,
		.ihl = 5,
		.tos = 0,
		.tot_len = bpf_htons(bpf_ntohs(ipv6_hdr->payload_len) + sizeof(struct iphdr)),
		.id = 0,
		.frag_off = bpf_htons(0x01 << 14),
		.ttl = ipv6_hdr->hop_limit,
		.protocol = (nxt_hdr_type == IPPROTO_ICMPV6)? IPPROTO_ICMP : ipv6_hdr->nexthdr,
		.saddr = flow_value->addr.nat64_v4_addr,
		.daddr = ipv6_hdr->daddr.in6_u.u6_addr32[3],
		.check = 0
	};
	tmp_ipv4.check = compute_ipv4_hdr_checksum((__u16 *)&tmp_ipv4, sizeof(tmp_ipv4));

	memcpy(&ipv6_tmp, ipv6_hdr, sizeof(struct ipv6hdr)); // needed for icmp checksum calculation


	void *old_data_end = (void *)(long)ctx->data_end;
	if(bpf_xdp_adjust_head(ctx, NAT64_V6_V4_HDR_LENGTH_DIFF) != 0) {
		return NAT64_ERROR;
	}

	void *shift_data = (void *)(long)ctx->data;
	void *shift_data_end = (void *)(long)ctx->data_end;

	//bpf_printk("shift_data=%p, shift_data_end=%p, old_data_end=%p", shift_data, shift_data_end, old_data_end);

	struct ethhdr *shift_eth = shift_data;
	assert_len(shift_eth, shift_data_end);
	memcpy(shift_eth, &tmp_eth, ETH_HLEN);

	struct iphdr *ipv4 = (struct iphdr *)((void *)(shift_eth + 1));
	assert_len(ipv4, shift_data_end);
	memcpy(ipv4, &tmp_ipv4, sizeof(tmp_ipv4));

	ret = modify_l4_proto_hdr(ctx, &ipv6_tmp, ipv4, nxt_hdr_type, (void *)(ipv4 + 1),
								NAT64_FLOW_DIRECTION_OUTGOING, flow_value);

	if (NAT64_FAILED(ret)) {
		//bpf_printk("Failed to modify l4 protocol header for outgoing packets");
		return NAT64_ERROR;
	}

	return NAT64_OK;
}


__attribute__((__always_inline__)) static inline int
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
	if (NAT64_FAILED(ret)) {
		//bpf_printk("Failed to fill flow signature for a IPv6 packet");
		return NAT64_ERROR;
		
	}

	flow_value = bpf_map_lookup_elem(&nat64_v6_v4_map, &flow_sig);

	if (!flow_value) {
		flow_value = &new_flow_value;
		flow_value->last_seen = bpf_ktime_get_ns();
		ret = fetch_nat64_addr_and_port(ctx->ingress_ifindex, &flow_sig, flow_value);
		if (NAT64_FAILED(ret)) {
			//bpf_printk("Failed to fetch an assigned nat64 addr and port");
			return NAT64_ERROR;
		}
		//bpf_printk("fliow value IP after %u", flow_value->addr.nat64_v4_addr);
	}

		// Update the last seen timestamp
	flow_value->last_seen = bpf_ktime_get_ns();

	ret = convert_v6_pkt_to_v4_pkt(ctx, flow_value, eth, ipv6_hdr);
	if (NAT64_FAILED(ret)) {
		//bpf_printk("Failed to convert v6 pkt to v4 pkt");
		NAT64_ERROR;
	}

	return NAT64_OK;
}


__attribute__((__always_inline__)) static inline int
convert_v4_pkt_to_v6_pkt(struct xdp_md *ctx, const struct nat64_table_value *flow_value,
						struct ethhdr *eth_hdr, struct iphdr *ipv4_hdr)
{
	int ret;
	__u8 nxt_hdr_type = ipv4_hdr->protocol;
	struct iphdr ipv4_tmp = {0};
	memcpy(&ipv4_tmp, ipv4_hdr, sizeof(struct iphdr));

	// Prepare new Ethernet header
	struct ethhdr tmp_eth = {};
	memcpy(&tmp_eth, eth_hdr, ETH_HLEN);
	tmp_eth.h_proto = bpf_htons(ETH_P_IPV6);

	// Prepare new IPv6 header
	struct ipv6hdr tmp_ipv6 = {
		.version = 6,
		.flow_lbl = {0},
		.payload_len = bpf_htons(bpf_ntohs(ipv4_hdr->tot_len) - sizeof(struct iphdr)),
		.nexthdr = (nxt_hdr_type == IPPROTO_ICMP)? IPPROTO_ICMPV6 : nxt_hdr_type,
		.hop_limit = ipv4_hdr->ttl,
	};
	memcpy(&tmp_ipv6.saddr, &nat64_ipv6_prefix, 12);
	memcpy(&tmp_ipv6.saddr.s6_addr32[3], &ipv4_hdr->saddr, 4);
	memcpy(&tmp_ipv6.daddr, flow_value->addr.original_ip6, sizeof(tmp_ipv6.daddr));

	// Adjust packet size
	if (bpf_xdp_adjust_head(ctx, - NAT64_V6_V4_HDR_LENGTH_DIFF) != 0) {
		return NAT64_ERROR;
	}

	void *shift_data = (void *)(long)ctx->data;
	void *shift_data_end = (void *)(long)ctx->data_end;

	// Write new Ethernet header
	struct ethhdr *shift_eth = shift_data;
	assert_len(shift_eth, shift_data_end);
	memcpy(shift_eth, &tmp_eth, ETH_HLEN);

	// Write new IPv6 header
	struct ipv6hdr *ipv6 = (struct ipv6hdr *)((void *)(shift_eth + 1));
	assert_len(ipv6, shift_data_end);
	memcpy(ipv6, &tmp_ipv6, sizeof(tmp_ipv6));

	ret = modify_l4_proto_hdr(ctx, ipv6, &ipv4_tmp, nxt_hdr_type, (void *)(ipv6 + 1),
								NAT64_FLOW_DIRECTION_INCOMING, flow_value);

	if (NAT64_FAILED(ret)) {
		//bpf_printk("Failed to modify l4 protocol header for incoming packet");
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

__attribute__((__always_inline__)) static inline int
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
		//bpf_printk("Failed to fill flow signature for IPv4 packet");
		return NAT64_ERROR;
	}

	// Lookup the flow in the NAT64 v4->v6 map
	flow_value = bpf_map_lookup_elem(&nat64_v4_v6_map, &flow_sig);
	if (!flow_value) {
		// If not found, this might be a new incoming connection or an unsolicited packet
		//bpf_printk("No NAT64 mapping found for incoming IPv4 packet");
		return NAT64_OK; // or XDP_DROP, depending on your security policy
	}

	// Update the last seen timestamp
	flow_value->last_seen = bpf_ktime_get_ns();

	// Convert the IPv4 packet to IPv6
	ret = convert_v4_pkt_to_v6_pkt(ctx, flow_value, eth, ipv4_hdr);
	if (NAT64_FAILED(ret)) {
		//bpf_printk("Failed to convert IPv4 packet to IPv6");
		return NAT64_ERROR;
	}
	return NAT64_OK;
}


__attribute__((__always_inline__)) static inline int
nat64_parse_l2(struct xdp_md *ctx)
{

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 iface_index = ctx->ingress_ifindex; // Get the interface index from the context

	struct ethhdr *eth = data;
	assert_len(eth, data_end);

	//bpf_printk("data: %p, data_end: %p", data, data_end);

	// Update the packet count for the interface
	update_packet_count(iface_index);
	//bpf_printk("ebpf_nat64 packet received");
	
	if(eth->h_proto == bpf_htons(ETH_P_IP)) {
		return process_ipv4_pkt(ctx, eth + 1, eth);
	}

	if(eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		return process_ipv6_pkt(ctx, eth + 1, eth);
	}
	return NAT64_OK;
}

SEC("xdp")
int xdp_nat64(struct xdp_md *ctx)
{
	if (NAT64_FAILED(nat64_parse_l2(ctx)))
		return XDP_DROP;
	else
		return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
