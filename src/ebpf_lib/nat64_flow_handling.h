#ifndef NAT64_FLOW_HANDLING_H
#define NAT64_FLOW_HANDLING_H

#include <bpf/bpf_helpers.h>

#include "nat64_kern.h"
#include "nat64_kern_log.h"
#include "nat64_table_tuple.h"
#include "nat64_addr_port_assignment.h"


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
	__type(key, __u32);
	__type(value, struct nat64_address_port_assignment);
	__uint(max_entries, NAT64_ATTACH_IFACE_MAX_CNT);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat64_addr_assignment_map SEC(".maps");

struct {
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, NAT64_NEW_FLOW_EVENT_RINGBUFFER_SIZE);
} nat64_new_flow_event_rb SEC (".maps") /* event ringbuf to inform userspace prog in terms of new IPv6 flow */;

static __always_inline int
send_new_flow_event(__u32 iface_index)
{
	struct nat64_ipv6_new_flow_event *event;

	event = bpf_ringbuf_reserve(&nat64_new_flow_event_rb, sizeof(struct nat64_ipv6_new_flow_event), 0);
	if (!event) {
		NAT64_LOG_ERROR("Failed to reserve a new flow event", NAT64_LOG_IFACE_INDEX(iface_index));
		return NAT64_ERROR;
	}
	event->iface_index = iface_index;

	bpf_ringbuf_submit(event, 0);
	return NAT64_OK;
}

static __always_inline int
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
			memcpy(flow_sig->addr.v6.src_ip6.u6_addr32, &ipv6->saddr.in6_u.u6_addr32, sizeof(flow_sig->addr.v6.src_ip6));
			memcpy(flow_sig->addr.v6.dst_ip6.u6_addr32, &ipv6->daddr.in6_u.u6_addr32, sizeof(flow_sig->addr.v6.dst_ip6));
			break;
		}
		default:
			NAT64_LOG_ERROR("Only support IPv4 or IPv6 packets", );
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
			NAT64_LOG_ERROR("Does not support other icmp type", );
			return NAT64_ERROR;
		}
		flow_sig->src_port = (__be16)icmp_hdr->type;
		flow_sig->dst_port = icmp_hdr->un.echo.id;
	} else {
		NAT64_LOG_ERROR("Unsupported L4 protocol", NAT64_LOG_L4_PROTOCOL(nxt_hdr));
		return NAT64_ERROR; 
	}

	if (ip_version == NAT64_IP_VERSION_V4) {
		NAT64_LOG_DEBUG("Filled a flow signature", NAT64_LOG_L4_PROTOCOL(flow_sig->protocol),
						NAT64_LOG_SRC_IPV4(flow_sig->addr.v4.src_ip), NAT64_LOG_DST_IPV4(flow_sig->addr.v4.dst_ip),
						NAT64_LOG_L4_PROTO_SRC_PORT(bpf_ntohs(flow_sig->src_port)), NAT64_LOG_L4_PROTO_DST_PORT(bpf_ntohs(flow_sig->dst_port)));
	} else {
		NAT64_LOG_DEBUG("Filled a flow signature", NAT64_LOG_L4_PROTOCOL(flow_sig->protocol),
						NAT64_LOG_SRC_IPV6(flow_sig->addr.v6.src_ip6.u6_addr8), NAT64_LOG_DST_IPV6(flow_sig->addr.v6.dst_ip6.u6_addr8),
						NAT64_LOG_L4_PROTO_SRC_PORT(bpf_ntohs(flow_sig->src_port)), NAT64_LOG_L4_PROTO_DST_PORT(bpf_ntohs(flow_sig->dst_port)));
	}

	return NAT64_OK;
}


static __always_inline int
store_nat64_flow_records(const struct nat64_table_tuple *outgoing_flow_sig,
				const struct nat64_table_value *outgoing_flow_value)
{
	int ret;
	struct nat64_table_tuple incoming_flow_sig = {0};
	struct nat64_table_value incoming_flow_value = {0};

	// Store outgoing (v6 to v4) flow in nat64_v6_v4_map
	ret = bpf_map_update_elem(&nat64_v6_v4_map, outgoing_flow_sig, outgoing_flow_value, BPF_NOEXIST);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to store outgoing flow in nat64_v6_v4_map", NAT64_LOG_ERRNO(ret));
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
	incoming_flow_value.timeout_value = outgoing_flow_value->timeout_value;

	NAT64_LOG_DEBUG("Created incoming flow signature (reversion)", NAT64_LOG_L4_PROTOCOL(incoming_flow_sig.protocol),
					NAT64_LOG_L4_PROTO_SRC_PORT(bpf_ntohs(incoming_flow_sig.src_port)), NAT64_LOG_L4_PROTO_SRC_PORT(bpf_ntohs(incoming_flow_sig.dst_port)),
					NAT64_LOG_SRC_IPV4(incoming_flow_sig.addr.v4.src_ip), NAT64_LOG_DST_IPV4(incoming_flow_sig.addr.v4.dst_ip));


	// Store incoming (v4 to v6) flow in nat64_v4_v6_map
	ret = bpf_map_update_elem(&nat64_v4_v6_map, &incoming_flow_sig, &incoming_flow_value, BPF_NOEXIST);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to store incoming flow in nat64_v4_v6_map", NAT64_LOG_ERRNO(ret));
		// If this fails, we should remove the entry we just added to nat64_v6_v4_map
		bpf_map_delete_elem(&nat64_v6_v4_map, outgoing_flow_sig);
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

static __always_inline int
process_nat64_new_outgoing_ipv6_flow(__u32 iface_index,
							const struct nat64_table_tuple *outgoing_flow_sig, struct nat64_table_value *outgoing_flow_value)
{
	struct nat64_address_port_assignment *assignment;
	struct nat64_address_port_item *item;

	int ret;
	
	bool new_flow_event_sent = false;
	bool succeed = false;

	for (int i = 0; i < NAT64_ADDR_PORT_ASSIGNMENT_FETCH_RETRY; i++) {
		// Lookup the assignment for the given interface
		assignment = bpf_map_lookup_elem(&nat64_addr_assignment_map, &iface_index);
		if (!assignment) {
			NAT64_LOG_ERROR("No NAT64 address assignment found for interface", NAT64_LOG_IFACE_INDEX(iface_index));
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
					NAT64_LOG_ERROR("Failed to send a new flow event", NAT64_LOG_IFACE_INDEX(iface_index));
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

		NAT64_LOG_DEBUG("Fetched NAT64 address and port", NAT64_LOG_IPV4(outgoing_flow_value->addr.nat64_v4_addr),
						NAT64_LOG_PORT(bpf_ntohs(outgoing_flow_value->port.nat64_port)));

		ret = send_new_flow_event(iface_index);
		if (NAT64_FAILED(ret)) {
			NAT64_LOG_ERROR("Failed to send a new flow event", NAT64_LOG_IFACE_INDEX(iface_index));
			return NAT64_ERROR;
		}

		ret = store_nat64_flow_records(outgoing_flow_sig, outgoing_flow_value);
		if (NAT64_FAILED(ret)) {
			NAT64_LOG_ERROR("Failed to store nat64 flow records");
			return NAT64_ERROR;
		}

		succeed = true;
	}

	if (!succeed) {
		NAT64_LOG_ERROR("Failed to get an unused nat address/port assignment");
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

static __always_inline struct nat64_table_value *
nat64_kern_get_flow_value_by_key(enum nat64_flow_direction direction, const struct nat64_table_tuple *flow_sig)
{
	struct nat64_table_value *flow_value = NULL;

	if (direction == NAT64_FLOW_DIRECTION_OUTGOING)
		flow_value = bpf_map_lookup_elem(&nat64_v6_v4_map, flow_sig);
	else
		flow_value = bpf_map_lookup_elem(&nat64_v4_v6_map, flow_sig);

	return flow_value;
}

#endif
