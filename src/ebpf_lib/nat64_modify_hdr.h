// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0



#ifndef NAT64_MODIFY_HDR_H
#define NAT64_MODIFY_HDR_H

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "include/nat64_common.h"
#include "include/nat64_table_tuple.h"
#include "nat64_kern_log.h"

#include "nat64_icmp_error_handling.h"


__attribute__((__always_inline__)) static void
convert_icmpv6_to_icmpv4(struct xdp_md *ctx, void *nxt_ptr, __u16 l4_length, const struct ipv6hdr *ipv6_hdr, const struct nat64_table_value *flow_value)
{
	__u8 type;
	__be32 cksum_tmp;


	struct icmp6hdr icmp6_hdr = {0};
	struct icmphdr *icmp_hdr;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	type = ((struct icmp6hdr *)nxt_ptr)->icmp6_type;
	icmp_hdr = (struct icmphdr *)nxt_ptr;
	if (type == ICMPV6_ECHO_REQUEST)
		icmp_hdr->type = ICMP_ECHO;
	else
		icmp_hdr->type = ICMP_ECHOREPLY;
			
	icmp_hdr->un.echo.id = flow_value->port.nat64_port;
	icmp_hdr->checksum = 0;

	if (__is_icmp_icmp6_cksum_recalc_enabled)
		icmp_hdr->checksum = compute_icmp_cksum(data + sizeof(struct ethhdr) + sizeof(struct iphdr), data_end, l4_length);
}

__attribute__((__always_inline__)) static int
convert_tcp_udp_proto_port(struct xdp_md *ctx, struct ipv6hdr *ipv6_hdr, struct iphdr *ipv4_hdr,
						__u8 nxt_hdr, void *nxt_ptr,
						enum nat64_flow_direction direction, const struct nat64_table_value *flow_value)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 old_port, new_port;
	
	switch (nxt_hdr) {
		case IPPROTO_TCP: {
			struct tcphdr *tcp_hdr = (struct tcphdr *)nxt_ptr;
			if (direction == NAT64_FLOW_DIRECTION_OUTGOING) {
				old_port = tcp_hdr->source;
				new_port = flow_value->port.nat64_port;
				tcp_hdr->source = new_port;
			} else {
				old_port = tcp_hdr->dest;
				new_port = flow_value->port.original_port;
				tcp_hdr->dest = new_port;
			}
			if (__is_tcp_udp_cksum_recalc_enabled)
				tcp_hdr->check = update_tcp_udp_checksum(tcp_hdr->check, old_port, new_port, ipv6_hdr, ipv4_hdr, direction);
			else
				tcp_hdr->check = 0;
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr *udp_hdr = (struct udphdr *)nxt_ptr;
			if (direction == NAT64_FLOW_DIRECTION_OUTGOING) {
				old_port = udp_hdr->source;
				new_port = flow_value->port.nat64_port;
				udp_hdr->source = new_port;
			} else {
				old_port = udp_hdr->dest;
				new_port = flow_value->port.original_port;
				udp_hdr->dest = new_port;
			}
			if (__is_tcp_udp_cksum_recalc_enabled)
				udp_hdr->check = update_tcp_udp_checksum(udp_hdr->check, old_port, new_port, ipv6_hdr, ipv4_hdr, direction);
			else
				udp_hdr->check = 0;
			break;
		}
		default:
			NAT64_LOG_ERROR("Unknown l4 type when converting tcp/udp proto port");
			return NAT64_ERROR; // Unsupported protocol
	}
	return NAT64_OK;
}

__attribute__((__always_inline__)) static int
convert_icmpv4_icmpv6_inner_hdrs(struct xdp_md *ctx, const struct nat64_table_value *flow_value)
{
	char cached_hdrs[NAT64_EHT_IPv6_ICMPv6_HDR_LEN] = {0};
	struct ipv6hdr tmp_inner_ipv6_hdr = {0};
	int ret;
	__u16 truncated_length = 0;
	void *data, *data_end;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	struct ipv6hdr *outer_ipv6_hdr = (struct ipv6hdr *)(data + sizeof(struct ethhdr));

	assert_len(outer_ipv6_hdr, data_end);
	__u16 l4_length = bpf_ntohs(outer_ipv6_hdr->payload_len);

	// cache the outer headers
	bpf_probe_read_kernel(cached_hdrs, NAT64_EHT_IPv6_ICMPv6_HDR_LEN, (void *)(long)ctx->data);

	// remove outer eth/ipv6/icmp6 hdr
	if (bpf_xdp_adjust_head(ctx, NAT64_EHT_IPv6_ICMPv6_HDR_LEN))
		return NAT64_ERROR;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	struct iphdr *inner_ipv4_hdr = (struct iphdr *)data;

	assert_len(inner_ipv4_hdr, data_end);

	struct iphdr inner_ipv4_tmp = {0};

	memcpy(&inner_ipv4_tmp, inner_ipv4_hdr, sizeof(struct iphdr));

	// Convert inner IPv4 header to IPv6
	struct ipv6hdr tmp_inner_ipv6 = {
		.version = 6,
		.flow_lbl = {0},
		.payload_len = bpf_htons(bpf_ntohs(inner_ipv4_hdr->tot_len) - sizeof(struct iphdr)),
		.nexthdr =  inner_ipv4_hdr->protocol,
		.hop_limit = inner_ipv4_hdr->ttl,
	};
	memcpy(&tmp_inner_ipv6.saddr, flow_value->addr.original_ip6, sizeof(tmp_inner_ipv6.saddr));
	memcpy(&tmp_inner_ipv6.daddr, &nat64_ipv6_prefix, 12);
	memcpy(&tmp_inner_ipv6.daddr.s6_addr32[3], &inner_ipv4_hdr->daddr, 4);

	// Adjust packet size to expand inner IPv4 header to IPv6
	if (bpf_xdp_adjust_head(ctx, (-NAT64_V6_V4_HDR_LENGTH_DIFF)) != 0)
		return NAT64_ERROR;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	struct ipv6hdr *inner_ipv6 = (struct ipv6hdr *)data;

	assert_len(inner_ipv6, data_end);
	memcpy(inner_ipv6, &tmp_inner_ipv6, sizeof(tmp_inner_ipv6));

	// continue to change the inner l4 protocol header
	if (inner_ipv6->nexthdr == IPPROTO_TCP || inner_ipv6->nexthdr == IPPROTO_UDP) {
		if (inner_ipv6->nexthdr == IPPROTO_TCP) {
			struct tcphdr *tcp_hdr = (struct tcphdr *)(inner_ipv6 + 1);

			assert_len(tcp_hdr, data_end);
		} else {
			struct udphdr *udp_hdr = (struct udphdr *)(inner_ipv6 + 1);

			assert_len(udp_hdr, data_end);
		}
		ret = convert_tcp_udp_proto_port(ctx, inner_ipv6, &inner_ipv4_tmp,
										inner_ipv6->nexthdr, (void *)(inner_ipv6 + 1), NAT64_FLOW_DIRECTION_OUTGOING,
										flow_value); // used flow_value's nat64_port, which should be same as original_port
		if (NAT64_FAILED(ret)) {
			NAT64_LOG_ERROR("Failed to change inner L4 proto port");
			return NAT64_ERROR;
		}
	} else {
		NAT64_LOG_ERROR("Unsupported inner IPv4 icmp err L4 protocol", NAT64_LOG_L4_PROTOCOL(inner_ipv6->nexthdr));
		return NAT64_ERROR;
	}

	// truncate piggybacked data to facilitate cksum computation
	if (l4_length > NAT64_ICMP6_MAX_MSG_SIZE) {
		// allowed bytes count is smaller due to change of inner header (v4 ->v6)
		truncated_length = l4_length - (NAT64_ICMP6_MAX_MSG_SIZE - NAT64_V6_V4_HDR_LENGTH_DIFF);
		if (data + truncated_length > data_end) {
			NAT64_LOG_ERROR("Packet too small after head adjust");
			return NAT64_ERROR;
		}

		if (bpf_xdp_adjust_tail(ctx, truncated_length) != 0) {
			NAT64_LOG_ERROR("Failed to truncate piggybacked data from icmp err msg");
			return NAT64_ERROR;
		}
	}

	// restore the cached outer headers
	if (bpf_xdp_adjust_head(ctx, (-NAT64_EHT_IPv6_ICMPv6_HDR_LEN))) // expand the header's head space
		return NAT64_ERROR;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	struct ethhdr *restore_eth = data;

	assert_len(restore_eth, data_end);

	if (data + NAT64_EHT_IPv6_ICMPv6_HDR_LEN > data_end) {
		NAT64_LOG_ERROR("Packet too small after head adjust");
		return NAT64_ERROR;
	}
	memcpy(data, cached_hdrs, NAT64_EHT_IPv6_ICMPv6_HDR_LEN);

	// adjust the outer ipv6 payload length after one or two adjustment
	struct ipv6hdr *restore_ipv6 = (struct ipv6hdr *)(data + sizeof(struct ethhdr));

	assert_len(restore_ipv6, data_end);

	restore_ipv6->payload_len = bpf_htons(bpf_ntohs(restore_ipv6->payload_len)
										+ NAT64_V6_V4_HDR_LENGTH_DIFF
										- truncated_length);

	return NAT64_OK;
}

__attribute__((__always_inline__)) static int
convert_icmpv4_to_icmpv6(struct xdp_md *ctx, struct icmphdr *icmp_hdr,
						const struct nat64_table_value *flow_value) {
	int ret;
	__u16 cksum;
	__be32 icmp6_cksum, ipv6_pseudo_hdr_cksum, cksum_tmp;
	struct icmphdr cached_icmp_hdr = {0};
	struct icmp6hdr *icmp6_hdr;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	memcpy(&cached_icmp_hdr, icmp_hdr, sizeof(struct icmphdr));

	icmp6_hdr = (struct icmp6hdr *)icmp_hdr;
	icmp6_hdr->icmp6_cksum = 0;

	switch (cached_icmp_hdr.type) {
	case ICMP_ECHO:
		icmp6_hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
		icmp6_hdr->icmp6_dataun.u_echo.identifier = flow_value->port.nat64_port;
		break;
	case ICMP_ECHOREPLY:
		icmp6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
		icmp6_hdr->icmp6_dataun.u_echo.identifier = flow_value->port.nat64_port;
		break;
	case ICMP_DEST_UNREACH:
		ret = convert_icmpv4_to_icmpv6_dest_unreach(&cached_icmp_hdr, icmp6_hdr);
		if (NAT64_FAILED(ret)) {
			NAT64_LOG_ERROR("Failed to convert icmpv4 dest unreach to icmpv6 dest unreach");
			return NAT64_ERROR;
		}

		ret = convert_icmpv4_icmpv6_inner_hdrs(ctx, flow_value);
		if (NAT64_FAILED(ret)) {
			NAT64_LOG_ERROR("Failed to convert icmpv4 dest unreach inner hdrs");
			return NAT64_ERROR;
		}

		NAT64_LOG_DEBUG("Converted ICMP dest unreach to ICMPv6 dest unreach", NAT64_LOG_ICMP_CODE(cached_icmp_hdr.code));
		break;
	default:
		NAT64_LOG_ERROR("Unsupported ICMP type", NAT64_LOG_ICMP_TYPE(cached_icmp_hdr.type));
		return NAT64_ERROR;
	}


	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	struct ipv6hdr *ipv6_hdr = (struct ipv6hdr *)(data + sizeof(struct ethhdr));

	assert_len(ipv6_hdr, data_end);

	icmp6_hdr = (struct icmp6hdr *)(ipv6_hdr + 1);
	assert_len(icmp6_hdr, data_end);
	icmp6_hdr->icmp6_cksum = 0;

	if (__is_icmp_icmp6_cksum_recalc_enabled)
		icmp6_hdr->icmp6_cksum = compute_icmp6_cksum(ipv6_hdr, data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr), data_end, bpf_ntohs(ipv6_hdr->payload_len));

	return NAT64_OK;
}


__attribute__((__always_inline__)) static int
modify_l4_proto_hdr(struct xdp_md *ctx, 
					struct ipv6hdr *ipv6_hdr, struct iphdr *ipv4_hdr,
					__u8 nxt_hdr_type, void *l4_hdr,
					enum nat64_flow_direction flow_direction,
					const struct nat64_table_value *flow_value)
{
	int ret;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (nxt_hdr_type == IPPROTO_TCP || nxt_hdr_type == IPPROTO_UDP) {
		if (nxt_hdr_type == IPPROTO_TCP) {
			struct tcphdr *tcp_hdr = (struct tcphdr *)l4_hdr;
			assert_len(tcp_hdr, data_end);
		} else {
			struct udphdr *udp_hdr = (struct udphdr *)l4_hdr;
			assert_len(udp_hdr, data_end);
		}
		ret = convert_tcp_udp_proto_port(ctx, ipv6_hdr, ipv4_hdr, nxt_hdr_type, l4_hdr, flow_direction, flow_value);
		if (NAT64_FAILED(ret)) {
			NAT64_LOG_ERROR("Failed to change L4 proto port");
			return NAT64_ERROR;
		}
	} else if (nxt_hdr_type == IPPROTO_ICMPV6) {
		struct icmp6hdr *icmp6_hdr = (struct icmp6hdr *)l4_hdr;
		assert_len(icmp6_hdr, data_end);
		
		convert_icmpv6_to_icmpv4(ctx, l4_hdr, bpf_ntohs(ipv6_hdr->payload_len), ipv6_hdr, flow_value);
	} else if (nxt_hdr_type == IPPROTO_ICMP) {
		struct icmphdr *icmp_hdr = (struct icmphdr *)l4_hdr;
		assert_len(icmp_hdr, data_end);
		
		convert_icmpv4_to_icmpv6(ctx, icmp_hdr, flow_value);
	} else {
		NAT64_LOG_ERROR("Unsupported L4 protocol of outgoing traffic", NAT64_LOG_L4_PROTOCOL(nxt_hdr_type));
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

static __always_inline int
convert_v4_pkt_to_v6_pkt(struct xdp_md *ctx,
						const struct nat64_table_value *flow_value,
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
		NAT64_LOG_ERROR("Failed to modify l4 protocol header for incoming packet");
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

static __always_inline int
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

	struct iphdr tmp_ipv4 = {
		.version = 4,
		.ihl = 5,
		.tos = 0,
		.tot_len = bpf_htons(bpf_ntohs(ipv6_hdr->payload_len) + sizeof(struct iphdr)),
		.id = 0,
		.frag_off = bpf_htons(0x01 << 14), // set DO NOT FRAGMENT flag
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

	struct ethhdr *shift_eth = shift_data;
	assert_len(shift_eth, shift_data_end);
	memcpy(shift_eth, &tmp_eth, ETH_HLEN);

	struct iphdr *ipv4 = (struct iphdr *)((void *)(shift_eth + 1));
	assert_len(ipv4, shift_data_end);
	memcpy(ipv4, &tmp_ipv4, sizeof(tmp_ipv4));

	ret = modify_l4_proto_hdr(ctx, &ipv6_tmp, ipv4, nxt_hdr_type, (void *)(ipv4 + 1),
								NAT64_FLOW_DIRECTION_OUTGOING, flow_value);

	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to modify l4 protocol header for outgoing packets");
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

#endif
