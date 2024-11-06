#ifndef __NAT64_MODIFY_HDR_H
#define __NAT64_MODIFY_HDR_H

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

#define NAT64_V6_V4_HDR_LENGTH_DIFF ((int)(sizeof(struct ipv6hdr) - sizeof(struct iphdr)))


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

	cksum_tmp = icmp_wsum_accumulate(data + sizeof(struct ethhdr) + sizeof(struct iphdr), data_end, l4_length);
	icmp_hdr->checksum = csum_fold(cksum_tmp);

}


__attribute__((__always_inline__)) static void
convert_icmpv4_to_icmpv6(struct xdp_md *ctx, void *nxt_ptr, __u16 l4_length, const struct ipv6hdr *ipv6_hdr, const struct nat64_table_value *flow_value) {
	__u8 type;
	__u16 cksum;
	__be32 icmp6_cksum, ipv6_pseudo_hdr_cksum, cksum_tmp;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	type = ((struct icmphdr *)nxt_ptr)->type;
	struct icmp6hdr *icmp6_hdr = (struct icmp6hdr *)nxt_ptr;
	if (type == ICMP_ECHO)
		icmp6_hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
	else
		icmp6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
	icmp6_hdr->icmp6_dataun.u_echo.identifier = flow_value->port.original_port;
	icmp6_hdr->icmp6_cksum = 0;

	ipv6_pseudo_hdr_cksum = ipv6_pseudohdr_checksum(ipv6_hdr, IPPROTO_ICMPV6, bpf_ntohs(ipv6_hdr->payload_len), 0);
	icmp6_cksum = icmp_wsum_accumulate(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr), data_end, l4_length);
	cksum_tmp = csum_add(ipv6_pseudo_hdr_cksum, icmp6_cksum);
	icmp6_hdr->icmp6_cksum = csum_fold(cksum_tmp);
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
			tcp_hdr->check = update_tcp_udp_checksum(tcp_hdr->check, old_port, new_port, ipv6_hdr, ipv4_hdr, direction);
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
			udp_hdr->check = update_tcp_udp_checksum(udp_hdr->check, old_port, new_port, ipv6_hdr, ipv4_hdr, direction);
			break;
		}
		default:
			NAT64_LOG_ERROR("Unknown l4 type when converting tcp/udp proto port");
			return NAT64_ERROR; // Unsupported protocol
	}
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
			return XDP_DROP;
		}
	} else if (nxt_hdr_type == IPPROTO_ICMPV6) {
		struct icmp6hdr *icmp6_hdr = (struct icmp6hdr *)l4_hdr;
		assert_len(icmp6_hdr, data_end);
		
		convert_icmpv6_to_icmpv4(ctx, l4_hdr, bpf_ntohs(ipv6_hdr->payload_len), ipv6_hdr, flow_value);
	} else if (nxt_hdr_type == IPPROTO_ICMP) {
		struct icmphdr *icmp_hdr = (struct icmphdr *)l4_hdr;
		assert_len(icmp_hdr, data_end);
		
		convert_icmpv4_to_icmpv6(ctx, l4_hdr, bpf_ntohs(ipv6_hdr->payload_len), ipv6_hdr, flow_value);
	} else {
		NAT64_LOG_ERROR("Unsupported L4 protocol of outgoing traffic", NAT64_LOG_L4_PROTOCOL(nxt_hdr_type));
		return NAT64_ERROR;
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
		NAT64_LOG_ERROR("Failed to modify l4 protocol header for incoming packet");
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
