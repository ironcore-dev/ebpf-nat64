#ifndef __NAT64_MODIFY_HDR_H
#define __NAT64_MODIFY_HDR_H

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "nat64_common.h"
#include "nat64_table_tuple.h"
#include "nat64_print.h"


__attribute__((__always_inline__)) static int
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

	bpf_printk("Input parameters: nxt_ptr=%p, l4_length=%u, data_end=%p, ipv6_hdr=%p, flow_value=%p", nxt_ptr, l4_length, data_end, ipv6_hdr, flow_value);

	cksum_tmp = icmp_wsum_accumulate(data + sizeof(struct ethhdr) + sizeof(struct iphdr), data_end, l4_length);
	icmp_hdr->checksum = csum_fold(cksum_tmp);

	return NAT64_OK;
}


__attribute__((__always_inline__)) static int
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
	
	return NAT64_OK;
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
			bpf_printk("Unknown l4 type");
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
			bpf_printk("TCP checksum incoming flow: %x", tcp_hdr->check);
		} else {
			struct udphdr *udp_hdr = (struct udphdr *)l4_hdr;
			assert_len(udp_hdr, data_end);
		}
		ret = convert_tcp_udp_proto_port(ctx, ipv6_hdr, ipv4_hdr, nxt_hdr_type, l4_hdr, flow_direction, flow_value);
		if (NAT64_FAILED(ret)) {
			bpf_printk("Failed to change L4 proto port");
			return XDP_DROP;
		}
	} else if (nxt_hdr_type == IPPROTO_ICMPV6) {
		struct icmp6hdr *icmp6_hdr = (struct icmp6hdr *)l4_hdr;
		assert_len(icmp6_hdr, data_end);
		ret = convert_icmpv6_to_icmpv4(ctx, l4_hdr, bpf_ntohs(ipv6_hdr->payload_len), ipv6_hdr, flow_value);
		if (NAT64_FAILED(ret)) {
			bpf_printk("Failed to convert icmpv6 to icmp");
			return NAT64_ERROR;
		}
	} else if (nxt_hdr_type == IPPROTO_ICMP) {
		struct icmphdr *icmp_hdr = (struct icmphdr *)l4_hdr;
		assert_len(icmp_hdr, data_end);
		
		ret = convert_icmpv4_to_icmpv6(ctx, l4_hdr, bpf_ntohs(ipv6_hdr->payload_len), ipv6_hdr, flow_value);
		if (NAT64_FAILED(ret)) {
			bpf_printk("Failed to convert icmpv6 to icmp");
			return NAT64_ERROR;
		}
	} else {
		bpf_printk("Unsupported L4 protocol of outgoing traffic, L4 proto id: %d", nxt_hdr_type);
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

#endif
