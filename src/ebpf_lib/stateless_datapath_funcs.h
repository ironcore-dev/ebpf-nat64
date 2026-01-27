// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef STATELESS_DATAPATH_FUNCS_H
#define STATELESS_DATAPATH_FUNCS_H

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

#include "nat64_common.h"
#include "nat64_kern_config.h"
#include "nat64_kern_log.h"
#include "nat64_checksum.h"
#include "nat64_exporter.h"
#include "nat64_ipv6_addr_check.h"

#include "stateless_datapath_maps.h"

// Stateless BPF Functions
static __always_inline int
convert_v6_pkt_to_v4_pkt_stateless(struct xdp_md *ctx, const __u32 *nat64_v4_addr,
									struct ethhdr *eth_hdr, struct ipv6hdr *ipv6_hdr)
{
	int ret;
	__u8 nxt_hdr_type = ipv6_hdr->nexthdr;
	struct ipv6hdr ipv6_tmp = {0};
	memcpy(&ipv6_tmp, ipv6_hdr, sizeof(struct ipv6hdr));

	struct ethhdr tmp_eth = {0};
	memcpy(&tmp_eth, eth_hdr, ETH_HLEN);
	tmp_eth.h_proto = bpf_htons(ETH_P_IP);

	struct iphdr tmp_ipv4 = {
		.version = 4,
		.ihl = 5,
		.tos = 0,
		.tot_len = bpf_htons(bpf_ntohs(ipv6_hdr->payload_len) + sizeof(struct iphdr)),
		.id = 0,
		.frag_off = bpf_htons(0x01 << 14),
		.ttl = ipv6_hdr->hop_limit,
		.protocol = (nxt_hdr_type == IPPROTO_ICMPV6) ? IPPROTO_ICMP : nxt_hdr_type,
		.saddr = *nat64_v4_addr,
		.daddr = ipv6_hdr->daddr.in6_u.u6_addr32[3],
		.check = 0
	};
	tmp_ipv4.check = compute_ipv4_hdr_checksum((__u16 *)&tmp_ipv4, sizeof(tmp_ipv4));

	if(bpf_xdp_adjust_head(ctx, NAT64_V6_V4_HDR_LENGTH_DIFF) != 0)
		return NAT64_ERROR;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *shift_eth = data;
	assert_len(shift_eth, data_end);
	memcpy(shift_eth, &tmp_eth, ETH_HLEN);

	struct iphdr *ipv4 = (struct iphdr *)((void *)(shift_eth + 1));
	assert_len(ipv4, data_end);
	memcpy(ipv4, &tmp_ipv4, sizeof(tmp_ipv4));

	if (nxt_hdr_type == IPPROTO_TCP) {
		if (__is_tcp_udp_cksum_recalc_enabled) {
			struct tcphdr *tcp_hdr = (struct tcphdr *)(ipv4 + 1);
			assert_len(tcp_hdr, data_end);
			tcp_hdr->check = update_tcp_udp_checksum(tcp_hdr->check, 0, 0,
													&ipv6_tmp, ipv4, NAT64_FLOW_DIRECTION_OUTGOING);
		} else {
			struct tcphdr *tcp_hdr = (struct tcphdr *)(ipv4 + 1);
			assert_len(tcp_hdr, data_end);
			tcp_hdr->check = 0;
		}
	} else if (nxt_hdr_type == IPPROTO_UDP) {
		if (__is_tcp_udp_cksum_recalc_enabled) {
			struct udphdr *udp_hdr = (struct udphdr *)(ipv4 + 1);
			assert_len(udp_hdr, data_end);
			udp_hdr->check = update_tcp_udp_checksum(udp_hdr->check, 0, 0,
													&ipv6_tmp, ipv4, NAT64_FLOW_DIRECTION_OUTGOING);
		} else {
			struct udphdr *udp_hdr = (struct udphdr *)(ipv4 + 1);
			assert_len(udp_hdr, data_end);
			udp_hdr->check = 0;
		}
	} else if (nxt_hdr_type == IPPROTO_ICMPV6) {
		struct icmp6hdr *icmp6_hdr = (struct icmp6hdr *)(ipv4 + 1);
		struct icmphdr *icmp_hdr = (struct icmphdr *)icmp6_hdr;
		assert_len(icmp_hdr, data_end);

		if (icmp6_hdr->icmp6_type == ICMPV6_ECHO_REQUEST)
			icmp_hdr->type = ICMP_ECHO;
		else
			icmp_hdr->type = ICMP_ECHOREPLY;

		icmp_hdr->un.echo.id = icmp6_hdr->icmp6_dataun.u_echo.identifier;
		icmp_hdr->checksum = 0;

		if (__is_icmp_icmp6_cksum_recalc_enabled)
			icmp_hdr->checksum = compute_icmp_cksum((void *)(long)ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr), data_end, bpf_ntohs(ipv6_tmp.payload_len));
	} else {
		// Other protocols are not handled in stateless mode
		NAT64_LOG_ERROR("Unsupported l4 protocol in stateless mode", NAT64_LOG_L4_PROTOCOL(nxt_hdr_type));
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

static __always_inline int
convert_v4_pkt_to_v6_pkt_stateless(struct xdp_md *ctx, const union ipv6_addr *original_ip6,
									struct ethhdr *eth_hdr, struct iphdr *ipv4_hdr)
{
	__u8 nxt_hdr_type = ipv4_hdr->protocol;

	struct iphdr ipv4_tmp = {0};
	memcpy(&ipv4_tmp, ipv4_hdr, sizeof(struct iphdr));

	struct ethhdr tmp_eth = {};
	memcpy(&tmp_eth, eth_hdr, ETH_HLEN);
	tmp_eth.h_proto = bpf_htons(ETH_P_IPV6);

	struct ipv6hdr tmp_ipv6 = {
		.version = 6,
		.flow_lbl = {0},
		.payload_len = bpf_htons(bpf_ntohs(ipv4_hdr->tot_len) - sizeof(struct iphdr)),
		.nexthdr = (nxt_hdr_type == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : nxt_hdr_type,
		.hop_limit = ipv4_hdr->ttl,
	};
	memcpy(&tmp_ipv6.saddr, &nat64_ipv6_prefix, 12);
	memcpy(&tmp_ipv6.saddr.s6_addr32[3], &ipv4_hdr->saddr, 4);
	memcpy(&tmp_ipv6.daddr, original_ip6, sizeof(tmp_ipv6.daddr));

	if (bpf_xdp_adjust_head(ctx, -NAT64_V6_V4_HDR_LENGTH_DIFF) != 0)
		return NAT64_ERROR;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *new_eth = data;
	assert_len(new_eth, data_end);
	memcpy(new_eth, &tmp_eth, sizeof(tmp_eth));

	struct ipv6hdr *new_ipv6 = (struct ipv6hdr *)(new_eth + 1);
	assert_len(new_ipv6, data_end);
	memcpy(new_ipv6, &tmp_ipv6, sizeof(tmp_ipv6));

	if (nxt_hdr_type == IPPROTO_TCP) {
		struct tcphdr *tcp_hdr = (struct tcphdr *)(new_ipv6 + 1);
		assert_len(tcp_hdr, data_end);
		if (__is_tcp_udp_cksum_recalc_enabled) {
			tcp_hdr->check = update_tcp_udp_checksum(tcp_hdr->check, 0, 0,
													new_ipv6, &ipv4_tmp, NAT64_FLOW_DIRECTION_INCOMING);
		} else {
			tcp_hdr->check = 0;
		}
	} else if (nxt_hdr_type == IPPROTO_UDP) {
		struct udphdr *udp_hdr = (struct udphdr *)(new_ipv6 + 1);
		assert_len(udp_hdr, data_end);
		if (__is_tcp_udp_cksum_recalc_enabled) {
			udp_hdr->check = update_tcp_udp_checksum(udp_hdr->check, 0, 0,
													new_ipv6, &ipv4_tmp, NAT64_FLOW_DIRECTION_INCOMING);
		} else {
			udp_hdr->check = 0;
		}
	} else if (nxt_hdr_type == IPPROTO_ICMP) {
		struct icmphdr *icmp_hdr = (struct icmphdr *)(new_ipv6 + 1);
		struct icmp6hdr *icmp6_hdr = (struct icmp6hdr *)icmp_hdr;
		assert_len(icmp_hdr, data_end);

		if (icmp_hdr->type == ICMP_ECHO)
			icmp6_hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
		else if (icmp_hdr->type == ICMP_ECHOREPLY)
			icmp6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;

		icmp6_hdr->icmp6_dataun.u_echo.identifier = icmp_hdr->un.echo.id;
		icmp6_hdr->icmp6_cksum = 0;

		if (__is_icmp_icmp6_cksum_recalc_enabled) {
				data = (void *)(long)ctx->data;
				data_end = (void *)(long)ctx->data_end;
				struct ipv6hdr *ipv6_hdr = (struct ipv6hdr *)(data + sizeof(struct ethhdr));
				assert_len(ipv6_hdr, data_end);
			icmp6_hdr->icmp6_cksum = compute_icmp6_cksum(ipv6_hdr, data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr), data_end, bpf_ntohs(ipv6_hdr->payload_len));
		}
	} else {
		// Other protocols are not handled in stateless mode
		NAT64_LOG_ERROR("Unsupported l4 protocol in stateless mode", NAT64_LOG_L4_PROTOCOL(nxt_hdr_type));
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

static __always_inline int
stateless_process_ipv6_pkt(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ipv6_hdr = (struct ipv6hdr *)nxt_ptr;
	assert_len(ipv6_hdr, data_end);

	if (!is_nat64_ipv6_address(ipv6_hdr))
		return NAT64_IGNORE;

	union ipv6_addr key = {0};
	memcpy(&key, &ipv6_hdr->saddr, sizeof(key));

	__u32 *value = bpf_map_lookup_elem(&nat64_stateless_v6_v4_map, &key);
	if (!value) {
		NAT64_LOG_DEBUG("No stateless mapping for IPv6 source, dropping packet");
		nat64_exporter_increment_drop_pkts();
		return NAT64_ERROR;
	}

	int ret = convert_v6_pkt_to_v4_pkt_stateless(ctx, value, eth, ipv6_hdr);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to convert v6 pkt to v4 pkt in stateless mode");
		nat64_exporter_increment_drop_pkts();
		return NAT64_ERROR;
	}
	// nat64_exporter_increment_translated_pkts();

	return NAT64_OK;
}

static __always_inline int
stateless_process_ipv4_pkt(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ipv4_hdr = (struct iphdr *)nxt_ptr;
	assert_len(ipv4_hdr, data_end);

	__u32 key = 0;
	key = ipv4_hdr->daddr;

	union ipv6_addr *value = bpf_map_lookup_elem(&nat64_stateless_v4_v6_map, &key);
	if (!value) {
		NAT64_LOG_DEBUG("No stateless mapping for IPv4 destination, ignoring packet");
		return NAT64_IGNORE;
	}

	int ret = convert_v4_pkt_to_v6_pkt_stateless(ctx, value, eth, ipv4_hdr);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to convert v4 pkt to v6 pkt in stateless mode");
		nat64_exporter_increment_drop_pkts();
		return NAT64_ERROR;
	}
	// nat64_exporter_increment_translated_pkts();

	return NAT64_OK;
}

#endif // STATELESS_DATAPATH_FUNCS_H
