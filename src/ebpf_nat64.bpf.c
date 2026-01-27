// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

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

#include "ebpf_lib/common_bpf_maps.h"
#include "ebpf_lib/datapath_selection.h"


static __always_inline int nat64_send_packet(struct xdp_md *ctx)
{
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
