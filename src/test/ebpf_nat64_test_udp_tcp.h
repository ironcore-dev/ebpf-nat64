// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0


#ifndef EBPF_NAT64_TEST_UDP_H_
#define EBPF_NAT64_TEST_UDP_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "ebpf_nat64_test_func.h"
#include "nat64_user_log.h"
#include "nat64_ebpf_skel_handler.h"

#include <arpa/inet.h>


static uint16_t selected_nat_port = 0;
static uint16_t selected_nat_port_second_round = 0;

// Helper function to create a basic IPv6 packet
static void craft_ipv6_udp_tcp_packet(char *packet, size_t *len, uint16_t proto,
	uint16_t l4_src_port, uint16_t l4_dst_port)
{
	struct ethhdr *eth = (struct ethhdr *)packet;
	struct ipv6hdr *ip6 = (struct ipv6hdr *)(packet + sizeof(struct ethhdr));
	struct udphdr *udp;
	struct tcphdr *tcp;

	if (proto == IPPROTO_UDP)
	udp = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
	else if (proto == IPPROTO_TCP)
	tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

	memset(packet, 0, *len);

	// Ethernet header
	eth->h_proto = htons(ETH_P_IPV6);
	memset(eth->h_source, 0x11, ETH_ALEN);
	memset(eth->h_dest, 0x22, ETH_ALEN);

	// IPv6 header
	ip6->version = 6;
	ip6->nexthdr = proto;
	ip6->payload_len = proto == IPPROTO_UDP ? htons(sizeof(struct udphdr)) : htons(sizeof(struct udphdr));
	ip6->hop_limit = 64;
	memcpy(ip6->saddr.s6_addr, ipv6_test_pkt_src_addr.u6_addr8, NAT64_IPV6_ADDR_LENGTH);
	memcpy(ip6->daddr.s6_addr, ipv6_test_pkt_dst_addr.u6_addr8, NAT64_IPV6_ADDR_LENGTH);

	// UDP header
	if (proto == IPPROTO_UDP) {
	udp->source = l4_src_port;
	udp->dest = l4_dst_port;
	udp->len = htons(sizeof(struct udphdr));
	udp->check = 0;  // Checksum left as 0 for simplicity
	} else if (proto == IPPROTO_TCP) {
	tcp->source = l4_src_port;
	tcp->dest = l4_dst_port;
	tcp->window = htons(65535);
	tcp->syn = 1;
	tcp->check = 0;
	}

	*len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + (proto == IPPROTO_UDP ? sizeof(struct udphdr) : sizeof(struct tcphdr));
}

// Helper function to check the validity of an IPv4 packet
static int validate_ipv4_udp_tcp_packet(const char *packet, uint16_t proto,
										uint16_t expected_l4_dst_port, uint16_t *selected_nat_port)
{
	const struct ethhdr *eth = (const struct ethhdr *)packet;
	const struct iphdr *ip4 = (const struct iphdr *)(packet + sizeof(*eth));
	const struct udphdr *udp;
	const struct tcphdr *tcp;

	uint16_t l4_src_port;
	uint16_t l4_dst_port;

	if (proto == IPPROTO_UDP)
		udp = (const struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
	else if (proto == IPPROTO_TCP)
		tcp = (const struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

	// Check Ethernet header
	if (eth->h_proto != htons(ETH_P_IP)) {
		NAT64_LOG_ERROR("Invalid Ethernet header proto field", NAT64_LOG_L4_PROTOCOL(ntohs(eth->h_proto)));
		return TEST_ERROR;
	}

	// Check IPv4 header
	if (ip4->version != 4) {
		NAT64_LOG_ERROR("Invalid IPv4 packet", NAT64_LOG_IP_VERSION(ip4->version));
		return TEST_ERROR;
	}

	if (ip4->saddr != ipv4_test_nat64_ip_addr) {
		NAT64_LOG_ERROR("Invalid source IPv4 address", NAT64_LOG_SRC_IPV4(ip4->saddr), NAT64_LOG_SRC_IPV4(ipv4_test_nat64_ip_addr));
		return TEST_ERROR;
	}

	if (ip4->daddr != htonl(ipv4_test_pkt_dst_addr)) {
		NAT64_LOG_ERROR("Invalid destination IPv4 address", NAT64_LOG_DST_IPV4(ip4->daddr));
		return TEST_ERROR;
	}

	// Check UDP header
	if (proto == IPPROTO_UDP) {
		l4_src_port = udp->source;
		l4_dst_port = udp->dest;
	} else if (proto == IPPROTO_TCP) {
		l4_src_port = tcp->source;
		l4_dst_port = tcp->dest;
	} else {
		NAT64_LOG_ERROR("Invalid l4 protocol", NAT64_LOG_L4_PROTOCOL(proto));
		return TEST_ERROR;
	}


	*selected_nat_port = l4_src_port;

	if (l4_dst_port != expected_l4_dst_port) {
		NAT64_LOG_ERROR("Invalid destination l4 port in ipv4 packet", NAT64_LOG_L4_PROTO_DST_PORT(l4_dst_port));
		return TEST_ERROR;
	}

	if (ntohs(l4_src_port) < ipv4_test_nat64_port_range[0] || ntohs(l4_src_port) > ipv4_test_nat64_port_range[1]) {
		NAT64_LOG_ERROR("Invalid source l4 port (selected NAT port)", NAT64_LOG_L4_PROTO_SRC_PORT(ntohs(l4_src_port)));
		return TEST_ERROR;
	}

	return TEST_PASS;
}

static void craft_ipv4_udp_tcp_packet(char *packet, size_t *len, uint16_t proto,
										uint16_t l4_src_port, uint16_t l4_dst_port)
{
	struct ethhdr *eth = (struct ethhdr *)packet;
	struct iphdr *ip4 = (struct iphdr *)(packet + sizeof(struct ethhdr));
	struct udphdr *udp;
	struct tcphdr *tcp;

	memset(packet, 0, *len);

	eth->h_proto = htons(ETH_P_IP);
	memset(eth->h_source, 0x22, ETH_ALEN);
	memset(eth->h_dest, 0x11, ETH_ALEN);

	ip4->version = 4;
	ip4->saddr = htonl(ipv4_test_pkt_dst_addr);
	ip4->daddr = ipv4_test_nat64_ip_addr;
	ip4->protocol = proto;
	ip4->ttl = 64;
	ip4->check = 0;
	ip4->tot_len = sizeof(struct iphdr) + (proto == IPPROTO_UDP ? sizeof(struct udphdr) : sizeof(struct tcphdr));

	if (proto == IPPROTO_UDP)
		udp = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
	else if (proto == IPPROTO_TCP)
		tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

	if (proto == IPPROTO_UDP) {
		udp->source = l4_src_port;
		udp->dest = l4_dst_port;
		udp->len = htons(sizeof(struct udphdr));
		udp->check = 0;
	} else if (proto == IPPROTO_TCP) {
		tcp->source = l4_src_port;
		tcp->dest = l4_dst_port;
		tcp->window = htons(65535);
		tcp->syn = 1;
		tcp->ack = 1;
		tcp->check = 0;
	}

	*len = sizeof(struct ethhdr) + sizeof(struct iphdr) + (proto == IPPROTO_UDP ? sizeof(struct udphdr) : sizeof(struct tcphdr));
}

static int validate_ipv6_udp_tcp_packet(const char *packet, uint16_t proto,
										uint16_t expected_l4_src_port, uint16_t expected_l4_dst_port)
{
	const struct ethhdr *eth = (const struct ethhdr *)packet;
	const struct ipv6hdr *ip6 = (const struct ipv6hdr *)(packet + sizeof(*eth));
	const struct udphdr *udp;
	const struct tcphdr *tcp;

	uint16_t l4_src_port;
	uint16_t l4_dst_port;

	if (proto == IPPROTO_UDP)
		udp = (const struct udphdr *)(packet + sizeof(*eth) + sizeof(*ip6));
	else if (proto == IPPROTO_TCP)
		tcp = (const struct tcphdr *)(packet + sizeof(*eth) + sizeof(*ip6));

	// check Ethernet header
	if (eth->h_proto != htons(ETH_P_IPV6)) {
		NAT64_LOG_ERROR("Invalid Ethernet header proto field (IPv6)", NAT64_LOG_L4_PROTOCOL(ntohs(eth->h_proto)));
		return TEST_ERROR;
	}

	// check IPv6 header
	if (ip6->version != 6) {
		NAT64_LOG_ERROR("Invalid IPv6 packet", NAT64_LOG_IP_VERSION(ip6->version));
		return TEST_ERROR;
	}

	if (memcmp(ip6->saddr.s6_addr, ipv6_test_pkt_dst_addr.u6_addr8, NAT64_IPV6_ADDR_LENGTH) != 0) {
		NAT64_LOG_ERROR("Invalid source IPv6 address", NAT64_LOG_SRC_IPV6(ip6->saddr.in6_u.u6_addr8));
		return TEST_ERROR;
	}

	if (memcmp(ip6->daddr.s6_addr, ipv6_test_pkt_src_addr.u6_addr8, NAT64_IPV6_ADDR_LENGTH) != 0) {
		NAT64_LOG_ERROR("Invalid destination IPv6 address", NAT64_LOG_DST_IPV6(ip6->daddr.in6_u.u6_addr8));
		return TEST_ERROR;
	}

	if (proto == IPPROTO_UDP) {
		l4_src_port = udp->source;
		l4_dst_port = udp->dest;
	} else if (proto == IPPROTO_TCP) {
		l4_src_port = tcp->source;
		l4_dst_port = tcp->dest;
	} else {
		NAT64_LOG_ERROR("Invalid l4 protocol", NAT64_LOG_L4_PROTOCOL(proto));
		return TEST_ERROR;
	}

	if (l4_src_port != expected_l4_dst_port) {
		NAT64_LOG_ERROR("Invalid source l4 port in IPv6 packet", NAT64_LOG_L4_PROTO_SRC_PORT(l4_src_port));
		return TEST_ERROR;
	}

	if (l4_dst_port != expected_l4_src_port) {
		NAT64_LOG_ERROR("Invalid destination l4 port in IPv6 packet", NAT64_LOG_L4_PROTO_DST_PORT(l4_dst_port));
		return TEST_ERROR;
	}

	return TEST_PASS;
}

static int test_udp_tcp_ipv6_to_ipv4(uint16_t proto, uint16_t l4_src_port, uint16_t l4_dst_port, uint16_t *selected_nat_port)
{
	int ret;
	char packet[128];
	char output[128];
	size_t packet_len = sizeof(packet);

	struct bpf_test_run_opts opts = {
		.sz = sizeof(struct bpf_test_run_opts),
		.data_in = packet,
		.data_out = output,
		.data_size_in = sizeof(packet),
		.data_size_out = sizeof(output),
		.repeat = 1,
		.retval = 0,
	};

	/****IPv6 UDP -> IPv4 UDP, twice****/
	craft_ipv6_udp_tcp_packet(packet, &packet_len, proto, l4_src_port, l4_dst_port);
								// htons(ipv6_test_pkt_l4_src_port), htons(ipv6_test_pkt_l4_dst_port));

	// Run the program with bpf_prog_test_run_opts
	ret = bpf_prog_test_run_opts(nat64_get_prog_fd(), &opts);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to test run in nat64_test_udp", NAT64_LOG_ERRNONUM(ret));
		return TEST_ERROR;
	}

	// Validate output
	if (opts.retval != 2) {
		NAT64_LOG_ERROR("IPV6 packet cannot pass through the program", NAT64_LOG_ERRNONUM(opts.retval));
		return TEST_ERROR;
	}

	ret = validate_ipv4_udp_tcp_packet(output, proto, l4_dst_port, selected_nat_port);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Output validation failed");
		return TEST_ERROR;
	}

	memset(output, 0, sizeof(output));
	return TEST_PASS;
}

static int test_udp_tcp_ipv4_to_ipv6(uint16_t proto, uint16_t l4_src_port, uint16_t l4_dst_port,
										uint16_t expected_l4_src_port, uint16_t expected_l4_dst_port)
{
	/****IPv4 L4 pkt -> IPv6 L4 pkt, once****/
	char packet2[128];
	char output2[256];
	size_t packet_len2 = sizeof(packet2);
	int ret;

	struct bpf_test_run_opts opts2 = {
		.sz = sizeof(struct bpf_test_run_opts),
		.data_in = packet2,
		.data_out = output2,
		.data_size_in = sizeof(packet2),
		.data_size_out = sizeof(output2),
		.repeat = 1,
		.retval = 0,
	};

	craft_ipv4_udp_tcp_packet(packet2, &packet_len2, proto, l4_src_port, l4_dst_port);

	memset(output2, 0, sizeof(output2));
	ret = bpf_prog_test_run_opts(nat64_get_prog_fd(), &opts2);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to test run in nat64_test_udp (IPv4 -> IPv6)", NAT64_LOG_ERRNO(ret));
		return TEST_ERROR;
	}

	// Validate output
	if (opts2.retval != 2) {
		NAT64_LOG_ERROR("IPV4 Packet cannot pass through the program", NAT64_LOG_ERRNONUM(opts2.retval));
		return TEST_ERROR;
	}

	ret = validate_ipv6_udp_tcp_packet(output2, proto, expected_l4_src_port, expected_l4_dst_port);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Output validation failed");
		return TEST_ERROR;
	}

	return TEST_PASS;
}

int nat64_test_udp(void)
{
	int ret;

	// first round echo
	ret = test_udp_tcp_ipv6_to_ipv4(IPPROTO_UDP, htons(ipv6_test_pkt_l4_src_port),
									htons(ipv6_test_pkt_l4_dst_port), &selected_nat_port);
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	ret = test_udp_tcp_ipv4_to_ipv6(IPPROTO_UDP, htons(ipv6_test_pkt_l4_dst_port), selected_nat_port,
									htons(ipv6_test_pkt_l4_src_port), htons(ipv6_test_pkt_l4_dst_port));
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	// second round echo
	ret = test_udp_tcp_ipv6_to_ipv4(IPPROTO_UDP, htons(ipv6_test_pkt_l4_src_port),
									htons(ipv6_test_pkt_l4_dst_port), &selected_nat_port_second_round);
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	if (selected_nat_port_second_round != selected_nat_port) {
			NAT64_LOG_ERROR("Selected NAT port is NOT the same as the first packet");
			return TEST_ERROR;
	}

	ret = test_udp_tcp_ipv4_to_ipv6(IPPROTO_UDP, htons(ipv6_test_pkt_l4_dst_port), selected_nat_port_second_round,
									htons(ipv6_test_pkt_l4_src_port), htons(ipv6_test_pkt_l4_dst_port));
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	return TEST_PASS;
}

int nat64_test_tcp(void)
{
	int ret;

	// first round echo
	ret = test_udp_tcp_ipv6_to_ipv4(IPPROTO_TCP, htons(ipv6_test_pkt_l4_src_port),
									htons(ipv6_test_pkt_l4_dst_port), &selected_nat_port);
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	ret = test_udp_tcp_ipv4_to_ipv6(IPPROTO_TCP, htons(ipv6_test_pkt_l4_dst_port), selected_nat_port,
									htons(ipv6_test_pkt_l4_src_port), htons(ipv6_test_pkt_l4_dst_port));
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	// second round echo
	ret = test_udp_tcp_ipv6_to_ipv4(IPPROTO_TCP, htons(ipv6_test_pkt_l4_src_port),
									htons(ipv6_test_pkt_l4_dst_port), &selected_nat_port_second_round);
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	if (selected_nat_port_second_round != selected_nat_port) {
		NAT64_LOG_ERROR("Selected NAT port is NOT the same as the first packet");
		return TEST_ERROR;
	}

	ret = test_udp_tcp_ipv4_to_ipv6(IPPROTO_TCP, htons(ipv6_test_pkt_l4_dst_port), selected_nat_port_second_round,
									htons(ipv6_test_pkt_l4_src_port), htons(ipv6_test_pkt_l4_dst_port));
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	return TEST_PASS;
}



#endif
