#ifndef EBPF_NAT64_TEST_ICMP6_H
#define EBPF_NAT64_TEST_ICMP6_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "ebpf_nat64_test_func.h"
#include "nat64_user_log.h"
#include "nat64_ebpf_skel_handler.h"

#include <arpa/inet.h> 

static uint16_t selected_icmp6_id = 0;

static void craft_ipv6_icmp6_packet(char *packet, size_t *len) {
	struct ethhdr *eth = (struct ethhdr *)packet;
	struct ipv6hdr *ip6 = (struct ipv6hdr *)(packet + sizeof(struct ethhdr));
	struct icmp6hdr *icmp6 = (struct icmp6hdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

	memset(packet, 0, *len);

	// Ethernet header
	eth->h_proto = htons(ETH_P_IPV6);
	memset(eth->h_source, 0x11, ETH_ALEN);
	memset(eth->h_dest, 0x22, ETH_ALEN);

	// IPv6 header
	ip6->version = 6;
	ip6->nexthdr = IPPROTO_ICMPV6;
	ip6->hop_limit = 64;
	memcpy(ip6->saddr.s6_addr, ipv6_test_pkt_src_addr.u6_addr8, NAT64_IPV6_ADDR_LENGTH);
	memcpy(ip6->daddr.s6_addr, ipv6_test_pkt_dst_addr.u6_addr8, NAT64_IPV6_ADDR_LENGTH);

	// ICMPv6 header
	icmp6->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_dataun.u_echo.identifier = htons(100);
	icmp6->icmp6_dataun.u_echo.sequence = htons(2);

	*len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr);
}

static int validate_ipv4_icmp_packet(const char *packet, size_t len) {
	const struct ethhdr *eth = (const struct ethhdr *)packet;
	const struct iphdr *ip4 = (const struct iphdr *)(packet + sizeof(struct ethhdr));
	const struct icmphdr *icmp = (const struct icmphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

	if (eth->h_proto != htons(ETH_P_IP)) {
		NAT64_LOG_ERROR("Invalid Ethernet header proto field (ETH_P_IP)", NAT64_LOG_L4_PROTOCOL(ntohs(eth->h_proto)));
		return TEST_ERROR;
	}

	// check IPv4 header
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

	if (ip4->protocol != IPPROTO_ICMP) {
		NAT64_LOG_ERROR("Invalid ICMP protocol id in ipv4 header", NAT64_LOG_L4_PROTOCOL(ip4->protocol));
		return TEST_ERROR;
	}

	// check ICMP header
	if (icmp->type != ICMP_ECHO) {
		NAT64_LOG_ERROR("Invalid ICMP type", NAT64_LOG_ICMP_TYPE(icmp->type));
		return TEST_ERROR;
	}

	selected_icmp6_id = icmp->un.echo.id;

	if (icmp->un.echo.sequence != htons(2)) {
		NAT64_LOG_ERROR("Invalid ICMP sequence", NAT64_LOG_VALUE(htons(icmp->un.echo.sequence)));
		return TEST_ERROR;
	}

	if (ntohs(selected_icmp6_id) < ipv4_test_nat64_port_range[0] || ntohs(selected_icmp6_id) > ipv4_test_nat64_port_range[1]) {
		NAT64_LOG_ERROR("Invalid ICMP identifier (selected NAT port)", NAT64_LOG_L4_PROTO_SRC_PORT(ntohs(selected_icmp6_id)));
		return TEST_ERROR;
	}

	return TEST_PASS;
}


static void craft_ipv4_icmp_packet(char *packet, size_t *len)
{
	struct ethhdr *eth = (struct ethhdr *)packet;
	struct iphdr *ip4 = (struct iphdr *)(packet + sizeof(struct ethhdr));
	struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

	memset(packet, 0, *len);

	eth->h_proto = htons(ETH_P_IP);
	memset(eth->h_source, 0x22, ETH_ALEN);
	memset(eth->h_dest, 0x11, ETH_ALEN);

	ip4->version = 4;
	ip4->saddr = htonl(ipv4_test_pkt_dst_addr);
	ip4->daddr = ipv4_test_nat64_ip_addr;
	ip4->protocol = IPPROTO_ICMP;
	ip4->ttl = 64;
	ip4->check = 0;
	ip4->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);

	icmp->type = ICMP_ECHOREPLY;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.id = selected_icmp6_id;
	icmp->un.echo.sequence = htons(2);

	*len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr);
}


static int validate_ipv6_icmp6_packet(const char *packet, size_t len)
{
	const struct ethhdr *eth = (const struct ethhdr *)packet;
	const struct ipv6hdr *ip6 = (const struct ipv6hdr *)(packet + sizeof(*eth));
	const struct icmp6hdr *icmp6 = (const struct icmp6hdr *)(packet + sizeof(*eth) + sizeof(*ip6));


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

	//check ICMPv6 header
	if (icmp6->icmp6_type != ICMPV6_ECHO_REPLY) {
		NAT64_LOG_ERROR("Invalid ICMPv6 type", NAT64_LOG_ICMP_TYPE(icmp6->icmp6_type));
		return TEST_ERROR;
	}

	if (icmp6->icmp6_dataun.u_echo.identifier != htons(100)) {
		NAT64_LOG_ERROR("Invalid ICMPv6 identifier", NAT64_LOG_VALUE(htons(icmp6->icmp6_dataun.u_echo.identifier)));
		return TEST_ERROR;
	}

	if (icmp6->icmp6_dataun.u_echo.sequence != htons(2)) {
		NAT64_LOG_ERROR("Invalid ICMPv6 sequence", NAT64_LOG_VALUE(htons(icmp6->icmp6_dataun.u_echo.sequence)));
		return TEST_ERROR;
	}

	return TEST_PASS;

}

static int test_icmp6_to_icmp(void)
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


	// send one icmp6 packet
	craft_ipv6_icmp6_packet(packet, &packet_len);

	ret = bpf_prog_test_run_opts(nat64_get_prog_fd(), &opts);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to test run in nat64_test_icmp6", NAT64_LOG_ERRNONUM(ret));
		return TEST_ERROR;
	}

	if (opts.retval != 2) {
		NAT64_LOG_ERROR("IPV4 Packet cannot pass through the program", NAT64_LOG_ERRNONUM(opts.retval));
		return TEST_ERROR;
	}

	ret = validate_ipv4_icmp_packet(output, opts.data_size_out);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Output validation failed");
		return TEST_ERROR;
	}

	// send same icmp6 packet again
	ret = bpf_prog_test_run_opts(nat64_get_prog_fd(), &opts);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to test run in nat64_test_icmp6", NAT64_LOG_ERRNONUM(ret));
		return TEST_ERROR;
	}

	if (opts.retval != 2) {
		NAT64_LOG_ERROR("IPV4 Packet cannot pass through the program", NAT64_LOG_ERRNONUM(opts.retval));
		return TEST_ERROR;
	}

	ret = validate_ipv4_icmp_packet(output, opts.data_size_out);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Output validation failed");
		return TEST_ERROR;
	}

	return TEST_PASS;
}

static int test_icmp_to_icmp6(void)
{
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

	craft_ipv4_icmp_packet(packet2, &packet_len2);

	ret = bpf_prog_test_run_opts(nat64_get_prog_fd(), &opts2);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to test run in nat64_test_icmp6", NAT64_LOG_ERRNONUM(ret));
		return TEST_ERROR;
	}

	if (opts2.retval != 2) {
		NAT64_LOG_ERROR("IPV4 Packet cannot pass through the program", NAT64_LOG_ERRNONUM(opts2.retval));
		return TEST_ERROR;
	}

	ret = validate_ipv6_icmp6_packet(output2, opts2.data_size_out);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Output validation failed");
		return TEST_ERROR;
	}

	return TEST_PASS;
}

int nat64_test_icmp6(void)
{
	int ret;

	ret = test_icmp6_to_icmp();
	if (NAT64_FAILED(ret)) {
		return TEST_ERROR;
	}

	ret = test_icmp_to_icmp6();
	if (NAT64_FAILED(ret)) {
		return TEST_ERROR;
	}

	return TEST_PASS;
}





#endif
