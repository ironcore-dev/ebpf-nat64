#ifndef EBPF_NAT64_TEST_PEAK_UDP_H_
#define EBPF_NAT64_TEST_PEAK_UDP_H_

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
#include "ebpf_nat64_test_udp_tcp.h"

#include <arpa/inet.h>

static uint16_t selected_nat_port_first_flow = 0;
static uint16_t selected_nat_port_second_flow = 0;

const uint16_t ipv4_test_second_pkt_l4_src_port_second = 0x4321;

int nat64_test_peak_udp(void)
{
	int ret;

	// first flow echo
	ret = test_udp_tcp_ipv6_to_ipv4(IPPROTO_UDP, htons(ipv6_test_pkt_l4_src_port),
									htons(ipv6_test_pkt_l4_dst_port), &selected_nat_port_first_flow);
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	ret = test_udp_tcp_ipv4_to_ipv6(IPPROTO_UDP, htons(ipv6_test_pkt_l4_dst_port), selected_nat_port_first_flow,
									htons(ipv6_test_pkt_l4_src_port), htons(ipv6_test_pkt_l4_dst_port));
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	// second flow echo
	ret = test_udp_tcp_ipv6_to_ipv4(IPPROTO_UDP, htons(ipv4_test_second_pkt_l4_src_port_second),
									htons(ipv6_test_pkt_l4_dst_port), &selected_nat_port_second_flow);
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	ret = test_udp_tcp_ipv4_to_ipv6(IPPROTO_UDP, htons(ipv6_test_pkt_l4_dst_port), selected_nat_port_second_flow,
									htons(ipv4_test_second_pkt_l4_src_port_second), htons(ipv6_test_pkt_l4_dst_port));
	if (NAT64_FAILED(ret))
		return TEST_ERROR;

	// check if the selected NAT ports are different
	if (selected_nat_port_second_flow == selected_nat_port_first_flow) {
		NAT64_LOG_ERROR("Selected NAT ports are same for two different flows", NAT64_LOG_L4_PROTO_SRC_PORT(ntohs(selected_nat_port_first_flow)));
		return TEST_ERROR;
	}

	return TEST_PASS;
}


#endif
