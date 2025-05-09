// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0



// #include <linux/in.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "nat64_common.h"

#include "nat64_user_log.h"
#include "ebpf_nat64_test_func.h"
#include "ebpf_nat64_test_udp_tcp.h"
#include "ebpf_nat64_test_icmp6.h"
#include "ebpf_nat64_test_peak_udp.h"
#include "nat64_ebpf_skel_handler.h"
#include "nat64_addr_port_assignment.h"
#include "nat64_conf.h"

#include <arpa/inet.h>

const union ipv6_addr ipv6_test_pkt_dst_addr = {
	.u6_addr8 = { 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0x03, 0x01 }
};

const union ipv6_addr ipv6_test_pkt_src_addr = {
	.u6_addr8 = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }
};

const uint32_t ipv4_test_pkt_dst_addr = 0xC0000301; // target ipv4 address
const uint16_t ipv6_test_pkt_l4_src_port = 0x1234; // source port
const uint16_t ipv6_test_pkt_l4_dst_port = 0x5678;

uint32_t ipv4_test_nat64_ip_addr = 0; // source ipv4 address -- NAT64 IP address
uint16_t ipv4_test_nat64_port_range[2] = {0, 0}; // NAT64 port range

extern int attach_iface_index[NAT64_ATTACH_IFACE_MAX_CNT];
extern int attach_iface_cnt;

static void nat64_test_add_dummy_iface(void)
{
	attach_iface_info[0].iface_index = 1;
	attach_iface_info[0].direction = NAT64_IFACE_DIRECTION_SOUTH;
	attach_iface_cnt = 1;
}

int nat64_test_get_cmd_conf(int argc, char **argv)
{
	int ret;

	if (NAT64_FAILED(nat64_parse_args(argc, argv)))
		return NAT64_ERROR;

	ret = parse_addr_port_pool_str(nat64_get_addr_port_pool_str());
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to parse addr:port pool string");
		return NAT64_ERROR;
	}

	nat64_test_add_dummy_iface();

	return NAT64_OK;
}


static void init_test_env(void)
{
	const struct nat64_address_ports_range *nat64_addr_port_pool = nat64_get_parsed_addr_port_pool();

	ipv4_test_nat64_ip_addr = nat64_addr_port_pool[0].addr;
	ipv4_test_nat64_port_range[0] = nat64_addr_port_pool[0].port_range[0];
	ipv4_test_nat64_port_range[1] = nat64_addr_port_pool[0].port_range[1];

}


int nat64_run_tests(void)
{
	init_test_env();

	if (nat64_test_udp() != TEST_PASS) {
		NAT64_LOG_ERROR("Failed to run nat64 UDP test");
		return TEST_ERROR;
	} else {
		printf("UDP test passed \n");
	}

	sleep(5);
	if (nat64_test_tcp() != TEST_PASS) {
		NAT64_LOG_ERROR("Failed to run nat64 TCP test");
		return TEST_ERROR;
	} else {
		printf("TCP test passed \n");
	}

	sleep(5);
	if (nat64_test_icmp6() != TEST_PASS) {
		NAT64_LOG_ERROR("Failed to run nat64 ICMP6 test");
		return TEST_ERROR;
	} else {
		printf("ICMP6 test passed \n");
	}
	sleep(5);

	if (nat64_test_peak_udp() != TEST_PASS) {
		NAT64_LOG_ERROR("Failed to run nat64 peak UDP test");
		return TEST_ERROR;
	} else {
		printf("Peak UDP test passed \n");
	}
	sleep(5);

	return TEST_PASS;
}

