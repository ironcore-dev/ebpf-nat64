#ifndef EBPF_NAT64_TEST_FUNC_H_
#define EBPF_NAT64_TEST_FUNC_H_


#include "nat64_common.h"

#define TEST_ERROR NAT64_ERROR
#define TEST_PASS NAT64_OK
#define TEST_FAILED(ret) NAT64_FAILED(ret)


extern const union ipv6_addr nat64_ipv6_prefix;
extern const union ipv6_addr nat64_ipv6_mask;


extern const union ipv6_addr ipv6_test_pkt_dst_addr;
extern const union ipv6_addr ipv6_test_pkt_src_addr;

extern const uint32_t ipv4_test_pkt_dst_addr;
extern uint32_t ipv4_test_nat64_ip_addr;
extern uint16_t ipv4_test_nat64_port_range[2];
extern const uint16_t ipv6_test_pkt_l4_src_port;
extern const uint16_t ipv6_test_pkt_l4_dst_port;


int nat64_run_tests(void);
int nat64_test_get_cmd_conf(int argc, char **argv);

#endif
