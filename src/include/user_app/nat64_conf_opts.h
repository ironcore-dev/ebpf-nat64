// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0


#ifndef NAT64_CONF_OPTS_H
#define NAT64_CONF_OPTS_H

#include <getopt.h>
#include <unistd.h>

#define NAT64_CONF_DEFAULT_CONF_FILE "/etc/nat64_config.conf"

void nat64_print_usage(const char *prgname);

int nat64_parse_args(int argc, char **argv);
int nat64_parse_config_file(const char *env_filename);

const char *nat64_get_addr_port_pool_str(void);
const char *nat64_get_attach_south_iface_str(void);
const char *nat64_get_attach_north_iface_str(void);

#ifdef STATELESS_NAT64
const char *nat64_get_nat64_address_mapping_str(void);
#endif

bool nat64_get_skb_mode(void);
bool nat64_get_enable_icmp_icmp6_cksum_recalc(void);
bool nat64_get_enable_tcp_udp_cksum_recalc(void);
__u16 nat64_get_log_level(void);
bool nat64_get_enable_multi_page_mode(void);
bool nat64_get_enable_json_log(void);
bool nat64_get_enable_test_mode(void);
int nat64_get_forwarding_mode(void);


#endif
