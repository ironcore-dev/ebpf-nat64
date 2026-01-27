// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0


#ifndef NAT64_CONF_H
#define NAT64_CONF_H

#include "nat64_common.h"
#include "nat64_conf_opts.h"
#include <netinet/in.h>
#include "nat64_ipaddr.h"

struct ebpf_nat64_bpf;

enum nat64_iface_direction {
	NAT64_IFACE_DIRECTION_NORTH, // internet facing
	NAT64_IFACE_DIRECTION_SOUTH, // private network facing
};

struct nat64_attach_iface_info {
	int iface_index;
	enum nat64_iface_direction direction;
};

extern struct nat64_attach_iface_info attach_iface_info[NAT64_ATTACH_IFACE_MAX_CNT];
extern int attach_iface_cnt;

#ifdef STATELESS_NAT64
struct nat64_stateless_mapping {
	union ipv6_addr v6_addr;
	__u32 v4_addr;
};
extern struct nat64_stateless_mapping stateless_mappings[5];
extern int stateless_mapping_cnt;
int parse_nat64_address_mapping_str(const char *mapping_str);

#else
const struct nat64_address_ports_range *nat64_get_parsed_addr_port_pool(void);
int parse_addr_port_pool_str(const char *nat64_addr_port_pool_str);

#endif


int nat64_populate_conf_to_maps(struct ebpf_nat64_bpf *skel);

int nat64_get_cmd_conf(int argc, char **argv);

void nat64_print_parsed_results(void);

int nat64_get_parsed_addr_port_cnt(void);
int nat64_get_parsed_attach_iface_cnt(void);
const struct nat64_attach_iface_info *nat64_get_parsed_attach_iface_info(void);
int nat64_set_kernel_config(void);

#endif
