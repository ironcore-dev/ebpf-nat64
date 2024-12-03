#ifndef NAT64_CONF_H
#define NAT64_CONF_H

#include "nat64_common.h"
#include "nat64_conf_opts.h"

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

int nat64_get_cmd_conf(int argc, char **argv);

int nat64_get_parsed_addr_port_cnt(void);
int nat64_get_parsed_attach_iface_cnt(void);
const struct nat64_address_ports_range *nat64_get_parsed_addr_port_pool(void);
const struct nat64_attach_iface_info *nat64_get_parsed_attach_iface_info(void);
int nat64_set_kernel_config(void);
int parse_addr_port_pool_str(const char *nat64_addr_port_pool_str);

#endif
