#ifndef __NAT64_CONF_H
#define __NAT64_CONF_H

#include <arpa/inet.h> 

#include "nat64_common.h"
#include "nat64_conf_opts.h"

int nat64_get_cmd_conf(int argc, char **argv);

int nat64_get_parsed_addr_port_cnt(void);
int nat64_get_parsed_attach_iface_cnt(void);
const struct nat64_address_ports_range* nat64_get_parsed_addr_port_pool(void);
const int* nat64_get_parsed_attach_iface_index(void);

int nat64_set_kernel_config(void);

#endif
