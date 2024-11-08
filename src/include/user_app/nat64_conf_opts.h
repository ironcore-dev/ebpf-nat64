
#ifndef __NAT64_CONF_OPTS_H
#define __NAT64_CONF_OPTS_H

#include <getopt.h>
#include <unistd.h>

void nat64_print_usage(const char *prgname);

int nat64_parse_args(int argc, char **argv);

const char* nat64_get_addr_port_pool_str(void);
const char* nat64_get_attach_iface_str(void);
bool nat64_get_skb_mode(void);
__u16 nat64_get_log_level(void);


#endif
