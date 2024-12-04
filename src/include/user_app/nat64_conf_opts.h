
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
bool nat64_get_skb_mode(void);
bool nat64_get_disable_cksum_recalc_flag(void);
__u16 nat64_get_log_level(void);


#endif
