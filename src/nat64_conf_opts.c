#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "nat64_common.h"
#include "nat64_conf_opts.h"
#include "nat64_log_common.h"
#include "nat64_user_log.h"

#define OPT_LOG_LEVEL	"log-level"
#define OPT_ADDR_PORT_POOL "addr-port-pool"
#define OPT_ATTACH_IFACE "interface"
#define OPT_ENABLE_SKB_MODE "skb-mode"

/*argument parsing related definitions*/
static const char short_options[] = "d" /* debug */
				"D"	 /* debug */
				"h";

static int debug_mode = 0;
static uint16_t log_level = 0;
static int enable_skb_mode = 0;
static char nat64_addr_port_pool_str[256] = {0};
static char nat64_attach_iface_str[256] = {0};


enum {
	OPT_MIN_NUM = 256,
	OPT_LOG_LEVEL_NUM,
	OPT_ADDR_PORT_POOL_NUM,
	OPT_ATTACH_IFACE_NUM,
	OPT_ENABLE_SKB_MODE_NUM,
};

static const struct option lgopts[] = {
	{OPT_LOG_LEVEL, 1, 0, OPT_LOG_LEVEL_NUM},
	{OPT_ADDR_PORT_POOL, 1, 0, OPT_ADDR_PORT_POOL_NUM},
	{OPT_ATTACH_IFACE, 1, 0, OPT_ATTACH_IFACE_NUM},
	{OPT_ENABLE_SKB_MODE, 0, 0, OPT_ENABLE_SKB_MODE_NUM},
};


void nat64_print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s --"
		" -d"
		" [-D]"
		" -h"
		" --log-level (error|warning|info|debug)"
		""
		"\n",
		prgname);
}


static int get_log_level_from_name(const char *name) {
	if (strcmp(name, "error") == 0) {
		return NAT64_LOG_LEVEL_ERROR;
	} else if (strcmp(name, "warning") == 0) {
		return NAT64_LOG_LEVEL_WARNING;
	} else if (strcmp(name, "info") == 0) {
		return NAT64_LOG_LEVEL_INFO;
	} else if (strcmp(name, "debug") == 0) {
		return NAT64_LOG_LEVEL_DEBUG;
	} else {
		return NAT64_ERROR;  // Invalid log level name
	}
}


int nat64_parse_args(int argc, char **argv)
{
	char *prgname = argv[0];
	int option_index;
	char **argvopt;
	int opt, ret;

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
				  &option_index)) != EOF) {

		switch (opt) {
		case 'd':
		case 'D':
			debug_mode = 1;
			break;
		case 'h':
			nat64_print_usage(prgname);
			return NAT64_ERROR;
		case OPT_LOG_LEVEL_NUM:
			log_level = get_log_level_from_name(optarg);
			if (NAT64_FAILED(log_level)) {
				NAT64_LOG_ERROR("Invalid log level", NAT64_LOG_OPT_STR(optarg));
				nat64_print_usage(prgname);
				return NAT64_ERROR;
			}
			break;
		case OPT_ADDR_PORT_POOL_NUM:
			strncpy(nat64_addr_port_pool_str, optarg, 256);
			break;
		case OPT_ATTACH_IFACE_NUM:
			strncpy(nat64_attach_iface_str, optarg, 256);
			break;
		case OPT_ENABLE_SKB_MODE_NUM:
			enable_skb_mode = 1;
			break;
		default:
			nat64_print_usage(prgname);
			return NAT64_ERROR;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	ret = optind - 1;
	optind = 1; /* Reset getopt lib */

	return ret;
}


const char* nat64_get_addr_port_pool_str(void)
{
	return nat64_addr_port_pool_str;
}

const char* nat64_get_attach_iface_str(void)
{
	return nat64_attach_iface_str;
}

bool nat64_get_skb_mode(void)
{
	return enable_skb_mode;
}

uint16_t nat64_get_log_level(void)
{
	return log_level;
}

