#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "nat64_common.h"
#include "nat64_conf_opts.h"
#include "nat64_log_common.h"
#include "nat64_user_log.h"

#define OPT_DISPLAY_HELP "help"
#define OPT_LOG_LEVEL	"log-level"
#define OPT_ADDR_PORT_POOL "addr-port-pool"
#define OPT_ATTACH_NORTH_IFACE "north-interface"
#define OPT_ATTACH_SOUTH_IFACE "south-interface"
#define OPT_ENABLE_SKB_MODE "skb-mode"
#define OPT_DISABLE_CKSUM_RECALC "disable-cksum-recalc"

/*argument parsing related definitions*/
static const char short_options[] = "d" /* debug */
				"D"	 /* debug */
				"h";

static int log_level = 0;
static bool enable_skb_mode = 0;
static char nat64_attach_north_iface_str[256] = {0};
static char nat64_attach_south_iface_str[256] = {0};
static char nat64_addr_port_pool_str[256] = {0};
static bool disable_cksum_recalc = 0;


enum {
	OPT_MIN_NUM = 256,
	OPT_DISPLAY_HELP_NUM,
	OPT_LOG_LEVEL_NUM,
	OPT_ADDR_PORT_POOL_NUM,
	OPT_ATTACH_SOUTH_IFACE_NUM,
	OPT_ATTACH_NORTH_IFACE_NUM,
	OPT_ENABLE_SKB_MODE_NUM,
	OPT_DISABLE_CKSUM_RECALC_NUM,
};

static const struct option nat64_conf_longopts[] = {
	{OPT_DISPLAY_HELP, 0, 0, OPT_DISPLAY_HELP_NUM},
	{OPT_LOG_LEVEL, 1, 0, OPT_LOG_LEVEL_NUM},
	{OPT_ADDR_PORT_POOL, 1, 0, OPT_ADDR_PORT_POOL_NUM},
	{OPT_ATTACH_NORTH_IFACE, 1, 0, OPT_ATTACH_NORTH_IFACE_NUM},
	{OPT_ATTACH_SOUTH_IFACE, 1, 0, OPT_ATTACH_SOUTH_IFACE_NUM},
	{OPT_ENABLE_SKB_MODE, 0, 0, OPT_ENABLE_SKB_MODE_NUM},
	{OPT_DISABLE_CKSUM_RECALC, 0, 0, OPT_DISABLE_CKSUM_RECALC_NUM},
};


void nat64_print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s --"
		" --help [-h]"
		" --log-level (error|warning|info|debug)"
		" --addr-port-pool <addr:port-range>"
		" --north-iface <iface1,iface2,...>"
		" --south-iface <iface1,iface2,...>"
		" --disable-cksum-recalc"
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

	while ((opt = getopt_long(argc, argvopt, short_options, nat64_conf_longopts,
				  &option_index)) != EOF) {

		switch (opt) {
		case 'h':
		case OPT_DISPLAY_HELP_NUM:
			nat64_print_usage(prgname);
			return NAT64_ERROR;
		case OPT_LOG_LEVEL_NUM:
			if (optarg == NULL) {
				NAT64_LOG_ERROR("Log level is required");
				nat64_print_usage(prgname);
				return NAT64_ERROR;
			}
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
		case OPT_ATTACH_SOUTH_IFACE_NUM:
			strncpy(nat64_attach_south_iface_str, optarg, 256);
			break;
		case OPT_ATTACH_NORTH_IFACE_NUM:
			strncpy(nat64_attach_north_iface_str, optarg, 256);
			break;
		case OPT_ENABLE_SKB_MODE_NUM:
			enable_skb_mode = 1;
			break;
		case OPT_DISABLE_CKSUM_RECALC_NUM:
			disable_cksum_recalc = 1;
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

static const struct option *get_opt_by_name(const char *name)
{
	const struct option *longopt;

	// accessing the generated longopts array here
	for (longopt = nat64_conf_longopts; longopt->name; ++longopt)
		if (!strcmp(name, longopt->name))
			return longopt;

	return NULL;
}

// config file parsing related functions are inspired from the dpservice project
static int dp_argparse_string(const char *arg, char *dst, size_t dst_size)
{
	size_t len = strlen(arg);

	if (len >= dst_size) {
		fprintf(stderr, "Value '%s' is too long (max %lu characters)\n", arg, dst_size-1);
		return NAT64_ERROR;
	}

	memcpy(dst, arg, len+1);  // including \0
	return NAT64_OK;
}


static int parse_line(char *line, int lineno)
{
	char *key;
	char *argument;
	const struct option *longopt;
	int ret = NAT64_OK;

	// Ignore comments and empty lines
	if (*line == '#' || *line == '\n')
		return NAT64_OK;

	key = strtok(line, " \t\n");
	if (!key) {
		NAT64_LOG_ERROR("Config file error: no key on line %d", lineno);
		return NAT64_ERROR;
	}

	longopt = get_opt_by_name(key);

	argument = strtok(NULL, " \t\n");
	if (!argument && (!longopt || longopt->has_arg)) {
		NAT64_LOG_ERROR("Config file error: value required for key '%s' on line %d", key, lineno);
		return NAT64_ERROR;
	}

	// Otherwise support all long options
	if (!longopt) {
		NAT64_LOG_ERROR("Config file: unknown key '%s'", key);
		return NAT64_ERROR;
	}

	switch (longopt->val) {
	case OPT_ADDR_PORT_POOL_NUM:
		ret = dp_argparse_string(argument, nat64_addr_port_pool_str, sizeof(nat64_addr_port_pool_str));
		break;
	case OPT_ATTACH_SOUTH_IFACE_NUM:
		ret = dp_argparse_string(argument, nat64_attach_south_iface_str, sizeof(nat64_attach_south_iface_str));
		break;
	case OPT_ATTACH_NORTH_IFACE_NUM:
		ret = dp_argparse_string(argument, nat64_attach_north_iface_str, sizeof(nat64_attach_north_iface_str));
		break;
	case OPT_LOG_LEVEL_NUM:
		log_level = get_log_level_from_name(argument);
		break;
	case OPT_ENABLE_SKB_MODE_NUM:
		enable_skb_mode = 1;
		break;
	case OPT_DISABLE_CKSUM_RECALC_NUM:
		disable_cksum_recalc = 1;
		break;
	default:
		NAT64_LOG_ERROR("Config file: unknown option '%s'", key);
		ret = NAT64_ERROR;
	}

	return ret;
}

static int parse_file(FILE *file)
{
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	int lineno = 0;
	int ret = NAT64_OK;

	while ((linelen = getline(&line, &linesize, file)) > 0) {
		ret = parse_line(line, lineno);
		if (NAT64_FAILED(ret))
			break;
		lineno++;
	}

	free(line);
	return ret;
}


int nat64_parse_config_file(const char *env_filename)
{
	int ret;
	FILE *file;
	const char *filename = env_filename ? env_filename : NAT64_CONF_DEFAULT_CONF_FILE;

	file = fopen(filename, "r");
	if (!file) {
		if (!env_filename || !*filename)
			return NAT64_OK;
		NAT64_LOG_ERROR("Error opening config file '%s'", filename);
		return NAT64_ERROR;
	}

	ret = parse_file(file);

	fclose(file);
	return ret;
}

const char *nat64_get_addr_port_pool_str(void)
{
	return nat64_addr_port_pool_str;
}

const char *nat64_get_attach_south_iface_str(void)
{
	return nat64_attach_south_iface_str;
}

const char *nat64_get_attach_north_iface_str(void)
{
	return nat64_attach_north_iface_str;
}

bool nat64_get_skb_mode(void)
{
	return enable_skb_mode;
}

bool nat64_get_disable_cksum_recalc_flag(void)
{
	return disable_cksum_recalc;
}

uint16_t nat64_get_log_level(void)
{
	return log_level;
}

