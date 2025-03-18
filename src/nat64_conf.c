#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>

#include "nat64_conf.h"
#include "nat64_user_log.h"
#include "nat64_addr_port_assignment.h"

#include "nat64_ebpf_skel_handler.h"



/*NAT64 configuration variables*/
static struct nat64_address_ports_range nat64_addr_port_pool[NAT64_ADDR_PORT_POOL_SIZE] = {0};
static int addr_port_item_cnt = 0;

struct nat64_attach_iface_info attach_iface_info[NAT64_ATTACH_IFACE_MAX_CNT] = {0};
int attach_iface_cnt = 0;

int parse_addr_port_pool_str(const char *nat64_addr_port_pool_str)
{
	char *pool_str = strdup(nat64_addr_port_pool_str);
	char *token, *saveptr;
	int i = 0;

	token = strtok_r(pool_str, ",", &saveptr);
	while (token != NULL && i < NAT64_ADDR_PORT_POOL_SIZE) {
		char *addr_port_str = strdup(token);
		char *addr_str, *port_str;

		addr_str = strtok(addr_port_str, ":");
		port_str = strtok(NULL, ":");

		if (addr_str != NULL && port_str != NULL) {
			nat64_addr_port_pool[i].addr = inet_addr(addr_str);
			char *port_range_str = strdup(port_str);
			nat64_addr_port_pool[i].port_range[0] = atoi(strtok(port_range_str, "-"));
			nat64_addr_port_pool[i].port_range[1] = atoi(strtok(NULL, "-"));
			free(port_range_str);
			i++;
			addr_port_item_cnt++;
		}
		free(addr_port_str);
		token = strtok_r(NULL, ",", &saveptr);
	}
	free(pool_str);

	if (token != NULL) {
		// More than three combinations, return error
		NAT64_LOG_ERROR("More than allowed addr:port combinations provided", NAT64_LOG_VALUE(NAT64_ADDR_PORT_POOL_SIZE));
		return NAT64_ERROR;
	}
	return NAT64_OK;
}


static int parse_attach_iface_str(const char *nat64_attach_iface_str, enum nat64_iface_direction direction)
{
	char *iface_str = strdup(nat64_attach_iface_str);
	char *token, *saveptr;

	token = strtok_r(iface_str, ",", &saveptr);
	while (token != NULL && attach_iface_cnt < NAT64_ATTACH_IFACE_MAX_CNT) {
		int iface_index = if_nametoindex(token);
		if (iface_index == 0) {
			fprintf(stderr, "Error: Interface %s does not exist.\n", token);
			free(iface_str);
			return NAT64_ERROR;
		}
		attach_iface_info[attach_iface_cnt].iface_index = iface_index;
		attach_iface_info[attach_iface_cnt].direction = direction;
		attach_iface_cnt++;
		token = strtok_r(NULL, ",", &saveptr);
	}

	if (token != NULL) {
		NAT64_LOG_ERROR("More than allowed interfaces provided", NAT64_LOG_VALUE(NAT64_ATTACH_IFACE_MAX_CNT));
		free(iface_str);
		return NAT64_ERROR;
	}
	free(iface_str);
	return NAT64_OK;
}

static int convert_parsed_args(void)
{
	int ret;

	ret = parse_addr_port_pool_str(nat64_get_addr_port_pool_str());
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to parse addr:port pool string");
		return NAT64_ERROR;
	}

	ret = parse_attach_iface_str(nat64_get_attach_south_iface_str(), NAT64_IFACE_DIRECTION_SOUTH);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to parse attaching southinterface string");
		return NAT64_ERROR;
	}

	ret = parse_attach_iface_str(nat64_get_attach_north_iface_str(), NAT64_IFACE_DIRECTION_NORTH);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to parse attaching north interface string");
		return NAT64_ERROR;
	}

	return NAT64_OK;
}


int nat64_get_parsed_addr_port_cnt(void)
{
	return addr_port_item_cnt;
}

const struct nat64_address_ports_range *nat64_get_parsed_addr_port_pool(void)
{
	return nat64_addr_port_pool;
}

int nat64_get_parsed_attach_iface_cnt(void)
{
	return attach_iface_cnt;
}

const struct nat64_attach_iface_info *nat64_get_parsed_attach_iface_info(void)
{
	return attach_iface_info;
}


static void print_addr_port_pool(void)
{
	int addr_port_item_cnt = nat64_get_parsed_addr_port_cnt();
	const struct nat64_address_ports_range *nat64_addr_port_pool = nat64_get_parsed_addr_port_pool();

	for (int i = 0; i < addr_port_item_cnt; i++) {
		NAT64_LOG_INFO("Added a combination of a nat address and a port range", NAT64_LOG_IPV4(nat64_addr_port_pool[i].addr),
						NAT64_LOG_MIN_PORT(nat64_addr_port_pool[i].port_range[0]),
						NAT64_LOG_MAX_PORT(nat64_addr_port_pool[i].port_range[1]));

	}
}

static void print_iface_indexes(void)
{
	int iface_cnt = nat64_get_parsed_attach_iface_cnt();
	const struct nat64_attach_iface_info *attach_iface_info = nat64_get_parsed_attach_iface_info();
	
	for (int i = 0; i < iface_cnt; i++)
		NAT64_LOG_INFO("Added an interface index", NAT64_LOG_IFACE_INDEX(attach_iface_info[i].iface_index),
						NAT64_LOG_VALUE(attach_iface_info[i].direction));
}

void nat64_print_parsed_results(void)
{
	print_addr_port_pool();
	print_iface_indexes();
}

int nat64_get_cmd_conf(int argc, char **argv)
{
	if (NAT64_FAILED(nat64_parse_args(argc, argv)))
		return NAT64_ERROR;

	if (NAT64_FAILED(convert_parsed_args()))
		return NAT64_ERROR;

	return NAT64_OK;
}

int nat64_set_kernel_config(void)
{
	__u16 key = NAT64_KERNEL_CONFIG_MAP_KEY;
	int ret;

	struct nat64_kernel_config config = {
		.log_level = nat64_get_log_level(),
		.disable_cksum_recalc = nat64_get_disable_cksum_recalc_flag(),
	};

	ret = bpf_map_update_elem(nat64_get_kernel_config_map_fd(), &key, &config, BPF_NOEXIST);
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to load kernel config", NAT64_LOG_ERRNO(ret));
		return NAT64_ERROR;
	}

	return NAT64_OK;
}
