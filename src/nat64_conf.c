#include <stdio.h>
#include <net/if.h>

#include "include/user_app/nat64_conf.h"


/*NAT64 configuration variables*/
static int addr_port_item_cnt = 0;
static int attach_iface_cnt = 0;

static struct nat64_address_ports_range nat64_addr_port_pool[NAT64_ADDR_PORT_POOL_SIZE] = {0};
static int attach_iface_index[NAT64_ATTACH_IFACE_MAX_CNT] = {0};


static int parse_addr_port_pool_str(const char *nat64_addr_port_pool_str)
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
		fprintf(stderr, "Error: More than %d addr:port combinations provided.\n", NAT64_ADDR_PORT_POOL_SIZE);
		return NAT64_ERROR;
	}
	return NAT64_OK;
}


static int parse_attach_iface_str(const char *nat64_attach_iface_str)
{
	char *iface_str = strdup(nat64_attach_iface_str);
	char *token, *saveptr;
	int i = 0;

	token = strtok_r(iface_str, ",", &saveptr);
	while (token != NULL && i < NAT64_ATTACH_IFACE_MAX_CNT) {
		int iface_index = if_nametoindex(token);
		if (iface_index == 0) {
			fprintf(stderr, "Error: Interface %s does not exist.\n", token);
			free(iface_str);
			return NAT64_ERROR;
		}
		attach_iface_index[i] = iface_index;
		i++;
		attach_iface_cnt++;
		token = strtok_r(NULL, ",", &saveptr);
	}

	if (token != NULL) {
		fprintf(stderr, "Error: More than %d interfaces provided \n", NAT64_ATTACH_IFACE_MAX_CNT);
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
		fprintf(stderr, "Error: More than %d addr:port combinations provided.\n", NAT64_ADDR_PORT_POOL_SIZE);
		return NAT64_ERROR; // Exit if parsing addr:port pool fails
	}

	ret = parse_attach_iface_str(nat64_get_attach_iface_str());
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Error: More than %d attaching interface provided.\n", NAT64_ATTACH_IFACE_MAX_CNT);
		return NAT64_ERROR; // Exit if parsing addr:port pool fails
	}

	return NAT64_OK;
}


int nat64_get_parsed_addr_port_cnt(void)
{
	return addr_port_item_cnt;
}

const struct nat64_address_ports_range* nat64_get_parsed_addr_port_pool(void)
{
	return nat64_addr_port_pool;
}

int nat64_get_parsed_attach_iface_cnt(void)
{
	return attach_iface_cnt;
}

const int* nat64_get_parsed_attach_iface_index(void)
{
	return attach_iface_index;
}

int nat64_get_cmd_conf(int argc, char **argv)
{
	if (NAT64_FAILED(nat64_parse_args(argc, argv)))
		return NAT64_ERROR;

	if (NAT64_FAILED(convert_parsed_args())) {
		printf("Failed to convert parsed cmd args \n");
		return NAT64_ERROR;
	}

	return NAT64_OK;
}



