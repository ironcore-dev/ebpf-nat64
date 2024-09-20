#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <arpa/inet.h> 

#include <bpf/bpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include "ebpf_nat64.skel.h"


#define NAT64_OK 0;
#define NAT64_ERROR (-1);

#define NAT64_FAILED(RET) \
	((RET) < 0)

/*argument parsing related definitions*/
static const char short_options[] = "d" /* debug */
				"D"	 /* debug */;

static int debug_mode = 0;
static char nat64_addr_port_pool_str[256] = {0};

#define OPT_ADDR_PORT_POOL "addr-port-pool"

enum {
	OPT_MIN_NUM = 256,
	OPT_ADDR_PORT_POOL_NUM,
};

static const struct option lgopts[] = {
	{OPT_ADDR_PORT_POOL, 1, 0, OPT_ADDR_PORT_POOL_NUM},
};


/*NAT64 configuration variables*/
#define NAT64_ADDR_PORT_POOL_SIZE 3

static int addr_port_item_cnt = 0;

struct nat64_addr_port_pool_t {
	uint32_t addr;
	uint16_t port_range[2];
};


struct nat64_addr_port_pool_t nat64_addr_port_pool[NAT64_ADDR_PORT_POOL_SIZE];


/*arument parsing related functions*/
static void nat64_print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s --"
		" -d"
		" [-D]"
		"\n",
		prgname);
}

static int nat64_parse_args(int argc, char **argv)
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
		/* Intended fallthrough */
		case 'D':
			debug_mode = 1;
			break;
		/* Long options */
		case OPT_ADDR_PORT_POOL_NUM:
			strncpy(nat64_addr_port_pool_str, optarg, 256);
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


/*NAT64 configuratation related prepareation functions*/
static int nat64_parse_addr_port_pool_str(const char *nat64_addr_port_pool_str)
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

static void nat64_print_addr_port_pool(void)
{
	int i;
	for (i = 0; i < addr_port_item_cnt; i++) {
		struct in_addr addr; // Declare a struct in_addr
		addr.s_addr = nat64_addr_port_pool[i].addr; // Assign the uint32_t to the struct
		printf("Address: %s, Port Range: %d-%d\n", 
			inet_ntoa(addr), 
			nat64_addr_port_pool[i].port_range[0], 
			nat64_addr_port_pool[i].port_range[1]);
	}
}


static int nat64_prepare_internal_configuration(void)
{
	int ret;

	ret = nat64_parse_addr_port_pool_str(nat64_addr_port_pool_str);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Error: More than %d addr:port combinations provided.\n", NAT64_ADDR_PORT_POOL_SIZE);
		return NAT64_ERROR; // Exit if parsing addr:port pool fails
	}

	return NAT64_OK;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv){
	struct ebpf_nat64_bpf *skel;
	int err;

	nat64_parse_args(argc, argv);

	err = nat64_prepare_internal_configuration();
	if(NAT64_FAILED(err))
		return 1;

	nat64_print_addr_port_pool();
	
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = ebpf_nat64_bpf__open_and_load();
	if (!skel) {
	fprintf(stderr, "Failed to open BPF skeleton\n");
	return 1;
	}

	/* Attach xdp handler */
	err = ebpf_nat64_bpf__attach(skel);
	if (err) {
	fprintf(stderr, "Failed to attach BPF skeleton\n");
	goto cleanup;
	}

	while (1) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	ebpf_nat64_bpf__destroy(skel);
	return -err;
}
