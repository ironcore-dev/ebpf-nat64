#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "nat64_user.h"

static void process_stop_signal(int signum __attribute__((unused)))
{
	
	NAT64_LOG_INFO("Terminating the program");
	nat64_stop_running_threads();
	nat64_unload_prog_from_ifaces();
	nat64_destroy_prog_maps();
	nat64_destroy_prog_skeleton();

	NAT64_LOG_INFO("Terminated the program");
	exit(0); // Exit the program
}

int main(int argc, char **argv)
{
	int ret = 0;

	ret = nat64_parse_config_file(getenv("NAT64_CONF_FILE"));
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to parse config file");
		return 1;
	}

	ret = nat64_get_cmd_conf(argc, argv);
	if(NAT64_FAILED(ret))
		return 1;
	
	libbpf_set_print(nat64_libbpf_print_fn);

	signal(SIGINT, process_stop_signal);

	/* Open load and verify BPF application */
	ret = nat64_open_and_load_prog_skeleton();
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to open BPF skeleton");
		return 1;
	}

	ret = nat64_initialize_prog_map_fds();
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to initialize prog map fds");
		goto delete_prog;
	}
	
	ret = nat64_addr_port_manage_init();
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to initialize addr port manage");
		goto delete_prog;
	}

	ret = nat64_set_kernel_config();
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to load kernel config");
		goto delete_prog;
	}

	ret = nat64_create_running_threads();
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to create running threads");
		goto delete_prog;
	}

	// /* Attach xdp handler */
	ret = nat64_load_prog_onto_ifaces();
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to attach xdp handler");
		goto stop_running_threads;
	}

	while (1)
		sleep(1);

stop_running_threads:
	nat64_stop_running_threads();
	nat64_unload_prog_from_ifaces();
delete_prog:
	nat64_destroy_prog_maps();
	nat64_destroy_prog_skeleton();

	return ret;
}
