#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "nat64_user_log.h"
#include "nat64_ebpf_skel_handler.h"
#include "nat64_running_thread.h"
#include "nat64_addr_port_manage.h"
#include "ebpf_nat64_test_func.h"

extern const union ipv6_addr nat64_ipv6_prefix;
extern const union ipv6_addr nat64_ipv6_mask;


static void process_stop_signal(int signum)
{
	
	NAT64_LOG_INFO("Terminating the program");
	nat64_stop_running_threads();
	nat64_destroy_prog_maps();
	nat64_destroy_prog_skeleton();

	NAT64_LOG_INFO("Terminated the program");
	exit(0); // Exit the program
}

int main(int argc, char **argv){
	int ret = 0;

	ret = nat64_test_get_cmd_conf(argc, argv);
	if(NAT64_FAILED(ret))
		return 1;
	
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

	ret = nat64_run_tests();
	if (NAT64_FAILED(ret)) {
		NAT64_LOG_ERROR("Failed to test function");
		ret = 1;
		goto stop_running_threads;
	}
	printf("All tests passed \n");
	raise(SIGINT);
	
	while (1) {
		sleep(1);
	}

stop_running_threads:
	nat64_stop_running_threads();
delete_prog:
	nat64_destroy_prog_maps();
	nat64_destroy_prog_skeleton();

	return ret;
}
