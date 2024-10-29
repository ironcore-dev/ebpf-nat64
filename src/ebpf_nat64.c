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

#include "include/user_app/nat64_user.h"



static void nat64_print_addr_port_pool(void)
{
	int addr_port_item_cnt = nat64_get_parsed_addr_port_cnt();
	const struct nat64_address_ports_range *nat64_addr_port_pool = nat64_get_parsed_addr_port_pool();

	for (int i = 0; i < addr_port_item_cnt; i++) {
		struct in_addr addr; // Declare a struct in_addr
		addr.s_addr = nat64_addr_port_pool[i].addr; // Assign the __u32 to the struct
		printf("Address: %s, Port Range: %d-%d\n", 
			inet_ntoa(addr), 
			nat64_addr_port_pool[i].port_range[0], 
			nat64_addr_port_pool[i].port_range[1]);
	}
}


static void nat64_print_iface_indexes(void)
{
	int iface_cnt = nat64_get_parsed_attach_iface_cnt();
	const int *attach_iface_index = nat64_get_parsed_attach_iface_index();
	for (int i = 0; i < iface_cnt; i++) {
		printf("Interface Index: %d\n", attach_iface_index[i]);
	}
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}



static void process_stop_signal(int signum)
{
	
	NAT64_LOG_INFO("Terminating the program");
	nat64_stop_running_threads();
	nat64_unload_prog_from_ifaces();
	nat64_destroy_prog_maps();
	nat64_destroy_prog_skeleton();

	NAT64_LOG_INFO("Terminated the program...");
	exit(0); // Exit the program
}

int main(int argc, char **argv){
	int ret = 0;

	ret = nat64_get_cmd_conf(argc, argv);
	if(NAT64_FAILED(ret))
		return 1;

	nat64_print_addr_port_pool();
	nat64_print_iface_indexes();
	
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, process_stop_signal);

	/* Open load and verify BPF application */
	ret = nat64_open_and_load_prog_skeleton();
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	ret = nat64_initialize_prog_map_fds();
	if (NAT64_FAILED(ret))
		goto delete_prog;
	
	ret = nat64_addr_port_manage_init();
	if (NAT64_FAILED(ret))
		goto delete_prog;

	ret = nat64_create_running_threads();
	if (NAT64_FAILED(ret))
		goto delete_prog;

	// /* Attach xdp handler */
	ret = nat64_load_prog_onto_ifaces();
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto detach_prog;
	}

	while (1) {
		// fprintf(stderr, ".");
		sleep(1);
	}

	// Normal exit path
	ret = 0;
	goto detach_prog;

detach_prog:
	nat64_unload_prog_from_ifaces();
stop_running_threads:
	nat64_stop_running_threads();
delete_prog:
	nat64_destroy_prog_maps();
	nat64_destroy_prog_skeleton();

	return ret;
}
