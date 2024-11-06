#ifndef __NAT64_EBPF_SKEL_HANDLER_H
#define __NAT64_EBPF_SKEL_HANDLER_H

#include "ebpf_nat64.skel.h"

#define NAT64_SHARED_MAP_PIN_PATH "/sys/fs/bpf"

#define NAT64_MAP_FACTORY(GENERATOR) \
	GENERATOR(address_port_range_map) \
	GENERATOR(address_assignment_map) \
	GENERATOR(address_port_in_use_map) \
	GENERATOR(v6_v4_map)	\
	GENERATOR(v4_v6_map)	\
	GENERATOR(new_flow_event_rb) \
	GENERATOR(kernel_log_event_rb) \


#define NAT64_MAP_FD_GETTER(name) int nat64_get_##name##_fd(void);


int nat64_open_and_load_prog_skeleton(void);
int nat64_initialize_prog_map_fds(void);

int nat64_attach_prog_skeleton_to_iface(int iface_index, unsigned int xdp_flags);
int nat64_detach_prog_skeleton_from_iface(int iface_index, unsigned int xdp_flags);

int nat64_destroy_prog_maps(void);
void nat64_destroy_prog_skeleton(void);

int nat64_load_prog_onto_ifaces(void);
void nat64_unload_prog_from_ifaces(void);

// Getter functions for map file descriptors
NAT64_MAP_FACTORY(NAT64_MAP_FD_GETTER)


#endif
