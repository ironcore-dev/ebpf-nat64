#ifndef __NAT64_ADDR_PORT_MANAGE_H
#define __NAT64_ADDR_PORT_MANAGE_H

#include "nat64_ipaddr.h"
#include "nat64_ebpf_skel_handler.h"
#include "nat64_conf.h"

#define NAT64_ASSIGNMET_LIVENESS_IN_SEC 10
#define NAT64_ASSIGNMET_LIVENESS_IN_NANO (1000ULL * 1000ULL * 1000ULL * NAT64_ASSIGNMET_LIVENESS_IN_SEC)

#define NAT64_EXPIRED_ENTRY_CLEANUP_INTERVAL_SEC 10

int nat64_addr_port_manage_init(void);

void* nat64_thread_search_and_remove_expired_entries(void* arg);
void* nat64_thread_process_new_flow_event(void* arg);

void nat64_addr_port_manage_loop_exit(void);

#endif
