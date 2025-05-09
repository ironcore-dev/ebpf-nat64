// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0


#ifndef NAT64_ADDR_PORT_MANAGE_H
#define NAT64_ADDR_PORT_MANAGE_H

#include "nat64_ipaddr.h"
#include "nat64_ebpf_skel_handler.h"
#include "nat64_conf.h"

#define NAT64_EXPIRED_ENTRY_CLEANUP_INTERVAL_SEC 10

int nat64_addr_port_manage_init(void);

void* nat64_thread_search_and_remove_expired_entries(void* arg);
void* nat64_thread_process_new_flow_event(void* arg);

void nat64_addr_port_manage_loop_exit(void);

#endif
