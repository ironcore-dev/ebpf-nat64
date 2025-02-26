#ifndef NAT64_LOG_COMMON_H
#define NAT64_LOG_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// #include "vmlinux.h"

#include <bpf/bpf_endian.h>

#include "nat64_ipaddr.h"

// Define event types
#define NAT64_LOG_LEVEL_ERROR	0
#define NAT64_LOG_LEVEL_WARNING	1
#define NAT64_LOG_LEVEL_INFO	2
#define NAT64_LOG_LEVEL_DEBUG	3

// Define maximum string sizes
#define NAT64_LOG_MSG_SIZE		256
#define NAT64_LOG_MAX_ENTRIES	8
#define NAT64_LOG_KEY_SIZE		32
#define NAT64_LOG_VALUE_SIZE	128

// Define value types
#define NAT64_LOG_TYPE_STR		1
#define NAT64_LOG_TYPE_INT		2
#define NAT64_LOG_TYPE_UINT		3
#define NAT64_LOG_TYPE_IPV4		4
#define NAT64_LOG_TYPE_IPV6		5


// Value structure
struct nat64_kernel_log_value {
	__u16 type;
	char key[NAT64_LOG_KEY_SIZE];
	union {
		char value_str[NAT64_LOG_VALUE_SIZE];
		__u32 value_uint;
		__s32 value_int;
		__u32 ipv4_addr;
		union ipv6_addr ipv6_addr;
		__u16 port;
	} value;
};

// Event structure
struct nat64_kernel_log_event {
	__u8 log_value_entry_count;  // number of key-value pairs
	__u32 log_level;
	// __u64 timestamp;
	char msg[NAT64_LOG_MSG_SIZE];
	struct nat64_kernel_log_value entries[NAT64_LOG_MAX_ENTRIES];
};


int nat64_log_init(void);

#endif 
