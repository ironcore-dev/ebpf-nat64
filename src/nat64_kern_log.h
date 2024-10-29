#ifndef __NAT64_KERN_LOG_H
#define __NAT64_KERN_LOG_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "nat64_log_common.h"

#define NAT64_KERNEL_LOG_EVENT_RINGBUF_ENTRY_CNT 64
#define NAT64_KERNEL_LOG_EVENT_RINGBUF_SIZE \
		(sizeof(struct nat64_kernel_log_event) * NAT64_KERNEL_LOG_EVENT_RINGBUF_ENTRY_CNT)


struct {
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, NAT64_KERNEL_LOG_EVENT_RINGBUF_SIZE);
} nat64_kernel_log_event_rb SEC (".maps") /* event ringbuf to inform userspace prog in terms of new IPv6 flow */;

static __u8 __log_level;

#define NAT64_KERNEL_LOG_EVENT_PREPARE(LEVEL, MSG) \
	struct nat64_kernel_log_event *event; \
	event = bpf_ringbuf_reserve(&nat64_kernel_log_event_rb, sizeof(struct nat64_kernel_log_event), 0); \
	if (!event) { \
		return 0; \
	} \
	__builtin_memset(event, 0, sizeof(struct nat64_kernel_log_event)); \
	event->timestamp = bpf_ktime_get_ns(); \
	event->log_level = NAT64_LOG_LEVEL_##LEVEL; \
	bpf_probe_read_str(event->msg, sizeof(event->msg), MSG); \

// Macro to submit the event
#define NAT64_KERNEL_LOG_EVENT_SUBMIT() do { \
	bpf_ringbuf_submit(event, 0); \
} while (0)

// Macro to add a string key-value pair to the event
#define NAT64_LOG_ADD_STR(KEY, VALUE) do { \
	if (event->log_value_entry_count < NAT64_LOG_MAX_ENTRIES) { \
		struct nat64_kernel_log_value *entry = &event->entries[event->log_value_entry_count++]; \
		bpf_probe_read_str(entry->key, sizeof(entry->key), KEY); \
		entry->type = NAT64_LOG_TYPE_STR; \
		bpf_probe_read_str(entry->value.value_str, sizeof(entry->value.value_str), VALUE); \
	} \
} while (0)

// Macro to add an integer key-value pair to the event
#define NAT64_LOG_ADD_INT(KEY, VALUE) do { \
	if (event->log_value_entry_count < NAT64_LOG_MAX_ENTRIES) { \
		struct nat64_kernel_log_value *entry = &event->entries[event->log_value_entry_count++]; \
		bpf_probe_read_str(entry->key, sizeof(entry->key), KEY); \
		entry->type = NAT64_LOG_TYPE_INT; \
		entry->value.value_int = VALUE; \
	} \
} while (0)

// Macro to add an IPv4 address key-value pair to the event
#define NAT64_LOG_ADD_IPV4(KEY, VALUE) do { \
	if (event->log_value_entry_count < NAT64_LOG_MAX_ENTRIES) { \
		struct nat64_kernel_log_value *entry = &event->entries[event->log_value_entry_count++]; \
		bpf_probe_read_str(entry->key, sizeof(entry->key), KEY); \
		entry->type = NAT64_LOG_TYPE_IPV4; \
		entry->value.ipv4 = VALUE; \
	} \
} while (0)

// Macro to add an IPv6 address key-value pair to the event
#define NAT64_LOG_ADD_IPV6(KEY, VALUE) do { \
	if (event->log_value_entry_count < NAT64_LOG_MAX_ENTRIES) { \
		struct nat64_kernel_log_value *entry = &event->entries[event->log_value_entry_count++]; \
		bpf_probe_read_str(entry->key, sizeof(entry->key), KEY); \
		entry->type = NAT64_LOG_TYPE_IPV6; \
		__builtin_memcpy(entry->value.ipv6, VALUE, 16); \
	} \
} while (0)

// Macro to add a port number key-value pair to the event
#define NAT64_LOG_ADD_PORT(KEY, VALUE) do { \
	if (event->log_value_entry_count < NAT64_LOG_MAX_ENTRIES) { \
		struct nat64_kernel_log_value *entry = &event->entries[event->log_value_entry_count++]; \
		bpf_probe_read_str(entry->key, sizeof(entry->key), KEY); \
		entry->type = NAT64_LOG_TYPE_PORT; \
		entry->value.port = VALUE; \
	} \
} while (0)

#define NAT64_STRUCTURE_LOG(LEVEL, MSG, ...) do { \
	if (NAT64_LOG_LEVEL_##LEVEL <= __log_level) { \
		NAT64_KERNEL_LOG_EVENT_PREPARE(LEVEL, MSG); \
		__VA_ARGS__; \
		NAT64_KERNEL_LOG_EVENT_SUBMIT(); \
	} \
} while (0)

#define NAT64_LOG_ERROR(MSG, ...)	NAT64_STRUCTURE_LOG(ERROR, MSG, ##__VA_ARGS__)
#define NAT64_LOG_WARNING(MSG, ...)	NAT64_STRUCTURE_LOG(WARNING, MSG, ##__VA_ARGS__)
#define NAT64_LOG_INFO(MSG, ...)	NAT64_STRUCTURE_LOG(INFO, MSG,  ##__VA_ARGS__)
#define NAT64_LOG_DEBUG(MSG, ...)	NAT64_STRUCTURE_LOG(DEBUG, MSG, ##__VA_ARGS__)


#endif


