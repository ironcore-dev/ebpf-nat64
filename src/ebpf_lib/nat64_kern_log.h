#ifndef NAT64_KERN_LOG_H
#define NAT64_KERN_LOG_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "nat64_common.h"
#include "include/nat64_log_common.h"

#define NAT64_KERNEL_LOG_EVENT_RINGBUF_ENTRY_CNT 64
#define NAT64_KERNEL_LOG_EVENT_RINGBUF_SIZE \
		(sizeof(struct nat64_kernel_log_event) * NAT64_KERNEL_LOG_EVENT_RINGBUF_ENTRY_CNT)


struct {
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, NAT64_KERNEL_LOG_EVENT_RINGBUF_SIZE);
} nat64_kernel_log_event_rb SEC (".maps") /* event ringbuf to inform userspace prog in terms of new IPv6 flow */;

// static __u8 __log_level = NAT64_LOG_LEVEL_DEBUG;


// event->timestamp = bpf_ktime_get_ns();
// memset(event, 0, sizeof(struct nat64_kernel_log_event));
#define NAT64_KERNEL_LOG_EVENT_PREPARE(LEVEL, MSG) \
	event->log_value_entry_count = 0; \
	event->log_level = NAT64_LOG_LEVEL_##LEVEL; \
	bpf_probe_read_kernel_str(event->msg, sizeof(event->msg), MSG); \

// Macro to submit the event
#define NAT64_KERNEL_LOG_EVENT_SUBMIT() do { \
	bpf_ringbuf_submit(event, 0); \
} while (0)

// Macro to add a string key-value pair to the event
#define NAT64_LOG_ADD_STR(KEY, VALUE) ({ \
	if (event->log_value_entry_count < NAT64_LOG_MAX_ENTRIES) { \
		struct nat64_kernel_log_value *entry = &event->entries[event->log_value_entry_count++]; \
		bpf_probe_read_kernel_str(entry->key, sizeof(entry->key), KEY); \
		entry->type = NAT64_LOG_TYPE_STR; \
		bpf_probe_read_str(entry->value.value_str, sizeof(entry->value.value_str), VALUE); \
	} \
})

// Macro to add an integer key-value pair to the event
#define NAT64_LOG_ADD_INT(KEY, VALUE) ({ \
	if (event->log_value_entry_count < NAT64_LOG_MAX_ENTRIES) { \
		struct nat64_kernel_log_value *entry = &event->entries[event->log_value_entry_count++]; \
		bpf_probe_read_kernel_str(entry->key, sizeof(entry->key), KEY); \
		entry->type = NAT64_LOG_TYPE_INT; \
		entry->value.value_int = VALUE; \
	} \
})

#define NAT64_LOG_ADD_UINT(KEY, VALUE) ({ \
	if (event->log_value_entry_count < NAT64_LOG_MAX_ENTRIES) { \
		struct nat64_kernel_log_value *entry = &event->entries[event->log_value_entry_count++]; \
		bpf_probe_read_kernel_str(entry->key, sizeof(entry->key), KEY); \
		entry->type = NAT64_LOG_TYPE_UINT; \
		entry->value.value_uint = VALUE; \
	} \
})


// Macro to add an IPv4 address key-value pair to the event
#define NAT64_LOG_ADD_IPV4(KEY, VALUE) ({ \
	if (event->log_value_entry_count < NAT64_LOG_MAX_ENTRIES) { \
		struct nat64_kernel_log_value *entry = &event->entries[event->log_value_entry_count++]; \
		bpf_probe_read_kernel_str(entry->key, sizeof(entry->key), KEY); \
		entry->type = NAT64_LOG_TYPE_IPV4; \
		entry->value.ipv4_addr = VALUE; \
	} \
})

// Macro to add an IPv6 address key-value pair to the event

#define NAT64_LOG_ADD_IPV6(KEY, VALUE) ({ \
	if (event->log_value_entry_count < NAT64_LOG_MAX_ENTRIES) { \
		struct nat64_kernel_log_value *entry = &event->entries[event->log_value_entry_count++]; \
		bpf_probe_read_kernel_str(entry->key, sizeof(entry->key), KEY); \
		entry->type = NAT64_LOG_TYPE_IPV6; \
		__builtin_memcpy(entry->value.ipv6_addr.u6_addr8, (void *)VALUE, NAT64_IPV6_ADDR_LENGTH); \
	} \
})

#define NAT64_LOG_VALUE(VALUE) NAT64_LOG_ADD_INT("value", VALUE)
#define NAT64_LOG_IPV4(VALUE) NAT64_LOG_ADD_IPV4("ipv4", VALUE)
#define NAT64_LOG_IPV6(VALUE) NAT64_LOG_ADD_IPV6("ipv6", VALUE)
#define NAT64_LOG_SRC_IPV4(VALUE) NAT64_LOG_ADD_IPV4("src_ipv4", VALUE)
#define NAT64_LOG_DST_IPV4(VALUE) NAT64_LOG_ADD_IPV4("dst_ipv4", VALUE)
#define NAT64_LOG_SRC_IPV6(VALUE) NAT64_LOG_ADD_IPV6("src_ipv6", VALUE)
#define NAT64_LOG_DST_IPV6(VALUE) NAT64_LOG_ADD_IPV6("dst_ipv6", VALUE)

#define NAT64_LOG_IP_VERSION(VALUE) NAT64_LOG_ADD_INT("ip_version", VALUE)
#define NAT64_LOG_L4_PROTOCOL(VALUE) NAT64_LOG_ADD_INT("l4_protocol", VALUE)

#define NAT64_LOG_PORT(VALUE) NAT64_LOG_ADD_INT("port", VALUE)
#define NAT64_LOG_L4_PROTO_PORT(VALUE) NAT64_LOG_ADD_UINT("l4_proto_port", VALUE)
#define NAT64_LOG_L4_PROTO_SRC_PORT(VALUE) NAT64_LOG_ADD_UINT("l4_proto_src_port", VALUE)
#define NAT64_LOG_L4_PROTO_DST_PORT(VALUE) NAT64_LOG_ADD_UINT("l4_proto_dst_port", VALUE)
#define NAT64_LOG_ICMP_TYPE(VALUE) NAT64_LOG_ADD_UINT("icmp_type", VALUE)
#define NAT64_LOG_ICMPV6_TYPE(VALUE) NAT64_LOG_ADD_UINT("icmpv6_type", VALUE)
#define NAT64_LOG_ICMP_IDENTIFIER(VALUE) NAT64_LOG_ADD_UINT("icmp_identifier", VALUE)
#define NAT64_LOG_ICMPV6_IDENTIFIER(VALUE) NAT64_LOG_ADD_UINT("icmpv6_identifier", VALUE)

#define NAT64_LOG_IFACE_INDEX(VALUE) NAT64_LOG_ADD_UINT("iface_index", VALUE)
#define NAT64_LOG_ERRNO(VALUE) NAT64_LOG_ADD_INT("errno", VALUE)
#define NAT64_LOG_TCP_STATE(VALUE) NAT64_LOG_ADD_UINT("tcp_state", VALUE)
#define NAT64_LOG_TCP_FLAGS(VALUE) NAT64_LOG_ADD_UINT("tcp_flags", VALUE)

#define NAT64_LOG_ARGS(...) __VA_ARGS__

#define NAT64_KERN_RINGBUFFER_LOG(LEVEL, MSG, ...) do { \
	if (NAT64_LOG_LEVEL_##LEVEL <= __log_level) { \
		struct nat64_kernel_log_event *event; \
		event = bpf_ringbuf_reserve(&nat64_kernel_log_event_rb, sizeof(struct nat64_kernel_log_event), 0); \
		if (event) { \
			NAT64_KERNEL_LOG_EVENT_PREPARE(LEVEL, MSG); \
			NAT64_LOG_ARGS(__VA_ARGS__); \
			NAT64_KERNEL_LOG_EVENT_SUBMIT(); \
		} \
	} \
} while (0)

#define NAT64_LOG_ERROR(MSG, ...)	NAT64_KERN_RINGBUFFER_LOG(ERROR, MSG, ##__VA_ARGS__)
#define NAT64_LOG_WARNING(MSG, ...)	NAT64_KERN_RINGBUFFER_LOG(WARNING, MSG, ##__VA_ARGS__)
#define NAT64_LOG_INFO(MSG, ...)	NAT64_KERN_RINGBUFFER_LOG(INFO, MSG,  ##__VA_ARGS__)
#define NAT64_LOG_DEBUG(MSG, ...)	NAT64_KERN_RINGBUFFER_LOG(DEBUG, MSG, ##__VA_ARGS__)


#endif


