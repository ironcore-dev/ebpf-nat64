#ifndef NAT64_TCP_STATE_TRACKING_H
#define NAT64_TCP_STATE_TRACKING_H

#include <linux/tcp.h>

#include "nat64_table_tuple.h"
#include "nat64_flow_handling.h"
#include "nat64_ipaddr.h"

#define NAT64_TCP_FLAGS_OFFSET 13

#define NAT64_TCP_FLAG_SYN 0x0002
#define NAT64_TCP_FLAG_RST 0x0004
#define NAT64_TCP_FLAG_ACK 0x0010
#define NAT64_TCP_FLAG_FIN 0x0001
#define NAT64_TCP_FLAG_SYNACK (NAT64_TCP_FLAG_SYN|NAT64_TCP_FLAG_ACK)


enum nat64_flow_tcp_state {
	NAT64_FLOW_TCP_STATE_NONE,
	NAT64_FLOW_TCP_STATE_NEW_SYN,
	NAT64_FLOW_TCP_STATE_NEW_SYNACK,
	NAT64_FLOW_TCP_STATE_ESTABLISHED,
	NAT64_FLOW_TCP_STATE_FINWAIT,
	NAT64_FLOW_TCP_STATE_RST_FIN,
};

static __always_inline void
set_timeout_tcp_flow(const struct nat64_table_tuple *flow_sig, struct nat64_table_value *flow_value,
								struct nat64_table_value *reverse_flow_value)
{
	if (flow_value->tcp_state == NAT64_FLOW_TCP_STATE_ESTABLISHED) {
		flow_value->timeout_value = (__u16)NAT64_ASSIGNMENT_LIVENESS_TCP_ESTABLISHED_IN_SEC;
		reverse_flow_value->timeout_value = flow_value->timeout_value;
	} else {
		flow_value->timeout_value = (__u16)NAT64_ASSIGNMENT_LIVENESS_IN_SEC;
		reverse_flow_value->timeout_value = flow_value->timeout_value;
	}
}


static __always_inline int change_reverse_traffic_tcp_state(enum nat64_flow_direction original_direction,
												const struct nat64_table_tuple *flow_sig, struct nat64_table_value *flow_value,
												__u32 new_state)
{
	struct nat64_table_tuple reverse_flow_sig = {0};
	struct nat64_table_value *reverse_flow_value = NULL;
	enum nat64_flow_direction reverse_direction = original_direction == NAT64_FLOW_DIRECTION_OUTGOING ? NAT64_FLOW_DIRECTION_INCOMING : NAT64_FLOW_DIRECTION_OUTGOING;

	nat64_fill_reverse_key(original_direction, flow_sig, flow_value, &reverse_flow_sig);

	reverse_flow_value = nat64_kern_get_flow_value_by_key(reverse_direction, &reverse_flow_sig);
	if (!reverse_flow_value) {
		NAT64_LOG_ERROR("Failed to get reverse flow value and failed to change tcp state");
		return NAT64_ERROR;
	}

	bpf_spin_lock(&reverse_flow_value->item_semaphore);
	reverse_flow_value->tcp_state = new_state;
	set_timeout_tcp_flow(flow_sig, flow_value, reverse_flow_value);
	bpf_spin_unlock(&reverse_flow_value->item_semaphore);

	return NAT64_OK;
}

static __always_inline int
nat64_process_tcp_state(enum nat64_flow_direction direction, void *data_end,
						const struct nat64_table_tuple *flow_sig, struct nat64_table_value *flow_value,
						const struct tcphdr *tcp_hdr)
{
	assert_len(tcp_hdr, data_end);
	__u16 tcp_flags = *((unsigned char *)tcp_hdr + NAT64_TCP_FLAGS_OFFSET);

	if (tcp_flags & NAT64_TCP_FLAG_RST) {
		flow_value->tcp_state = NAT64_FLOW_TCP_STATE_RST_FIN;
		if (NAT64_FAILED(change_reverse_traffic_tcp_state(direction, flow_sig, flow_value, flow_value->tcp_state)))
			return NAT64_ERROR;
	} else if (tcp_flags & NAT64_TCP_FLAG_FIN) {
		if (flow_value->tcp_state == NAT64_FLOW_TCP_STATE_ESTABLISHED)
			flow_value->tcp_state = NAT64_FLOW_TCP_STATE_FINWAIT;
		else
			flow_value->tcp_state = NAT64_FLOW_TCP_STATE_RST_FIN;

		if (NAT64_FAILED(change_reverse_traffic_tcp_state(direction, flow_sig, flow_value, flow_value->tcp_state)))
			return NAT64_ERROR;

	} else {
		switch (flow_value->tcp_state) {
		case NAT64_FLOW_TCP_STATE_NONE:
		case NAT64_FLOW_TCP_STATE_RST_FIN:
			if (tcp_flags & NAT64_TCP_FLAG_SYN) {
				flow_value->tcp_state = NAT64_FLOW_TCP_STATE_NEW_SYN;
				if (NAT64_FAILED(change_reverse_traffic_tcp_state(direction, flow_sig, flow_value, flow_value->tcp_state)))
					return NAT64_ERROR;
			}
			break;
		case NAT64_FLOW_TCP_STATE_NEW_SYN:
			if (tcp_flags & NAT64_TCP_FLAG_SYNACK) {
				flow_value->tcp_state = NAT64_FLOW_TCP_STATE_NEW_SYNACK;
				if (NAT64_FAILED(change_reverse_traffic_tcp_state(direction, flow_sig, flow_value, flow_value->tcp_state)))
					return NAT64_ERROR;
			}
			break;
		case NAT64_FLOW_TCP_STATE_NEW_SYNACK:
			if (tcp_flags & NAT64_TCP_FLAG_ACK) {
				flow_value->tcp_state = NAT64_FLOW_TCP_STATE_ESTABLISHED;
				if (NAT64_FAILED(change_reverse_traffic_tcp_state(direction, flow_sig, flow_value, flow_value->tcp_state)))
					return NAT64_ERROR;
			}
			break;
		default:
			// FIN-states already handled above
			break;
		}
	}

	return NAT64_OK;
}

#endif
