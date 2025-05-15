#ifndef _NAT64_ICMP_ERROR_HANDLING_H_
#define _NAT64_ICMP_ERROR_HANDLING_H_

#include <bpf/bpf_helpers.h>

#include <linux/icmpv6.h>
#include <linux/icmp.h>

#include "nat64_kern.h"
#include "nat64_kern_log.h"
#include "nat64_table_tuple.h"
#include "nat64_addr_port_assignment.h"

#define NAT64_
#define NAT64_ICMP6_MAX_MSG_SIZE (512)

static __always_inline int
parse_icmp_err_msg(struct nat64_table_tuple *flow_sig, void *data_end,
					struct icmphdr *icmp_hdr, void *nxt_ptr)
{
	switch (icmp_hdr->code) {
	case ICMP_NET_UNREACH:
	case ICMP_HOST_UNREACH:
	case ICMP_SR_FAILED:
	case ICMP_NET_UNKNOWN:
	case ICMP_HOST_UNKNOWN:
	case ICMP_HOST_ISOLATED:
	case ICMP_NET_UNR_TOS:
	case ICMP_HOST_UNR_TOS:
	case ICMP_PROT_UNREACH:
	case ICMP_PORT_UNREACH:
	case ICMP_FRAG_NEEDED:
		break;
	default:
		NAT64_LOG_WARNING("Unsupported icmp error code", NAT64_LOG_ICMP_CODE(icmp_hdr->code));
		return NAT64_ERROR;
	}

	struct iphdr *inner_ipv4 = (struct iphdr *)(nxt_ptr);
	assert_len(inner_ipv4, data_end);

	flow_sig->version = NAT64_IP_VERSION_V4;
	flow_sig->protocol = inner_ipv4->protocol;

	flow_sig->addr.v4.src_ip = inner_ipv4->daddr;
	flow_sig->addr.v4.dst_ip = inner_ipv4->saddr;

	if (flow_sig->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp_hdr = (struct tcphdr *)(inner_ipv4 + 1);
		assert_len(tcp_hdr, data_end);
		flow_sig->src_port = tcp_hdr->dest;
		flow_sig->dst_port = tcp_hdr->source;
	} else if (flow_sig->protocol == IPPROTO_UDP) {
		struct udphdr *udp_hdr = (struct udphdr *)(inner_ipv4 + 1);
		assert_len(udp_hdr, data_end);
		flow_sig->src_port = udp_hdr->dest;
		flow_sig->dst_port = udp_hdr->source;
	} else {
		NAT64_LOG_ERROR("Cannot parse icmp error msg containing non TCP/UDP info", NAT64_LOG_L4_PROTOCOL(flow_sig->protocol));
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-3
static __always_inline int
convert_icmpv4_to_icmpv6_dest_unreach(struct icmphdr *icmp_hdr, struct icmp6hdr *icmp6_hdr)
{
	__u32 mtu;

	icmp6_hdr->icmp6_type = ICMPV6_DEST_UNREACH;

	switch (icmp_hdr->code) {
	case ICMP_NET_UNREACH:
	case ICMP_HOST_UNREACH:
	case ICMP_SR_FAILED:
	case ICMP_NET_UNKNOWN:
	case ICMP_HOST_UNKNOWN:
	case ICMP_HOST_ISOLATED:
	case ICMP_NET_UNR_TOS:
	case ICMP_HOST_UNR_TOS:
		icmp6_hdr->icmp6_type = ICMPV6_DEST_UNREACH;
		icmp6_hdr->icmp6_code = ICMPV6_NOROUTE;
		icmp6_hdr->icmp6_cksum = 0;
		break;
	case ICMP_PROT_UNREACH:
		icmp6_hdr->icmp6_type = ICMPV6_PARAMPROB;
		icmp6_hdr->icmp6_code = ICMPV6_UNK_NEXTHDR;
		icmp6_hdr->icmp6_cksum = 0;
		break;
	case ICMP_PORT_UNREACH:
		icmp6_hdr->icmp6_type = ICMPV6_DEST_UNREACH;
		icmp6_hdr->icmp6_code = ICMPV6_PORT_UNREACH;
		icmp6_hdr->icmp6_cksum = 0;
		break;
	case ICMP_FRAG_NEEDED:
		mtu = bpf_ntohs(icmp_hdr->un.frag.mtu) + NAT64_V6_V4_HDR_LENGTH_DIFF; // or just use the same value?
		if (mtu < 1280) {
			mtu = 1280;
			NAT64_LOG_WARNING("Received MTU is too small, set to 1280");
		}
		icmp6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
		icmp6_hdr->icmp6_code = 0;
		icmp6_hdr->icmp6_mtu = bpf_htonl(mtu);
		icmp6_hdr->icmp6_cksum = 0;
		break;
	default:
		NAT64_LOG_ERROR("Unsupported icmp error code", NAT64_LOG_ICMP_CODE(icmp_hdr->code));
		return NAT64_ERROR;
	}
	return NAT64_OK;
}



#endif
