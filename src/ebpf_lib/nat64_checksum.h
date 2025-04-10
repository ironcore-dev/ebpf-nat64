#ifndef NAT64_CHECKSUM_H
#define NAT64_CHECKSUM_H

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../include/nat64_common.h"

static __always_inline void reduce_func(__u32 *csum_buffer)
{
	__u32 tmp = (*csum_buffer >> 16) + (*csum_buffer & 0xFFFF);
	*csum_buffer = (tmp > 0xFFFF) ? tmp - 0xFFFF : tmp;
}

#define REDUCE {reduce_func(&csum_buffer); }


/** helper functions copied from https://github.com/cilium/cilium/blob/main/bpf/include/bpf/csum.h **/
static __always_inline __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline __u32 csum_unfold(__u16 csum)
{
	return (__u32)(~csum & 0xFFFF);
}

static __always_inline __u32 csum_add(__u32 csum, __u32 addend)
{
	csum += addend;
	return csum + (csum < addend);
}

static __always_inline __u32 csum_sub(__u32 csum, __u32 addend)
{
	return csum_add(csum, ~addend);
}

static __always_inline void calc_pseudo_ip_ip6_csum(__u32 *csum, int proto,
													struct ipv6hdr *ipv6_hdr, struct iphdr *iph)
{
	__u32 csum_buffer = *csum;

	if (proto == NAT64_IP_VERSION_V4) {
		csum_buffer += (__u16)iph->saddr; REDUCE
		csum_buffer += (__u16)(iph->saddr >> 16); REDUCE
		csum_buffer += (__u16)iph->daddr; REDUCE
		csum_buffer += (__u16)(iph->daddr >> 16); REDUCE

		csum_buffer += (__u16)iph->protocol << 8; REDUCE
		csum_buffer += bpf_htons(bpf_ntohs(iph->tot_len) - sizeof(struct iphdr)); REDUCE

	} else {
		for (int i = 0; i < 16; i += 2)
			csum_buffer += ipv6_hdr->saddr.in6_u.u6_addr8[i] + (ipv6_hdr->saddr.in6_u.u6_addr8[i+1] << 8U); REDUCE

		for (int i = 0; i < 16; i += 2)
			csum_buffer += ipv6_hdr->daddr.in6_u.u6_addr8[i] + (ipv6_hdr->daddr.in6_u.u6_addr8[i+1] << 8U); REDUCE

		csum_buffer += (__u16)ipv6_hdr->nexthdr << 8; REDUCE
		csum_buffer += ipv6_hdr->payload_len; REDUCE
	}

	*csum = csum_buffer;
}

static __always_inline __u16 update_tcp_udp_checksum(__u32 old_cksum, __u16 old_port, __u16 new_port,
													struct ipv6hdr *ipv6_hdr,
													struct iphdr *ipv4_hdr, enum nat64_flow_direction direction)
{
	__u32 csum_buffer = csum_unfold(old_cksum);

	__u32 ipv4_pseudo_hdr_cksum = 0;
	__u32 ipv6_pseudo_hdr_cksum = 0;

	// IPv6 -> IPv4 (OUTGOING)
	if (direction == NAT64_FLOW_DIRECTION_OUTGOING) {
		calc_pseudo_ip_ip6_csum(&ipv4_pseudo_hdr_cksum, NAT64_IP_VERSION_V4, NULL, ipv4_hdr);
		calc_pseudo_ip_ip6_csum(&ipv6_pseudo_hdr_cksum, NAT64_IP_VERSION_V6, ipv6_hdr, NULL);

		csum_buffer += ((~ipv6_pseudo_hdr_cksum) & 0xFFFF); REDUCE
		csum_buffer += ipv4_pseudo_hdr_cksum; REDUCE
	} else {
		// Reverse: IPv4 → IPv6 (INCOMING)
		calc_pseudo_ip_ip6_csum(&ipv4_pseudo_hdr_cksum, NAT64_IP_VERSION_V4, NULL, ipv4_hdr);
		calc_pseudo_ip_ip6_csum(&ipv6_pseudo_hdr_cksum, NAT64_IP_VERSION_V6, ipv6_hdr, NULL);

		csum_buffer += ((~ipv4_pseudo_hdr_cksum) & 0xFFFF); REDUCE
		csum_buffer += ipv6_pseudo_hdr_cksum; REDUCE
	}

	// Add port change
	csum_buffer += (~old_port & 0xFFFF); REDUCE
	csum_buffer += new_port; REDUCE

	return csum_fold(csum_buffer);
}

static inline __u16 compute_ipv4_hdr_checksum(const __u16 *buf, int bufsz)
{
	__u32 sum = 0;

	while (bufsz > 1) {
		sum += *buf;
		buf++;
		bufsz -= 2;
	}

	if (bufsz == 1) {
		sum += *(__u8 *)buf;
	}

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

// borrowed from https://github.com/cilium/cilium/blob/main/bpf/lib/lb.h#L2147
static __always_inline
__u32 icmp_icmp6_csum_accumulate(void *data_start, void *data_end, int sample_len)
{
	__u32 csum_buffer = 0;

	#define body(i) if ((i) > sample_len) \
		return csum_buffer; \
	if (data_start + (i) + sizeof(__u16) > data_end) { \
		if (data_start + (i) + sizeof(__u8) <= data_end)\
			csum_buffer += *(__u8 *)(data_start + (i)); REDUCE \
		return csum_buffer; \
	} \
	csum_buffer += *(__u16 *)(data_start + (i)); \
	REDUCE

	#define body4(i) body(i)\
		body(i + 2) \
		body(i + 4) \
		body(i + 6)

	#define body16(i) body4(i)\
		body4(i + 8) \
		body4(i + 16) \
		body4(i + 24)

	#define body128(i) body16(i)\
		body16(i + 32) \
		body16(i + 64) \
		body16(i + 96)

	body128(0)
	body128(128)
	body128(256)
	body128(384)
	body128(512)

	return csum_buffer;
}

static __always_inline
__u16 compute_icmp_cksum(void *data_begin, void *data_end, int sample_len)
{
	__u32 cksum_tmp = 0;

	cksum_tmp = icmp_icmp6_csum_accumulate(data_begin, data_end, sample_len);

	return csum_fold(cksum_tmp);
}

static __always_inline
__u16 compute_icmp6_cksum(struct ipv6hdr *ipv6_hdr, void *data_begin, void *data_end, int sample_len)
{
	__u32 icmp6_cksum = 0, ipv6_pseudo_hdr_cksum = 0, csum_buffer = 0;

	calc_pseudo_ip_ip6_csum(&ipv6_pseudo_hdr_cksum, NAT64_IP_VERSION_V6, ipv6_hdr, NULL);
	icmp6_cksum = icmp_icmp6_csum_accumulate(data_begin, data_end, sample_len);
	csum_buffer = ipv6_pseudo_hdr_cksum + icmp6_cksum; REDUCE

	return csum_fold(csum_buffer);
}


#endif
