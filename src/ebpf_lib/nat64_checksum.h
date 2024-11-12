#ifndef NAT64_CHECKSUM_H
#define NAT64_CHECKSUM_H


#include <linux/ipv6.h>
#include <linux/ip.h>
#include <string.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../include/nat64_common.h"


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

static __always_inline __u32 csum_diff(const void *from, __u32 size_from,
					const void *to,   __u32 size_to,
					__u32 seed)
{
	__s64 csum_diff_result = bpf_csum_diff(from, size_from, to, size_to, seed);
	if (csum_diff_result < 0) {
		return 0;
	}

	return (__u32) csum_diff_result;
}

static __always_inline __be32 ipv6_pseudohdr_checksum(const struct ipv6hdr *hdr,
													__u8 next_hdr,
													__u16 payload_len, __be32 sum)
{
	__be32 nexthdr = bpf_htonl((__u32)next_hdr);
	__be32 len = bpf_htonl((__u32)payload_len);

	sum = csum_diff(NULL, 0, &hdr->saddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &hdr->daddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &len, sizeof(len), sum);
	sum = csum_diff(NULL, 0, &nexthdr, sizeof(nexthdr), sum);

	return sum;
}

static __always_inline __be32 ipv4_pseudohdr_checksum(const struct iphdr *hdr,
													__u8 next_proto,
													__u16 payload_len, __be32 sum)
{
	__be32 saddr = hdr->saddr;
	__be32 daddr = hdr->daddr;
	__be32 len = bpf_htonl((__u32)payload_len);
	__be32 proto = bpf_htonl((__u32)next_proto);
	__be16 proto_short = (__be16)(proto & 0xFFFF);

	sum = csum_diff(NULL, 0, &saddr, sizeof(saddr), sum);
	sum = csum_diff(NULL, 0, &daddr, sizeof(daddr), sum);
	sum = csum_diff(NULL, 0, &proto_short, sizeof(proto_short), sum);
	sum = csum_diff(NULL, 0, &len, sizeof(len), sum);

	return sum;
}


static inline __u16
compute_ipv4_hdr_checksum(const __u16 *buf, int bufsz) {
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

static __always_inline __u16 update_tcp_udp_checksum(__u32 old_cksum, __u16 old_port, __u16 new_port,
												struct ipv6hdr *ipv6_hdr,
												struct iphdr *ipv4_hdr, enum nat64_flow_direction direction)
{
	__u32 csum = csum_unfold(old_cksum);

	if (direction == NAT64_FLOW_DIRECTION_OUTGOING) {
		csum = csum_diff(&ipv6_hdr->saddr, 16, &ipv4_hdr->saddr, 4, csum);
		csum = csum_diff(&ipv6_hdr->daddr, 16, &ipv4_hdr->daddr, 4, csum);
	} else {
		csum = csum_diff(&ipv4_hdr->saddr, 4, &ipv6_hdr->saddr, 16, csum);
		csum = csum_diff(&ipv4_hdr->daddr, 4, &ipv6_hdr->daddr, 16, csum);
	}
	csum = csum + (~old_port & 0xFFFF) + new_port;

	return csum_fold(csum);
}

// borrowed from https://github.com/cilium/cilium/blob/main/bpf/lib/lb.h#L2147
static __always_inline
__u32 icmp_wsum_accumulate(void *data_start, void *data_end, int sample_len)
{
	/* Unrolled loop to calculate the checksum of the ICMP sample
	 * Done manually because the compiler refuses with #pragma unroll
	 */
	__u32 wsum = 0;

	#define body(i) if ((i) > sample_len) \
		return wsum; \
	if (data_start + (i) + sizeof(__u16) > data_end) { \
		if (data_start + (i) + sizeof(__u8) <= data_end)\
			wsum += *(__u8 *)(data_start + (i)); \
		return wsum; \
	} \
	wsum += *(__u16 *)(data_start + (i));

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
	body128(256)
	body128(512)
	body128(768)
	body128(1024)

	return wsum;
}

#endif
