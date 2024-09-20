#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
