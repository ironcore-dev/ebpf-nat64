#ifndef NAT64_USER_H
#define NAT64_USER_H


#include <linux/icmpv6.h>
#include <linux/icmp.h>

#include "nat64_common.h"
#include "nat64_user.h"
#include "nat64_table_tuple.h"
#include "nat64_print.h"
#include "ebpf_nat64.skel.h"

#define NAT64_ASSIGNMET_LIVENESS_IN_SEC 10
#define NAT64_ASSIGNMET_LIVENESS_IN_NANO (1000ULL * 1000ULL * 1000ULL * NAT64_ASSIGNMET_LIVENESS_IN_SEC)

#endif
