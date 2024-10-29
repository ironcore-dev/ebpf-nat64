#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>

#include "include/user_app/nat64_addr_port_manage.h"


const union ipv6_addr nat64_ipv6_prefix = {
	.u6_addr8 = { 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
const union ipv6_addr nat64_ipv6_mask = {
	.u6_addr8 = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 }
};


static __u32 nat64_ip_in_use;
static struct ring_buffer *new_flow_event_rb = NULL;
static volatile bool addr_port_manage_running = true;


/**Helper functions used in this file**/
static uint64_t get_current_time_ns() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
// Helper function to get a random port within a range
static __u16 get_random_port(__u16 min, __u16 max) {
	return min + (rand() % (max - min + 1));
}

/*NAT64 configuratation related prepareation functions*/
static int populate_addr_port_range_map(void)
{
	int ret;
	int addr_port_item_cnt = nat64_get_parsed_addr_port_cnt();
	const struct nat64_address_ports_range* nat64_addr_port_pool = nat64_get_parsed_addr_port_pool();


	for (int i = 0; i < addr_port_item_cnt; i++) {
		struct nat64_address_ports_range range = {0};
		__u32 ipv4_addr = nat64_addr_port_pool[i].addr;

		if (!i) {
			nat64_ip_in_use = ipv4_addr; // record the first address as the starting point
			printf("nat64_ip_in_use init to %u \n", nat64_ip_in_use);
		}

		// Set the port range
		range.port_range[0] = nat64_addr_port_pool[i].port_range[0];
		range.port_range[1] = nat64_addr_port_pool[i].port_range[1];

		// Update the map
		ret = bpf_map_update_elem(nat64_get_address_port_range_map_fd(), &ipv4_addr, &range, BPF_NOEXIST);
		if (NAT64_FAILED(ret)) {
			fprintf(stderr, "Failed to update nat64_address_port_range_map for IP %u.%u.%u.%u: %s\n",
					(ipv4_addr >> 24) & 0xFF, (ipv4_addr >> 16) & 0xFF,
					(ipv4_addr >> 8) & 0xFF, ipv4_addr & 0xFF,
					strerror(errno));
			return NAT64_ERROR;
		}

		printf("Added NAT64 address %u.%u.%u.%u with port range %u-%u to map\n",
				(ipv4_addr >> 24) & 0xFF, (ipv4_addr >> 16) & 0xFF,
				(ipv4_addr >> 8) & 0xFF, ipv4_addr & 0xFF,
				range.port_range[0], range.port_range[1]);
	}

	return NAT64_OK;
}


static int init_addr_port_assignment_map(__u32 iface_index, __u32 addr, __u16 port)
{
	struct nat64_address_port_assignment new_assignment = {0};
	int ret;

	new_assignment.address_port_item.nat_addr = addr;
	new_assignment.address_port_item.nat_port = port;
	new_assignment.address_port_item.used = 0;  // Set to unused

	printf("new_assignment.address_port_item.nat_addr %u, new_assignment.address_port_item.nat_port %u \n", new_assignment.address_port_item.nat_addr, new_assignment.address_port_item.nat_port);

	ret = bpf_map_update_elem(nat64_get_address_assignment_map_fd(), &iface_index, &new_assignment, BPF_NOEXIST);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Failed to add new address port assignment item for interface %d, ret: %d \n", iface_index, ret);
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

// Helper function to check if an address/port combination is in use
static bool is_addr_port_in_use(__u32 addr, __u16 port) {
	int ret;
	__u8 dummy;
	struct nat64_address_port_item key = {0};
	
	// struct nat64_address_port_item key = {
	//	.nat_addr = addr,
	//	.nat_port = port,
	//}
	// does not work due to padding values

	key.nat_addr = addr;
	key.nat_port = port;

	ret = bpf_map_lookup_elem_flags(nat64_get_address_port_in_use_map_fd(), &key, &dummy, 0);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Failed to lookup address port in use map for addr %u.%u.%u.%u, port %u: %s, %d\n",
				(addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
				(addr >> 8) & 0xFF, addr & 0xFF, port, strerror(errno), ret);
		if (ret == -ENOENT)
			return false;
	}
	return true;
}

// Helper function to add an address/port combination to the in-use map
static int add_addr_port_to_in_use(__u32 addr, __u16 port) {
	int ret;

	struct nat64_address_port_item key = {0};
	__u8 dummy = 1;

	key.nat_addr = addr;
	key.nat_port = port;

	ret = bpf_map_update_elem(nat64_get_address_port_in_use_map_fd(), &key, &dummy, BPF_NOEXIST);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Cannot add addr + port: addr %u.%u.%u.%u, port %u: %s, %d\n",
				(addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
				(addr >> 8) & 0xFF, addr & 0xFF, port, strerror(errno), ret);
		return NAT64_ERROR;
	}
	
	return NAT64_OK;
}


// Helper function to get the next available NAT64 IP address
static __u32 get_next_nat64_ip(__u32 current_ip) {
	__u32 next_key;
	if (bpf_map_get_next_key(nat64_get_address_port_range_map_fd(), &current_ip, &next_key) != 0) {
		// If there's no next key, wrap around to the first key
		bpf_map_get_next_key(nat64_get_address_port_range_map_fd(), NULL, &next_key);
	}
	return next_key;
}


static int compute_and_update_addr_port_assignment(__u32 iface_index) {
	struct nat64_address_port_assignment assignment={0}, new_assignment = {0};
	__u16 chosen_port;
	int ret;
	__u32 initial_ip = nat64_ip_in_use;
	int found = 0;
	struct nat64_address_ports_range range = {0};

	do {
		// Get the port range for the current NAT64 IP
		ret = bpf_map_lookup_elem(nat64_get_address_port_range_map_fd(), &nat64_ip_in_use, &range);
		if (NAT64_FAILED(ret)) {
			fprintf(stderr, "Failed to get port range for IP %u.%u.%u.%u\n",
					(nat64_ip_in_use >> 24) & 0xFF, (nat64_ip_in_use >> 16) & 0xFF,
					(nat64_ip_in_use >> 8) & 0xFF, nat64_ip_in_use & 0xFF);
			return NAT64_ERROR;
		}

		for (int attempt = 0; attempt < NAT64_PORT_MAX_RANDOM_RETRY; attempt++) {
			// Random attempt
			chosen_port = get_random_port(range.port_range[0], range.port_range[1]);
			if (!is_addr_port_in_use(nat64_ip_in_use, chosen_port)) {
				found = 1;
				break;
			}
		}

		if (found)
			break;
			
		for (chosen_port = range.port_range[0]; chosen_port <= range.port_range[1]; chosen_port++) {
			if (!is_addr_port_in_use(nat64_ip_in_use, chosen_port)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			// Move to the next NAT64 IP address
			nat64_ip_in_use = get_next_nat64_ip(nat64_ip_in_use);
		}
	} while (!found && nat64_ip_in_use != initial_ip);

	if (!found) {
		fprintf(stderr, "No available ports for any NAT64 IP address\n");
		return NAT64_ERROR;
	}

	// Look up the existing assignment, if not initialize the first assignment for the interface
	ret = bpf_map_lookup_elem_flags(nat64_get_address_assignment_map_fd(), &iface_index, &assignment, BPF_F_LOCK);
	if (NAT64_FAILED(ret)) {
		if (ret == -ENOENT) {
			// If not found, create a new assignment
			printf("nat64_init_address_port_assignment_map for iface %u, ip %u, port %u \n", iface_index, nat64_ip_in_use, chosen_port);
			ret = init_addr_port_assignment_map(iface_index, nat64_ip_in_use, chosen_port);
			if (NAT64_FAILED(ret)) {
				printf("Failed to nat64_init_address_port_assignment_map \n");
				return NAT64_ERROR;
			}

			ret = add_addr_port_to_in_use(nat64_ip_in_use, chosen_port);
			if (NAT64_FAILED(ret)) {
				fprintf(stderr, "Failed to add address/port to in-use map: %s\n", strerror(errno));
				return NAT64_ERROR;
			}
			return NAT64_OK;
		}

		return NAT64_ERROR;
	}

	// Acquire the spinlock
	if (!assignment.address_port_item.used)// if this assignment is not used. just return.
		return NAT64_OK;

	// Modify the assignment
	new_assignment.address_port_item.nat_addr = nat64_ip_in_use;
	new_assignment.address_port_item.nat_port = chosen_port;
	new_assignment.address_port_item.used = 0;  // Set to unused

	printf("chosen: new_assignment.address_port_item.nat_addr %u, new_assignment.address_port_item.nat_port %u \n", new_assignment.address_port_item.nat_addr, new_assignment.address_port_item.nat_port);

	ret = bpf_map_update_elem(nat64_get_address_assignment_map_fd(), &iface_index, &new_assignment, BPF_F_LOCK | BPF_ANY);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Failed to update address port assignment map for interface %u\n", iface_index);
		return NAT64_ERROR;
	}

	// Add the chosen address/port to the in-use map
	ret = add_addr_port_to_in_use(nat64_ip_in_use, chosen_port);
	if (ret != 0) {
		fprintf(stderr, "Failed to add address/port to in-use map: %s\n", strerror(errno));
		return NAT64_ERROR;
	}

	// Move to the next NAT64 IP address for the next call
	nat64_ip_in_use = get_next_nat64_ip(nat64_ip_in_use);

	return NAT64_OK;
}

static int init_iface_addr_port_assignment(void) {

	int iface_cnt = nat64_get_parsed_attach_iface_cnt();
	const int *attach_iface_index = nat64_get_parsed_attach_iface_index();
	
	srand(time(NULL));  // Initialize random seed

	for (int i = 0; i < iface_cnt; i++) {
		// TODO: differentiate the inner-facing and outer-facing interfaces later
		if (compute_and_update_addr_port_assignment(attach_iface_index[i]) != 0) {
			fprintf(stderr, "Failed to initialize NAT64 assignment for interface %u\n", attach_iface_index[i]);
			return NAT64_ERROR;
		}
	}
	return NAT64_OK;
}

static int compute_reverse_key_value(bool is_v6_v4_map, const struct nat64_table_tuple *key, const struct nat64_table_value *value,
								struct nat64_table_tuple *reverse_key, struct nat64_table_value *reverse_value)
{
	if (is_v6_v4_map) {
		reverse_key->version = NAT64_IP_VERSION_V4; // IPv4
		reverse_key->addr.v4.src_ip = key->addr.v6.dst_ip6.u6_addr32[3]; // Last 4 bytes of IPv6 dst
		reverse_key->addr.v4.dst_ip = value->addr.nat64_v4_addr;
		if (key->protocol == IPPROTO_TCP || key->protocol == IPPROTO_UDP) {
			reverse_key->protocol = key->protocol;
			reverse_key->src_port = key->dst_port; // Swap src and dst
			reverse_key->dst_port = value->port.nat64_port;
		} else {
			reverse_key->protocol = IPPROTO_ICMP;
			reverse_key->src_port = ICMP_ECHOREPLY;
			reverse_key->dst_port = value->port.nat64_port;
		}

		printf("get_reverse_key_value v6\n");
		// print_addr_bytes(key);
		// print_addr_bytes(reverse_key);
		// if (NAT64_FAILED(bpf_map_lookup_elem(nat64_get_v4_v6_map_fd(), reverse_key, reverse_value))) {
		// 	printf("Failed to lookup element in v4_v6 map\n");
		// 	return NAT64_ERROR;
		// }

	} else {
		reverse_key->version = NAT64_IP_VERSION_V6; // IPv6
		memcpy(&reverse_key->addr.v6.src_ip6, &value->addr.original_ip6, NAT64_IPV6_ADDR_LENGTH);
		memcpy(&reverse_key->addr.v6.dst_ip6.u6_addr8, &nat64_ipv6_prefix, 12);
		memcpy(&reverse_key->addr.v6.dst_ip6.u6_addr32[3], &key->addr.v4.src_ip, 4);
		if (key->protocol == IPPROTO_TCP || key->protocol == IPPROTO_UDP) {
			reverse_key->protocol = key->protocol;
			reverse_key->src_port = value->port.original_port; // Swap src and dst
			reverse_key->dst_port = key->src_port;
		} else {
			reverse_key->protocol = IPPROTO_ICMPV6;
			reverse_key->src_port = bpf_htons(ICMPV6_ECHO_REQUEST);
			reverse_key->dst_port = key->src_port;
		}

		// print_addr_bytes(key);
		// print_addr_bytes(reverse_key);
		// if (NAT64_FAILED(bpf_map_lookup_elem(nat64_get_v6_v4_map_fd(), reverse_key, reverse_value))) {
		// 	printf("Failed to lookup element in v6_v4 map\n");
		// 	return NAT64_ERROR;
		// }
	}
	return NAT64_OK;
}


static int remove_allocated_addr_port(const struct nat64_table_value *value)
{
	int ret;

	struct nat64_address_port_item key = {0};
	
	key.nat_addr = value->addr.nat64_v4_addr;
	key.nat_port = bpf_ntohs(value->port.nat64_port);

	ret = bpf_map_delete_elem(nat64_get_address_port_in_use_map_fd(), &key);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Failed to lookup and delete address port in use map for addr %u.%u.%u.%u, port %u: %s\n",
				(key.nat_addr >> 24) & 0xFF, (key.nat_addr >> 16) & 0xFF,
				(key.nat_addr >> 8) & 0xFF, key.nat_addr & 0xFF, key.nat_port, strerror(errno));
		return NAT64_ERROR;
	}

	printf("Removed used allocated addr port \n");

	return NAT64_OK;
}

static void cleanup_expired_entries(int map_fd) {
	struct nat64_table_tuple key = {0}, next_key={0}, reverse_key={0};
	struct nat64_table_value value={0}, reverse_value={0};
	bool is_v6_v4_map = map_fd == nat64_get_v6_v4_map_fd();
	int reverse_map_fd = is_v6_v4_map? nat64_get_v4_v6_map_fd() : nat64_get_v6_v4_map_fd();
	__u64 current_time;

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == NAT64_OK) {
		if (!NAT64_FAILED(bpf_map_lookup_elem(map_fd, &next_key, &value))) {
			current_time = get_current_time_ns();

			if ((__u64)(current_time - value.last_seen) > NAT64_ASSIGNMET_LIVENESS_IN_NANO) {
				if (NAT64_FAILED(compute_reverse_key_value(is_v6_v4_map, &next_key, &value, &reverse_key, &reverse_value))) {
					printf("Cannot get the reverse key and value \n");
					bpf_map_delete_elem(map_fd, &next_key);
					remove_allocated_addr_port(&value);
					continue;
				}

			if ((__u64)(current_time - reverse_value.last_seen) > NAT64_ASSIGNMET_LIVENESS_IN_NANO) {
					bpf_map_delete_elem(map_fd, &next_key);
					bpf_map_delete_elem(reverse_map_fd, &reverse_key);
					remove_allocated_addr_port(&value);
					printf("Removed expired entry from maps\n");
				}
			}
		}
		key = next_key;
	}
}


int nat64_addr_port_manage_init(void)
{
	if (NAT64_FAILED(populate_addr_port_range_map())) {
		fprintf(stderr, "Failed to populate address port range map\n");
		return NAT64_ERROR;
	}

	if (NAT64_FAILED(init_iface_addr_port_assignment())) {
		fprintf(stderr, "Failed to init address port assignment \n");
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

static int nat64_new_flow_event_handler(void *ctx, void *data, size_t data_sz)
{
	const struct nat64_ipv6_new_flow_event *e = data;
	int ret;

	printf("New IPv6 flow event received for interface %u\n", e->iface_index);

	ret = compute_and_update_addr_port_assignment(e->iface_index);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Failed to compute address port assignment for interface %u\n", e->iface_index);
	}

	return NAT64_OK;
}

void *nat64_thread_process_new_flow_event(void *arg)
{
	int err;
	

	new_flow_event_rb = ring_buffer__new(nat64_get_new_flow_event_rb_fd(), nat64_new_flow_event_handler, NULL, NULL);
	if (!new_flow_event_rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		return NULL;
	}

	while (addr_port_manage_running) {
		err = ring_buffer__poll(new_flow_event_rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	ring_buffer__free(new_flow_event_rb);
	return NULL;
}


void* nat64_thread_search_and_remove_expired_entries(void* arg)
{
	while (addr_port_manage_running) {
		cleanup_expired_entries(nat64_get_v6_v4_map_fd());
		cleanup_expired_entries(nat64_get_v4_v6_map_fd());
		sleep(NAT64_EXPIRED_ENTRY_CLEANUP_INTERVAL_SEC);  // Sleep for NAT64_EXPIRED_ENTRY_CLEANUP_INTERVAL_SEC seconds
	}
	return NULL;
}

void nat64_addr_port_manage_loop_exit(void)
{
	addr_port_manage_running = false;
}
