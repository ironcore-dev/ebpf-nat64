#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <arpa/inet.h> 
#include <signal.h>
#include <pthread.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "nat64_user.h"

/*argument parsing related definitions*/
static const char short_options[] = "d" /* debug */
				"D"	 /* debug */;

static int debug_mode = 0;
static int enable_skb_mode = 0;
static char nat64_addr_port_pool_str[256] = {0};
static char nat64_attach_iface_str[256] = {0};

#define OPT_ADDR_PORT_POOL "addr-port-pool"
#define OPT_ATTACH_IFACE "interface"
#define OPT_ENABLE_SKB_MODE "skb-mode"

enum {
	OPT_MIN_NUM = 256,
	OPT_ADDR_PORT_POOL_NUM,
	OPT_ATTACH_IFACE_NUM,
	OPT_ENABLE_SKB_MODE_NUM,
};

static const struct option lgopts[] = {
	{OPT_ADDR_PORT_POOL, 1, 0, OPT_ADDR_PORT_POOL_NUM},
	{OPT_ATTACH_IFACE, 1, 0, OPT_ATTACH_IFACE_NUM},
	{OPT_ENABLE_SKB_MODE, 0, 0, OPT_ENABLE_SKB_MODE_NUM},
};


/*NAT64 configuration variables*/
static int addr_port_item_cnt = 0;
static int iface_cnt = 0;

struct nat64_addr_port_pool_t {
	__u32 addr;
	__u16 port_range[2];
};

static __u32 nat64_ip_in_use;

struct nat64_addr_port_pool_t nat64_addr_port_pool[NAT64_ADDR_PORT_POOL_SIZE];
int attach_iface_index[NAT64_ATTACH_IFACE_MAX_CNT];

/*XDP / ebpf configurations*/
__u32 xdp_flags;
struct ebpf_nat64_bpf *skel = NULL;

// Static variables for map file descriptors
static int nat64_addr_port_range_map_fd = -1;
static int nat64_addr_port_assignment_map_fd = -1;
static int nat64_addr_port_in_use_map_fd = -1;
static int nat64_new_flow_event_ringbuffer_fd = -1;

static int nat64_v6_v4_map_fd = -1;
static int nat64_v4_v6_map_fd = -1;

static struct ring_buffer *rb = NULL;


// multi threading variables
static pthread_t nat64_ipv6_flow_event_thread;
static pthread_t nat64_addr_port_map_cleanup_thread;
static volatile bool running = true;

/*arument parsing related functions*/
static void nat64_print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s --"
		" -d"
		" [-D]"
		"\n",
		prgname);
}

static int nat64_parse_args(int argc, char **argv)
{
	char *prgname = argv[0];
	int option_index;
	char **argvopt;
	int opt, ret;

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
				  &option_index)) != EOF) {

		switch (opt) {
		case 'd':
		/* Intended fallthrough */
		case 'D':
			debug_mode = 1;
			break;
		/* Long options */
		case OPT_ADDR_PORT_POOL_NUM:
			strncpy(nat64_addr_port_pool_str, optarg, 256);
			break;
		case OPT_ATTACH_IFACE_NUM:
			strncpy(nat64_attach_iface_str, optarg, 256);
			break;
		case OPT_ENABLE_SKB_MODE_NUM:
			enable_skb_mode = 1;
			break;
		default:
			nat64_print_usage(prgname);
			return NAT64_ERROR;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	ret = optind - 1;
	optind = 1; /* Reset getopt lib */

	return ret;
}

/*NAT64 configuratation related prepareation functions*/
static int nat64_parse_addr_port_pool_str(const char *nat64_addr_port_pool_str)
{
	char *pool_str = strdup(nat64_addr_port_pool_str);
	char *token, *saveptr;
	int i = 0;

	token = strtok_r(pool_str, ",", &saveptr);
	while (token != NULL && i < NAT64_ADDR_PORT_POOL_SIZE) {
		char *addr_port_str = strdup(token);
		char *addr_str, *port_str;

		addr_str = strtok(addr_port_str, ":");
		port_str = strtok(NULL, ":");

		if (addr_str != NULL && port_str != NULL) {
			nat64_addr_port_pool[i].addr = inet_addr(addr_str);
			char *port_range_str = strdup(port_str);
			nat64_addr_port_pool[i].port_range[0] = atoi(strtok(port_range_str, "-"));
			nat64_addr_port_pool[i].port_range[1] = atoi(strtok(NULL, "-"));
			free(port_range_str);
			i++;
			addr_port_item_cnt++;
		}
		free(addr_port_str);
		token = strtok_r(NULL, ",", &saveptr);
	}
	free(pool_str);

	if (token != NULL) {
		// More than three combinations, return error
		fprintf(stderr, "Error: More than %d addr:port combinations provided.\n", NAT64_ADDR_PORT_POOL_SIZE);
		return NAT64_ERROR;
	}
	return NAT64_OK;
}


static void unpin_and_remove_maps(void)
{

	char pin_path[256];
	const char *pin_basedir = NAT64_SHARED_MAP_PIN_PATH;
	// List of map names to unpin
	const char *map_names[] = {
		"nat64_address_assignment_map",
		"nat64_v4_v6_map",
		"nat64_v6_v4_map",
		// "nat64_address_port_in_use_map",
		// Add other map names here
	};

	if (NAT64_FAILED(bpf_object__unpin_maps(skel->obj, pin_basedir))) {
		if (errno != ENOENT)
			// Handle any error other than file not existing
			fprintf(stderr, "Failed to unpin map: %s\n", strerror(errno));
	}

	for (size_t i = 0; i < sizeof(map_names) / sizeof(map_names[0]); i++) {
 		snprintf(pin_path, sizeof(pin_path), "%s/%s", pin_basedir, map_names[i]);
		if (NAT64_FAILED(unlink(pin_path))) {
			if (errno != ENOENT)
				// Handle any error other than file not existing
				fprintf(stderr, "Failed to remove pinned map file: %s\n", strerror(errno));
		}
	}

}


// Function to initialize map file descriptors
int initialize_map_fds(struct ebpf_nat64_bpf *skel) {
	nat64_addr_port_range_map_fd = bpf_map__fd(skel->maps.nat64_address_port_range_map);
	nat64_addr_port_assignment_map_fd = bpf_map__fd(skel->maps.nat64_address_assignment_map);
	nat64_addr_port_in_use_map_fd = bpf_map__fd(skel->maps.nat64_address_port_in_use_map);
	nat64_new_flow_event_ringbuffer_fd = bpf_map__fd(skel->maps.nat64_new_flow_event_rb);

	nat64_v6_v4_map_fd = bpf_map__fd(skel->maps.nat64_v6_v4_map);
	nat64_v4_v6_map_fd = bpf_map__fd(skel->maps.nat64_v4_v6_map);

	if (nat64_addr_port_range_map_fd < 0
		|| nat64_addr_port_assignment_map_fd < 0
		|| nat64_addr_port_in_use_map_fd < 0
		|| nat64_addr_port_range_map_fd <0
		|| nat64_new_flow_event_ringbuffer_fd < 0
		|| nat64_v6_v4_map_fd < 0
		|| nat64_v4_v6_map_fd < 0) {
		fprintf(stderr, "Failed to find required maps\n");
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

int nat64_populate_address_port_range_map(void)
{
	int ret;
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
		ret = bpf_map_update_elem(nat64_addr_port_range_map_fd, &ipv4_addr, &range, BPF_NOEXIST);
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

// Helper function to get a random port within a range
static __u16 get_random_port(__u16 min, __u16 max) {
	return min + (rand() % (max - min + 1));
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

	ret = bpf_map_lookup_elem_flags(nat64_addr_port_in_use_map_fd, &key, &dummy, 0);
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

	ret = bpf_map_update_elem(nat64_addr_port_in_use_map_fd, &key, &dummy, BPF_NOEXIST);
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
	if (bpf_map_get_next_key(nat64_addr_port_range_map_fd, &current_ip, &next_key) != 0) {
		// If there's no next key, wrap around to the first key
		bpf_map_get_next_key(nat64_addr_port_range_map_fd, NULL, &next_key);
	}
	return next_key;
}


static int nat64_init_address_port_assignment_map(__u32 iface_index, __u32 addr, __u16 port)
{
	struct nat64_address_port_assignment new_assignment = {0};
	int ret;

	new_assignment.address_port_item.nat_addr = addr;
	new_assignment.address_port_item.nat_port = port;
	new_assignment.address_port_item.used = 0;  // Set to unused

	printf("new_assignment.address_port_item.nat_addr %u, new_assignment.address_port_item.nat_port %u \n", new_assignment.address_port_item.nat_addr, new_assignment.address_port_item.nat_port);

	ret = bpf_map_update_elem(nat64_addr_port_assignment_map_fd, &iface_index, &new_assignment, BPF_NOEXIST);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Failed to add new address port assignment item for interface %d, ret: %d \n", iface_index, ret);
		return NAT64_ERROR;
	}

	return NAT64_OK;
}


static int nat64_compute_address_port_assignment(__u32 iface_index) {
	struct nat64_address_port_assignment assignment={0}, new_assignment = {0};
	__u16 chosen_port;
	int ret;
	__u32 initial_ip = nat64_ip_in_use;
	int found = 0;
	struct nat64_address_ports_range range = {0};

	do {
		// Get the port range for the current NAT64 IP
		ret = bpf_map_lookup_elem(nat64_addr_port_range_map_fd, &nat64_ip_in_use, &range);
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
	ret = bpf_map_lookup_elem_flags(nat64_addr_port_assignment_map_fd, &iface_index, &assignment, BPF_F_LOCK);
	if (NAT64_FAILED(ret)) {
		if (ret == -ENOENT) {
			// If not found, create a new assignment
			printf("nat64_init_address_port_assignment_map for iface %u, ip %u, port %u \n", iface_index, nat64_ip_in_use, chosen_port);
			ret = nat64_init_address_port_assignment_map(iface_index, nat64_ip_in_use, chosen_port);
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

	ret = bpf_map_update_elem(nat64_addr_port_assignment_map_fd, &iface_index, &new_assignment, BPF_F_LOCK | BPF_ANY);
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

static int nat64_new_ipv6_flow_event_handler(void *ctx, void *data, size_t data_sz)
{
	const struct nat64_ipv6_new_flow_event *e = data;
	int ret;

	printf("New IPv6 flow event received for interface %u\n", e->iface_index);

	ret = nat64_compute_address_port_assignment(e->iface_index);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Failed to compute address port assignment for interface %u\n", e->iface_index);
	}

	return NAT64_OK;
}

static void *nat64_process_ipv6_new_flow_event_thread(void *arg)
{
	int map_fd = *(int *)arg;
	int err;

	rb = ring_buffer__new(map_fd, nat64_new_ipv6_flow_event_handler, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		return NULL;
	}

	while (running) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
	return NULL;
}

static int start_nat64_ipv6_new_flow_event_processing(int map_fd)
{
	int ret;

	// Start the event processing thread
	ret = pthread_create(&nat64_ipv6_flow_event_thread, NULL, nat64_process_ipv6_new_flow_event_thread, &map_fd);
	if (ret != 0) {
		fprintf(stderr, "Failed to create event processing thread: %s\n", strerror(ret));
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

static int nat64_stop_ipv6_new_flow_event_processing()
{
	running = false;
	pthread_join(nat64_ipv6_flow_event_thread, NULL);
	return NAT64_OK;
}

static int nat64_stop_map_cleanup_loop()
{
	running = false;
	pthread_join(nat64_addr_port_map_cleanup_thread, NULL);
	return NAT64_OK;
}

static uint64_t get_current_time_ns() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int get_reverse_key_value(bool is_v6_v4_map, const struct nat64_table_tuple *key, const struct nat64_table_value *value,
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
		print_addr_bytes(key);
		print_addr_bytes(reverse_key);
		if (NAT64_FAILED(bpf_map_lookup_elem(nat64_v4_v6_map_fd, reverse_key, reverse_value))) {
			printf("Failed to lookup element in v4_v6 map\n");
			return NAT64_ERROR;
		}

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

		printf("get_reverse_key_value v4 \n");
		print_addr_bytes(key);
		print_addr_bytes(reverse_key);
		if (NAT64_FAILED(bpf_map_lookup_elem(nat64_v6_v4_map_fd, reverse_key, reverse_value))) {
			printf("Failed to lookup element in v6_v4 map\n");
			return NAT64_ERROR;
		}
	}
	return NAT64_OK;
}


static int remove_allocated_addr_port(const struct nat64_table_value *value)
{
	int ret;

	struct nat64_address_port_item key = {0};
	
	key.nat_addr = value->addr.nat64_v4_addr;
	key.nat_port = bpf_ntohs(value->port.nat64_port);

	ret = bpf_map_delete_elem(nat64_addr_port_in_use_map_fd, &key);
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
	bool is_v6_v4_map = map_fd == nat64_v6_v4_map_fd;
	int reverse_map_fd = is_v6_v4_map? nat64_v4_v6_map_fd : nat64_v6_v4_map_fd;
	__u64 current_time;

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == NAT64_OK) {
		if (!NAT64_FAILED(bpf_map_lookup_elem(map_fd, &next_key, &value))) {
			current_time = get_current_time_ns();

			if ((__u64)(current_time - value.last_seen) > NAT64_ASSIGNMET_LIVENESS_IN_NANO) {
				printf("found a expired entry, is_v6_v4 %d \n", is_v6_v4_map);
				if (NAT64_FAILED(get_reverse_key_value(is_v6_v4_map, &next_key, &value, &reverse_key, &reverse_value))) {
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

void* cleanup_thread_func(void* arg) {
	while (running) {
		cleanup_expired_entries(nat64_v6_v4_map_fd);
		cleanup_expired_entries(nat64_v4_v6_map_fd);
		sleep(5);  // Sleep for 5 seconds
	}

	return NULL;
}

// Function to start the cleanup thread
int start_cleanup_thread(void) {

	if (pthread_create(&nat64_addr_port_map_cleanup_thread, NULL, cleanup_thread_func, NULL) != 0) {
		perror("Failed to create cleanup thread");
		return NAT64_ERROR;
	}

	// Detach the thread so it cleans up automatically when it exits
	pthread_detach(nat64_addr_port_map_cleanup_thread);

	return NAT64_OK;
}


static int initialize_nat64_address_assignments(void) {

	srand(time(NULL));  // Initialize random seed

	for (int i = 0; i < iface_cnt; i++) {
		// TODO: differentiate the inner-facing and outer-facing interfaces later
		if (nat64_compute_address_port_assignment(attach_iface_index[i]) != 0) {
			fprintf(stderr, "Failed to initialize NAT64 assignment for interface %u\n", attach_iface_index[i]);
			return NAT64_ERROR;
		}
	}
	return NAT64_OK;
}

static void nat64_print_addr_port_pool(void)
{
	int i;
	for (i = 0; i < addr_port_item_cnt; i++) {
		struct in_addr addr; // Declare a struct in_addr
		addr.s_addr = nat64_addr_port_pool[i].addr; // Assign the __u32 to the struct
		printf("Address: %s, Port Range: %d-%d\n", 
			inet_ntoa(addr), 
			nat64_addr_port_pool[i].port_range[0], 
			nat64_addr_port_pool[i].port_range[1]);
	}
}

static int nat64_parse_attach_iface_str(const char *nat64_attach_iface_str)
{
	char *iface_str = strdup(nat64_attach_iface_str);
	char *token, *saveptr;
	int i = 0;

	token = strtok_r(iface_str, ",", &saveptr);
	while (token != NULL && i < NAT64_ATTACH_IFACE_MAX_CNT) {
		int iface_index = if_nametoindex(token);
		if (iface_index == 0) {
			fprintf(stderr, "Error: Interface %s does not exist.\n", token);
			free(iface_str);
			return NAT64_ERROR;
		}
		attach_iface_index[i] = iface_index;
		i++;
		iface_cnt++;
		token = strtok_r(NULL, ",", &saveptr);
	}

	if (token != NULL) {
		fprintf(stderr, "Error: More than %d interfaces provided \n", NAT64_ATTACH_IFACE_MAX_CNT);
		free(iface_str);
		return NAT64_ERROR;
	}
	free(iface_str);
	return NAT64_OK;
}


static int nat64_parse_configurations(void)
{
	int ret;

	ret = nat64_parse_addr_port_pool_str(nat64_addr_port_pool_str);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Error: More than %d addr:port combinations provided.\n", NAT64_ADDR_PORT_POOL_SIZE);
		return NAT64_ERROR; // Exit if parsing addr:port pool fails
	}

	ret = nat64_parse_attach_iface_str(nat64_attach_iface_str);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Error: More than %d attaching interface provided.\n", NAT64_ATTACH_IFACE_MAX_CNT);
		return NAT64_ERROR; // Exit if parsing addr:port pool fails
	}

	return NAT64_OK;
}

static void nat64_print_iface_indexes(void)
{
	int i;
	for (i = 0; i < iface_cnt; i++) {
		printf("Interface Index: %d\n", attach_iface_index[i]);
	}
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}


static int nat64_attach_prog_to_interface(int iface_index, int prog_fd)
{
	int err;
	
	xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
	xdp_flags |= enable_skb_mode? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;

	err = bpf_xdp_attach(iface_index, prog_fd, xdp_flags, NULL);
	if (NAT64_FAILED(err)) {
		if (err == -EEXIST || err == -EBUSY) {
			err = bpf_xdp_detach(iface_index, xdp_flags, NULL);
			if (NAT64_FAILED(err)) {
				sprintf(stderr, "Failed to dettach existing xdp program: %d \n", err);
				return NAT64_ERROR;
			}
			err = bpf_xdp_attach(iface_index, prog_fd, xdp_flags, NULL);
			if (NAT64_FAILED(err)) {
				sprintf(stderr, "Failed to re-attach xdp program: %d \n", err);
				return NAT64_ERROR;
			}
			return NAT64_OK;
		}
		fprintf(stderr,"Failed to attach xdp program on interface %d: %d \n", iface_index, err);
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

static int nat64_attach_xdp_prog(struct ebpf_nat64_bpf *skel)
{
	int err;
	int attached_iface_cnt = 0;

	for (int i = 0; i < iface_cnt; i++) {
		err = nat64_attach_prog_to_interface(attach_iface_index[i], bpf_program__fd(skel->progs.xdp_nat64));
		if (NAT64_FAILED(err))
			break;
		attached_iface_cnt++;
	}

	if (attached_iface_cnt < iface_cnt) {
		for (int i = 0; i < attached_iface_cnt; i++) {
			err = bpf_xdp_detach(attach_iface_index[i], xdp_flags, NULL);
			if (NAT64_FAILED(err)) {
				fprintf(stderr, "Failed to dettach existing xdp program: %d \n", err);
				continue;
			}
		}
		fprintf(stderr, "Failed to attach xdp prog to interfaces, detaching... \n");
		return NAT64_ERROR;
	}
	return NAT64_OK;
}

static void nat64_detach_prog_from_interfaces(void)
{
	int err;

	// Detach the XDP program from each interface
	for (int i = 0; i < iface_cnt; i++) {
		err = bpf_xdp_detach(attach_iface_index[i], xdp_flags, NULL);
		if (err) {
			fprintf(stderr, "Failed to detach XDP program from interface %d: %d\n", attach_iface_index[i], err);
		} else {
			printf("Detached XDP program from interface %d\n", attach_iface_index[i]);
		}
	}
}

static void nat64_destroy_prog_skel(void)
{
	if (skel) {
		ebpf_nat64_bpf__destroy(skel);
		printf("BPF skeleton destroyed\n");
	}
}


static void process_stop_signal(int signum)
{

	nat64_stop_map_cleanup_loop();
	nat64_stop_ipv6_new_flow_event_processing();
	nat64_detach_prog_from_interfaces();
	unpin_and_remove_maps();
	nat64_destroy_prog_skel();

	exit(0); // Exit the program
}

int main(int argc, char **argv){
	int ret = 0;

	nat64_parse_args(argc, argv);
	ret = nat64_parse_configurations();
	if(NAT64_FAILED(ret))
		return 1;

	nat64_print_addr_port_pool();
	nat64_print_iface_indexes();
	
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, process_stop_signal);

	/* Open load and verify BPF application */
	skel = ebpf_nat64_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	ret = initialize_map_fds(skel);
	if (NAT64_FAILED(ret))
		goto delete_prog;
	
	ret = nat64_populate_address_port_range_map();
	if (NAT64_FAILED(ret))
		goto delete_prog;

	ret = initialize_nat64_address_assignments();
	if (NAT64_FAILED(ret))
		goto delete_prog;

	ret = start_nat64_ipv6_new_flow_event_processing(nat64_new_flow_event_ringbuffer_fd);
	if (NAT64_FAILED(ret))
		goto stop_rb_poll;

	ret = start_cleanup_thread();
	if (NAT64_FAILED(ret))
		goto stop_rb_poll;

	/* Attach xdp handler */
	ret = nat64_attach_xdp_prog(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto detach_prog;
	}

	while (running) {
		fprintf(stderr, ".");
		sleep(1);
	}

	// Normal exit path
	ret = 0;
	goto detach_prog;

detach_prog:
	nat64_detach_prog_from_interfaces();
stop_map_cleanup:
	nat64_stop_map_cleanup_loop();
stop_rb_poll:
	nat64_stop_ipv6_new_flow_event_processing();
delete_prog:
	unpin_and_remove_maps();
	nat64_destroy_prog_skel();

	return ret;
}
