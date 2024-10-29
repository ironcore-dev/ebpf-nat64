#include "nat64_running_thread.h"
#include "nat64_addr_port_manage.h"
#include "nat64_user_log.h"

// multi threading variables
static pthread_t nat64_ipv6_flow_event_thread;
static pthread_t nat64_addr_port_map_cleanup_thread;
static pthread_t nat64_kernel_log_printer_thread;
static volatile bool running = true;



int nat64_create_running_threads(void)
{
	int ret;

	// Start the event processing thread
	ret = pthread_create(&nat64_ipv6_flow_event_thread, NULL, nat64_thread_process_new_flow_event, NULL);
	if (NAT64_FAILED(ret)) {
		fprintf(stderr, "Failed to create event processing thread: %s\n", strerror(ret));
		return NAT64_ERROR;
	}

	// Start the cleanup thread
	ret = pthread_create(&nat64_addr_port_map_cleanup_thread, NULL, nat64_thread_search_and_remove_expired_entries, NULL);
	if (NAT64_FAILED(ret)) {
		nat64_addr_port_manage_loop_exit();
		fprintf(stderr, "Failed to create cleanup thread: %s\n", strerror(ret));
		return NAT64_ERROR;
	}

	ret = pthread_create(&nat64_kernel_log_printer_thread, NULL, nat64_thread_process_kernel_log_event, NULL);
	if (NAT64_FAILED(ret)) {
		nat64_kernel_log_printer_loop_exit();
		fprintf(stderr, "Failed to create kernel log printer thread: %s\n", strerror(ret));
		return NAT64_ERROR;
	}


	return NAT64_OK;
}

int nat64_stop_running_threads(void)
{
	int ret;


	NAT64_LOG_INFO("Stopping the address port management thread...");
	nat64_addr_port_manage_loop_exit();
	ret = pthread_join(nat64_ipv6_flow_event_thread, NULL);
	if (NAT64_FAILED(ret))
		printf("Failed to join event processing thread: %s\n", strerror(ret));

	ret = pthread_join(nat64_addr_port_map_cleanup_thread, NULL);
	if (NAT64_FAILED(ret))
		printf("Failed to join cleanup thread: %s\n", strerror(ret));

	NAT64_LOG_INFO("Stopping the kernel log printer thread...");
	nat64_kernel_log_printer_loop_exit();
	ret = pthread_join(nat64_kernel_log_printer_thread, NULL);
	if (NAT64_FAILED(ret))
		printf("Failed to join kernel log printer thread: %s\n", strerror(ret));

	return NAT64_OK;
}

