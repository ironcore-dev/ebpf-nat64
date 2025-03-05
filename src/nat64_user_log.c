
// the logging code in this file is adapted from the dpservice logging code
// https://github.com/ironcore-dev/dpservice
// https://github.com/ironcore-dev/dpservice/blob/main/src/dp_log.c

#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "nat64_user_log.h"
#include "nat64_common.h"
#include "nat64_conf.h"
#include "nat64_ebpf_skel_handler.h"

#define TIMESTAMP_FMT "%Y-%m-%d %H:%M:%S"
#define TIMESTAMP_NUL "0000-00-00 00:00:00.000"
#define TIMESTAMP_MAXSIZE sizeof(TIMESTAMP_NUL)

// prevent unnecessary `if (log_json)`
#define FORMAT_HEADER log_formatter[0]
#define FORMAT_ENDLINE log_formatter[1]
#define FORMAT_STR log_formatter[2]
#define FORMAT_INT log_formatter[3]
#define FORMAT_UINT log_formatter[4]
#define FORMAT_IPV4 log_formatter[5]
// #define FORMAT_PTR log_formatter[6]
static const char *const log_formatter_text[] = {
	/* header  */ "%s %.1s %s: %s",
	/* endline */ "\n",
	/* str     */ ", %s: %s",
	/* int     */ ", %s: %d",
	/* uint    */ ", %s: %d",
	/* ipv4    */ ", %s: %u.%u.%u.%u",
	// /* ptr     */ ", %s: %p",
};
static const char *const log_formatter_json[] = {
	/* header  */ "{ \"ts\": \"%s\", \"level\": \"%s\", \"logger\": \"%s\", \"msg\": \"%s\"",
	/* endline */ " }\n",
	/* str     */ ", \"%s\": \"%s\"",
	/* int     */ ", \"%s\": %d",
	/* uint    */ ", \"%s\": %u",
	/* ipv4    */ ", \"%s\": \"%u.%u.%u.%u\"",
	// /* ptr     */ ", \"%s\": \"%p\"",
};
static const char *const log_sources_text[] = {
	"KERNEL", "USERSPACE"
};
static const char *const log_sources_json[] = {
	"kernel", "userspace"
};
static const char *const log_levels[] = {
	"ERROR", "WARNING", "INFO", "DEBUG"
};

static bool log_json = false;
// static uint16_t _log_level = NAT64_LOG_LEVEL_ERROR;
static const char *const *log_formatter = log_formatter_text;
static const char *const *log_sources = log_sources_text;

static struct ring_buffer *kernel_log_event_rb = NULL;
static volatile bool kernel_log_printer_running = true;


int dp_log_init(void)
{

	log_json = false;
	if (log_json) {
		log_formatter = log_formatter_json;
		log_sources = log_sources_json;
	}

	return NAT64_OK;
}

static inline int convert_ipv6_to_str(const union ipv6_addr *ipv6, char *dest, int dest_len)
{
	if (!inet_ntop(AF_INET6, &ipv6->u6_addr8, dest, dest_len))
		return -errno;

	return NAT64_ERROR;
}


static inline int get_timestamp(char *buf)
{
	struct timespec now;
	struct tm tmnow;
	size_t offset;

	// coarse time is enough unless we want < 1ms precision
	if (clock_gettime(CLOCK_REALTIME_COARSE, &now) < 0 || !gmtime_r(&now.tv_sec, &tmnow))
		return NAT64_ERROR;

	offset = strftime(buf, TIMESTAMP_MAXSIZE, TIMESTAMP_FMT, &tmnow);
	if (!offset)
		return NAT64_ERROR;

	offset += snprintf(buf+offset, TIMESTAMP_MAXSIZE-offset, ".%.03lu", now.tv_nsec / 1000000);
	if (offset >= TIMESTAMP_MAXSIZE)
		return NAT64_ERROR;

	return NAT64_OK;
}

static const char *json_escape(const char *message, char *buf, size_t bufsize)
{
	size_t bufpos = 0;
	char c;
	uint8_t hi, lo;

	for (const char *input = message; *input; ++input) {
		c = *input;
		if (c < 0x20) {
			if (bufpos + 6 >= bufsize)
				break;
			hi = c >> 4;
			lo = c & 0xF;
			buf[bufpos++] = '\\';
			buf[bufpos++] = 'u';
			buf[bufpos++] = '0';
			buf[bufpos++] = '0';
			buf[bufpos++] = (char)('0' + hi);
			buf[bufpos++] = (char)(lo >= 10 ? 'a' + (lo-10) : '0' + lo);
		} else if (c == '\\' || c == '\"') {
			if (bufpos + 2 >= bufsize)
				break;
			buf[bufpos++] = '\\';
			buf[bufpos++] = c;
		} else {
			if (bufpos + 1 >= bufsize)
				break;
			buf[bufpos++] = c;
		}
	}

	buf[bufpos] = '\0';
	return buf;
}

static const char *escape_message(const char *message, char *buf, size_t bufsize)
{
	return log_json ? json_escape(message, buf, bufsize) : message;
}


void nat64_macro_log(unsigned int level, unsigned int log_source,
			 const char *message, ...)
{

	if (level > nat64_get_log_level())
		return;

	char timestamp[TIMESTAMP_MAXSIZE];
	va_list args;
	FILE *f;
	const char *key = NULL;
	int format;
	char escaped[3072];  // worst-case: 512 encoded characters (\u1234)
	const char *str_value;
	uint32_t ipv4_value;

	if (NAT64_FAILED(get_timestamp(timestamp)))
		memcpy(timestamp, TIMESTAMP_NUL, TIMESTAMP_MAXSIZE);  // including \0

	f = stdout;

	flockfile(f);
	
	// check the message for printf-format to prevent issues
	for (const char *cur = message; *cur; ++cur)
		assert(*cur != '%');

	fprintf(f, FORMAT_HEADER, timestamp,
			log_levels[level], log_sources[log_source],
			escape_message(message, escaped, sizeof(escaped)));

	va_start(args, message);

	while ((key = va_arg(args, const char *))) {
		format = va_arg(args, int);
		switch(format) {
			case NAT64_LOG_TYPE_STR:
				str_value = escape_message(va_arg(args, const char *), escaped, sizeof(escaped));
				fprintf(f, FORMAT_STR, key, str_value);
				break;
			case NAT64_LOG_TYPE_INT:
				fprintf(f, FORMAT_INT, key, va_arg(args, int));
				break;
			case NAT64_LOG_TYPE_UINT:
				fprintf(f, FORMAT_UINT, key, va_arg(args, unsigned int));
				break;
			case NAT64_LOG_TYPE_IPV4:
				ipv4_value = va_arg(args, uint32_t);
				fprintf(f, FORMAT_IPV4, key, ((ipv4_value)) & 0xFF,
										 ((ipv4_value) >> 8) & 0xFF,
										 ((ipv4_value) >> 16) & 0xFF,
										 (ipv4_value >> 24) & 0xFF);
				break;
			case NAT64_LOG_TYPE_IPV6:
				// re-use the escaping buffer for IP conversion
				convert_ipv6_to_str(va_arg(args, const union ipv6_addr *), escaped,sizeof(escaped));
				fprintf(f, FORMAT_STR, key, escaped);
				break;
			default:
				assert(false);
				goto parse_error;
			}
	}
parse_error:
	va_end(args);

	fputs(FORMAT_ENDLINE, f);

	fflush(f);

	funlockfile(f);
}

static void nat64_kern_log_print(unsigned int level, unsigned int log_source,
						const char *message, const void **args)
{
	if (level > nat64_get_log_level())
		return;

	char timestamp[TIMESTAMP_MAXSIZE];
	FILE *f;
	char escaped[3072];  // worst-case: 512 encoded characters
	const char *str_value;
	uint32_t ipv4_value;

	if (NAT64_FAILED(get_timestamp(timestamp)))
		memcpy(timestamp, TIMESTAMP_NUL, TIMESTAMP_MAXSIZE);

	f = stdout;
	flockfile(f);

	for (const char *cur = message; *cur; ++cur)
		assert(*cur != '%');

	fprintf(f, FORMAT_HEADER, timestamp,
			log_levels[level], log_sources[log_source],
			escape_message(message, escaped, sizeof(escaped)));

	for (const void **curr = args; *curr != NULL; curr += 3) {
		const char *key = (const char *)*curr;
		uint16_t type = *(uint16_t *)*(curr + 1);
		const void *value = *(curr + 2);

		switch(type) {
			case NAT64_LOG_TYPE_STR:
				str_value = escape_message(message, escaped, sizeof(escaped));
				fprintf(f, FORMAT_STR, key, str_value);
				break;
			case NAT64_LOG_TYPE_INT:
				fprintf(f, FORMAT_INT, key, *(int *)value);
				break;
			case NAT64_LOG_TYPE_UINT:
				fprintf(f, FORMAT_UINT, key, *(unsigned int *)value);
				break;
			case NAT64_LOG_TYPE_IPV4:
				ipv4_value = *(uint32_t *)value;
				fprintf(f, FORMAT_IPV4, key, ((ipv4_value)) & 0xFF,
										 ((ipv4_value) >> 8) & 0xFF,
										 ((ipv4_value) >> 16) & 0xFF,
										 (ipv4_value >> 24) & 0xFF);
				break;
			case NAT64_LOG_TYPE_IPV6:
				convert_ipv6_to_str((const union ipv6_addr *)value, escaped, sizeof(escaped));
				fprintf(f, FORMAT_STR, key, escaped);
				break;
			default:
				assert(false);
				goto parse_error;
			}
	}

parse_error:
	fputs(FORMAT_ENDLINE, f);
	fflush(f);
	funlockfile(f);
}

static int nat64_kernel_log_event_handler(void *ctx __attribute__((unused)), void *data, size_t data_sz __attribute__((unused)))
{
	const struct nat64_kernel_log_event *log_event = data;
	const void *log_args[NAT64_LOG_MAX_ENTRIES * 3] = {0};  // 3 args per entry (key, type, value)
	int arg_count = 0;
	
	// Build arguments array from log_event entries
	for (int i = 0; i < log_event->log_value_entry_count; i++) {
		const struct nat64_kernel_log_value *entry = &log_event->entries[i];
		
		log_args[arg_count++] = entry->key;
		log_args[arg_count++] = (void *) &(entry->type);
		
		switch (entry->type) {
			case NAT64_LOG_TYPE_STR:
				log_args[arg_count++] = entry->value.value_str;
				break;
			case NAT64_LOG_TYPE_INT:
				log_args[arg_count++] = &entry->value.value_int;
				break;
			case NAT64_LOG_TYPE_UINT:
				log_args[arg_count++] = &entry->value.value_uint;
				break;
			case NAT64_LOG_TYPE_IPV4:
				log_args[arg_count++] = &entry->value.ipv4_addr;
				break;
			case NAT64_LOG_TYPE_IPV6:
				log_args[arg_count++] = &entry->value.ipv6_addr;
				break;
		}
	}
	
	// Add NULL terminator
	log_args[arg_count] = NULL;
	
	// Call nat64_log_print with the collected arguments
	nat64_kern_log_print(log_event->log_level, NAT64_LOG_SOURCE_KERNEL, 
				log_event->msg, log_args);
	
	return NAT64_OK;
}


void *nat64_thread_process_kernel_log_event(void *arg __attribute__((unused)))
{
	int err;
	
	kernel_log_event_rb = ring_buffer__new(nat64_get_kernel_log_event_rb_fd(), nat64_kernel_log_event_handler, NULL, NULL);
	if (!kernel_log_event_rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		return NULL;
	}

	while (kernel_log_printer_running) {
		err = ring_buffer__poll(kernel_log_event_rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	ring_buffer__free(kernel_log_event_rb);
	return NULL;
}

void nat64_kernel_log_printer_loop_exit(void)
{
	kernel_log_printer_running = false;
}

int nat64_libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	uint16_t current_log_level = nat64_get_log_level();
	FILE *f;
	char timestamp[TIMESTAMP_MAXSIZE];
	char escaped[3072];
	uint16_t nat64_level;

	switch (level) {
	case LIBBPF_WARN:
		if (current_log_level < NAT64_LOG_LEVEL_WARNING)
			return 0;
		nat64_level = NAT64_LOG_LEVEL_WARNING;
		break;
	case LIBBPF_INFO:
		if (current_log_level < NAT64_LOG_LEVEL_INFO)
			return 0;
		nat64_level = NAT64_LOG_LEVEL_INFO;
		break;
	case LIBBPF_DEBUG:
		if (current_log_level < NAT64_LOG_LEVEL_DEBUG)
			return 0;
		nat64_level = NAT64_LOG_LEVEL_DEBUG;
		break;
	default:
		return 0;
	}

	if (NAT64_FAILED(get_timestamp(timestamp)))
		memcpy(timestamp, TIMESTAMP_NUL, TIMESTAMP_MAXSIZE);

	f = stdout;
	flockfile(f);

	fprintf(f, FORMAT_HEADER, timestamp,
			log_levels[nat64_level], "LIBBPF",
			escape_message("", escaped, sizeof(escaped)));

	vfprintf(f, format, args);

	fflush(f);
	funlockfile(f);

	return 0;
}
