
#include <linux/if_link.h> /* depend on kernel-headers installed */


#include "nat64_common.h"
#include "nat64_user.h"
#include "nat64_ebpf_skel_handler.h"
#include "nat64_user_log.h"


#define NAT64_MAP_FD_DEFINE(name) \
		static int nat64_##name##_fd = -1;


#define NAT64_MAP_NAME(name) \
		"nat64_" #name ,


#define NAT64_MAP_FD_GETTER_IMPL(name) \
	int nat64_get_##name##_fd(void) { \
		return nat64_##name##_fd; \
	}


#define NAT64_MAP_FD_INIT(name) \
	 nat64_##name##_fd = bpf_map__fd( skel->maps.nat64_##name);


#define NAT64_MAP_FD_CHECK(name) \
	if (NAT64_FAILED(nat64_##name##_fd)) { \
		NAT64_LOG_ERROR("Failed to find a required map", NAT64_LOG_MAP_NAME("nat64_" #name)); \
	};


const static char *pin_basedir = NAT64_SHARED_MAP_PIN_PATH;

// List of map names to unpin
const static char *map_names[] = {
	NAT64_MAP_FACTORY(NAT64_MAP_NAME)
		// Add other shared and pinned map names here
};


static struct ebpf_nat64_bpf *skel = NULL;
static __u32 xdp_flags;


// Static variables for map file descriptors
NAT64_MAP_FACTORY(NAT64_MAP_FD_DEFINE)


/*XDP / ebpf configurations*/
int nat64_open_and_load_prog_skeleton(void)
{
	int ret;
	skel = ebpf_nat64_bpf__open();
	if (!skel) {
		NAT64_LOG_ERROR("Failed to open skeleton");
		return NAT64_ERROR;
	}

	ret = ebpf_nat64_bpf__load(skel);
	if (NAT64_FAILED(ret)) {
		ebpf_nat64_bpf__destroy(skel);
		NAT64_LOG_ERROR("Failed to load skeleton", NAT64_LOG_ERRNO(ret));
		return NAT64_ERROR;
	}
	return NAT64_OK;
}


// Function to initialize map file descriptors
int nat64_initialize_prog_map_fds(void) {
	if (!skel) {
		NAT64_LOG_ERROR("Failed to initialize map fds due to empty skeleton");
		return NAT64_ERROR;
	}

	NAT64_MAP_FACTORY(NAT64_MAP_FD_INIT)
	NAT64_MAP_FACTORY(NAT64_MAP_FD_CHECK)

	return NAT64_OK;
}


void nat64_destroy_prog_maps(void)
{

	char pin_path[256];
	int ret;

	ret = bpf_object__unpin_maps(skel->obj, pin_basedir);
	if (NAT64_FAILED(ret)) {
		if (errno != ENOENT)
			NAT64_LOG_ERROR("Failed to unpin map", NAT64_LOG_ERRNO(errno));
	}

	for (size_t i = 0; i < sizeof(map_names) / sizeof(map_names[0]); i++) {
 		snprintf(pin_path, sizeof(pin_path), "%s/%s", pin_basedir, map_names[i]);
		if (NAT64_FAILED(unlink(pin_path))) {
			if (errno != ENOENT)
				NAT64_LOG_ERROR("Failed to remove pinned map file", NAT64_LOG_ERRNO(errno));
		}
	}

}

int nat64_attach_prog_skeleton_to_iface(int iface_index, unsigned int xdp_flags)
{
	int err, prog_fd;

	if (!skel) {
		NAT64_LOG_ERROR("Failed to attach skeleton to interfaces due to empty skeleton");
		return NAT64_ERROR;
	}
	
	prog_fd = bpf_program__fd(skel->progs.xdp_nat64);
	
	err = bpf_xdp_attach(iface_index, prog_fd, xdp_flags, NULL);
	if (NAT64_FAILED(err)) {
		if (err == -EEXIST || err == -EBUSY) {
			if (NAT64_FAILED(nat64_detach_prog_skeleton_from_iface(iface_index, xdp_flags)))
				return NAT64_ERROR;

			err = bpf_xdp_attach(iface_index, prog_fd, xdp_flags, NULL);
			if (NAT64_FAILED(err)) {
				NAT64_LOG_ERROR("Failed to re-attach xdp program", NAT64_LOG_ERRNO(err));
				return NAT64_ERROR;
			}
			return NAT64_OK;
		}
		fprintf(stderr,"Failed to attach xdp program on interface %d: %d \n", iface_index, err);
		return NAT64_ERROR;
	}

	return NAT64_OK;
}

int nat64_detach_prog_skeleton_from_iface(int iface_index, unsigned int xdp_flags)
{
	int err;
	err = bpf_xdp_detach(iface_index, xdp_flags, NULL);
	if (NAT64_FAILED(err)) {
		NAT64_LOG_ERROR("Failed to detach existing xdp program", NAT64_LOG_ERRNO(err));
		return NAT64_ERROR;
	}
	return NAT64_OK;
}

int nat64_load_prog_onto_ifaces(void)
{
	int err;
	int attached_iface_cnt = 0;
	int iface_cnt = nat64_get_parsed_attach_iface_cnt();
	const int *attach_iface_index = nat64_get_parsed_attach_iface_index();

	xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
	xdp_flags |= nat64_get_skb_mode()? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;

	for (int i = 0; i < iface_cnt; i++) {
		err = nat64_attach_prog_skeleton_to_iface(attach_iface_index[i], xdp_flags);
		if (NAT64_FAILED(err))
			break;
		attached_iface_cnt++;
	}

	if (attached_iface_cnt < iface_cnt) {
		NAT64_LOG_ERROR("Failed to attach xdp prog to all interfaces, detaching...");
		for (int i = 0; i < attached_iface_cnt; i++) {
			if (NAT64_FAILED(nat64_detach_prog_skeleton_from_iface(attach_iface_index[i], xdp_flags)))
				continue;
		}
		return NAT64_ERROR;
	}
	return NAT64_OK;
}

void nat64_unload_prog_from_ifaces(void)
{
	int iface_cnt = nat64_get_parsed_attach_iface_cnt();
	const int *attach_iface_index = nat64_get_parsed_attach_iface_index();

	// Detach the XDP program from each interface
	for (int i = 0; i < iface_cnt; i++) {
		if (NAT64_FAILED(nat64_detach_prog_skeleton_from_iface(attach_iface_index[i], xdp_flags)))
			NAT64_LOG_ERROR("Failed to detach XDP program from interface", NAT64_LOG_VALUE(attach_iface_index[i]));
		else
			NAT64_LOG_INFO("Detached XDP program from interface", NAT64_LOG_VALUE(attach_iface_index[i]));
	}
}

void nat64_destroy_prog_skeleton(void)
{
	if (skel) {
		ebpf_nat64_bpf__destroy(skel);
		NAT64_LOG_INFO("BPF skeleton destroyed");
	}
}

int nat64_get_prog_fd(void)
{
	return bpf_program__fd(skel->progs.xdp_nat64);
}

NAT64_MAP_FACTORY(NAT64_MAP_FD_GETTER_IMPL)
