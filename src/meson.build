# Define source and header files
bpf_common_header_files = [
	'include/nat64_common.h',
	'include/nat64_addr_port_assignment.h',
	'include/nat64_ipaddr.h',
	'include/nat64_log_common.h',
	'include/nat64_table_tuple.h',
	'include/nat64_exporter_stats.h',
	'ebpf_lib/common_bpf_maps.h', # NEW: Common BPF maps
]


bpf_kern_header_files = [
	'ebpf_lib/nat64_kern.h',
	'ebpf_lib/nat64_checksum.h',
	'ebpf_lib/nat64_kern_log.h',
	'ebpf_lib/nat64_icmp_error_handling.h',
	'ebpf_lib/nat64_profile.h',
	'ebpf_lib/nat64_exporter.h',
	'ebpf_lib/datapath_selection.h', # NEW: Selector for main process_ipvX_pkt
] #header files used to compile the BPF kernel program


bpf_prog_flags = [clang, '-g', '-O2', '-target', 'bpf',
				'-D__TARGET_ARCH_' + arch,
				'-I' + meson.current_source_dir(),
				'-I' + meson.current_source_dir() / 'ebpf_lib',
				'-I' + meson.current_source_dir() / 'include',
				clang_includes]

if get_option('stateless')
  bpf_prog_flags += '-DSTATELESS_NAT64'
  bpf_kern_header_files += 'ebpf_lib/stateless_datapath_maps.h'
  bpf_kern_header_files += 'ebpf_lib/stateless_datapath_funcs.h'
else
  bpf_prog_flags += '-DSTATEFUL_NAT64'
  bpf_kern_header_files += 'ebpf_lib/stateful_datapath_maps.h'
  bpf_kern_header_files += 'ebpf_lib/stateful_datapath_funcs.h'
  bpf_kern_header_files += 'ebpf_lib/nat64_tcp_state_tracking.h'
  bpf_kern_header_files += 'ebpf_lib/nat64_flow_handling.h'
  bpf_kern_header_files += 	'ebpf_lib/nat64_modify_hdr.h'
endif

bpf_prog = custom_target('ebpf_nat64_bpf',
	input : ['ebpf_nat64.bpf.c'],
	output : 'ebpf_nat64.bpf.built.o',
	command : bpf_prog_flags + ['-c', '@INPUT@', '-o', '@OUTPUT@'],
	depends : [vmlinux_h],
	depend_files : [bpf_common_header_files, bpf_kern_header_files],
	build_by_default : true
)

# Strip debug info from BPF object
stripped_bpf = custom_target('ebpf_nat64_stripped_bpf',
	input : bpf_prog,
	output : 'ebpf_nat64.bpf.o',
	command : [llvm_strip, '-g', '@INPUT@', '-o', '@OUTPUT@'],
	build_by_default : true
)

# Generate BPF skeleton
bpf_skel = custom_target('bpf_skel',
	input : stripped_bpf,
	output : 'ebpf_nat64.skel.h',
	command : [bpftool, 'gen', 'skeleton', '@INPUT@'],
	capture : true,
	build_by_default : true
)


user_app_headers = [
	'include/user_app/nat64_conf.h',
	'include/user_app/nat64_conf_opts.h',
	'include/user_app/nat64_user.h',
	'include/user_app/nat64_ebpf_skel_handler.h',
	'include/user_app/nat64_running_thread.h',
	'include/user_app/nat64_user_log.h',
] #header files used to compile the BPF userspace program

app_shared_sources = [
	'nat64_conf.c',
	'nat64_conf_opts.c',
	'nat64_ebpf_skel_handler.c',
	'nat64_running_thread.c',
	'nat64_user_log.c',
]

if not get_option('stateless')
  app_shared_sources += 'nat64_addr_port_manage.c'
endif

user_app_sources = [
	'ebpf_nat64.c',
] #source files used to compile the BPF userspace program

executable('ebpf_nat64',
	[user_app_sources, app_shared_sources, bpf_skel],
	include_directories : [
		include_directories('include'),
		include_directories('include/user_app'),
	],
	dependencies : [libbpf_dep, libelf, libz, thread_dep],
	install : true
)


if not get_option('stateless')
test_app_sources = [
	'test/ebpf_nat64.test.c',
	'test/ebpf_nat64_test_func.c',
]


executable('ebpf_nat64_test',
	[test_app_sources, app_shared_sources, bpf_skel,],
	include_directories : [
		include_directories('include'),
		include_directories('include/user_app'),
		include_directories('test'),
	],
	dependencies : [libbpf_dep, libelf, libz, thread_dep],
	install : true
)
endif
