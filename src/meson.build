# Define source and header files
bpf_kern_header_files = [
	'nat64_table_tuple.h',
	'nat64_print.h',
	'nat64_kern.h',
	'nat64_checksum.h',
	'nat64_modify_hdr.h',
	'nat64_ipaddr.h',
	'nat64_common.h',
	'nat64_addr_port_assignment.h'
	]  # Add header files as needed

bpf_kern_source_files = [
	'ebpf_nat64.bpf.c'
	]  # Add other source files as needed


header_dir = meson.current_source_dir()
bpf_kern_headers = []
foreach h : bpf_kern_header_files
    bpf_kern_headers += files(header_dir / h)
endforeach

# Build BPF code
bpf_prog = custom_target('ebpf_nat64_bpf',
	input : ['ebpf_nat64.bpf.c'],
	output : 'ebpf_nat64.bpf.built.o',
	command : [clang, '-g', '-O2', '-target', 'bpf',
				'-D__TARGET_ARCH_' + arch, '-I' + meson.current_source_dir(),
				'-I' + libbpf_src, clang_includes, '-c', '@INPUT@', '-o', '@OUTPUT@'],
	depends : [libbpf, bpftool],
	depend_files : bpf_kern_header_files,
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

# Main application
executable('ebpf_nat64',
	['ebpf_nat64.c', bpf_skel],
	include_directories : inc,
	dependencies : [libbpf_dep, libelf, libz, thread_dep],
	link_with : libbpf,
	install : true
)
