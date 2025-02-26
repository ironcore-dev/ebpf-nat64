project('ebpf-nat64', 'c',
version : '0.1',
default_options : ['warning_level=2', 'c_std=gnu99'])

# Define a specific output directory
output_dir = meson.project_build_root() / 'output/'

# Ensure the output directory exists
run_command('mkdir', '-p', output_dir, check: true)

cc = meson.get_compiler('c')
clang = find_program('clang', required : true)
llvm_strip = find_program('llvm-strip', required : true)
go = find_program('go', required : true)
bpf2go = find_program('bpf2go', required : true)

# Define paths
libbpf_src = meson.current_source_dir() / 'libbpf/src'
bpftool_src = meson.current_source_dir() / 'bpftool/src'
vmlinux_dir = 'vmlinux'

# Get architecture
arch = run_command('uname', '-m', check: true).stdout().strip()
arch = arch.replace('x86_64', 'x86').replace('aarch64', 'arm64').replace('ppc64le', 'powerpc').replace('mips', 'mips').replace('arm', 'arm').replace('riscv64', 'riscv')
vmlinux_header = join_paths(vmlinux_dir, arch, 'vmlinux.h')

# Include directories
inc = include_directories('.', 'libbpf/include/uapi', vmlinux_dir)

# Compile flags
add_project_arguments('-D__TARGET_ARCH_' + arch, language : 'c')
add_project_arguments('-g', '-Wall', language : 'c')

# Dependencies
libbpf_dep = dependency('libbpf', fallback: ['libbpf', 'libbpf_dep'])
libelf = dependency('libelf')
libz = dependency('zlib')
thread_dep = dependency('threads')

# Get Clang's default includes
clang_includes = []
search_start = false
foreach line : run_command(clang, '-v', '-E', '-', check: false, capture: true).stderr().split('\n')
	if search_start
		if line.strip() == 'End of search list.'
			break
		endif
		if line.strip().startswith('/')
			clang_includes += ['-idirafter', line.strip()]
		endif
	elif line.strip() == '#include <...> search starts here:'
		search_start = true
	endif
endforeach

clang_includes += ['-idirafter', meson.current_source_dir() / 'libbpf/include/uapi']  # Add the kernel headers
clang_includes += ['-idirafter', meson.current_source_dir() / 'vmlinux']  # Add the kernel headers


# Build libbpf
libbpf_built = custom_target('libbpf_built',
	output : 'libbpf_built',
	command : [
		'make',
		'-C', libbpf_src,
		'BUILD_STATIC_ONLY=1',
		'OBJDIR=' + output_dir / 'libbpf',
		'DESTDIR=' + output_dir,
		'INCLUDEDIR=', 'LIBDIR=', 'UAPIDIR=',
		'install'
	],
	build_by_default : true
)

libbpf_built_lib= output_dir + 'libbpf.a'
libbpf = custom_target('libbpf',
	input : libbpf_built,
	output : 'libbpf.a',
	command : ['cp', libbpf_built_lib, '@OUTPUT@'],
	build_by_default : true,
	depends : libbpf_built
)

# Build bpftool
bpftool_output_dir = output_dir + 'bpftool/'
run_command('mkdir', '-p', bpftool_output_dir, check: true)

bpftool_build = custom_target('bpftool_build',
	output : 'bpftool_build',
	command : ['make', 'ARCH=', 'CROSS_COMPILE=', 'OUTPUT=' + bpftool_output_dir, '-C', bpftool_src, 'bootstrap'],
	build_by_default : true
)

bpftool_built_binary = bpftool_output_dir + 'bootstrap/bpftool'
bpftool = custom_target('bpftool',
	input : bpftool_build,
	output : 'bpftool',
	command : ['cp', bpftool_built_binary, '@OUTPUT@'],
	build_by_default : true,
	depends : bpftool_build
)

subdir('src')
subdir('exporter')
