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

# Find system-installed bpftool
bpftool = find_program('bpftool', required : true)

# Get architecture
arch = run_command('uname', '-m', check: true).stdout().strip()
arch = arch.replace('x86_64', 'x86').replace('aarch64', 'arm64').replace('ppc64le', 'powerpc').replace('mips', 'mips').replace('arm', 'arm').replace('riscv64', 'riscv')

# Generate vmlinux.h at build time
vmlinux_h = custom_target('vmlinux.h',
	output : 'vmlinux.h',
	command : [
		bpftool,
		'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux',
		'format', 'c'
	],
	capture : true,
	build_by_default : true
)

# Compile flags
add_project_arguments('-D__TARGET_ARCH_' + arch, language : 'c')
add_project_arguments('-g', '-Wall', language : 'c')

# Dependencies
libbpf_dep = dependency('libbpf', version : '>=1.3.0', required : true)
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

clang_includes += ['-idirafter', '/usr/include']  # System headers
clang_includes += ['-idirafter', meson.current_build_dir()]  # Generated vmlinux.h


subdir('src')
subdir('exporter')
