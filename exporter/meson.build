# Build BPF code
exporter_bpf2go = custom_target('exporter_bpf2go',
	input : ['exporter.bpf.c'],
	output : 'exporter_bpfel.go',
	command : [bpf2go, '-cc', 'clang', '-cflags', '-O2 -g -Wall ' + '-I' + meson.current_source_dir() / '../src/include',
				'-target', 'bpfel',
				'exporter', '@INPUT@', '--', clang_includes],
	depends : [],
	depend_files : [],
	env: {'GOPACKAGE': 'main'},
	build_by_default : true
)

exporter_go = custom_target('exporter_go',
	input: ['exporter.go', exporter_bpf2go, 'exporter.bpf.c'],
	output: 'exporter',
	command: ['sh', '-c',
		'''
		cp "@CURRENT_SOURCE_DIR@/exporter.go" "@0@/exporter/" &&
		cp "@CURRENT_SOURCE_DIR@/go.sum" "@0@/exporter/" &&
		cp "@CURRENT_SOURCE_DIR@/go.mod" "@0@/exporter/" &&
		cp "@0@/exporter_bpfel.go" "@0@/exporter/" &&
		cp "@0@/exporter_bpfel.o" "@0@/exporter/" &&
		cd "@0@/exporter" &&
		go build -o "@0@/@OUTPUT@" .
		'''.format(meson.project_build_root())],
	depends: [exporter_bpf2go],
	build_by_default: true
)
