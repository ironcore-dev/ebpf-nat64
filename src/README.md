# Structure of the code repository
A functional eBPF program consists of two parts: a eBPF kernel program and a userspace program. Usually they are coupled due to the shared data structures and logic interactions, putting them into one root repository but with necessary separation of files can make the repository more organized and easier to understand.

The repository of this project is organized as follows:

- `src/`: the root directory of the code repository, containing the source code of the eBPF kernel program and the userspace program. In this directory, `ebpf_nat64.bpf.c` is the main source code for the eBPF kernel program. It is the main entry point of processing an incoming packet in the XDP path. `ebpf_nat64.c` is the main source code for the userspace program. It is responsible of loading the kernel program and interacting with it in terms of NAT64 address and port management.
- `src/ebpf_lib/`: the directory containing the header files for the eBPF kernel program, `ebpf_nat64.bpf.c`. These header files define maps and static functions that can be called by the kernel part. The rest of the source files (.c files) under this root directory are the implementation of functions for the userspace program, `ebpf_nat64.c`.
- `src/include/`: the directory contains the header files defined shared data structures between the kernel part and the userspace part. `src/include/user_app/` contains the header files particularly defined for and exclusively used by the userspace program, `ebpf_nat64.c`.
- `src/test/`: the test directory contains the code for the testing program, `test_ebpf_nat64.c`.


