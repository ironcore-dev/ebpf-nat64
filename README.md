# Overview
This is a NAT64 implementation using eBPF, which runs on one data center router. It translates outgoing IPv6 packets targeting the special IPv6 prefixed address (64::ff9b::/64) to IPv4 packets and vice versa.

# Getting Started
In order to compile and run the program, you need to install the dependencies by running:
```
sudo apt install meson ninja-build clang libbpf-dev linux-headers-$(uname -r)
```

After installing the dependencies, you can compile and run the program by running the following commands:
```
git submodule update --init --recursive
meson build
ninja -C build
```
It is going to generate a `build` directory containing the compiled program for both execution and testing.


To execute the program, you need to specify the address and port pool for the NAT64 prefix. You also need to specify the interfaces to run the program. Normally, the interfaces are the physical interfaces of the router that connect to the Internet and the private network. For example, if you want to attach the program to the interfaces `enp59s0f0np0` and `enp59s0f1np1`, and use the exposed IPv4 address 5.5.5.5 for the NAT64 address and the port range 10000-30000 for the translated ports, you can run the following command:
```
sudo ./build/src/ebpf_nat64 --addr-port-pool 5.5.5.5:10000-30000 --interface enp59s0f0np0,enp59s0f1np1 --log-level [error/warning/info/debug]
```

Press `Ctrl-C` to terminate the program.


