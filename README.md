# eBPF NAT64

This is a simple NAT64 implementation using eBPF, which runs on one data center router. It translates IPv6 packets to IPv4 packets and vice versa.

## Compile and run

```
git submodule update --init --recursive
meson build
ninja -C build
sudo ./build/src/ebpf_nat64 --addr-port-pool 192.168.9.1:100-120 --interface enp59s0f0np0,enp59s0f1np1
```
