# Usage

## Compiling and running the program
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
sudo ./build/src/ebpf_nat64 --addr-port-pool 5.5.5.5:10000-30000 --north-interface internet-iface --south-interface intranet-iface --log-level [error/warning/info/debug]
```

Press `Ctrl-C` to terminate the program.

## Running the program with Docker image
A docker file is provided to build the program and run it in a container. You can build the docker image or use the pre-build package. To run the docker image, you first need to prepare a configuration file for the program. The configuration file is a text file with the following format:

```
addr_port_pool=5.5.5.5:10000-30000
north_interface=internet-iface
south_interface=intranet-iface
log_level=error
```

The default path for the configuration file is `/etc/nat64_config.conf`. You can also specify the path to the configuration file by setting the `NAT64_CONF_FILE` environment variable when you start the container. Meanwhile, it is needed to mount the configuration file to the container when you start it. For example, you can run the following command to start the container:

```
sudo docker run --rm --privileged -it -v /sys/fs/bpf:/sys/fs/bpf  -v /sys/kernel/debug:/sys/kernel/debug -v /etc/nat64_config.conf:/etc/nat64_config.conf  ghcr.io/ironcore-dev/ebpf-nat64:sha-5ff61a0
```


# Code testing
The code testing is based on the capability of trigging execution of the kernel program without actually attaching it to any network interface. This API is provided by the `bpf_prog_test_run_opts` in the `libbpf` [library](https://libbpf.readthedocs.io/en/latest/api.html).

Run the following command to test the code after compilation:
```
sudo ./build/src/ebpf_nat64_test --addr-port-pool 192.168.9.1:100-120 --log-level error
```
