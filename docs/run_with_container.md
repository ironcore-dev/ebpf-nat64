# Running the program with container image
A docker file is provided to build the program and run it in a container. You can build the container image or use the pre-build package. To run the container image, you first need to prepare a configuration file for the program. The configuration file is a text file with the following format:

```
addr_port_pool 5.5.5.5:10000-30000
north_interface internet-iface
south_interface intranet-iface
log_level error
```

The default path for the configuration file is `/etc/nat64_config.conf`. You can also specify the path to the configuration file by setting the `NAT64_CONF_FILE` environment variable when you start the container. Meanwhile, it is needed to mount the configuration file to the container when you start it.

## Naively running the program with container image
Natively running the nat64 container means that the container is given the permission to access host's network namespace. It is the simplest way to hook this program to the host's networking interfaces facing internet and intranet.

For example, you can run the following command to start the container:

```
sudo REGISTRY_AUTH_FILE=$HOME/.config/containers/auth.json podman run --rm --privileged -it --network host -v /sys/fs/bpf:/sys/fs/bpf  -v /sys/kernel/debug:/sys/kernel/debug -v /etc/nat64_config.conf:/etc/nat64_config.conf  ghcr.io/ironcore-dev/ebpf-nat64:sha-5ff61a0
```

or
```
sudo podman run --rm --privileged -it --network host -v /sys/fs/bpf:/sys/fs/bpf  -v /sys/kernel/debug:/sys/kernel/debug -v /etc/nat64_config.conf:/etc/nat64_config.conf  ghcr.io/ironcore-dev/ebpf-nat64:sha-5ff61a0
```

## Running the program with container image in a prepared network namespace
Of course, you can also run the program in a prepared network namespace. By using veth pairs and appropriate routes, you can minimize the impact of the program on the host's network namespace. For example, assuming that you have a namespace prepared and its name is `ns-router`, you can run the following command to start the container. Note that, since it is still a private project, you need to configure the registry authentication file to pull the container image.

```
sudo REGISTRY_AUTH_FILE=$HOME/.config/containers/auth.json podman run --rm --privileged -it  --network ns:/run/netns/ns-router -v /sys/fs/bpf:/sys/fs/bpf  -v /sys/kernel/debug:/sys/kernel/debug -v /etc/nat64_config.conf:/etc/nat64_config.conf  ghcr.io/ironcore-dev/ebpf-nat64:sha-5ff61a0
```


if you build the container image by yourself or once the container image is pushed to the public registry, you can use the following command to start the container:
```
sudo podman run --rm --privileged -it  --network ns:/run/netns/ns-router -v /sys/fs/bpf:/sys/fs/bpf  -v /sys/kernel/debug:/sys/kernel/debug -v /etc/nat64_config.conf:/etc/nat64_config.conf  ghcr.io/ironcore-dev/ebpf-nat64:sha-5ff61a0
```


