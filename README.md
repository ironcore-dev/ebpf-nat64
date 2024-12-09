# Overview
This is a NAT64 implementation using eBPF, which runs on one data center router. It translates outgoing IPv6 packets targeting the special IPv6 prefixed address (64::ff9b::/64) to IPv4 packets and vice versa. Compared with the state-of-the-art implementation, such as [Tundra-nat64](https://github.com/vitlabuda/tundra-nat64), one of the advantages is that, ebpf-nat64 does not just support NAT64 on a single host. It is designed to run on a gateway router and multiplex a NAT64's address by using a pool of transport layer ports.

# Documentation
For more details please refer to documentation folder [docs](./docs).

## Contributing
We`d love to get a feedback from you.
Please report bugs, suggestions or post question by opening a [Github issue](https://github.com/ironcore-dev/ebpf-nat64/issues)

## License
[Apache License 2.0](/LICENSE)



