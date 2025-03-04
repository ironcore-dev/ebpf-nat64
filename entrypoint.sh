#!/bin/sh
set -e

if ! mount | grep -q "^bpf on /sys/fs/bpf"; then
	mount -t bpf none /sys/fs/bpf
fi

exec /app/ebpf_nat64 "$@"
