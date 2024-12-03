#Cannot run on debian
FROM ubuntu:latest As builder

WORKDIR /app

RUN apt-get update && \
	apt-get install -y build-essential git cmake pkg-config \
					zlib1g-dev libevent-dev \
					libelf-dev llvm \
					clang libc6-dev-i386 \
					meson \
					ninja-build \
					ca-certificates \
					libbpf-dev \
					gcc-multilib


COPY .git .git
COPY .gitmodules .gitmodules

RUN git submodule update --init --recursive

COPY meson.build meson.build
COPY vmlinux/ vmlinux/
COPY src/ src/

RUN meson build && ninja -C build


FROM builder AS runner
RUN cp build/src/ebpf_nat64 /app/ebpf_nat64
RUN rm -rf build

RUN mkdir -p /sys/fs/bpf

COPY <<'EOF' /app/entrypoint.sh
#!/bin/sh
set -e

if ! mount | grep -q "^bpf on /sys/fs/bpf"; then
	mount -t bpf none /sys/fs/bpf
fi

exec /app/ebpf_nat64 "$@"
EOF

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]


FROM builder AS tester
RUN cp build/src/ebpf_nat64_test /app/ebpf_nat64_test
RUN rm -rf build

RUN mkdir -p /sys/fs/bpf

COPY <<'EOF' /app/entrypoint.sh
#!/bin/sh
set -e

if ! mount | grep -q "^bpf on /sys/fs/bpf"; then
	mount -t bpf none /sys/fs/bpf
fi

exec /app/ebpf_nat64_test "$@"
EOF

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh", "--addr-port-pool", "5.5.5.5:1000-2000", "--log-level", "error"	]
