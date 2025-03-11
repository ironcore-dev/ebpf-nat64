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



FROM ubuntu:latest AS runner
WORKDIR /app

RUN apt-get update && apt-get install -y \
	iproute2 \
	iputils-ping \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/build/src/ebpf_nat64 /app/ebpf_nat64

RUN mkdir -p /sys/fs/bpf

COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]



FROM ubuntu:latest AS tester
WORKDIR /app

RUN apt-get update && apt-get install -y \
	libelf-dev \
	&& rm -rf /var/lib/apt/lists/*

copy --from=builder /app/build/src/ebpf_nat64_test /app/ebpf_nat64_test
RUN rm -rf build

RUN mkdir -p /sys/fs/bpf

COPY entrypoint.sh /app/entrypoint.sh

RUN sed -i 's/ebpf_nat64/ebpf_nat64_test/' /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh", "--addr-port-pool", "5.5.5.5:1000-2000", "--log-level", "error"	]
