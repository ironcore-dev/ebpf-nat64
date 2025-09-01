#Cannot run on debian
FROM ubuntu:25.04 AS builder

ARG TARGETARCH

WORKDIR /app

RUN apt-get update && \
	apt-get install -y build-essential git cmake pkg-config \
					zlib1g-dev libevent-dev \
					libelf-dev llvm \
					clang libc6-dev-i386 \
					meson curl \
					ninja-build \
					ca-certificates \
					libbpf-dev \
					gcc-multilib \
					bpftool


RUN curl -Ls https://golang.org/dl/go1.23.1.linux-${TARGETARCH}.tar.gz | tar xz -C /usr/local/
ENV PATH="${PATH}:/usr/local/go/bin"

COPY .git .git
COPY .gitmodules .gitmodules

RUN git submodule update --init --recursive
RUN GOBIN=/usr/local/bin go install github.com/cilium/ebpf/cmd/bpf2go@latest

COPY meson.build meson.build
COPY src/ src/
COPY exporter exporter/


RUN meson build && ninja -C build



FROM ubuntu:25.04 AS runner
WORKDIR /app

RUN apt-get update && apt-get install -y \
	iproute2 \
	iputils-ping \
	libbpf-dev \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/build/src/ebpf_nat64 /app/ebpf_nat64
COPY --from=builder /app/build/exporter/exporter /app/nat64_exporter

RUN mkdir -p /sys/fs/bpf

COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]



FROM ubuntu:25.04 AS tester
WORKDIR /app

RUN apt-get update && apt-get install -y \
	libbpf-dev \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/build/src/ebpf_nat64_test /app/ebpf_nat64_test
RUN rm -rf build

RUN mkdir -p /sys/fs/bpf

COPY entrypoint.sh /app/entrypoint.sh

RUN sed -i 's/ebpf_nat64/ebpf_nat64_test/' /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh", "--addr-port-pool", "5.5.5.5:1000-2000", "--log-level", "error", "--test-mode"]
