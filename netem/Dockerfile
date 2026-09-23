# The netem harness's image: the toolchain that builds the node, plus tc, ping,
# pkill and iptables to drive it. See README.md.
FROM rust:1.88-slim
RUN apt-get update -qq \
 && apt-get install -y -qq -o Acquire::Retries=5 build-essential iproute2 iputils-ping procps iptables >/dev/null \
 && rm -rf /var/lib/apt/lists/*
