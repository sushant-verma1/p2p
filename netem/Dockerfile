# The netem harness's image: the toolchain that builds the node, plus tc, ping,
# pkill and iptables to drive it, and python3 for dht.py, which runs inside it. See README.md.
FROM rust:1.88-slim
RUN apt-get update -qq \
 && apt-get install -y -qq -o Acquire::Retries=5 build-essential git iproute2 iputils-ping procps iptables python3 >/dev/null \
 && rm -rf /var/lib/apt/lists/*

# The same five commands CI runs, available in the Linux environment that
# drives the privileged netem harness.
RUN rustup component add rustfmt clippy \
 && cargo install --locked cargo-audit@0.22.2 cargo-deny@0.20.2
