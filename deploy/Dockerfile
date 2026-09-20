# Stage 1: Build ULPX binaries
FROM rust:1.98 AS builder
WORKDIR /usr/src/ulpx
COPY . .
RUN cargo build --release --workspace

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /usr/src/ulpx/target/release/ulpx /usr/local/bin/ulpx
COPY --from=builder /usr/src/ulpx/target/release/ulpx-serve /usr/local/bin/ulpx-serve

# Standard local offline store path
ENV ULPX_STORE_PATH=/data/.ulpx_store
ENV ULPX_SERVE_ADDR=0.0.0.0:3000

EXPOSE 3000
VOLUME ["/data"]

CMD ["ulpx-serve"]
