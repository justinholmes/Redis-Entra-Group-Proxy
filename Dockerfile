FROM rust:1.87-slim-bookworm as builder
WORKDIR /app

# Install dependencies for building
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Create the final image
FROM debian:bookworm-slim
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/redis-entra-proxy /app/redis-entra-proxy

# Copy the example env file
COPY .env.example /app/.env.example

# Expose the default port
EXPOSE 6388

# Run the application
CMD ["/app/redis-entra-proxy"]
