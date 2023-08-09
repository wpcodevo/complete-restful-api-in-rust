# Stage 1: Dependency Preparation
FROM messense/rust-musl-cross:x86_64-musl as chef
ENV SQLX_OFFLINE=true
RUN cargo install cargo-chef
WORKDIR /complete-restful-api-in-rust

# Install OpenSSL and pkg-config for musl-based image
RUN apt-get update && apt-get install -y libssl-dev pkg-config

# Set OpenSSL directory for openssl-sys crate
ENV OPENSSL_DIR=/usr/local/musl

# Stage 2: Dependency Caching
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Build Application and SQLx Migrations
FROM chef AS builder
COPY --from=planner /complete-restful-api-in-rust/recipe.json recipe.json

# Install the appropriate pkg-config wrapper for cross-compilation
RUN apt-get update && apt-get install -y pkg-config-arm-linux-gnueabihf

# Set necessary environment variables for cross-compilation with pkg-config
ENV PKG_CONFIG_DIR=/usr/lib/arm-linux-gnueabihf/pkgconfig
ENV PKG_CONFIG_LIBDIR=/usr/lib/arm-linux-gnueabihf/pkgconfig
ENV PKG_CONFIG_SYSROOT_DIR=/usr/arm-linux-gnueabihf

RUN cargo chef cook --release --target arm-unknown-linux-gnueabihf --recipe-path recipe.json

COPY . .

RUN cargo build --release --target arm-unknown-linux-gnueabihf

# Stage 4: Create Minimal Image
FROM scratch
COPY --from=builder /complete-restful-api-in-rust/target/arm-unknown-linux-gnueabihf/release/complete-restful-api-in-rust /complete-restful-api-in-rust
EXPOSE 8000
ENTRYPOINT ["/complete-restful-api-in-rust"]
