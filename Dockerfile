# Stage 1: Dependency Preparation
FROM messense/rust-musl-cross:x86_64-musl as chef
ENV SQLX_OFFLINE=true
RUN cargo install cargo-chef
WORKDIR /complete-restful-api-in-rust

# Install OpenSSL and pkg-config
RUN apt-get update && apt-get install -y libssl-dev pkg-config

# Stage 2: Dependency Caching
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Build Application and SQLx Migrations
FROM chef AS builder
COPY --from=planner /complete-restful-api-in-rust/recipe.json recipe.json

RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json

COPY . .

RUN cargo build --release --target x86_64-unknown-linux-musl

# Stage 4: Create Minimal Image
FROM scratch
COPY --from=builder /complete-restful-api-in-rust/target/x86_64-unknown-linux-musl/release/complete-restful-api-in-rust /complete-restful-api-in-rust
EXPOSE 8000
ENTRYPOINT ["/complete-restful-api-in-rust"]