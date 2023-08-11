# Builder Stage
FROM rust:1.71 as builder
ENV SQLX_OFFLINE=true

# Create a new Rust project
RUN USER=root cargo new --bin complete-restful-api-in-rust
WORKDIR /complete-restful-api-in-rust

# Copy and build dependencies
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --locked
RUN rm src/*.rs

# Copy the source code and build the application
COPY . .
RUN cargo build --release --locked

# Production Stage
FROM debian:buster-slim
ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /complete-restful-api-in-rust/target/release/complete-restful-api-in-rust ${APP}/complete-restful-api-in-rust

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

ENTRYPOINT ["./complete-restful-api-in-rust"]
EXPOSE 8000
