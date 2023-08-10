FROM rust:1.71 as builder

RUN USER=root cargo new --bin complete-restful-api-in-rust
WORKDIR /complete-restful-api-in-rust
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --lock
RUN rm src/*.rs

COPY . .

RUN rm ./target/release/deps/complete-restful-api-in-rust*
RUN cargo build --release


FROM debian:buster-slim
ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8000

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /complete-restful-api-in-rust/target/release/complete-restful-api-in-rust ${APP}/complete-restful-api-in-rust

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./complete-restful-api-in-rust"]