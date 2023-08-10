FROM ekidd/rust-musl-builder:latest as builder

RUN USER=root cargo new --bin complete-restful-api-in-rust
WORKDIR /complete-restful-api-in-rust
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
RUN cargo build --release
RUN rm src/*.rs

ADD . ./

RUN rm ./target/x86_64-unknown-linux-musl/release/deps/complete-restful-api-in-rust*
RUN cargo build --release


FROM alpine:latest

ARG APP=/usr/src/app

EXPOSE 8000

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN addgroup -S $APP_USER \
    && adduser -S -g $APP_USER $APP_USER

RUN apk update \
    && apk add --no-cache ca-certificates tzdata \
    && rm -rf /var/cache/apk/*

COPY --from=builder /home/rust/src/complete-restful-api-in-rust/target/x86_64-unknown-linux-musl/release/complete-restful-api-in-rust ${APP}/complete-restful-api-in-rust

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./complete-restful-api-in-rust"]