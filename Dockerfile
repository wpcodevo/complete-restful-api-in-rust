# Use the Rust musl-builder image for building
FROM ekidd/rust-musl-builder:latest as builder

WORKDIR /usr/src/app

# Copy and build dependencies
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

# Copy the source code and build the application
COPY . .
RUN cargo build --release

# Stage 2: Create the Minimal Production Image
FROM alpine:latest

ARG APP=/usr/src/app

EXPOSE 8000

ENV TZ=Etc/UTC \
    APP_USER=appuser

# Create and set the user
RUN addgroup -S $APP_USER \
    && adduser -S -g $APP_USER $APP_USER

# Install necessary packages and certificates
RUN apk update \
    && apk add --no-cache ca-certificates tzdata \
    && rm -rf /var/cache/apk/*

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/complete-restful-api-in-rust ${APP}/complete-restful-api-in-rust

# Set ownership and working directory
RUN chown -R $APP_USER:$APP_USER ${APP}
USER $APP_USER
WORKDIR ${APP}

# Run the application
CMD ["./complete-restful-api-in-rust"]
