# Stage 1: Build the Rust Application
FROM rust:1.71 as builder

# Set the working directory
WORKDIR /app

# Copy only the dependency manifests and lock file
COPY Cargo.toml Cargo.lock ./

# Build the dependencies
RUN cargo build --release

# Copy the source code
COPY src ./src

# Build the application
RUN cargo build --release

# Stage 2: Create the Final Image
FROM debian:buster-slim

# Install system dependencies (if needed)
RUN apt-get update && \
    apt-get install -y libssl-dev

# Set the working directory
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/complete-restful-api-in-rust .


# Expose the port the application will run on
EXPOSE 8000

# Command to run the application
CMD ["./complete-restful-api-in-rust"]
