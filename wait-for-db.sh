#!/bin/sh

# Function to wait for the PostgreSQL database to be ready
wait_for_db() {
    echo "Waiting for the database to be ready..."
    until pg_isready -h $POSTGRES_HOST -p $POSTGRES_PORT >/dev/null 2>&1; do
        sleep 1
    done
    echo "Database is ready!"
}

# Function to install sqlx-cli and apply migrations
install_and_apply_migrations() {
    echo "Installing sqlx-cli..."
    cargo install sqlx-cli --no-default-features --features postgres
    echo "sqlx-cli installed!"
    
    echo "Applying migrations..."
    sqlx migrate run
    echo "Migrations applied!"
}

# Print the environment variables
echo "POSTGRES_HOST: $POSTGRES_HOST"
echo "POSTGRES_PORT: $POSTGRES_PORT"
# Add other environment variables as needed

# Determine the action based on the argument passed to the script
if [ "$1" = "api-start" ]; then
    wait_for_db
    install_and_apply_migrations
    shift
    exec "$@"
else
    exec "$@"
fi