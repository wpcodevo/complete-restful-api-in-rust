#!/bin/sh

# Function to install sqlx-cli and apply migrations
install_and_apply_migrations() {
    echo "Installing sqlx-cli..."
    cargo install sqlx-cli --no-default-features --features postgres
    echo "sqlx-cli installed!"
    
    echo "Applying migrations..."
    sqlx migrate run
    echo "Migrations applied!"
}

# Determine the action based on the argument passed to the script
if [ "$1" = "api-start" ]; then
    wait_for_db
    install_and_apply_migrations
    shift
    exec "$@"
else
    exec "$@"
fi