dev:
	docker-compose up -d
	
dev-down:
	docker-compose down

migrate-up:
	sqlx migrate run

migrate-down:
	sqlx migrate revert

start-server:
	cargo watch -q -c -w src/ -x run

install:
	cargo add actix-web
	cargo add actix-cors
	cargo add serde_json
	cargo add serde --features derive
	cargo add chrono --features serde
	cargo add env_logger
	cargo add dotenv
	cargo add uuid --features "serde v4"
	cargo add sqlx --features "runtime-async-std-native-tls postgres chrono uuid"
	cargo add jsonwebtoken
	cargo add argon2
	cargo add rand_core --features "std"
	# HotReload
	cargo install cargo-watch
	# SQLX-CLI
	cargo install sqlx-cli --no-default-features --features postgres
	# Deploy
	sudo apt-get update
	sudo apt-get install docker.io
	sudo apt-get install docker-compose