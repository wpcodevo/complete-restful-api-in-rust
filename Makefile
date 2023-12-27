vps-commands:
	apt-get install docker
	apt-get install docker-compose

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
	cargo add async-trait
	cargo add serde -F derive
	cargo add chrono -F serde
	cargo add futures-util
	cargo add env_logger
	cargo add dotenv
	cargo add uuid -F "serde v4"
	cargo add sqlx -F "tls-native-tls runtime-async-std postgres chrono uuid"
	cargo add jsonwebtoken
	cargo add argon2
	cargo add openssl-probe
	cargo add validator -F derive
	cargo add utoipa -F "chrono actix_extras"
	cargo add utoipa-rapidoc -F actix-web
	cargo add utoipa-redoc -F actix-web
	cargo add utoipa-swagger-ui -F actix-web
	# HotReload
	cargo install cargo-watch
	# SQLX-CLI
	cargo install sqlx-cli --no-default-features --features postgres
	# Deploy
	sudo apt-get update
	sudo apt-get install docker.io
	sudo apt-get install docker-compose