use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::{
    config::Config,
    db::{DBClient, UserExt},
};

#[allow(dead_code)]
pub struct TestUser {
    name: &'static str,
    email: &'static str,
    password: &'static str,
}

#[allow(dead_code)]
pub async fn init_test_users(pool: &Pool<Postgres>) -> (Uuid, Uuid, Uuid) {
    let db_client = DBClient::new(pool.clone());

    let users: Vec<TestUser> = vec![
        TestUser {
            name: "John Doe",
            email: "johndoe@gmail.com",
            password: "password1234",
        },
        TestUser {
            name: "Nico Smith",
            email: "nicosmith@gmail.com",
            password: "123justgetit",
        },
        TestUser {
            name: "Michelle Like",
            email: "michellelike@gmail.com",
            password: "mostsecurepass",
        },
    ];

    let mut user_ids = vec![];

    for user_data in users {
        let user = db_client
            .save_user(user_data.name, user_data.email, user_data.password)
            .await
            .unwrap();
        user_ids.push(user.id);
    }

    (
        user_ids[0].clone(),
        user_ids[1].clone(),
        user_ids[2].clone(),
    )
}

#[allow(dead_code)]
pub fn get_test_config() -> Config {
    Config {
        database_url: "".to_string(),
        jwt_secret: "my-jwt-secret".to_string(),
        jwt_maxage: 60,
        port: 8000,
    }
}
