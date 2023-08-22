use crate::models::UserRole;
use async_trait::async_trait;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::models::User;

#[derive(Debug, Clone)]
pub struct DBClient {
    pool: Pool<Postgres>,
}

impl DBClient {
    pub fn new(pool: Pool<Postgres>) -> Self {
        DBClient { pool }
    }
}

#[async_trait]
pub trait UserExt {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error>;
    async fn get_users(&self, page: u32, limit: usize) -> Result<Vec<User>, sqlx::Error>;
    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
    ) -> Result<User, sqlx::Error>;
    async fn save_admin_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
    ) -> Result<User, sqlx::Error>;
}

#[async_trait]
impl UserExt for DBClient {
    async fn get_user(
        &self,
        user_id: Option<uuid::Uuid>,
        name: Option<&str>,
        email: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error> {
        let mut user: Option<User> = None;

        if let Some(user_id) = user_id {
            user = sqlx::query_as!(User, r#"SELECT id,name, email, password, photo,verified,created_at,updated_at,role as "role: UserRole" FROM users WHERE id = $1"#, user_id)
                .fetch_optional(&self.pool)
                .await?;
        } else if let Some(name) = name {
            user = sqlx::query_as!(User, r#"SELECT id,name, email, password, photo,verified,created_at,updated_at,role as "role: UserRole" FROM users WHERE name = $1"#, name)
                .fetch_optional(&self.pool)
                .await?;
        } else if let Some(email) = email {
            user = sqlx::query_as!(User, r#"SELECT id,name, email, password, photo,verified,created_at,updated_at,role as "role: UserRole" FROM users WHERE email = $1"#, email)
                .fetch_optional(&self.pool)
                .await?;
        }

        Ok(user)
    }

    async fn get_users(&self, page: u32, limit: usize) -> Result<Vec<User>, sqlx::Error> {
        let offset = (page - 1) * limit as u32;

        let users = sqlx::query_as!(
            User,
            r#"SELECT id,name, email, password, photo,verified,created_at,updated_at,role as "role: UserRole" FROM users
            LIMIT $1 OFFSET $2"#,
            limit as i64,
            offset as i64
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id,name, email, password, photo,verified,created_at,updated_at,role as "role: UserRole""#,
            name.into(),
            email.into(),
            password.into()
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn save_admin_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id,name, email, password, photo,verified,created_at,updated_at,role as "role: UserRole""#,
            name.into(),
            email.into(),
            password.into(),
            UserRole::Admin as UserRole
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }
}