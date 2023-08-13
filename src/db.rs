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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::init_test_users;

    #[sqlx::test]
    async fn test_get_user_by_id(pool: Pool<Postgres>) {
        let (id_one, _, _) = init_test_users(&pool).await;
        let db_client = DBClient::new(pool);

        let user = db_client
            .get_user(Some(id_one), None, None)
            .await
            .unwrap_or_else(|err| panic!("Failed to get user by id: {}", err))
            .expect("User not found");

        assert_eq!(user.id, id_one);
    }

    #[sqlx::test]
    async fn test_get_user_by_name(pool: Pool<Postgres>) {
        init_test_users(&pool).await;
        let db_client = DBClient::new(pool);

        let name_to_find = "Nico Smith";

        let user = db_client
            .get_user(None, Some(name_to_find), None)
            .await
            .unwrap_or_else(|err| panic!("Failed to get user by name: {}", err))
            .expect("User not found");

        assert_eq!(user.name, name_to_find);
    }

    #[sqlx::test]
    async fn test_get_user_by_nonexistent_name(pool: Pool<Postgres>) {
        init_test_users(&pool).await;
        let db_client = DBClient::new(pool);

        let name = "Nonexistent Name";

        let user = db_client
            .get_user(None, Some(name), None)
            .await
            .expect("Failed to get user by name");

        assert!(user.is_none(), "Expected user to be None");
    }

    #[sqlx::test]
    async fn test_get_user_by_email(pool: Pool<Postgres>) {
        init_test_users(&pool).await;
        let db_client = DBClient::new(pool);

        let email = "johndoe@gmail.com";

        let user = db_client
            .get_user(None, None, Some(email))
            .await
            .expect("Failed to get user by email")
            .expect("User not found");

        assert_eq!(user.email, email);
    }

    #[sqlx::test]
    async fn test_get_user_by_nonexistent_email(pool: Pool<Postgres>) {
        init_test_users(&pool).await;
        let db_client = DBClient::new(pool);

        let email = "nonexistent@example.com";

        let user = db_client.get_user(None, None, Some(email)).await.unwrap();

        assert!(user.is_none());
    }

    #[sqlx::test]
    async fn test_get_users(pool: Pool<Postgres>) {
        init_test_users(&pool).await;
        let db_client = DBClient::new(pool);

        let users = db_client.get_users(1, 10).await.unwrap();

        assert_eq!(users.len(), 3);
    }

    #[sqlx::test]
    async fn test_save_user(pool: Pool<Postgres>) {
        init_test_users(&pool).await;
        let db_client = DBClient::new(pool);
        let name = "Peace Jocy";
        let email = "peacejocy@hotmail.com";
        let password = "newPassword";

        db_client.save_user(name, email, password).await.unwrap();

        let user = db_client
            .get_user(None, Some(name), None)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user.email, email);
        assert_eq!(user.name, name);
    }

    #[sqlx::test]
    async fn test_save_user_but_email_is_taken(pool: Pool<Postgres>) {
        init_test_users(&pool).await;
        let db_client = DBClient::new(pool);

        let name = "John Doe";
        let email = "johndoe@gmail.com";
        let password = "randompass123";

        let saved_result = db_client.save_user(name, email, password).await;

        match saved_result {
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                // Unique constraint violation detected, test passes
            }
            _ => {
                assert!(false, "Expected unique constraint violation error");
            }
        }
    }

    #[sqlx::test]
    async fn test_save_user_with_long_name_fails(pool: Pool<Postgres>) {
        init_test_users(&pool).await;
        let db_client = DBClient::new(pool);

        let long_name = "a".repeat(150);
        let email = "email@example.com";
        let password = "newPassword";

        let saved_result = db_client
            .save_user(long_name.as_str(), email, password)
            .await;

        assert!(saved_result.is_err(), "Expected save to fail");
    }
}
