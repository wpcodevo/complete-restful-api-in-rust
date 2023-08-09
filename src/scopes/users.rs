use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Scope};

use crate::{
    db::UserExt,
    dtos::{FilterUserDto, UserData, UserResponseDto},
    error::{ErrorMessage, HttpError},
    extractors::authentication_token,
    AppState,
};

pub fn users_scope() -> Scope {
    web::scope("/api/users").route("/me", web::get().to(get_me))
}

async fn get_me(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    _: authentication_token::AuthMiddleware,
) -> Result<HttpResponse, HttpError> {
    let ext = req.extensions();
    let user_id = ext.get::<uuid::Uuid>().unwrap();

    let result = app_state
        .db_client
        .get_user(Some(*user_id), None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::unauthorized(ErrorMessage::UserNoLongerExist))?;

    Ok(HttpResponse::Ok().json(UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: FilterUserDto::filter(&user),
        },
    }))
}

#[cfg(test)]
mod tests {
    use actix_web::{http, test, App};
    use sqlx::{Pool, Postgres};

    use crate::{
        db::DBClient,
        utils::{
            test_utils::{get_test_config, init_test_users},
            token,
        },
    };

    use super::*;

    #[sqlx::test]
    async fn test_get_me_with_valid_token(pool: Pool<Postgres>) {
        let (user_id, _, _) = init_test_users(&pool).await;
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let token =
            token::create_token(&user_id.to_string(), config.jwt_secret.as_bytes(), 60).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/users").route("/me", web::get().to(get_me))),
        )
        .await;

        let req = test::TestRequest::get()
            .insert_header((http::header::AUTHORIZATION, format!("Bearer {}", token)))
            .uri("/api/users/me")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let body = test::read_body(resp).await;

        let user_response: UserResponseDto =
            serde_json::from_slice(&body).expect("Failed to deserialize user response from JSON");
        let user = user_response.data.user;

        assert_eq!(user_id.to_string(), user.id);
    }

    #[sqlx::test]
    async fn test_get_me_with_ivalid_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/users").route("/me", web::get().to(get_me))),
        )
        .await;

        let req = test::TestRequest::get()
            .insert_header((
                http::header::AUTHORIZATION,
                format!("Bearer {}", "invlaid_token"),
            ))
            .uri("/api/users/me")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let body = test::read_body(resp).await;
        let expected_message = "Authentication token is invalid or expired";

        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actual_message = body_json["message"].as_str().unwrap();

        assert_eq!(actual_message, expected_message);
    }

    #[sqlx::test]
    async fn test_get_me_with_missing_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/users").route("/me", web::get().to(get_me))),
        )
        .await;

        let req = test::TestRequest::get().uri("/api/users/me").to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let body = test::read_body(resp).await;
        let expected_message = "You are not logged in, please provide token";

        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actual_message = body_json["message"].as_str().unwrap();

        assert_eq!(actual_message, expected_message);
    }

    #[sqlx::test]
    async fn test_get_me_with_expired_token(pool: Pool<Postgres>) {
        let (user_id, _, _) = init_test_users(&pool).await;
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let expired_token =
            token::create_token(&user_id.to_string(), config.jwt_secret.as_bytes(), -60).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/users").route("/me", web::get().to(get_me))),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/users/me")
            .insert_header((
                http::header::AUTHORIZATION,
                format!("Bearer {}", expired_token),
            ))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let body = test::read_body(resp).await;
        let expected_message = "Authentication token is invalid or expired";

        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actual_message = body_json["message"].as_str().unwrap();

        assert_eq!(actual_message, expected_message);
    }
}
