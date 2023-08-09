use core::fmt;
use std::future::{ready, Ready};

use actix_web::error::ErrorUnauthorized;
use actix_web::{dev::Payload, Error as ActixWebError};
use actix_web::{http, web, FromRequest, HttpMessage, HttpRequest};
use serde::Serialize;

use crate::{utils, AppState};

#[derive(Debug, Serialize)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

pub struct AuthMiddleware {
    pub user_id: uuid::Uuid,
}

impl FromRequest for AuthMiddleware {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let data = req.app_data::<web::Data<AppState>>().unwrap();

        let token = req
            .cookie("token")
            .map(|c| c.value().to_string())
            .or_else(|| {
                req.headers()
                    .get(http::header::AUTHORIZATION)
                    .map(|h| h.to_str().unwrap().split_at(7).1.to_string())
            });

        if token.is_none() {
            let json_error = ErrorResponse {
                status: "fail".to_string(),
                message: "You are not logged in, please provide token".to_string(),
            };
            return ready(Err(ErrorUnauthorized(json_error)));
        }

        let user_id =
            match utils::token::decode_token(&token.unwrap(), data.env.jwt_secret.as_bytes()) {
                Ok(id) => id,
                Err(e) => {
                    return ready(Err(ErrorUnauthorized(ErrorResponse {
                        status: "fail".to_string(),
                        message: e.message,
                    })))
                }
            };

        let user_id = uuid::Uuid::parse_str(user_id.as_str()).unwrap();
        req.extensions_mut()
            .insert::<uuid::Uuid>(user_id.to_owned());

        ready(Ok(AuthMiddleware { user_id }))
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{get, test, App, HttpResponse};
    use sqlx::{Pool, Postgres};

    use crate::{
        db::DBClient,
        utils::{test_utils::get_test_config, token},
    };

    use super::*;

    #[get("/")]
    async fn handler(_: AuthMiddleware) -> HttpResponse {
        HttpResponse::Ok().into()
    }

    #[sqlx::test]
    async fn test_auth_middelware_valid_token(pool: Pool<Postgres>) {
        let user_id = uuid::Uuid::new_v4();
        let db_client = DBClient::new(pool);
        let config = get_test_config();

        let token =
            token::create_token(&user_id.to_string(), config.jwt_secret.as_bytes(), 60).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(handler),
        )
        .await;

        let req = test::TestRequest::default()
            .insert_header((http::header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[sqlx::test]
    async fn test_auth_middleware_missing_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool);
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(handler),
        )
        .await;

        let req = test::TestRequest::default().to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let body = test::read_body(resp).await;
        let expected_message = "You are not logged in, please provide token";

        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actual_message = body_json["message"].as_str().unwrap();

        assert_eq!(actual_message, expected_message);
    }

    #[sqlx::test]
    async fn test_auth_middleware_invalid_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool);
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(handler),
        )
        .await;

        let req = test::TestRequest::default()
            .insert_header((
                http::header::AUTHORIZATION,
                format!("Bearer {}", "invalid_token"),
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
