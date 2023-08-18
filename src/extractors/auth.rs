use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::{ErrorForbidden, ErrorInternalServerError, ErrorUnauthorized};
use actix_web::{http, web, HttpMessage};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::task::{Context, Poll};

use crate::db::UserExt;
use crate::error::{ErrorMessage, ErrorResponse, HttpError};
use crate::models::UserRole;
use crate::{utils, AppState};

pub struct RequireAuth;

impl<S> Transform<S, ServiceRequest> for RequireAuth
where
    S: Service<
        ServiceRequest,
        Response = ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
    >,
    S::Future: 'static,
{
    type Response = ServiceResponse<actix_web::body::BoxBody>;
    type Error = actix_web::Error;
    type Transform = AuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware {
            service,
            allowed_roles: vec![UserRole::User, UserRole::Moderator, UserRole::Admin],
        }))
    }
}

pub struct RequireOnlyAdmin;

impl<S> Transform<S, ServiceRequest> for RequireOnlyAdmin
where
    S: Service<
        ServiceRequest,
        Response = ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
    >,
    S::Future: 'static,
{
    type Response = ServiceResponse<actix_web::body::BoxBody>;
    type Error = actix_web::Error;
    type Transform = AuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware {
            service,
            allowed_roles: vec![UserRole::Admin],
        }))
    }
}

pub struct AuthMiddleware<S> {
    service: S,
    allowed_roles: Vec<UserRole>,
}

impl<S> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<
        ServiceRequest,
        Response = ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
    >,
    S::Future: 'static,
{
    type Response = ServiceResponse<actix_web::body::BoxBody>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, actix_web::Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
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
                message: ErrorMessage::TokenNotProvided.to_string(),
            };
            return Box::pin(ready(Err(ErrorUnauthorized(json_error))));
        }

        let app_state = req.app_data::<web::Data<AppState>>().unwrap();
        let user_id = match utils::token::decode_token(
            &token.unwrap(),
            app_state.env.jwt_secret.as_bytes(),
        ) {
            Ok(id) => id,
            Err(e) => {
                return Box::pin(ready(Err(ErrorUnauthorized(ErrorResponse {
                    status: "fail".to_string(),
                    message: e.message,
                }))))
            }
        };

        let user_id = uuid::Uuid::parse_str(user_id.as_str()).unwrap();
        req.extensions_mut().insert::<uuid::Uuid>(user_id);

        let cloned_app_state = app_state.clone();
        let allowed_roles = self.allowed_roles.clone();
        let future = self.service.call(req);

        Box::pin(async move {
            let result = cloned_app_state
                .db_client
                .get_user(Some(user_id.clone()), None, None)
                .await
                .map_err(|e| ErrorInternalServerError(HttpError::server_error(e.to_string())))?;

            let user = result.ok_or(ErrorUnauthorized(ErrorResponse {
                status: "fail".to_string(),
                message: ErrorMessage::UserNoLongerExist.to_string(),
            }))?;

            // Check if user's role matches the required role
            if allowed_roles.contains(&user.role) {
                let response = future.await?;
                // req.extensions_mut().insert::<User>(user);
                Ok(response)
            } else {
                let json_error = ErrorResponse {
                    status: "fail".to_string(),
                    message: ErrorMessage::PermissionDenied.to_string(),
                };
                Err(ErrorForbidden(json_error))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{cookie::Cookie, get, test, App, HttpResponse};
    use sqlx::{Pool, Postgres};

    use crate::{
        db::DBClient,
        extractors::auth::{RequireAuth, RequireOnlyAdmin},
        utils::{password, test_utils::get_test_config, token},
    };

    use super::*;

    #[get("/", wrap = "RequireAuth")]
    async fn handler_with_requireauth() -> HttpResponse {
        HttpResponse::Ok().into()
    }

    #[get("/", wrap = "RequireOnlyAdmin")]
    async fn handler_with_requireonlyadmin() -> HttpResponse {
        HttpResponse::Ok().into()
    }

    #[sqlx::test]
    async fn test_auth_middelware_valid_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool);
        let config = get_test_config();

        let hashed_password = password::hash("password123").unwrap();

        let user = db_client
            .save_user("John", "john@example.com", &hashed_password)
            .await
            .unwrap();

        let token =
            token::create_token(&user.id.to_string(), config.jwt_secret.as_bytes(), 60).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(handler_with_requireauth),
        )
        .await;

        let req = test::TestRequest::default()
            .insert_header((http::header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[sqlx::test]
    async fn test_auth_middelware_valid_token_with_cookie(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool);
        let config = get_test_config();

        let hashed_password = password::hash("password123").unwrap();

        let user = db_client
            .save_user("John", "john@example.com", &hashed_password)
            .await
            .unwrap();

        let token =
            token::create_token(&user.id.to_string(), config.jwt_secret.as_bytes(), 60).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(handler_with_requireauth),
        )
        .await;

        let req = test::TestRequest::default()
            .cookie(Cookie::new("token", token))
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
                .service(handler_with_requireauth),
        )
        .await;

        let req = test::TestRequest::default().to_request();
        let result = test::try_call_service(&app, req).await.err();

        match result {
            Some(err) => {
                let expected_status = http::StatusCode::UNAUTHORIZED;
                let actual_status = err.as_response_error().status_code();

                assert_eq!(actual_status, expected_status);

                let err_response: ErrorResponse = serde_json::from_str(&err.to_string())
                    .expect("Failed to deserialize JSON string");
                let expected_message = ErrorMessage::TokenNotProvided.to_string();
                assert_eq!(err_response.message, expected_message);
            }
            None => {
                panic!("Service call succeeded, but an error was expected.");
            }
        }
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
                .service(handler_with_requireauth),
        )
        .await;

        let req = test::TestRequest::default()
            .insert_header((
                http::header::AUTHORIZATION,
                format!("Bearer {}", "invalid_token"),
            ))
            .to_request();

        let result = test::try_call_service(&app, req).await.err();

        match result {
            Some(err) => {
                let expected_status = http::StatusCode::UNAUTHORIZED;
                let actual_status = err.as_response_error().status_code();

                assert_eq!(actual_status, expected_status);

                let err_response: ErrorResponse = serde_json::from_str(&err.to_string())
                    .expect("Failed to deserialize JSON string");
                let expected_message = ErrorMessage::InvalidToken.to_string();
                assert_eq!(err_response.message, expected_message);
            }
            None => {
                panic!("Service call succeeded, but an error was expected.");
            }
        }
    }

    #[sqlx::test]
    async fn test_auth_middleware_access_admin_only_endpoint_fail(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool);
        let config = get_test_config();

        let hashed_password = password::hash("password123").unwrap();

        let user = db_client
            .save_user("John", "john@example.com", &hashed_password)
            .await
            .unwrap();

        let token =
            token::create_token(&user.id.to_string(), config.jwt_secret.as_bytes(), 60).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(handler_with_requireonlyadmin),
        )
        .await;

        let req = test::TestRequest::default()
            .insert_header((http::header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();

        let result = test::try_call_service(&app, req).await.err();

        match result {
            Some(err) => {
                let expected_status = http::StatusCode::FORBIDDEN;
                let actual_status = err.as_response_error().status_code();

                assert_eq!(actual_status, expected_status);

                let err_response: ErrorResponse = serde_json::from_str(&err.to_string())
                    .expect("Failed to deserialize JSON string");
                let expected_message = ErrorMessage::PermissionDenied.to_string();
                assert_eq!(err_response.message, expected_message);
            }
            None => {
                panic!("Service call succeeded, but an error was expected.");
            }
        }
    }

    #[sqlx::test]
    async fn test_auth_middleware_access_admin_only_endpoint_success(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let hashed_password = password::hash("password123").unwrap();
        let user = db_client
            .save_admin_user("John Doe", "johndoe@gmail.com", &hashed_password)
            .await
            .unwrap();

        let token =
            token::create_token(&user.id.to_string(), config.jwt_secret.as_bytes(), 60).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(handler_with_requireonlyadmin),
        )
        .await;

        let req = test::TestRequest::default()
            .insert_header((http::header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }
}
