use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::{ErrorForbidden, ErrorInternalServerError, ErrorUnauthorized};
use actix_web::{http, web, HttpMessage};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use serde::Serialize;
use std::fmt;
use std::task::{Context, Poll};

use crate::db::UserExt;
use crate::error::{ErrorMessage, HttpError};
use crate::models::UserRole;
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
