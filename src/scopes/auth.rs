use actix_web::{
    cookie::time::Duration as ActixWebDuration, cookie::Cookie, web, HttpResponse, Responder, Scope,
};
use serde_json::json;
use validator::Validate;

use crate::{
    db::UserExt,
    dtos::{
        FilterUserDto, LoginUserDto, RegisterUserDto, UserData, UserLoginResponseDto,
        UserResponseDto,
    },
    error::{ErrorMessage, HttpError},
    extractors::auth::RequireAuth,
    models::UserRole,
    utils::{password, token},
    AppState,
};

pub fn auth_scope() -> Scope {
    web::scope("/api/auth")
        .route("/register", web::post().to(register))
        .route("/login", web::post().to(login))
        .route(
            "/logout",
            web::post().to(logout).wrap(RequireAuth::allowed_roles(vec![
                UserRole::User,
                UserRole::Moderator,
                UserRole::Admin,
            ])),
        )
}

#[utoipa::path(
    post,
    path = "/api/auth/register",
    tag = "Register Account Endpoint",
    request_body(content = RegisterUserDto, description = "Credentials to create account", example = json!({"email": "johndoe@example.com","name": "John Doe","password": "password123","passwordConfirm": "password123"})),
    responses(
        (status=201, description= "Account created successfully", body= UserResponseDto ),
        (status=400, description= "Validation Errors", body= Response),
        (status=409, description= "User with email already exists", body= Response),
        (status=500, description= "Internal Server Error", body= Response ),
    )
)]
pub async fn register(
    app_state: web::Data<AppState>,
    body: web::Json<RegisterUserDto>,
) -> Result<HttpResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let hashed_password =
        password::hash(&body.password).map_err(|e| HttpError::server_error(e.to_string()))?;

    let result = app_state
        .db_client
        .save_user(&body.name, &body.email, &hashed_password)
        .await;

    match result {
        Ok(user) => Ok(HttpResponse::Created().json(UserResponseDto {
            status: "success".to_string(),
            data: UserData {
                user: FilterUserDto::filter_user(&user),
            },
        })),
        Err(sqlx::Error::Database(db_err)) => {
            if db_err.is_unique_violation() {
                Err(HttpError::unique_constraint_voilation(
                    ErrorMessage::EmailExist,
                ))
            } else {
                Err(HttpError::server_error(db_err.to_string()))
            }
        }
        Err(e) => Err(HttpError::server_error(e.to_string())),
    }
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "Login Endpoint",
    request_body(content = LoginUserDto, description = "Credentials to log in to your account", example = json!({"email": "johndoe@example.com","password": "password123"})),
    responses(
        (status=200, description= "Login successfull", body= UserLoginResponseDto ),
        (status=400, description= "Validation Errors", body= Response ),
        (status=500, description= "Internal Server Error", body= Response ),
    )
)]
pub async fn login(
    app_state: web::Data<AppState>,
    body: web::Json<LoginUserDto>,
) -> Result<HttpResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, Some(&body.email))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::unauthorized(ErrorMessage::WrongCredentials))?;

    let password_matches = password::compare(&body.password, &user.password)
        .map_err(|_| HttpError::unauthorized(ErrorMessage::WrongCredentials))?;

    if password_matches {
        let token = token::create_token(
            &user.id.to_string(),
            &app_state.env.jwt_secret.as_bytes(),
            app_state.env.jwt_maxage,
        )
        .map_err(|e| HttpError::server_error(e.to_string()))?;
        let cookie = Cookie::build("token", token.to_owned())
            .path("/")
            .max_age(ActixWebDuration::new(60 * &app_state.env.jwt_maxage, 0))
            .http_only(true)
            .finish();

        Ok(HttpResponse::Ok()
            .cookie(cookie)
            .json(UserLoginResponseDto {
                status: "success".to_string(),
                token,
            }))
    } else {
        Err(HttpError::unauthorized(ErrorMessage::WrongCredentials))
    }
}

#[utoipa::path(
    post,
    path = "/api/auth/logout",
    tag = "Logout Endpoint",
    responses(
        (status=200, description= "Logout successfull" ),
        (status=400, description= "Validation Errors", body= Response ),
        (status=401, description= "Unauthorize Error", body= Response),
        (status=500, description= "Internal Server Error", body= Response ),
    ),
    security(
       ("token" = [])
   )
)]
pub async fn logout() -> impl Responder {
    let cookie = Cookie::build("token", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(json!({"status": "success"}))
}

#[cfg(test)]
mod tests {
    use actix_web::{http, test, App};
    use sqlx::{Pool, Postgres};

    use crate::{db::DBClient, error::ErrorResponse, utils::test_utils::get_test_config};

    use super::*;

    #[sqlx::test]
    async fn test_register_valid_user(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route("/register", web::post().to(register))),
        )
        .await;

        let name = "John Doe".to_string();
        let email = "john@example.com".to_string();
        let password = "password123".to_string();
        let password_confirm = "password123".to_string();
        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(RegisterUserDto {
                name: name.clone(),
                email: email.clone(),
                password: password.clone(),
                password_confirm: password_confirm.clone(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::CREATED);

        let body = test::read_body(resp).await;
        let user_response: UserResponseDto =
            serde_json::from_slice(&body).expect("Failed to deserialize user response from JSON");
        let user = &user_response.data.user;

        assert_eq!(user.name, name);
        assert_eq!(user.email, email);
    }

    #[sqlx::test]
    async fn test_register_duplicate_email(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        db_client
            .save_user("John", "john@example.com", "password123")
            .await
            .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route("/register", web::post().to(register))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(RegisterUserDto {
                name: "John Doe".to_string(),
                email: "john@example.com".to_string(),
                password: "password123".to_string(),
                password_confirm: "password123".to_string(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::CONFLICT);

        let body = test::read_body(resp).await;
        let expected_message = "An User with this email already exists";

        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actual_message = body_json["message"].as_str().unwrap();

        assert_eq!(actual_message, expected_message);
    }

    #[sqlx::test]
    async fn test_login_valid_credentials(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let hashed_password = password::hash("password123").unwrap();

        db_client
            .save_user("John", "john@example.com", &hashed_password)
            .await
            .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route("/login", web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(LoginUserDto {
                email: "john@example.com".to_string(),
                password: "password123".to_string(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let body = test::read_body(resp).await;

        let body_json: UserLoginResponseDto = serde_json::from_slice(&body).unwrap();

        assert!(!body_json.token.is_empty());
    }

    #[sqlx::test]
    async fn test_login_valid_credentials_receive_cookie(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let hashed_password = password::hash("password123").unwrap();

        db_client
            .save_user("John", "john@example.com", &hashed_password)
            .await
            .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route("/login", web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(LoginUserDto {
                email: "john@example.com".to_string(),
                password: "password123".to_string(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;

        let token_cookie = resp
            .response()
            .cookies()
            .find(|cookie| cookie.name() == "token");

        assert!(token_cookie.is_some());
    }

    #[sqlx::test]
    async fn test_login_with_nonexistent_user_credentials(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route("/login", web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(LoginUserDto {
                email: "john@example.com".to_string(),
                password: "password123".to_string(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let body = test::read_body(resp).await;
        let expected_message = "Email or password is wrong";

        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actual_message = body_json["message"].as_str().unwrap();

        assert_eq!(actual_message, expected_message);
    }

    #[sqlx::test]
    async fn test_login_with_wrong_email(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let hashed_password = password::hash("password123").unwrap();
        db_client
            .save_user("John", "john@example.com", &hashed_password)
            .await
            .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route("/login", web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(LoginUserDto {
                email: "wrongemail@example.com".to_string(),
                password: "password123".to_string(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let body = test::read_body(resp).await;
        let expected_message = "Email or password is wrong";

        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actual_message = body_json["message"].as_str().unwrap();

        assert_eq!(actual_message, expected_message);
    }

    #[sqlx::test]
    async fn test_login_with_wrong_password(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let hashed_password = password::hash("password123").unwrap();

        db_client
            .save_user("John", "john@example.com", &hashed_password)
            .await
            .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route("/login", web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(LoginUserDto {
                email: "john@example.com".to_string(),
                password: "wrongpassword".to_string(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let body = test::read_body(resp).await;
        let expected_message = "Email or password is wrong";

        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actual_message = body_json["message"].as_str().unwrap();

        assert_eq!(actual_message, expected_message);
    }

    #[sqlx::test]
    async fn test_login_with_no_data(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route("/login", web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        let body = test::read_body(resp).await;
        let body_str = String::from_utf8_lossy(&body);

        let expected_message = "Content type error";

        assert!(body_str.contains(expected_message));
    }

    #[sqlx::test]
    async fn test_login_with_empty_json_object(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route("/login", web::post().to(login))),
        )
        .await;

        let req = test::TestRequest::post()
            .set_json(json!({}))
            .uri("/api/auth/login")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

        let body = test::read_body(resp).await;
        let expected_message = "Json deserialize error: missing field";

        let body_str = String::from_utf8_lossy(&body);

        assert!(body_str.contains(expected_message));
    }

    #[sqlx::test]
    async fn test_logout_with_valid_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
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
                .service(web::scope("/api/auth").route(
                    "/logout",
                    web::post().to(logout).wrap(RequireAuth::allowed_roles(vec![
                        UserRole::User,
                        UserRole::Moderator,
                        UserRole::Admin,
                    ])),
                )),
        )
        .await;

        let req = test::TestRequest::post()
            .insert_header((http::header::AUTHORIZATION, format!("Bearer {}", token)))
            .uri("/api/auth/logout")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let body = test::read_body(resp).await;

        let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let status_field_value = body_json["status"].as_str().unwrap();

        assert_eq!(status_field_value, "success");
    }

    #[sqlx::test]
    async fn test_logout_with_invalid_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route(
                    "/logout",
                    web::post().to(logout).wrap(RequireAuth::allowed_roles(vec![
                        UserRole::User,
                        UserRole::Moderator,
                        UserRole::Admin,
                    ])),
                )),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/logout")
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
    async fn test_logout_with_misssing_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route(
                    "/logout",
                    web::post().to(logout).wrap(RequireAuth::allowed_roles(vec![
                        UserRole::User,
                        UserRole::Moderator,
                        UserRole::Admin,
                    ])),
                )),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/logout")
            .to_request();

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
    async fn test_logout_with_expired_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let user_id = uuid::Uuid::new_v4();
        let expired_token =
            token::create_token(&user_id.to_string(), config.jwt_secret.as_bytes(), -60).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/auth").route(
                    "/logout",
                    web::post().to(logout).wrap(RequireAuth::allowed_roles(vec![
                        UserRole::User,
                        UserRole::Moderator,
                        UserRole::Admin,
                    ])),
                )),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/logout")
            .insert_header((
                http::header::AUTHORIZATION,
                format!("Bearer {}", expired_token),
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
}
