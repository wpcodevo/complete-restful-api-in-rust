use actix_web::{web, HttpResponse, Scope};
use validator::Validate;

use crate::{
    db::UserExt,
    dtos::{FilterUserDto, RequestQueryDto, UserData, UserListResponseDto, UserResponseDto},
    error::HttpError,
    extractors::auth::{Authenticated, RequireAuth},
    models::UserRole,
    AppState,
};

pub fn users_scope() -> Scope {
    web::scope("/api/users")
        .route(
            "",
            web::get()
                .to(get_users)
                .wrap(RequireAuth::allowed_roles(vec![UserRole::Admin])),
        )
        .route(
            "/me",
            web::get().to(get_me).wrap(RequireAuth::allowed_roles(vec![
                UserRole::User,
                UserRole::Moderator,
                UserRole::Admin,
            ])),
        )
}

#[utoipa::path(
    get,
    path = "/api/users/me",
    tag = "Get Authenticated User Endpoint",
    responses(
        (status = 200, description= "Authenticated User", body = UserResponseDto),
        (status= 500, description= "Internal Server Error", body = Response )
       
    ),
    security(
       ("token" = [])
   )
)]
async fn get_me(user: Authenticated) -> Result<HttpResponse, HttpError> {
    let filtered_user = FilterUserDto::filter_user(&user);

    let response_data = UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };

    Ok(HttpResponse::Ok().json(response_data))
}

#[utoipa::path(
    get,
    path = "/api/users",
    tag = "Get All Users Endpoint",
    params(
        RequestQueryDto
    ),
    responses(
        (status = 200, description= "All Users", body = [UserResponseDto]),
        (status=401, description= "Authentication Error", body= Response),
        (status=403, description= "Permission Denied Error", body= Response),
        (status= 500, description= "Internal Server Error", body = Response )
       
    ),
    security(
       ("token" = [])
   )
)]
pub async fn get_users(
    query: web::Query<RequestQueryDto>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, HttpError> {
    let query_params: RequestQueryDto = query.into_inner();

    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    let users = app_state
        .db_client
        .get_users(page as u32, limit)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok(HttpResponse::Ok().json(UserListResponseDto {
        status: "success".to_string(),
        users: FilterUserDto::filter_users(&users),
        results: users.len(),
    }))
}

#[cfg(test)]
mod tests {
    use actix_web::{http, test, App};
    use sqlx::{Pool, Postgres};

    use crate::{
        db::DBClient,
        error::{ErrorMessage, ErrorResponse},
        utils::{
            password,
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
                .service(web::scope("/api/users").route(
                    "/me",
                    web::get().to(get_me).wrap(RequireAuth::allowed_roles(vec![
                        UserRole::User,
                        UserRole::Moderator,
                        UserRole::Admin,
                    ])),
                )),
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
    async fn test_get_me_with_invalid_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/users").route(
                    "/me",
                    web::get().to(get_me).wrap(RequireAuth::allowed_roles(vec![
                        UserRole::User,
                        UserRole::Moderator,
                        UserRole::Admin,
                    ])),
                )),
        )
        .await;

        let req = test::TestRequest::get()
            .insert_header((
                http::header::AUTHORIZATION,
                format!("Bearer {}", "invlaid_token"),
            ))
            .uri("/api/users/me")
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
    async fn test_get_me_with_missing_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(web::scope("/api/users").route(
                    "/me",
                    web::get().to(get_me).wrap(RequireAuth::allowed_roles(vec![
                        UserRole::User,
                        UserRole::Moderator,
                        UserRole::Admin,
                    ])),
                )),
        )
        .await;

        let req = test::TestRequest::get().uri("/api/users/me").to_request();

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
                .service(web::scope("/api/users").route(
                    "/me",
                    web::get().to(get_me).wrap(RequireAuth::allowed_roles(vec![
                        UserRole::User,
                        UserRole::Moderator,
                        UserRole::Admin,
                    ])),
                )),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/users/me")
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

    #[sqlx::test]
    async fn test_all_users_with_valid_token_with_admin_user(pool: Pool<Postgres>) {
        let (_, _, _) = init_test_users(&pool).await;
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let hashed_password = password::hash("password123").unwrap();
        let user = db_client
            .save_admin_user("Vivian", "vivian@example.com", &hashed_password)
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
                .service(
                    web::scope("/api/users").route(
                        "",
                        web::get()
                            .to(get_users)
                            .wrap(RequireAuth::allowed_roles(vec![UserRole::Admin])),
                    ),
                ),
        )
        .await;

        let req = test::TestRequest::get()
            .insert_header((http::header::AUTHORIZATION, format!("Bearer {}", token)))
            .uri("/api/users")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let body = test::read_body(resp).await;

        let user_list_response: UserListResponseDto =
            serde_json::from_slice(&body).expect("Failed to deserialize users response from JSON");

        assert_eq!(user_list_response.users.len(), 4);
    }

    #[sqlx::test]
    async fn test_all_users_with_page_one_and_limit_two_query_parameters(pool: Pool<Postgres>) {
        let (_, _, _) = init_test_users(&pool).await;
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let hashed_password = password::hash("password123").unwrap();
        let user = db_client
            .save_admin_user("Vivian", "vivian@example.com", &hashed_password)
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
                .service(
                    web::scope("/api/users").route(
                        "",
                        web::get()
                            .to(get_users)
                            .wrap(RequireAuth::allowed_roles(vec![UserRole::Admin])),
                    ),
                ),
        )
        .await;

        let req = test::TestRequest::get()
            .insert_header((http::header::AUTHORIZATION, format!("Bearer {}", token)))
            .uri("/api/users?page=1&limit=2")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let body = test::read_body(resp).await;

        let user_list_response: UserListResponseDto =
            serde_json::from_slice(&body).expect("Failed to deserialize users response from JSON");

        assert_eq!(user_list_response.users.len(), 2);
    }

    #[sqlx::test]
    async fn test_all_users_with_valid_token_by_regular_user(pool: Pool<Postgres>) {
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
                .service(
                    web::scope("/api/users").route(
                        "",
                        web::get()
                            .to(get_users)
                            .wrap(RequireAuth::allowed_roles(vec![UserRole::Admin])),
                    ),
                ),
        )
        .await;

        let req = test::TestRequest::get()
            .insert_header((http::header::AUTHORIZATION, format!("Bearer {}", token)))
            .uri("/api/users")
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
    async fn test_all_users_with_invalid_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(
                    web::scope("/api/users").route(
                        "",
                        web::get()
                            .to(get_users)
                            .wrap(RequireAuth::allowed_roles(vec![UserRole::Admin])),
                    ),
                ),
        )
        .await;

        let req = test::TestRequest::get()
            .insert_header((
                http::header::AUTHORIZATION,
                format!("Bearer {}", "invalid_token"),
            ))
            .uri("/api/users")
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
    async fn test_all_users_with_missing_token(pool: Pool<Postgres>) {
        let db_client = DBClient::new(pool.clone());
        let config = get_test_config();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    env: config.clone(),
                    db_client,
                }))
                .service(
                    web::scope("/api/users").route(
                        "",
                        web::get()
                            .to(get_users)
                            .wrap(RequireAuth::allowed_roles(vec![UserRole::Admin])),
                    ),
                ),
        )
        .await;

        let req = test::TestRequest::get().uri("/api/users").to_request();

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
}
