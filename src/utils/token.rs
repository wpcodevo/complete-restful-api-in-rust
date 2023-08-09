use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::{ErrorMessage, HttpError};

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

pub fn create_token(
    user_id: &str,
    secret: &[u8],
    expires_in_seconds: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    if user_id.is_empty() {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidSubject.into());
    }

    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + Duration::minutes(expires_in_seconds)).timestamp() as usize;
    let claims: TokenClaims = TokenClaims {
        sub: user_id.to_string(),
        exp,
        iat,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

pub fn decode_token<T: Into<String>>(token: T, secret: &[u8]) -> Result<String, HttpError> {
    let decoded = decode::<TokenClaims>(
        &token.into(),
        &DecodingKey::from_secret(secret),
        &Validation::new(Algorithm::HS256),
    );
    match decoded {
        Ok(token) => Ok(token.claims.sub),
        Err(_) => Err(HttpError::new(ErrorMessage::InvalidToken.to_string(), 401)),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_create_and_decoded_valid_token() {
        let user_id = "user123";
        let secret = b"my-secret-key";

        let token = create_token(user_id, secret, 60).unwrap();
        let decoded_user_id = decode_token(&token, secret).unwrap();

        assert_eq!(decoded_user_id, user_id);
    }

    #[test]
    fn test_create_token_with_empty_user_id() {
        let user_id = "";
        let secret = b"my-secret-key";

        let result = create_token(user_id, secret, 60);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().into_kind(),
            jsonwebtoken::errors::ErrorKind::InvalidSubject
        )
    }

    #[test]
    fn test_decoded_invalid_token() {
        let secret = b"my-secret-key";
        let invalid_token = "invalid-token";

        let result = decode_token(invalid_token, secret);

        assert!(result.is_err());
        assert_eq!(
            result.clone().unwrap_err().message,
            ErrorMessage::InvalidToken.to_string()
        );
        assert_eq!(result.unwrap_err().status, 401);
    }

    #[test]
    fn test_decode_expired_token() {
        let secret = b"my-secret-key";
        let expired_token = create_token("user123", secret, -60).unwrap();

        let result = decode_token(expired_token, secret);

        assert!(result.is_err());
        assert_eq!(
            result.clone().unwrap_err().message,
            ErrorMessage::InvalidToken.to_string()
        );
        assert_eq!(result.unwrap_err().status, 401);
    }
}
