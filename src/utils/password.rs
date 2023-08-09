use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::error::ErrorMessage;

const MAX_PASSWORD_LENGTH: usize = 64;

pub fn hash(password: impl Into<String>) -> Result<String, ErrorMessage> {
    let password = password.into();

    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ErrorMessage::HashingError)?
        .to_string();

    Ok(hashed_password)
}

pub fn compare(password: &str, hashed_password: &str) -> Result<bool, ErrorMessage> {
    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }

    let parsed_hash =
        PasswordHash::new(hashed_password).map_err(|_| ErrorMessage::InvalidHashFormat)?;

    let password_matches = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_or(false, |_| true);

    Ok(password_matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorMessage;

    fn setup_test() -> (String, String) {
        let password = "password123";
        let hashed_password = hash(password).unwrap();
        (password.to_string(), hashed_password)
    }

    #[test]
    fn test_compare_hashed_passwords_should_return_true() {
        let (password, hashed_password) = setup_test();

        assert_eq!(compare(&password, &hashed_password).unwrap(), true);
    }

    #[test]
    fn test_compare_hashed_passwords_should_return_false() {
        let (_, hashed_password) = setup_test();

        assert_eq!(compare("wrongpassword", &hashed_password).unwrap(), false);
    }

    #[test]
    fn test_compare_empty_password_should_return_fail() {
        let (_, hashed_password) = setup_test();

        assert_eq!(
            compare("", &hashed_password).unwrap_err(),
            ErrorMessage::EmptyPassword
        )
    }

    #[test]
    fn test_compare_long_password_should_return_fail() {
        let (_, hashed_password) = setup_test();

        let long_password = "a".repeat(1000);
        assert_eq!(
            compare(&long_password, &hashed_password).unwrap_err(),
            ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH)
        );
    }

    #[test]
    fn test_compare_invalid_hash_should_fail() {
        let invalid_hash = "invalid-hash";

        assert_eq!(
            compare("password123", invalid_hash).unwrap_err(),
            ErrorMessage::InvalidHashFormat
        )
    }

    #[test]
    fn test_hash_empty_password_should_fail() {
        let result = hash("");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ErrorMessage::EmptyPassword)
    }

    #[test]
    fn test_hash_long_password_should_fail() {
        let result = hash("a".repeat(1000));

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH)
        );
    }
}
