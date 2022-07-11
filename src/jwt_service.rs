use jsonwebtoken::errors::{Error, ErrorKind};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};
use log::{error, info};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct JwtValidationResult {
    pub valid: bool,
    pub message: String,
    pub principal_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,

    #[serde(default)]
    name: String,

    #[serde(default)]
    preferred_username: String,
}

// Separate out the authentication logic
pub async fn verify_jwt(
    jwks_list: &JwkSet,
    valid_issuers_array: &Vec<String>,
    _env_name: &str,
    validate_exp: bool,
    jwt_token: &str,
) -> Result<JwtValidationResult, Error> {
    // debug!
    info!("Method Token: {}", jwt_token); // debug!

    // Basic token validation
    // make sure type is Bearer

    // Decode the header and find the kid
    let header: Header = match decode_header(jwt_token) {
        Ok(header) => header,
        Err(e) => {
            error!("Error decoding header for token: {}.", e);
            return Err(jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken));
        }
    };

    let kid: String = match header.kid {
        Some(k) => k,
        None => {
            return Err(jsonwebtoken::errors::Error::from(
                ErrorKind::InvalidKeyFormat,
            ));
        }
    };

    let jwk = match jwks_list.find(&kid) {
        Some(j) => j.clone(),
        None => {
            error!("Unknown kid in token. Kid is not in JWKS.");
            return Err(jsonwebtoken::errors::Error::from(
                ErrorKind::InvalidKeyFormat,
            ));
        }
    };

    // Get the decode key and algorithm
    let (decoding_key, algorithm) = match get_decode_key_and_algorithm(jwk) {
        Ok((decoding_key, algorithm)) => (decoding_key, algorithm),
        Err(e) => {
            error!("Algorithm not supported. Error: {}", e);
            return Err(e);
        }
    };

    // Decode & Validate the token and retrieve the claims
    let verified_claims = match decode_and_validate_token(
        jwt_token,
        decoding_key,
        algorithm,
        valid_issuers_array,
        validate_exp,
    ) {
        Ok(verified_claims) => verified_claims,
        Err(e) => {
            error!("Error decoding and validating token. {}", e);
            return Err(e);
        }
    };

    return Ok(JwtValidationResult {
        valid: true,
        message: String::from("Validation success"),
        principal_id: verified_claims.name,
    });
}

// Use the rust jsonwebtoken crate to decode and validate a jwt token
fn decode_and_validate_token(
    jwt_token: &str,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
    valid_issuers_array: &Vec<String>,
    validate_exp: bool,
) -> Result<Claims, Error> {
    // Setup validations
    // Explicitly set the ones we want
    // @Issuer - Make sure only our list of accepted issuers
    // @Expiry - Make sure the token hasn't expired
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = validate_exp;
    validation.set_issuer(&[valid_issuers_array.get(0).unwrap()]);
    // Decode and validate the token
    // Assumption is that resulting claims are verified
    // If there is a validation error the lib throws and exception
    let decoded_token = decode::<Claims>(jwt_token, &decoding_key, &validation)?;

    return Ok(decoded_token.claims);
}

/// Method to find Decoding key and Algorithm from a JWK
fn get_decode_key_and_algorithm(jwk: Jwk) -> Result<(DecodingKey, Algorithm), Error> {
    // Check the algo - we only support RSA
    return match jwk.algorithm {
        AlgorithmParameters::RSA(ref rsa) => {
            // Setup the decode key
            let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap();

            Ok((decoding_key, jwk.common.algorithm.unwrap()))
        }
        _ => Err(jsonwebtoken::errors::Error::from(
            ErrorKind::InvalidAlgorithmName,
        )),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        get_jwk_set, get_unsupported_jwk_set, get_valid_issuer_list, get_valid_token,
    };

    #[tokio::test]
    async fn test_get_decode_key_and_algorithm() {
        let jwk_set: JwkSet = get_jwk_set();
        let jwk = jwk_set.keys.get(0).unwrap();

        get_decode_key_and_algorithm(jwk.clone()).expect("Expected successful parse.");
    }

    #[tokio::test]
    async fn test_get_decode_key_and_algorithm_unsupported_algorithm() {
        let jwk_set: JwkSet = get_unsupported_jwk_set();
        let jwk = jwk_set.keys.get(0).unwrap();

        get_decode_key_and_algorithm(jwk.clone())
            .err()
            .expect("Expected error");
    }

    #[tokio::test]
    async fn test_decode_and_validate_token() {
        let jwt_token = get_valid_token();
        let jwk_set: JwkSet = get_jwk_set();
        let jwk = jwk_set.keys.get(0).unwrap();
        let valid_issuers_array = get_valid_issuer_list();
        let validate_exp = false;
        let (decoding_key, algorithm) = get_decode_key_and_algorithm(jwk.clone()).unwrap();

        decode_and_validate_token(
            jwt_token.as_str(),
            decoding_key,
            algorithm,
            &valid_issuers_array,
            validate_exp,
        )
        .expect("Validation success expected.");
    }

    #[tokio::test]
    async fn test_decode_and_validate_expired_token() {
        let jwt_token = get_valid_token();
        let jwk_set: JwkSet = get_jwk_set();
        let jwk = jwk_set.keys.get(0).unwrap();
        let valid_issuers_array = get_valid_issuer_list();
        let validate_exp = true;
        let (decoding_key, algorithm) = get_decode_key_and_algorithm(jwk.clone()).unwrap();

        decode_and_validate_token(
            jwt_token.as_str(),
            decoding_key,
            algorithm,
            &valid_issuers_array,
            validate_exp,
        )
        .expect_err("Validation error expected.");
    }

    #[tokio::test]
    async fn test_decode_and_validate_token_invalid_issuer() {
        let jwt_token = get_valid_token();
        let jwk_set: JwkSet = get_jwk_set();
        let jwk = jwk_set.keys.get(0).unwrap();
        let valid_issuers_array = vec![String::from("https://someotherissuer.com")];
        let validate_exp = false;
        let (decoding_key, algorithm) = get_decode_key_and_algorithm(jwk.clone()).unwrap();

        decode_and_validate_token(
            jwt_token.as_str(),
            decoding_key,
            algorithm,
            &valid_issuers_array,
            validate_exp,
        )
        .expect_err("Validation error expected.");
    }

    #[tokio::test]
    async fn test_verify_jwt_success() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = get_valid_issuer_list();
        let env_name = "TEST";
        let validate_exp = false;
        let token = get_valid_token();

        verify_jwt(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            token.as_str(),
        )
        .await
        .expect("Expected successful validation.");
    }

    #[tokio::test]
    async fn test_verify_jwt_token_expired() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = get_valid_issuer_list();
        let env_name = "TEST";
        let validate_exp = true;
        let token = get_valid_token();

        verify_jwt(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            token.as_str(),
        )
        .await
        .expect_err("Expected token expiration error.");
    }

    #[tokio::test]
    async fn test_verify_jwt_invalid_token_issuer() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = vec![String::from("https://someotherissuer.com")];
        let env_name = "TEST";
        let validate_exp = false;
        let token = get_valid_token();

        verify_jwt(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            token.as_str(),
        )
        .await
        .expect_err("Expected issuer validation error.");
    }
}
