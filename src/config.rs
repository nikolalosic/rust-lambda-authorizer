use jsonwebtoken::jwk::JwkSet;
use lambda_runtime::Error;

pub struct Config {
    // JSON Web Key Set
    pub jwks: JwkSet,
    pub valid_issuers: Vec<String>,
    pub env_name: String,
}

impl Config {
    pub fn new() -> Result<Config, Error> {
        let jwks_string = std::env::var("JWKS_STRING")
            .expect("A JWKS_STRING must be set in this app's Lambda environment variables.");

        let valid_issuers = std::env::var("VALID_ISSUERS")
            .expect("A VALID_ISSUERS must be set in this app's Lambda environment variables.");

        let env_name = std::env::var("ENV_NAME")
            .expect("A ENV_NAME must be set in this app's Lambda environment variables.");

        // Get AWS config
        // let _shared_config = aws_config::load_from_env().await;
        // Parsing JWKS and Issuer List
        let jwks_list: JwkSet =
            serde_json::from_str(&jwks_string).expect("Error parsing JWKS string");
        let valid_issuers_array: Vec<String> =
            serde_json::from_str(&valid_issuers).expect("Error parsing valid issuers list");

        return Ok(Config {
            jwks: jwks_list,
            valid_issuers: valid_issuers_array,
            env_name,
        });
    }
}

pub fn configure_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // this needs to be set to false, otherwise ANSI color codes will
        // show up in a confusing manner in CloudWatch logs.
        .with_ansi(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .json()
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::set_env_vars;

    #[tokio::test]
    async fn test_new_config() {
        set_env_vars();

        let config: Config = Config::new().expect("Cannot parse config.");
        assert_eq!(
            config.valid_issuers,
            vec!["https://cognito-idp.ap-southeast-2.amazonaws.com/yyyy-xxxx"]
        );
        assert_eq!(config.env_name, "TEST");
        match config.jwks.find("test-rsa") {
            Some(j) => j.clone(),
            None => {
                panic!("KID missing.")
            }
        };
    }
}
