use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerPolicy, IamPolicyStatement};
use jsonwebtoken::jwk::JwkSet;
use std::env;

pub fn set_env_vars() {
    env::set_var("JWKS_STRING", get_jwks_string());
    env::set_var(
        "VALID_ISSUERS",
        "[\"https://cognito-idp.ap-southeast-2.amazonaws.com/yyyy-xxxx\"]",
    );
    env::set_var("ENV_NAME", "TEST");
}

fn get_jwks_string() -> String {
    return String::from(
        r#"{
            "keys": [
              {
                "kty": "RSA",
                "n": "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw",
                "e": "AQAB",
                "kid": "test-rsa",
                "alg":"RS256"
              }
            ]
          }"#,
    );
}

fn get_unsupported_jwks_string() -> String {
    return String::from(
        r#"{
            "keys": [
              {
                "kty":"EC",
                "alg":"ES256",
                "use":"enc",
                "kid":"k05TUSt7-V7KDjCq0_N",
                "crv":"P-256",
                "x":"Xej56MungXuFZwmk_xccvsMpCtXmqhvEEMCmHyAmKF0",
                "y":"Bozpu4Y4ThKdwORWFXQa9I75pKOvPUjUjE2Bk05TUSt"
              }
            ]
          }"#,
    );
}

pub fn get_jwk_set() -> JwkSet {
    let jwks_list: JwkSet =
        serde_json::from_str(get_jwks_string().as_str()).expect("Error parsing JWKS string");
    return jwks_list;
}

pub fn get_unsupported_jwk_set() -> JwkSet {
    let jwks_list: JwkSet = serde_json::from_str(get_unsupported_jwks_string().as_str())
        .expect("Error parsing JWKS string");
    return jwks_list;
}

pub fn get_valid_issuer_list() -> Vec<String> {
    return serde_json::from_str(
        &r#"["https://cognito-idp.ap-southeast-2.amazonaws.com/yyyy-xxxx"]"#,
    )
    .unwrap();
}

pub fn extract_first_from_policy(policy: &ApiGatewayCustomAuthorizerPolicy) -> (String, String) {
    let statement: &IamPolicyStatement = policy.statement.get(0).expect("Statement missing");

    let effect: &str = statement.effect.as_deref().expect("Effect missing");

    let resource: &str = statement.resource.get(0).expect("Resource missing");

    return (effect.to_string(), resource.to_string());
}

pub fn get_valid_token() -> String {
    // Generate a new valid token with the following claims
    // {
    //     "origin_jti": "b0661df2-26f1-471d-9080-8410743c90da",
    //     "custom:tenantId": "1234567xyz",
    //     "sub": "d1fdf006-3e99-415e-984e-b649beb2212f",
    //     "aud": "28iqrgirmnh3vc2dpldg4h19n",
    //     "event_id": "f0bbddfd-564f-4268-94b7-2b0e64f57d51",
    //     "token_use": "id",
    //     "auth_time": 1644823894,
    //     "iss": "https://cognito-idp.ap-southeast-2.amazonaws.com/yyyy-xxxx",
    //     "cognito:username": "niro.am",
    //     "exp": 1645391153,
    //     "iat": 1645474285,
    //     "jti": "e429cdc2-da3a-4bbb-8ac0-b9198e802f39"
    //   }
    //
    return String::from("eyJraWQiOiJ0ZXN0LXJzYSIsImFsZyI6IlJTMjU2In0.eyJvcmlnaW5fanRpIjoiYjA2NjFkZjItMjZmMS00NzFkLTkwODAtODQxMDc0M2M5MGRhIiwiY3VzdG9tOnRlbmFudElkIjoiMTIzNDU2N3h5eiIsInN1YiI6ImQxZmRmMDA2LTNlOTktNDE1ZS05ODRlLWI2NDliZWIyMjEyZiIsImF1ZCI6IjI4aXFyZ2lybW5oM3ZjMmRwbGRnNGgxOW4iLCJldmVudF9pZCI6ImYwYmJkZGZkLTU2NGYtNDI2OC05NGI3LTJiMGU2NGY1N2Q1MSIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjQ0ODIzODk0LCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmFwLXNvdXRoZWFzdC0yLmFtYXpvbmF3cy5jb20veXl5eS14eHh4IiwiY29nbml0bzp1c2VybmFtZSI6Im5pcm8uYW0iLCJleHAiOjE2NDUzOTExNTMsImlhdCI6MTY0NTQ3NDI4NSwianRpIjoiZTQyOWNkYzItZGEzYS00YmJiLThhYzAtYjkxOThlODAyZjM5In0.2UiUgopWyuvy1QK0f56HwZ9mZoF781Gf4IWO7pj_PHN0jdm1_uZt8JhQ4qmFY4Qfng8Yr14AEyf9oGhJte9FBSZWUzOyJ_w9smrWpZc_p49K6HDYfNoNEHhZ0HIRhR6IfKwqZCdQbK0S5L020QjzLN7RlxvwVfmzRMU-3veSfkQVRHJaFkW-djmf4xB4o-Kqvl9p0PBC5pMwAT-43A8rXQ1RV4BaTFMB2OpAe6vqoFxLc5jXIMEG18ehe6-c4fjJsWA131G91Xxe_alUd5uYNzAZWzz5JJYj3uigW-iml6Wnf82aEQzmScRt1PRr1UlkBcvcpnZ35DOp7KSNE7AjpQ");
}

pub fn get_valid_token_header_auth_success() -> String {
    return String::from(format!("Bearer {}", get_valid_token()));
}

pub fn get_invalid_token_type() -> String {
    // Missing Bearer keyword
    return String::from("eyJraWQiOiJ0ZXN0LXJzYSIsImFsZyI6IlJTMjU2In0.eyJvcmlnaW5fanRpIjoiYjA2NjFkZjItMjZmMS00NzFkLTkwODAtODQxMDc0M2M5MGRhIiwiY3VzdG9tOnRlbmFudElkIjoiMTIzNDU2N3h5eiIsInN1YiI6ImQxZmRmMDA2LTNlOTktNDE1ZS05ODRlLWI2NDliZWIyMjEyZiIsImF1ZCI6IjI4aXFyZ2lybW5oM3ZjMmRwbGRnNGgxOW4iLCJldmVudF9pZCI6ImYwYmJkZGZkLTU2NGYtNDI2OC05NGI3LTJiMGU2NGY1N2Q1MSIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjQ0ODIzODk0LCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmFwLXNvdXRoZWFzdC0yLmFtYXpvbmF3cy5jb20veXl5eS14eHh4IiwiY29nbml0bzp1c2VybmFtZSI6Im5pcm8uYW0iLCJleHAiOjE2NDUzOTExNTMsImlhdCI6MTY0NTQ3NDI4NSwianRpIjoiZTQyOWNkYzItZGEzYS00YmJiLThhYzAtYjkxOThlODAyZjM5In0.2UiUgopWyuvy1QK0f56HwZ9mZoF781Gf4IWO7pj_PHN0jdm1_uZt8JhQ4qmFY4Qfng8Yr14AEyf9oGhJte9FBSZWUzOyJ_w9smrWpZc_p49K6HDYfNoNEHhZ0HIRhR6IfKwqZCdQbK0S5L020QjzLN7RlxvwVfmzRMU-3veSfkQVRHJaFkW-djmf4xB4o-Kqvl9p0PBC5pMwAT-43A8rXQ1RV4BaTFMB2OpAe6vqoFxLc5jXIMEG18ehe6-c4fjJsWA131G91Xxe_alUd5uYNzAZWzz5JJYj3uigW-iml6Wnf82aEQzmScRt1PRr1UlkBcvcpnZ35DOp7KSNE7AjpQ");
}
