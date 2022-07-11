use super::api_gateway::ApiGatewayResponse;
use super::jwt_service;
use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerRequestTypeRequest, ApiGatewayCustomAuthorizerResponse,
    ApiGatewayV2CustomAuthorizerSimpleResponse, ApiGatewayV2httpRequest,
};
use jsonwebtoken::jwk::JwkSet;
use lambda_runtime::{Error, LambdaEvent};
use log::info;

fn validate_authorization_header(authorization_header: &str) -> Result<String, Error> {
    // Basic token validation
    // make sure type is Bearer
    let token: Vec<&str> = authorization_header.split(" ").collect();
    return match token[0] {
        "Bearer" => Ok(token[1].to_string()),
        other => {
            info!("Invalid Token Type={} (Expected Bearer)", other);
            Err(Error::from("Invalid token type."))
        }
    };
}

// Separate out the authentication logic
pub async fn auth_handler_v1(
    jwks_list: &JwkSet,
    valid_issuers_array: &Vec<String>,
    _env_name: &str,
    validate_exp: bool,
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse, Error> {
    let request_method_arn: String = event.payload.method_arn.unwrap_or("".to_string());
    let request_method_arn: &str = request_method_arn.as_ref();
    let authorization_header: String = event
        .payload
        .headers
        .get("Authorization")
        .expect("Authorization header value missing")
        .to_str()
        .expect("Cannot parse header")
        .to_string();

    info!("Method ARN: {}", request_method_arn);
    info!("Method Token: {}", authorization_header); // debug!

    let jwt_token = validate_authorization_header(authorization_header.as_str())?;

    return match jwt_service::verify_jwt(
        jwks_list,
        valid_issuers_array,
        _env_name,
        validate_exp,
        jwt_token.as_str(),
    )
    .await
    {
        Ok(r) => {
            let resp = ApiGatewayResponse {
                route_arn: request_method_arn.to_string(),
                principal_id: r.principal_id,
                allow: r.valid,
            };
            Ok(resp.to_response_v1())
        }
        Err(e) => {
            // we should also try to return principal here
            info!("Access not allowed. Error: {}", e);
            let resp = ApiGatewayResponse {
                route_arn: request_method_arn.to_string(),
                principal_id: String::from("Unknown"),
                allow: false,
            };
            Ok(resp.to_response_v1())
        }
    };
}

// Separate out the authentication logic
pub async fn auth_handler_v2(
    jwks_list: &JwkSet,
    valid_issuers_array: &Vec<String>,
    _env_name: &str,
    validate_exp: bool,
    event: LambdaEvent<ApiGatewayV2httpRequest>,
) -> Result<ApiGatewayV2CustomAuthorizerSimpleResponse, Error> {
    let route_key_arn: String = event.payload.route_key.unwrap_or("".to_string());
    let route_key_arn: &str = route_key_arn.as_ref();
    let authorization_header: String = event
        .payload
        .headers
        .get("Authorization")
        .expect("Authorization header value missing")
        .to_str()
        .expect("Cannot parse header")
        .to_string();

    info!("Route key ARN: {}", route_key_arn);
    info!("Method Token: {}", authorization_header); // debug!

    let jwt_token = validate_authorization_header(authorization_header.as_str())?;

    return match jwt_service::verify_jwt(
        jwks_list,
        valid_issuers_array,
        _env_name,
        validate_exp,
        jwt_token.as_str(),
    )
    .await
    {
        Ok(r) => {
            let resp = ApiGatewayResponse {
                route_arn: route_key_arn.to_string(),
                principal_id: r.principal_id,
                allow: r.valid,
            };
            Ok(resp.to_response_v2())
        }
        Err(e) => {
            // we should also try to return principal here
            info!("Access not allowed. Error: {}", e);
            let resp = ApiGatewayResponse {
                route_arn: route_key_arn.to_string(),
                principal_id: String::from("Unknown"),
                allow: false,
            };
            Ok(resp.to_response_v2())
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::auth_handlers::{auth_handler_v1, auth_handler_v2, validate_authorization_header};
    use crate::test_utils::{
        extract_first_from_policy, get_invalid_token_type, get_jwk_set, get_valid_issuer_list,
        get_valid_token_header_auth_success,
    };
    use aws_lambda_events::apigw::{
        ApiGatewayCustomAuthorizerRequestTypeRequest,
        ApiGatewayCustomAuthorizerRequestTypeRequestContext, ApiGatewayCustomAuthorizerResponse,
        ApiGatewayV2CustomAuthorizerSimpleResponse, ApiGatewayV2httpRequest,
        ApiGatewayV2httpRequestContext, ApiGatewayV2httpRequestContextHttpDescription,
    };
    use http::{HeaderMap, HeaderValue};
    use lambda_runtime::{Context, LambdaEvent};
    use std::string::String;

    fn get_valid_context() -> Context {
        let mut headers = HeaderMap::new();
        headers.insert(
            "lambda-runtime-aws-request-id",
            HeaderValue::from_static("my-id"),
        );
        headers.insert(
            "lambda-runtime-deadline-ms",
            HeaderValue::from_static("123"),
        );
        headers.insert(
            "lambda-runtime-invoked-function-arn",
            HeaderValue::from_static("arn::myarn"),
        );
        headers.insert(
            "lambda-runtime-trace-id",
            HeaderValue::from_static("traceid"),
        );
        return Context::try_from(headers).unwrap();
    }

    // fn get_

    #[tokio::test]
    async fn test_validate_authorization_header() {
        let header = "Token test";

        validate_authorization_header(header).expect_err("Error expected but not found.");

        let header = "Bearer test_token";

        let val = validate_authorization_header(header).expect("Token expected but not found.");

        assert_eq!(val, "test_token")
    }

    fn get_valid_event_v1(
        authorization_header: &str,
    ) -> LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest> {
        let mut headers = HeaderMap::new();
        if !authorization_header.is_empty() {
            headers.insert(
                "Authorization",
                HeaderValue::from_str(authorization_header).unwrap(),
            );
        }
        // setup valid jwk and issuer to match token signature
        let valid_ctx = get_valid_context();
        let test_event = ApiGatewayCustomAuthorizerRequestTypeRequest {
            type_: Some("TOKEN".to_string()),
            method_arn: Some(
                "arn:aws:execute-api:us-east-1:123456789012:example/prod/POST/{proxy+}".to_string(),
            ),
            resource: None,
            path: None,
            http_method: Default::default(),
            headers,
            multi_value_headers: Default::default(),
            query_string_parameters: Default::default(),
            multi_value_query_string_parameters: Default::default(),
            path_parameters: Default::default(),
            stage_variables: Default::default(),
            request_context: ApiGatewayCustomAuthorizerRequestTypeRequestContext {
                path: None,
                account_id: None,
                resource_id: None,
                stage: None,
                request_id: None,
                identity: None,
                resource_path: None,
                http_method: Default::default(),
                apiid: None,
            },
        };

        let event = LambdaEvent {
            payload: test_event,
            context: valid_ctx,
        };

        return event;
    }

    #[tokio::test]
    async fn test_auth_handler_v1_success() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = get_valid_issuer_list();
        let env_name = "TEST";
        let validate_exp = false;
        let token = get_valid_token_header_auth_success();
        let event = get_valid_event_v1(token.as_str());
        let res: ApiGatewayCustomAuthorizerResponse = auth_handler_v1(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            event,
        )
        .await
        .unwrap();

        let (effect, _resource) = extract_first_from_policy(&res.policy_document);
        assert_eq!(effect, "Allow");
    }

    #[tokio::test]
    async fn test_auth_handler_v1_token_expired() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = get_valid_issuer_list();
        let env_name = "TEST";
        let validate_exp = true;
        let token = get_valid_token_header_auth_success();
        let event = get_valid_event_v1(token.as_str());
        let res: ApiGatewayCustomAuthorizerResponse = auth_handler_v1(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            event,
        )
        .await
        .unwrap();

        let (effect, _resource) = extract_first_from_policy(&res.policy_document);
        assert_eq!(effect, "Deny");
    }

    #[tokio::test]
    async fn test_auth_handler_v1_invalid_token() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = vec![String::from("https://someotherissuer.com")];
        let env_name = "TEST";
        let validate_exp = false;
        let token = get_valid_token_header_auth_success();
        let event = get_valid_event_v1(token.as_str());
        let res: ApiGatewayCustomAuthorizerResponse = auth_handler_v1(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            event,
        )
        .await
        .unwrap();

        let (effect, _resource) = extract_first_from_policy(&res.policy_document);
        assert_eq!(effect, "Deny");
    }

    #[tokio::test]
    async fn test_auth_handler_v1_invalid_token_type() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = get_valid_issuer_list();
        let env_name = "TEST";
        let validate_exp = false;
        let token = get_invalid_token_type();
        let event = get_valid_event_v1(token.as_str());
        let res = auth_handler_v1(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            event,
        )
        .await
        .expect_err("Expected error.");
        assert_eq!(res.to_string(), "Invalid token type.");
    }

    #[tokio::test]
    #[should_panic(expected = "Authorization header value missing")]
    async fn test_auth_handler_v1_missing_authorization_header() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = get_valid_issuer_list();
        let env_name = "TEST";
        let validate_exp = false;
        let token = String::new();

        let event = get_valid_event_v1(token.as_str());
        let _res: ApiGatewayCustomAuthorizerResponse = auth_handler_v1(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            event,
        )
        .await
        .unwrap();
    }

    ///// V2

    fn get_valid_event_v2(authorization_header: &str) -> LambdaEvent<ApiGatewayV2httpRequest> {
        let mut headers = HeaderMap::new();
        if !authorization_header.is_empty() {
            headers.insert(
                "Authorization",
                HeaderValue::from_str(authorization_header).unwrap(),
            );
        }
        // setup valid jwk and issuer to match token signature
        let valid_ctx = get_valid_context();
        let test_event = ApiGatewayV2httpRequest {
            version: None,
            route_key: Some(
                "arn:aws:execute-api:us-east-1:123456789012:example/prod/POST/{proxy+}".to_string(),
            ),
            raw_path: None,
            raw_query_string: None,
            headers,
            query_string_parameters: Default::default(),
            path_parameters: Default::default(),
            stage_variables: Default::default(),
            body: None,
            request_context: ApiGatewayV2httpRequestContext {
                route_key: None,
                account_id: None,
                stage: None,
                request_id: None,
                authorizer: None,
                apiid: None,
                domain_name: None,
                domain_prefix: None,
                time: None,
                time_epoch: 0,
                http: ApiGatewayV2httpRequestContextHttpDescription {
                    method: Default::default(),
                    path: None,
                    protocol: None,
                    source_ip: None,
                    user_agent: None,
                },
                authentication: None,
            },
            cookies: None,
            is_base64_encoded: false,
        };

        let event = LambdaEvent {
            payload: test_event,
            context: valid_ctx,
        };

        return event;
    }

    #[tokio::test]
    async fn test_auth_handler_v2_success() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = get_valid_issuer_list();
        let env_name = "TEST";
        let validate_exp = false;
        let token = get_valid_token_header_auth_success();
        let event = get_valid_event_v2(token.as_str());
        let res: ApiGatewayV2CustomAuthorizerSimpleResponse = auth_handler_v2(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            event,
        )
        .await
        .unwrap();

        assert_eq!(res.is_authorized, true);
    }

    #[tokio::test]
    async fn test_auth_handler_v2_token_expired() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = get_valid_issuer_list();
        let env_name = "TEST";
        let validate_exp = true;
        let token = get_valid_token_header_auth_success();
        let event = get_valid_event_v2(token.as_str());
        let res: ApiGatewayV2CustomAuthorizerSimpleResponse = auth_handler_v2(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            event,
        )
        .await
        .unwrap();

        assert_eq!(res.is_authorized, false);
    }

    #[tokio::test]
    async fn test_auth_handler_v2_invalid_token() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = vec![String::from("https://someotherissuer.com")];
        let env_name = "TEST";
        let validate_exp = false;
        let token = get_valid_token_header_auth_success();
        let event = get_valid_event_v2(token.as_str());
        let res: ApiGatewayV2CustomAuthorizerSimpleResponse = auth_handler_v2(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            event,
        )
        .await
        .unwrap();

        assert_eq!(res.is_authorized, false);
    }

    #[tokio::test]
    async fn test_auth_handler_v2_invalid_token_type() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = get_valid_issuer_list();
        let env_name = "TEST";
        let validate_exp = false;
        let token = get_invalid_token_type();
        let event = get_valid_event_v2(token.as_str());
        let res = auth_handler_v2(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            event,
        )
        .await
        .expect_err("Expected error.");
        assert_eq!(res.to_string(), "Invalid token type.");
    }

    #[tokio::test]
    #[should_panic(expected = "Authorization header value missing")]
    async fn test_auth_handler_v2_missing_authorization_header() {
        let valid_jwk_list = get_jwk_set();
        let valid_issuers_array = get_valid_issuer_list();
        let env_name = "TEST";
        let validate_exp = false;
        let token = String::new();

        let event = get_valid_event_v2(token.as_str());
        let _res: ApiGatewayV2CustomAuthorizerSimpleResponse = auth_handler_v2(
            &valid_jwk_list,
            &valid_issuers_array,
            env_name,
            validate_exp,
            event,
        )
        .await
        .unwrap();
    }
}
