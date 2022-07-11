use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerResponse, ApiGatewayV2CustomAuthorizerSimpleResponse, IamPolicyStatement};
use serde::Serialize;
use serde_json::json;


/// Represents response that Api gateway expects. It can output result in multiple formats
#[derive(Debug, Serialize)]
pub struct ApiGatewayResponse {
    pub route_arn: String,
    pub principal_id: String,
    pub allow: bool,
}

impl ApiGatewayResponse {
    fn get_policy(&self, route_arn: &str, allow: bool) -> ApiGatewayCustomAuthorizerPolicy {
        return ApiGatewayCustomAuthorizerPolicy {
            version: Some("2012-10-17".to_string()),
            statement: vec![IamPolicyStatement {
                action: vec!["execute-api:Invoke".to_string()],
                resource: vec![route_arn.to_string()],
                effect: if allow { Some("Allow".to_string()) } else { Some("Deny".to_string()) },
            }],
        };
    }
    /// Returns response as version 1 api gateway response
    pub fn to_response_v1(&self) -> ApiGatewayCustomAuthorizerResponse {
        let policy: ApiGatewayCustomAuthorizerPolicy = self.get_policy(
            self.route_arn.as_str(), self.allow,
        );

        return ApiGatewayCustomAuthorizerResponse {
            principal_id: Some(self.principal_id.to_string()),
            policy_document: policy,
            context: json!({
            }),
            usage_identifier_key: None,
        };
    }

    /// Returns response as version 2 api gateway response
    pub fn to_response_v2(&self) -> ApiGatewayV2CustomAuthorizerSimpleResponse {
        return ApiGatewayV2CustomAuthorizerSimpleResponse {
            is_authorized: self.allow,
            context: json!({
            }),
        };
    }
}


#[cfg(test)]
mod tests {
    use crate::test_utils::extract_first_from_policy;
    use super::*;


    fn get_effect_and_resource(route_arn: String, principal_id: String, allow: bool) -> (String, String) {
        let resp: ApiGatewayResponse = ApiGatewayResponse {
            route_arn,
            allow,
            principal_id,
        };
        let policy = resp.get_policy(resp.route_arn.as_str(), allow);

        let (effect, resource) = extract_first_from_policy(&policy);

        (effect, resource)
    }

    #[tokio::test]
    async fn test_to_api_gateway_response_v1() {
        let route_arn: &str = "/my/route";
        let principal_id: &str = "myprincipal";
        let valid: bool = true;
        let resp = ApiGatewayResponse {
            route_arn: route_arn.to_string(),
            principal_id: principal_id.to_string(),
            allow: valid,
        };
        let res = resp.to_response_v1();
        let (effect, resource) = extract_first_from_policy(&res.policy_document);

        assert_eq!(res.principal_id.unwrap(), principal_id);
        assert_eq!(effect, "Allow");
        assert_eq!(resource, route_arn);
    }

    #[tokio::test]
    async fn test_to_api_gateway_response_v2() {
        let route_arn: &str = "/my/route";
        let principal_id: &str = "myprincipal";
        let valid: bool = true;
        let resp = ApiGatewayResponse {
            route_arn: route_arn.to_string(),
            principal_id: principal_id.to_string(),
            allow: valid,
        };
        let res = resp.to_response_v2();

        assert_eq!(res.is_authorized, true);
    }

    #[tokio::test]
    async fn test_get_policy_allow() {
        let route_arn: &str = "/my/route";
        let principal_id: &str = "my_principal";
        let (effect, resource) = get_effect_and_resource(
            route_arn.to_string(), principal_id.to_string(), true);
        assert_eq!(effect, String::from("Allow"));
        assert_eq!(resource, String::from(route_arn));
    }

    #[tokio::test]
    async fn test_get_policy_deny() {
        let route_arn: &str = "/my/route";
        let principal_id: &str = "my_principal";
        let (effect, resource) = get_effect_and_resource(
            route_arn.to_string(), principal_id.to_string(), false);
        assert_eq!(effect, String::from("Deny"));
        assert_eq!(resource, String::from(route_arn));
    }
}

