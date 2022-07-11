use aws_lambda_events::apigw::ApiGatewayCustomAuthorizerRequestTypeRequest;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use log::info;
use rust_lambda_authorizer::auth_handlers::auth_handler_v1;
use rust_lambda_authorizer::config::{configure_logging, Config};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Error> {
    configure_logging();
    // To support unit tests, allow override the expire validation flag
    static VALIDATE_EXP: bool = true;
    let config: Config = Config::new().expect("Config cannot be parsed.");

    info!("Parsing config done.");

    let func = service_fn(
        |event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>| {
            info!("Event: {}", json!(event.payload));
            info!("Context: {}", json!(event.context)); // debug!
            auth_handler_v1(
                &config.jwks,
                &config.valid_issuers,
                &config.env_name,
                VALIDATE_EXP,
                event,
            )
        },
    );

    lambda_runtime::run(func).await?;
    Ok(())
}
