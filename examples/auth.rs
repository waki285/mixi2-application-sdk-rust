use std::{env, error::Error, sync::Arc};

use mixi2::{ApiClientBuilder, ClientCredentialsAuthenticator};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let authenticator = Arc::new(
        ClientCredentialsAuthenticator::new(
            env::var("MIXI2_CLIENT_ID")?,
            env::var("MIXI2_CLIENT_SECRET")?,
            env::var("MIXI2_TOKEN_URL")?,
        )
        .await?,
    );

    let _client = ApiClientBuilder::new(authenticator)
        .with_endpoint(env::var("MIXI2_API_ENDPOINT")?)
        .build()
        .await?;

    Ok(())
}
