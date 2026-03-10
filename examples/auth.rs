use std::{env, error::Error};

use mixi2::{Authenticator, ClientCredentialsAuthenticator};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv().ok();

    let authenticator = ClientCredentialsAuthenticator::new(
        env::var("MIXI2_CLIENT_ID")?,
        env::var("MIXI2_CLIENT_SECRET")?,
    )
    .await?;
    let access_token = authenticator.access_token().await?;

    println!("{access_token}");

    Ok(())
}
