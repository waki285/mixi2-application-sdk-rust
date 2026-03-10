use std::{env, error::Error, sync::Arc};

use async_trait::async_trait;
use mixi2::{
    BoxError, ClientCredentialsAuthenticator, EventHandler, StreamClientBuilder,
    social::mixi::application::model::v1::Event,
};

struct PrintHandler;

#[async_trait]
impl EventHandler for PrintHandler {
    async fn handle(&self, event: &Event) -> Result<(), BoxError> {
        println!("received event: {:?}", event);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv().ok();

    let authenticator = Arc::new(
        ClientCredentialsAuthenticator::new(
            env::var("MIXI2_CLIENT_ID")?,
            env::var("MIXI2_CLIENT_SECRET")?,
        )
        .await?,
    );

    let mut watcher = StreamClientBuilder::new(authenticator).build().await?;

    watcher.watch(Arc::new(PrintHandler)).await?;

    Ok(())
}
