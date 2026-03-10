use std::{env, error::Error, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use mixi2::{
    BoxError, EventHandler, WebhookServer, WebhookService,
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

    let public_key_hex = env::var("MIXI2_WEBHOOK_PUBLIC_KEY")?;
    let public_key_bytes = hex::decode(public_key_hex)?;
    let public_key = VerifyingKey::from_bytes(public_key_bytes.as_slice().try_into()?)?;
    let address: SocketAddr = env::var("MIXI2_WEBHOOK_ADDR")?.parse()?;

    let service = WebhookService::new(public_key, Arc::new(PrintHandler));
    let server = WebhookServer::new(address, service);
    server.serve().await?;

    Ok(())
}
