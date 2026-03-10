# mixi2 Application SDK for Rust

Rust SDK for the mixi2 Application API.

This repository migrates [the original Go SDK](https://github.com/mixigroup/mixi2-application-sdk-go) into a single publishable Rust crate.

## Features

- Async-only API surface designed for Tokio
- Vendored `mixigroup/mixi2-api` protobuf snapshot at `v1.0.0`
- Authenticated facade covering every unary Application API RPC
- Webhook signature verification with Ed25519 and timestamp replay protection
- Streaming watcher with Go-compatible reconnect behavior
- High-level builders for validated requests without hiding raw generated types

## Quick Start

```rust
use std::sync::Arc;

use mixi2::{ApiClientBuilder, ClientCredentialsAuthenticator};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
let authenticator = Arc::new(
    ClientCredentialsAuthenticator::new("client-id", "client-secret").await?,
);

let mut client = ApiClientBuilder::new(authenticator).build().await?;

let _response = client
    .get_stamps(mixi2::GetStampsRequestBuilder::new().build())
    .await?;

Ok(())
}
```

## Examples

- `cargo run --example auth`
- `cargo run --example webhook`
- `cargo run --example stream`

Each example reads its configuration from environment variables and loads `.env`
automatically when present. `ClientCredentialsAuthenticator::new(...)` uses the
official token endpoint `https://application-auth.mixi.social/oauth2/token` by
default, and API clients default to `https://application-api.mixi.social`
unless you override the transport with `with_endpoint` or `with_channel`. Copy
`.env.example` to `.env`, fill in the values, and run the example you need.
The `auth` example prints the fetched bearer token to stdout.

## Development

```bash
cargo build --examples
cargo test
```

## License

Apache-2.0
