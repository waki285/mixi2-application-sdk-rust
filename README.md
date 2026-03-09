# mixi2 Application SDK for Rust

Rust SDK for the mixi2 Application API.

This repository migrates [the original Go SDK](https://github.com/mixigroup/mixi2-application-sdk-go) into a single publishable Rust crate.

## Package Layout

- `src/lib.rs`: public SDK facade and validated request builders
- `src/proto.rs`: vendored protobuf definitions and generated gRPC/prost types
- `src/auth.rs`: OAuth2 client-credentials authentication with cached bearer tokens
- `src/events.rs`: webhook verification and streaming event watcher utilities

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
    ClientCredentialsAuthenticator::new(
        "client-id",
        "client-secret",
        "https://mixi2.example.com/oauth/token",
    )
    .await?,
);

let mut client = ApiClientBuilder::new(authenticator)
    .with_endpoint("https://mixi2.example.com")
    .build()
    .await?;

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

Each example reads its configuration from environment variables.

## Development

```bash
cargo build --examples
cargo test
```

## License

Apache-2.0
