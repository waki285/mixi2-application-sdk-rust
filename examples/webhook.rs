use std::{
    env,
    error::Error,
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::VerifyingKey;
use mixi2::{
    BoxError, EventHandler, WebhookService,
    social::mixi::application::{r#const::v1::EventType, model::v1::Event},
};
use tokio::net::TcpListener;

struct PrintHandler;

#[async_trait]
impl EventHandler for PrintHandler {
    async fn handle(&self, event: &Event) -> Result<(), BoxError> {
        println!(
            "received event: event_type={}",
            event_type_label(event.event_type)
        );
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    handler: Arc<PrintHandler>,
    service: WebhookService<PrintHandler>,
}

async fn log_non_event_requests(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let response = next.run(req).await;

    if path != "/events" {
        println!("webhook request: {method} {path} -> {}", response.status());
    }

    response
}

fn parse_public_key(value: &str) -> Result<VerifyingKey, Box<dyn Error>> {
    let bytes = BASE64_STANDARD.decode(value).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidInput,
            format!("MIXI2_WEBHOOK_PUBLIC_KEY must be base64: {error}"),
        )
    })?;
    let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        IoError::new(
            ErrorKind::InvalidInput,
            "MIXI2_WEBHOOK_PUBLIC_KEY must decode to a 32-byte Ed25519 public key",
        )
    })?;

    VerifyingKey::from_bytes(&bytes).map_err(|error| {
        Box::new(IoError::new(
            ErrorKind::InvalidInput,
            format!("MIXI2_WEBHOOK_PUBLIC_KEY is not a valid Ed25519 public key: {error}"),
        )) as Box<dyn Error>
    })
}

async fn healthz_handler() -> StatusCode {
    StatusCode::OK
}

async fn webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let timestamp = header_value(&headers, "x-mixi2-application-event-timestamp");
    let signature = header_value(&headers, "x-mixi2-application-event-signature");
    let signature_length = if signature == "unavailable" {
        String::from("unavailable")
    } else {
        signature.len().to_string()
    };
    let body_hex = hex::encode(&body);
    let body_base64 = BASE64_STANDARD.encode(&body);

    match state.service.verify_and_decode(&headers, &body) {
        Ok(events) => {
            let event_types = if events.is_empty() {
                String::from("[]")
            } else {
                let labels = events
                    .iter()
                    .map(|event| event_type_label(event.event_type))
                    .collect::<Vec<_>>();
                format!("[{}]", labels.join(", "))
            };
            println!(
                "webhook request: POST /events -> 204 No Content, timestamp={timestamp}, signature={signature}, signature.len()={signature_length}, body.len()={}, body.hex={body_hex}, body.base64={body_base64}, events.len()={}, event_type={event_types}",
                body.len(),
                events.len(),
            );

            for event in events {
                if event.event_type == EventType::Ping as i32 {
                    continue;
                }

                if let Err(error) = state.handler.handle(&event).await {
                    eprintln!("failed to handle event: {error}");
                }
            }

            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => {
            let error_message = error.to_string();
            let response = error.into_response();
            println!(
                "webhook request: POST /events -> {}, reason={error_message}, timestamp={timestamp}, signature={signature}, signature.len()={signature_length}, body.len()={}, body.hex={body_hex}, body.base64={body_base64}, events.len()=unavailable, event_type=unavailable",
                response.status(),
                body.len(),
            );
            response
        }
    }
}

fn event_type_label(event_type: i32) -> String {
    match EventType::try_from(event_type) {
        Ok(event_type) => format!("{event_type:?}({})", event_type as i32),
        Err(_) => format!("Unknown({event_type})"),
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map_or(String::from("unavailable"), ToOwned::to_owned)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv().ok();

    let public_key = parse_public_key(&env::var("MIXI2_WEBHOOK_PUBLIC_KEY")?)?;
    let address: SocketAddr = env::var("MIXI2_WEBHOOK_ADDR")?.parse()?;

    let handler = Arc::new(PrintHandler);
    let service = WebhookService::new(public_key, Arc::clone(&handler));
    let state = AppState { handler, service };
    let app = Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/events", post(webhook_handler))
        .layer(middleware::from_fn(log_non_event_requests))
        .with_state(state);
    let listener = TcpListener::bind(address).await?;
    println!("webhook server listening on http://{address}");
    axum::serve(listener, app).await?;

    Ok(())
}
