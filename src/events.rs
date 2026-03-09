//! Event handling support for the mixi2 Rust SDK.

use std::{
    error::Error,
    io::Error as IoError,
    net::SocketAddr,
    num::ParseIntError,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    auth::{AuthError, Authenticator},
    proto::social::mixi::application::{
        r#const::v1::EventType,
        model::v1::Event,
        service::{
            application_stream::v1::{
                SubscribeEventsRequest, SubscribeEventsResponse,
                application_service_client::ApplicationServiceClient,
            },
            client_endpoint::v1::SendEventRequest,
        },
    },
};
use async_trait::async_trait;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature, SignatureError, Verifier, VerifyingKey};
use prost::Message;
use thiserror::Error;
use tokio::{net::TcpListener, time::sleep};
use tonic::{
    Request, Response as TonicResponse, Status,
    body::Body as TransportBody,
    client::GrpcService,
    codec::Streaming,
    codegen::{Body, Bytes as TonicBytes, StdError},
};
use tracing::{debug, error, info, warn};

const EVENTS_PATH: &str = "/events";
const HEALTH_PATH: &str = "/healthz";
const MAX_RECONNECT_ATTEMPTS: u8 = 3;
const TIMESTAMP_TOLERANCE_SECS: i64 = 300;

/// Boxed error type returned by event handlers.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Async handler for mixi2 events.
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Handles a single event.
    async fn handle(&self, event: &Event) -> Result<(), BoxError>;
}

/// Controls whether webhook events are processed inline or spawned onto Tokio.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DispatchMode {
    /// Returns `204 No Content` and continues processing on background tasks.
    #[default]
    Spawn,
    /// Processes each event before returning from the handler.
    Inline,
}

/// Errors returned before a webhook request is acknowledged.
#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("missing x-mixi2-application-event-signature")]
    MissingSignature,
    #[error("x-mixi2-application-event-signature is invalid")]
    InvalidSignatureEncoding(#[source] base64::DecodeError),
    #[error("x-mixi2-application-event-signature is invalid")]
    InvalidSignature(#[source] SignatureError),
    #[error("missing x-mixi2-application-event-timestamp")]
    MissingTimestamp,
    #[error("x-mixi2-application-event-timestamp is invalid")]
    InvalidTimestamp(#[source] ParseIntError),
    #[error("x-mixi2-application-event-timestamp is too old")]
    TimestampTooOld,
    #[error("x-mixi2-application-event-timestamp is in the future")]
    TimestampInFuture,
    #[error("signature is invalid")]
    SignatureMismatch,
    #[error("failed to parse request body")]
    InvalidBody(#[source] prost::DecodeError),
}

impl WebhookError {
    const fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidBody(_) => StatusCode::BAD_REQUEST,
            Self::MissingSignature
            | Self::InvalidSignatureEncoding(_)
            | Self::InvalidSignature(_)
            | Self::MissingTimestamp
            | Self::InvalidTimestamp(_)
            | Self::TimestampTooOld
            | Self::TimestampInFuture
            | Self::SignatureMismatch => StatusCode::UNAUTHORIZED,
        }
    }
}

impl IntoResponse for WebhookError {
    fn into_response(self) -> Response {
        (self.status_code(), self.to_string()).into_response()
    }
}

/// Errors returned by the streaming watcher.
#[derive(Debug, Error)]
pub enum StreamWatcherError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("failed to subscribe to the event stream")]
    Subscribe(#[source] Status),
    #[error("event stream reconnect attempts exhausted")]
    Reconnect(#[source] Status),
}

/// Verifies and dispatches incoming webhook requests.
pub struct WebhookService<H> {
    clock: Arc<dyn Clock>,
    dispatch_mode: DispatchMode,
    handler: Arc<H>,
    public_key: VerifyingKey,
}

impl<H> Clone for WebhookService<H> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            dispatch_mode: self.dispatch_mode,
            handler: Arc::clone(&self.handler),
            public_key: self.public_key,
        }
    }
}

impl<H> WebhookService<H>
where
    H: EventHandler + 'static,
{
    /// Creates a new webhook service using the given verifying key and handler.
    #[must_use]
    pub fn new(public_key: VerifyingKey, handler: Arc<H>) -> Self {
        Self {
            clock: Arc::new(SystemClock),
            dispatch_mode: DispatchMode::Spawn,
            handler,
            public_key,
        }
    }

    /// Overrides the dispatch mode.
    #[must_use]
    pub const fn with_dispatch_mode(mut self, dispatch_mode: DispatchMode) -> Self {
        self.dispatch_mode = dispatch_mode;
        self
    }

    /// Decodes a signed webhook payload after validating the signature and timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when the signature header is missing or invalid, the
    /// timestamp is outside the replay window, or the protobuf payload cannot
    /// be decoded.
    pub fn verify_and_decode(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Vec<Event>, WebhookError> {
        let signature = headers
            .get("x-mixi2-application-event-signature")
            .and_then(|value| value.to_str().ok())
            .ok_or(WebhookError::MissingSignature)?;
        let signature = BASE64_STANDARD
            .decode(signature)
            .map_err(WebhookError::InvalidSignatureEncoding)?;
        let signature =
            Signature::from_slice(&signature).map_err(WebhookError::InvalidSignature)?;

        let timestamp = headers
            .get("x-mixi2-application-event-timestamp")
            .and_then(|value| value.to_str().ok())
            .ok_or(WebhookError::MissingTimestamp)?;
        let timestamp = timestamp
            .parse::<i64>()
            .map_err(WebhookError::InvalidTimestamp)?;
        let now = self.clock.unix_timestamp();
        let diff = now - timestamp;
        if diff > TIMESTAMP_TOLERANCE_SECS {
            return Err(WebhookError::TimestampTooOld);
        }
        if diff < -TIMESTAMP_TOLERANCE_SECS {
            return Err(WebhookError::TimestampInFuture);
        }

        let mut data = Vec::with_capacity(body.len() + 20);
        data.extend_from_slice(body);
        data.extend_from_slice(timestamp.to_string().as_bytes());

        if self.public_key.verify(&data, &signature).is_err() {
            return Err(WebhookError::SignatureMismatch);
        }

        let request = SendEventRequest::decode(body).map_err(WebhookError::InvalidBody)?;
        Ok(request.events)
    }

    /// Builds an Axum router with `/healthz` and `/events`.
    pub fn router(self) -> Router {
        Router::new()
            .route(HEALTH_PATH, get(healthz_handler))
            .route(EVENTS_PATH, post(webhook_handler::<H>))
            .with_state(self)
    }

    async fn dispatch_events(&self, events: Vec<Event>) {
        for event in events {
            if is_ping_event(&event) {
                continue;
            }

            match self.dispatch_mode {
                DispatchMode::Spawn => {
                    let handler = Arc::clone(&self.handler);
                    tokio::spawn(async move {
                        if let Err(error) = handler.handle(&event).await {
                            error!(error = ?error, "failed to handle event");
                        }
                    });
                }
                DispatchMode::Inline => {
                    if let Err(error) = self.handler.handle(&event).await {
                        error!(error = ?error, "failed to handle event");
                    }
                }
            }
        }
    }

    async fn handle_http_request(&self, headers: HeaderMap, body: Bytes) -> Response {
        match self.verify_and_decode(&headers, &body) {
            Ok(events) => {
                self.dispatch_events(events).await;
                StatusCode::NO_CONTENT.into_response()
            }
            Err(error) => error.into_response(),
        }
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

/// Thin Axum server wrapper for webhook delivery.
pub struct WebhookServer<H> {
    address: SocketAddr,
    service: WebhookService<H>,
}

impl<H> Clone for WebhookServer<H> {
    fn clone(&self) -> Self {
        Self {
            address: self.address,
            service: self.service.clone(),
        }
    }
}

impl<H> WebhookServer<H>
where
    H: EventHandler + 'static,
{
    /// Creates a new server that serves the given webhook service.
    #[must_use]
    pub const fn new(address: SocketAddr, service: WebhookService<H>) -> Self {
        Self { address, service }
    }

    /// Returns the Axum router for embedding into another server.
    pub fn router(&self) -> Router {
        self.service.clone().router()
    }

    /// Binds a TCP listener and serves webhook traffic until the task is cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error when the TCP listener cannot be bound or the Axum
    /// server stops with an I/O failure.
    pub async fn serve(self) -> Result<(), IoError> {
        let listener = TcpListener::bind(self.address).await?;
        axum::serve(listener, self.service.router()).await
    }
}

/// Client abstraction used by the stream watcher.
#[async_trait]
pub trait SubscribeEventsClient: Send {
    /// Stream type returned by `subscribe_events`.
    type Stream: SubscribeEventsStream + Send;

    /// Starts the event subscription RPC.
    async fn subscribe_events(
        &mut self,
        request: Request<SubscribeEventsRequest>,
    ) -> Result<TonicResponse<Self::Stream>, Status>;
}

/// Async receive abstraction for stream testing.
#[async_trait]
pub trait SubscribeEventsStream: Send {
    /// Receives the next message from the stream.
    async fn recv(&mut self) -> Result<Option<SubscribeEventsResponse>, Status>;
}

#[async_trait]
impl SubscribeEventsStream for Streaming<SubscribeEventsResponse> {
    async fn recv(&mut self) -> Result<Option<SubscribeEventsResponse>, Status> {
        self.message().await
    }
}

#[async_trait]
impl<T> SubscribeEventsClient for ApplicationServiceClient<T>
where
    T: GrpcService<TransportBody> + Send,
    T::Error: Into<StdError>,
    T::Future: Send,
    T::ResponseBody: Body<Data = TonicBytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    type Stream = Streaming<SubscribeEventsResponse>;

    async fn subscribe_events(
        &mut self,
        request: Request<SubscribeEventsRequest>,
    ) -> Result<TonicResponse<Self::Stream>, Status> {
        Self::subscribe_events(self, request).await
    }
}

/// Watches the gRPC event stream and dispatches events to the provided handler.
pub struct StreamWatcher<C> {
    authenticator: Arc<dyn Authenticator>,
    client: C,
}

impl<C> StreamWatcher<C>
where
    C: SubscribeEventsClient,
{
    /// Creates a new stream watcher for the given client and authenticator.
    #[must_use]
    pub fn new(client: C, authenticator: Arc<dyn Authenticator>) -> Self {
        Self {
            authenticator,
            client,
        }
    }

    /// Watches the stream until the server closes it or reconnect attempts are exhausted.
    ///
    /// # Errors
    ///
    /// Returns an error when the initial subscribe request fails, authentication
    /// fails, or all reconnect attempts are exhausted.
    pub async fn watch<H>(&mut self, handler: Arc<H>) -> Result<(), StreamWatcherError>
    where
        H: EventHandler + 'static,
    {
        let mut stream = self.connect().await?;

        loop {
            match stream.recv().await {
                Ok(Some(response)) => {
                    for event in response.events {
                        if is_ping_event(&event) {
                            debug!("received ping event");
                            continue;
                        }

                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            if let Err(error) = handler.handle(&event).await {
                                error!(error = ?error, "failed to handle event");
                            }
                        });
                    }
                }
                Ok(None) => return Ok(()),
                Err(error) => {
                    debug!(error = ?error, "stream error, attempting reconnect");
                    stream = self.reconnect().await?;
                }
            }
        }
    }

    async fn connect(&mut self) -> Result<C::Stream, StreamWatcherError> {
        let mut request = Request::new(SubscribeEventsRequest {});
        self.authenticator.authorize(request.metadata_mut()).await?;
        let response = self
            .client
            .subscribe_events(request)
            .await
            .map_err(StreamWatcherError::Subscribe)?;
        Ok(response.into_inner())
    }

    async fn reconnect(&mut self) -> Result<C::Stream, StreamWatcherError> {
        let mut last_error = None;

        for attempt in 0..MAX_RECONNECT_ATTEMPTS {
            let delay = Duration::from_secs(1u64 << attempt);
            sleep(delay).await;

            match self.connect().await {
                Ok(stream) => {
                    info!("reconnected to event stream");
                    return Ok(stream);
                }
                Err(error @ StreamWatcherError::Auth(_)) => {
                    return Err(error);
                }
                Err(
                    error @ (StreamWatcherError::Subscribe(_) | StreamWatcherError::Reconnect(_)),
                ) => {
                    warn!(
                        attempt = attempt + 1,
                        max_attempts = MAX_RECONNECT_ATTEMPTS,
                        error = ?error,
                        "reconnect attempt failed"
                    );
                    last_error = Some(error);
                }
            }
        }

        match last_error {
            Some(StreamWatcherError::Subscribe(error) | StreamWatcherError::Reconnect(error)) => {
                Err(StreamWatcherError::Reconnect(error))
            }
            Some(StreamWatcherError::Auth(error)) => Err(StreamWatcherError::Auth(error)),
            None => Err(StreamWatcherError::Reconnect(Status::unknown(
                "reconnect attempts exhausted without an error",
            ))),
        }
    }
}

/// Test helpers that mirror the Go SDK fixtures.
pub mod testutil {
    use std::sync::Arc;

    use crate::proto::social::mixi::application::model::v1::Event;
    use async_trait::async_trait;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use tokio::sync::{Mutex, mpsc};

    use super::{BoxError, EventHandler};

    /// Records every handled event in memory.
    #[derive(Debug, Default)]
    pub struct MockEventHandler {
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl MockEventHandler {
        /// Returns a snapshot of the recorded events.
        pub async fn events(&self) -> Vec<Event> {
            self.events.lock().await.clone()
        }
    }

    #[async_trait]
    impl EventHandler for MockEventHandler {
        async fn handle(&self, event: &Event) -> Result<(), BoxError> {
            self.events.lock().await.push(event.clone());
            Ok(())
        }
    }

    /// Sends handled events into a Tokio channel.
    #[derive(Debug)]
    pub struct ChannelEventHandler {
        sender: mpsc::Sender<Event>,
    }

    impl ChannelEventHandler {
        /// Creates a new handler and its receiver.
        #[must_use]
        pub fn new(buffer: usize) -> (Self, mpsc::Receiver<Event>) {
            let (sender, receiver) = mpsc::channel(buffer);
            (Self { sender }, receiver)
        }
    }

    #[async_trait]
    impl EventHandler for ChannelEventHandler {
        async fn handle(&self, event: &Event) -> Result<(), BoxError> {
            let send_result = self.sender.send(event.clone()).await;
            if let Err(error) = send_result {
                return Err(Box::new(error));
            }
            Ok(())
        }
    }

    /// Generates an Ed25519 signing and verifying key pair for tests.
    #[must_use]
    pub fn generate_keypair() -> (VerifyingKey, SigningKey) {
        let secret = rand::random::<[u8; 32]>();
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    /// Signs a webhook request payload using the Go-compatible `body || timestamp` format.
    #[must_use]
    pub fn sign_request(body: &[u8], timestamp: &str, signing_key: &SigningKey) -> String {
        let mut data = Vec::with_capacity(body.len() + timestamp.len());
        data.extend_from_slice(body);
        data.extend_from_slice(timestamp.as_bytes());
        let signature = signing_key.sign(&data);
        BASE64_STANDARD.encode(signature.to_bytes())
    }
}

async fn healthz_handler() -> StatusCode {
    StatusCode::OK
}

async fn webhook_handler<H>(
    State(service): State<WebhookService<H>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    H: EventHandler + 'static,
{
    service.handle_http_request(headers, body).await
}

const fn is_ping_event(event: &Event) -> bool {
    event.event_type == EventType::Ping as i32
}

trait Clock: Send + Sync {
    fn unix_timestamp(&self) -> i64;
}

struct SystemClock;

impl Clock for SystemClock {
    fn unix_timestamp(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs().cast_signed())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use crate::proto::social::mixi::application::{
        r#const::v1::EventType,
        model::v1::Event,
        service::{
            application_stream::v1::SubscribeEventsResponse, client_endpoint::v1::SendEventRequest,
        },
    };
    use async_trait::async_trait;
    use axum::{
        body::Bytes,
        http::{HeaderMap, StatusCode},
    };
    use ed25519_dalek::SigningKey;
    use prost::Message;
    use tokio::{
        sync::Mutex,
        time::{Duration, sleep, timeout},
    };
    use tonic::{
        Request, Status,
        metadata::{MetadataMap, MetadataValue},
    };

    use super::{
        AuthError, Authenticator, BoxError, Clock, DispatchMode, EventHandler,
        MAX_RECONNECT_ATTEMPTS, StreamWatcher, SubscribeEventsClient, SubscribeEventsRequest,
        SubscribeEventsStream, TonicResponse, WebhookService, testutil,
    };

    #[derive(Debug)]
    struct FixedClock {
        now: i64,
    }

    impl Clock for FixedClock {
        fn unix_timestamp(&self) -> i64 {
            self.now
        }
    }

    #[derive(Debug)]
    struct FakeAuthenticator;

    #[async_trait]
    impl Authenticator for FakeAuthenticator {
        async fn access_token(&self) -> Result<String, AuthError> {
            Ok(String::from("test-token"))
        }

        async fn authorize(&self, metadata: &mut MetadataMap) -> Result<(), AuthError> {
            let value = MetadataValue::try_from("Bearer test-token");
            let value = match value {
                Ok(value) => value,
                Err(error) => panic!("invalid metadata: {error}"),
            };
            metadata.insert("authorization", value);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FailingAuthenticator;

    #[async_trait]
    impl Authenticator for FailingAuthenticator {
        async fn access_token(&self) -> Result<String, AuthError> {
            Err(AuthError::RequestToken(Box::new(io::Error::other(
                "auth failed",
            ))))
        }

        async fn authorize(&self, _metadata: &mut MetadataMap) -> Result<(), AuthError> {
            Err(AuthError::RequestToken(Box::new(io::Error::other(
                "auth failed",
            ))))
        }
    }

    #[derive(Debug)]
    struct FakeStream {
        results: VecDeque<Result<Option<SubscribeEventsResponse>, Status>>,
    }

    #[async_trait]
    impl SubscribeEventsStream for FakeStream {
        async fn recv(&mut self) -> Result<Option<SubscribeEventsResponse>, Status> {
            self.results.pop_front().unwrap_or_else(|| Ok(None))
        }
    }

    #[derive(Debug)]
    struct FakeStreamClient {
        call_count: Arc<AtomicUsize>,
        streams: VecDeque<Result<FakeStream, Status>>,
    }

    #[async_trait]
    impl SubscribeEventsClient for FakeStreamClient {
        type Stream = FakeStream;

        async fn subscribe_events(
            &mut self,
            _request: Request<SubscribeEventsRequest>,
        ) -> Result<TonicResponse<Self::Stream>, Status> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            match self.streams.pop_front() {
                Some(Ok(stream)) => Ok(TonicResponse::new(stream)),
                Some(Err(error)) => Err(error),
                None => Err(Status::unknown("no stream configured")),
            }
        }
    }

    #[derive(Debug)]
    struct RecordingHandler {
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl RecordingHandler {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        async fn len(&self) -> usize {
            self.events.lock().await.len()
        }
    }

    #[async_trait]
    impl EventHandler for RecordingHandler {
        async fn handle(&self, event: &Event) -> Result<(), BoxError> {
            self.events.lock().await.push(event.clone());
            Ok(())
        }
    }

    fn event_with_type(event_type: EventType) -> Event {
        Event {
            event_id: String::from("event-id"),
            event_type: event_type as i32,
            body: None,
        }
    }

    fn signed_headers(timestamp: &str, body: &[u8], signing_key: &SigningKey) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let signature = testutil::sign_request(body, timestamp, signing_key);
        let signature = match signature.parse() {
            Ok(signature) => signature,
            Err(error) => panic!("invalid signature header: {error}"),
        };
        let timestamp = match timestamp.parse() {
            Ok(timestamp) => timestamp,
            Err(error) => panic!("invalid timestamp header: {error}"),
        };
        headers.insert("x-mixi2-application-event-signature", signature);
        headers.insert("x-mixi2-application-event-timestamp", timestamp);
        headers
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn webhook_rejects_missing_signature() {
        let (public_key, _signing_key) = testutil::generate_keypair();
        let service = WebhookService::new(public_key, Arc::new(RecordingHandler::new()));

        let response = service
            .handle_http_request(HeaderMap::new(), Bytes::from_static(b"body"))
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn webhook_rejects_missing_timestamp() {
        let (public_key, signing_key) = testutil::generate_keypair();
        let service = WebhookService::new(public_key, Arc::new(RecordingHandler::new()));
        let body = Bytes::from_static(b"body");
        let mut headers = HeaderMap::new();
        let signature = testutil::sign_request(&body, "1", &signing_key);
        let signature = match signature.parse() {
            Ok(signature) => signature,
            Err(error) => panic!("invalid signature header: {error}"),
        };
        headers.insert("x-mixi2-application-event-signature", signature);

        let response = service.handle_http_request(headers, body).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn webhook_rejects_old_timestamp() {
        let (public_key, signing_key) = testutil::generate_keypair();
        let service = WebhookService::new(public_key, Arc::new(RecordingHandler::new()))
            .with_clock(Arc::new(FixedClock { now: 10_000 }));
        let body = Bytes::from_static(b"body");
        let headers = signed_headers("9500", &body, &signing_key);

        let response = service.handle_http_request(headers, body).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn webhook_rejects_future_timestamp() {
        let (public_key, signing_key) = testutil::generate_keypair();
        let service = WebhookService::new(public_key, Arc::new(RecordingHandler::new()))
            .with_clock(Arc::new(FixedClock { now: 10_000 }));
        let body = Bytes::from_static(b"body");
        let headers = signed_headers("10400", &body, &signing_key);

        let response = service.handle_http_request(headers, body).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn webhook_rejects_invalid_base64_signature() {
        let (public_key, _signing_key) = testutil::generate_keypair();
        let service = WebhookService::new(public_key, Arc::new(RecordingHandler::new()));
        let body = Bytes::from_static(b"body");
        let mut headers = HeaderMap::new();
        let signature = match "!!!not-base64!!!".parse() {
            Ok(signature) => signature,
            Err(error) => panic!("invalid signature header: {error}"),
        };
        let timestamp = match "100".parse() {
            Ok(timestamp) => timestamp,
            Err(error) => panic!("invalid timestamp header: {error}"),
        };
        headers.insert("x-mixi2-application-event-signature", signature);
        headers.insert("x-mixi2-application-event-timestamp", timestamp);

        let response = service.handle_http_request(headers, body).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn webhook_rejects_invalid_signature() {
        let (public_key, _signing_key) = testutil::generate_keypair();
        let (_wrong_public_key, wrong_signing_key) = testutil::generate_keypair();
        let service = WebhookService::new(public_key, Arc::new(RecordingHandler::new()))
            .with_clock(Arc::new(FixedClock { now: 10_000 }));
        let body = Bytes::from_static(b"body");
        let headers = signed_headers("10000", &body, &wrong_signing_key);

        let response = service.handle_http_request(headers, body).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn webhook_rejects_invalid_protobuf_body() {
        let (public_key, signing_key) = testutil::generate_keypair();
        let service = WebhookService::new(public_key, Arc::new(RecordingHandler::new()))
            .with_clock(Arc::new(FixedClock { now: 10_000 }));
        let body = Bytes::from_static(b"not-protobuf");
        let headers = signed_headers("10000", &body, &signing_key);

        let response = service.handle_http_request(headers, body).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn webhook_handles_valid_request() {
        let (public_key, signing_key) = testutil::generate_keypair();
        let handler = Arc::new(RecordingHandler::new());
        let service = WebhookService::new(public_key, Arc::clone(&handler))
            .with_clock(Arc::new(FixedClock { now: 10_000 }));
        let request = SendEventRequest {
            events: vec![event_with_type(EventType::Unspecified)],
        };
        let body = Bytes::from(request.encode_to_vec());
        let headers = signed_headers("10000", &body, &signing_key);

        let response = service.handle_http_request(headers, body).await;
        sleep(Duration::from_millis(50)).await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(handler.len().await, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn webhook_ignores_ping_event() {
        let (public_key, signing_key) = testutil::generate_keypair();
        let handler = Arc::new(RecordingHandler::new());
        let service = WebhookService::new(public_key, Arc::clone(&handler))
            .with_clock(Arc::new(FixedClock { now: 10_000 }));
        let request = SendEventRequest {
            events: vec![event_with_type(EventType::Ping)],
        };
        let body = Bytes::from(request.encode_to_vec());
        let headers = signed_headers("10000", &body, &signing_key);

        let response = service.handle_http_request(headers, body).await;
        sleep(Duration::from_millis(50)).await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(handler.len().await, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn webhook_inline_dispatch_waits_for_handler() {
        let (public_key, signing_key) = testutil::generate_keypair();
        let (channel_handler, mut receiver) = testutil::ChannelEventHandler::new(1);
        let service = WebhookService::new(public_key, Arc::new(channel_handler))
            .with_dispatch_mode(DispatchMode::Inline)
            .with_clock(Arc::new(FixedClock { now: 10_000 }));
        let request = SendEventRequest {
            events: vec![event_with_type(EventType::Unspecified)],
        };
        let body = Bytes::from(request.encode_to_vec());
        let headers = signed_headers("10000", &body, &signing_key);

        let response = service.handle_http_request(headers, body).await;
        let event = timeout(Duration::from_secs(1), receiver.recv()).await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(matches!(event, Ok(Some(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stream_watcher_handles_events_and_ignores_ping() {
        let (channel_handler, mut receiver) = testutil::ChannelEventHandler::new(1);
        let stream = FakeStream {
            results: VecDeque::from([Ok(Some(SubscribeEventsResponse {
                events: vec![
                    event_with_type(EventType::Ping),
                    event_with_type(EventType::Unspecified),
                ],
            }))]),
        };
        let client = FakeStreamClient {
            call_count: Arc::new(AtomicUsize::new(0)),
            streams: VecDeque::from([Ok(stream)]),
        };
        let mut watcher = StreamWatcher::new(client, Arc::new(FakeAuthenticator));

        let result = watcher.watch(Arc::new(channel_handler)).await;
        let event = timeout(Duration::from_secs(1), receiver.recv()).await;

        assert!(result.is_ok());
        assert!(
            matches!(event, Ok(Some(event)) if event.event_type == EventType::Unspecified as i32)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stream_watcher_reconnects_on_error() {
        let (channel_handler, mut receiver) = testutil::ChannelEventHandler::new(1);
        let stream_1 = FakeStream {
            results: VecDeque::from([Err(Status::unknown("stream error"))]),
        };
        let stream_2 = FakeStream {
            results: VecDeque::from([Ok(Some(SubscribeEventsResponse {
                events: vec![event_with_type(EventType::Unspecified)],
            }))]),
        };
        let call_count = Arc::new(AtomicUsize::new(0));
        let client = FakeStreamClient {
            call_count: Arc::clone(&call_count),
            streams: VecDeque::from([Ok(stream_1), Ok(stream_2)]),
        };
        let mut watcher = StreamWatcher::new(client, Arc::new(FakeAuthenticator));

        let result = watcher.watch(Arc::new(channel_handler)).await;
        let event = timeout(Duration::from_secs(2), receiver.recv()).await;

        assert!(result.is_ok());
        assert!(matches!(event, Ok(Some(_))));
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stream_watcher_fails_after_reconnect_budget() {
        let client = FakeStreamClient {
            call_count: Arc::new(AtomicUsize::new(0)),
            streams: VecDeque::from([
                Ok(FakeStream {
                    results: VecDeque::from([Err(Status::unknown("stream error"))]),
                }),
                Err(Status::unknown("connect failed")),
                Err(Status::unknown("connect failed")),
                Err(Status::unknown("connect failed")),
            ]),
        };
        let mut watcher = StreamWatcher::new(client, Arc::new(FakeAuthenticator));
        let handler = Arc::new(RecordingHandler::new());

        let result = watcher.watch(handler).await;

        assert!(matches!(
            result,
            Err(super::StreamWatcherError::Reconnect(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stream_watcher_returns_auth_error() {
        let client = FakeStreamClient {
            call_count: Arc::new(AtomicUsize::new(0)),
            streams: VecDeque::new(),
        };
        let mut watcher = StreamWatcher::new(client, Arc::new(FailingAuthenticator));
        let handler = Arc::new(RecordingHandler::new());

        let result = watcher.watch(handler).await;

        assert!(matches!(result, Err(super::StreamWatcherError::Auth(_))));
    }

    #[test]
    fn stream_watcher_reconnect_budget_matches_go_sdk() {
        assert_eq!(MAX_RECONNECT_ATTEMPTS, 3);
    }
}
