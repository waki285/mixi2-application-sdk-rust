//! Event handling support for the mixi2 Rust SDK.

#[cfg(any(feature = "stream", feature = "webhook-core", feature = "testutil"))]
use std::error::Error;
#[cfg(any(feature = "stream", feature = "webhook-core", feature = "testutil"))]
use std::sync::Arc;
#[cfg(feature = "stream")]
use std::time::Duration;
#[cfg(feature = "webhook-axum")]
use std::{io::Error as IoError, net::SocketAddr};
#[cfg(feature = "webhook-core")]
use std::{
    num::ParseIntError,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "stream")]
use crate::auth::{AuthError, Authenticator};
#[cfg(any(feature = "stream", feature = "webhook-axum"))]
use crate::proto::social::mixi::application::r#const::v1::EventType;
#[cfg(any(feature = "stream", feature = "webhook-core", feature = "testutil"))]
use crate::proto::social::mixi::application::model::v1::Event;
#[cfg(feature = "stream")]
use crate::proto::social::mixi::application::service::application_stream::v1::{
    SubscribeEventsRequest, SubscribeEventsResponse,
    application_service_client::ApplicationServiceClient,
};
#[cfg(feature = "webhook-core")]
use crate::proto::social::mixi::application::service::client_endpoint::v1::SendEventRequest;
#[cfg(any(feature = "stream", feature = "webhook-core", feature = "testutil"))]
use async_trait::async_trait;
#[cfg(feature = "webhook-axum")]
use axum::{
    Router,
    body::Bytes,
    extract::State,
    response::{IntoResponse, Response},
    routing::{get, post},
};
#[cfg(any(feature = "webhook-core", feature = "testutil"))]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
#[cfg(feature = "stream")]
use bytes::{Bytes as GrpcBytes, BytesMut};
#[cfg(feature = "webhook-core")]
use ed25519_dalek::{Signature, SignatureError, Verifier, VerifyingKey};
#[cfg(any(feature = "stream", feature = "webhook-core"))]
use http::HeaderMap;
#[cfg(any(feature = "stream", feature = "webhook-axum"))]
use http::StatusCode;
#[cfg(feature = "stream")]
use http::{
    HeaderValue, Method, Request as HttpRequest, Uri,
    header::{CONTENT_TYPE, TE},
};
#[cfg(feature = "stream")]
use http_body_util::{BodyExt, Full};
#[cfg(feature = "stream")]
use hyper::body::Incoming;
#[cfg(feature = "stream")]
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
#[cfg(feature = "stream")]
use hyper_util::{
    client::legacy::{Client as HttpClient, connect::HttpConnector},
    rt::TokioExecutor,
};
#[cfg(any(feature = "stream", feature = "webhook-core"))]
use prost::Message;
#[cfg(any(feature = "stream", feature = "webhook-core"))]
use thiserror::Error;
#[cfg(feature = "webhook-axum")]
use tokio::net::TcpListener;
#[cfg(feature = "stream")]
use tokio::time::sleep;
#[cfg(feature = "stream")]
use tonic::{
    Code, Request, Status,
    body::Body as TransportBody,
    client::GrpcService,
    codec::Streaming,
    codegen::{Body, Bytes as TonicBytes, StdError},
};
#[cfg(any(feature = "stream", feature = "webhook-axum"))]
use tracing::error;
#[cfg(feature = "stream")]
use tracing::{debug, info, warn};

#[cfg(feature = "webhook-axum")]
const EVENTS_PATH: &str = "/events";
#[cfg(feature = "webhook-axum")]
const HEALTH_PATH: &str = "/healthz";
#[cfg(feature = "stream")]
const MAX_RECONNECT_ATTEMPTS: u8 = 3;
// mixi2 stream responses can exceed the default 16 KiB HTTP/2 frame size that tonic advertises.
#[cfg(feature = "stream")]
const HTTP2_MAX_FRAME_SIZE: u32 = (1 << 24) - 1;
#[cfg(feature = "stream")]
const GRPC_FRAME_HEADER_LEN: usize = 5;
#[cfg(feature = "stream")]
const GRPC_ACCEPT_ENCODING_HEADER: &str = "grpc-accept-encoding";
#[cfg(feature = "stream")]
const GRPC_ACCEPT_ENCODING_VALUE: &str = "identity";
#[cfg(feature = "stream")]
const GRPC_CONTENT_TYPE: &str = "application/grpc";
#[cfg(feature = "stream")]
const STREAM_SUBSCRIBE_PATH: &str =
    "/social.mixi.application.service.application_stream.v1.ApplicationService/SubscribeEvents";
#[cfg(feature = "webhook-core")]
const TIMESTAMP_TOLERANCE_SECS: i64 = 300;

#[cfg(any(feature = "stream", feature = "webhook-core", feature = "testutil"))]
/// Boxed error type returned by event handlers.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

#[cfg(any(feature = "stream", feature = "webhook-core", feature = "testutil"))]
/// Async handler for mixi2 events.
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Handles a single event.
    async fn handle(&self, event: &Event) -> Result<(), BoxError>;
}

#[cfg(feature = "webhook-core")]
/// Controls whether webhook events are processed inline or spawned onto Tokio.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DispatchMode {
    /// Returns `204 No Content` and continues processing on background tasks.
    #[default]
    Spawn,
    /// Processes each event before returning from the handler.
    Inline,
}

#[cfg(feature = "webhook-core")]
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

#[cfg(feature = "webhook-axum")]
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

#[cfg(feature = "webhook-axum")]
impl IntoResponse for WebhookError {
    fn into_response(self) -> Response {
        (self.status_code(), self.to_string()).into_response()
    }
}

#[cfg(feature = "stream")]
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

#[cfg(feature = "webhook-core")]
/// Verifies and dispatches incoming webhook requests.
pub struct WebhookService<H> {
    clock: Arc<dyn Clock>,
    dispatch_mode: DispatchMode,
    handler: Arc<H>,
    public_key: VerifyingKey,
}

#[cfg(feature = "webhook-core")]
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

#[cfg(feature = "webhook-core")]
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

    #[cfg(feature = "webhook-axum")]
    /// Builds an Axum router with `/healthz` and `/events`.
    pub fn router(self) -> Router {
        Router::new()
            .route(HEALTH_PATH, get(healthz_handler))
            .route(EVENTS_PATH, post(webhook_handler::<H>))
            .with_state(self)
    }

    #[cfg(feature = "webhook-axum")]
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

    #[cfg(feature = "webhook-axum")]
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

#[cfg(feature = "webhook-axum")]
/// Thin Axum server wrapper for webhook delivery.
pub struct WebhookServer<H> {
    address: SocketAddr,
    service: WebhookService<H>,
}

#[cfg(feature = "webhook-axum")]
impl<H> Clone for WebhookServer<H> {
    fn clone(&self) -> Self {
        Self {
            address: self.address,
            service: self.service.clone(),
        }
    }
}

#[cfg(feature = "webhook-axum")]
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

#[cfg(feature = "stream")]
/// Client abstraction used by the stream watcher.
#[async_trait]
pub trait SubscribeEventsClient: Send {
    /// Starts the event subscription RPC.
    async fn subscribe_events(
        &mut self,
        request: Request<SubscribeEventsRequest>,
    ) -> Result<Box<dyn SubscribeEventsStream + Send>, Status>;
}

#[cfg(feature = "stream")]
/// Async receive abstraction for stream testing.
#[async_trait]
pub trait SubscribeEventsStream: Send {
    /// Receives the next message from the stream.
    async fn recv(&mut self) -> Result<Option<SubscribeEventsResponse>, Status>;
}

#[cfg(feature = "stream")]
#[async_trait]
impl SubscribeEventsStream for Streaming<SubscribeEventsResponse> {
    async fn recv(&mut self) -> Result<Option<SubscribeEventsResponse>, Status> {
        self.message().await
    }
}

#[cfg(feature = "stream")]
#[async_trait]
impl<T> SubscribeEventsClient for ApplicationServiceClient<T>
where
    T: GrpcService<TransportBody> + Send,
    T::Error: Into<StdError>,
    T::Future: Send,
    T::ResponseBody: Body<Data = TonicBytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    async fn subscribe_events(
        &mut self,
        request: Request<SubscribeEventsRequest>,
    ) -> Result<Box<dyn SubscribeEventsStream + Send>, Status> {
        let response = Self::subscribe_events(self, request).await?;
        Ok(Box::new(response.into_inner()))
    }
}

#[cfg(feature = "stream")]
type HttpStreamTransport = HttpClient<HttpsConnector<HttpConnector>, Full<GrpcBytes>>;

#[cfg(feature = "stream")]
pub struct HttpStreamClient {
    client: HttpStreamTransport,
    endpoint: Uri,
}

#[cfg(feature = "stream")]
impl HttpStreamClient {
    fn new(endpoint: Uri) -> Self {
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http2()
            .build();
        let mut builder = HttpClient::builder(TokioExecutor::new());
        builder.http2_only(true);
        builder.http2_max_frame_size(HTTP2_MAX_FRAME_SIZE);

        Self {
            client: builder.build(https),
            endpoint,
        }
    }

    fn subscribe_uri(&self) -> Result<Uri, Status> {
        let mut parts = self.endpoint.clone().into_parts();
        let base_path = parts
            .path_and_query
            .as_ref()
            .map_or("", |path_and_query| path_and_query.path());
        let path = if base_path.is_empty() || base_path == "/" {
            STREAM_SUBSCRIBE_PATH.to_owned()
        } else {
            format!(
                "{}{}",
                base_path.trim_end_matches('/'),
                STREAM_SUBSCRIBE_PATH
            )
        };
        let path_and_query = path.parse().map_err(|error| {
            Status::internal(format!("failed to build subscribe path: {error}"))
        })?;
        parts.path_and_query = Some(path_and_query);

        Uri::from_parts(parts)
            .map_err(|error| Status::internal(format!("failed to build subscribe uri: {error}")))
    }
}

#[cfg(feature = "stream")]
pub fn http_stream_client(endpoint: Uri) -> HttpStreamClient {
    HttpStreamClient::new(endpoint)
}

#[cfg(feature = "stream")]
#[async_trait]
impl SubscribeEventsClient for HttpStreamClient {
    async fn subscribe_events(
        &mut self,
        request: Request<SubscribeEventsRequest>,
    ) -> Result<Box<dyn SubscribeEventsStream + Send>, Status> {
        let uri = self.subscribe_uri()?;
        let (metadata, _extensions, message) = request.into_parts();
        let body = encode_grpc_request(message)?;
        let mut request = HttpRequest::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Full::new(GrpcBytes::from(body)))
            .map_err(|error| {
                Status::internal(format!("failed to build subscribe request: {error}"))
            })?;
        request.headers_mut().extend(metadata.into_headers());
        request
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(GRPC_CONTENT_TYPE));
        request
            .headers_mut()
            .insert(TE, HeaderValue::from_static("trailers"));
        request.headers_mut().insert(
            GRPC_ACCEPT_ENCODING_HEADER,
            HeaderValue::from_static(GRPC_ACCEPT_ENCODING_VALUE),
        );

        let response = self.client.request(request).await.map_err(|error| {
            Status::unknown(format!("stream transport request failed: {error}"))
        })?;

        if response.status() != StatusCode::OK {
            if let Some(status) = Status::from_header_map(response.headers()) {
                return Err(status);
            }
            return Err(map_http_status_without_grpc_status(response.status()));
        }

        validate_grpc_status(response.headers())?;

        Ok(Box::new(HttpGrpcStream {
            body: response.into_body(),
            pending: BytesMut::new(),
        }))
    }
}

#[cfg(feature = "stream")]
struct HttpGrpcStream {
    body: Incoming,
    pending: BytesMut,
}

#[cfg(feature = "stream")]
#[async_trait]
impl SubscribeEventsStream for HttpGrpcStream {
    async fn recv(&mut self) -> Result<Option<SubscribeEventsResponse>, Status> {
        loop {
            if let Some(message) = decode_grpc_response(&mut self.pending)? {
                return Ok(Some(message));
            }

            match self.body.frame().await {
                Some(Ok(frame)) => {
                    let frame = match frame.into_data() {
                        Ok(data) => {
                            self.pending.extend_from_slice(data.as_ref());
                            continue;
                        }
                        Err(frame) => frame,
                    };

                    let trailers = frame.into_trailers().map_err(|_frame| {
                        Status::unknown("received an unexpected non-data HTTP/2 frame")
                    })?;
                    validate_grpc_status(&trailers)?;
                    return Ok(None);
                }
                Some(Err(error)) => {
                    return Err(Status::unknown(format!(
                        "stream response body failed: {error}"
                    )));
                }
                None => {
                    if self.pending.is_empty() {
                        return Ok(None);
                    }

                    return Err(Status::unknown(
                        "stream ended with an incomplete gRPC message",
                    ));
                }
            }
        }
    }
}

#[cfg(feature = "stream")]
/// Watches the gRPC event stream and dispatches events to the provided handler.
pub struct StreamWatcher {
    authenticator: Arc<dyn Authenticator>,
    client: Box<dyn SubscribeEventsClient>,
}

#[cfg(feature = "stream")]
impl StreamWatcher {
    /// Creates a new stream watcher for the given client and authenticator.
    #[must_use]
    pub fn new(
        client: impl SubscribeEventsClient + 'static,
        authenticator: Arc<dyn Authenticator>,
    ) -> Self {
        Self {
            authenticator,
            client: Box::new(client),
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

    async fn connect(
        &mut self,
    ) -> Result<Box<dyn SubscribeEventsStream + Send>, StreamWatcherError> {
        let mut request = Request::new(SubscribeEventsRequest {});
        self.authenticator.authorize(request.metadata_mut()).await?;
        self.client
            .subscribe_events(request)
            .await
            .map_err(StreamWatcherError::Subscribe)
    }

    async fn reconnect(
        &mut self,
    ) -> Result<Box<dyn SubscribeEventsStream + Send>, StreamWatcherError> {
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

#[cfg(feature = "stream")]
fn encode_grpc_request(request: SubscribeEventsRequest) -> Result<Vec<u8>, Status> {
    let message = request.encode_to_vec();
    let message_len = u32::try_from(message.len())
        .map_err(|error| Status::internal(format!("request body is too large: {error}")))?;
    let mut body = Vec::with_capacity(GRPC_FRAME_HEADER_LEN + message.len());
    body.push(0);
    body.extend_from_slice(&message_len.to_be_bytes());
    body.extend_from_slice(&message);
    Ok(body)
}

#[cfg(feature = "stream")]
fn decode_grpc_response(pending: &mut BytesMut) -> Result<Option<SubscribeEventsResponse>, Status> {
    if pending.len() < GRPC_FRAME_HEADER_LEN {
        return Ok(None);
    }

    let header = pending
        .get(..GRPC_FRAME_HEADER_LEN)
        .and_then(|bytes| <&[u8; GRPC_FRAME_HEADER_LEN]>::try_from(bytes).ok())
        .ok_or_else(|| Status::internal("gRPC frame header truncated after length validation"))?;
    let &[compression_flag, len0, len1, len2, len3] = header;

    if compression_flag != 0 {
        return Err(Status::unimplemented(
            "compressed gRPC stream messages are not supported",
        ));
    }

    let message_len = usize::try_from(u32::from_be_bytes([len0, len1, len2, len3]))
        .map_err(|error| Status::internal(format!("failed to parse gRPC frame length: {error}")))?;
    let frame_len = GRPC_FRAME_HEADER_LEN
        .checked_add(message_len)
        .ok_or_else(|| Status::internal("gRPC frame length overflowed usize"))?;

    if pending.len() < frame_len {
        return Ok(None);
    }

    let frame = pending.split_to(frame_len);
    let message = frame
        .get(GRPC_FRAME_HEADER_LEN..)
        .ok_or_else(|| Status::internal("gRPC frame truncated after length validation"))
        .and_then(|body| {
            SubscribeEventsResponse::decode(body).map_err(|error| {
                Status::internal(format!("failed to decode subscribe response: {error}"))
            })
        })?;
    Ok(Some(message))
}

#[cfg(feature = "stream")]
fn validate_grpc_status(headers: &HeaderMap) -> Result<(), Status> {
    if let Some(status) = Status::from_header_map(headers)
        && status.code() != Code::Ok
    {
        return Err(status);
    }

    Ok(())
}

#[cfg(feature = "stream")]
fn map_http_status_without_grpc_status(status_code: StatusCode) -> Status {
    let code = match status_code {
        StatusCode::BAD_REQUEST => Code::Internal,
        StatusCode::UNAUTHORIZED => Code::Unauthenticated,
        StatusCode::FORBIDDEN => Code::PermissionDenied,
        StatusCode::NOT_FOUND => Code::Unimplemented,
        StatusCode::TOO_MANY_REQUESTS
        | StatusCode::BAD_GATEWAY
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::GATEWAY_TIMEOUT => Code::Unavailable,
        _ => Code::Unknown,
    };

    Status::new(
        code,
        format!(
            "grpc-status header missing, mapped from HTTP status code {}",
            status_code.as_u16()
        ),
    )
}

#[cfg(any(feature = "testutil", all(test, feature = "webhook-core")))]
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

#[cfg(feature = "webhook-axum")]
async fn healthz_handler() -> StatusCode {
    StatusCode::OK
}

#[cfg(feature = "webhook-axum")]
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

#[cfg(any(feature = "stream", feature = "webhook-axum"))]
const fn is_ping_event(event: &Event) -> bool {
    event.event_type == EventType::Ping as i32
}

#[cfg(feature = "webhook-core")]
trait Clock: Send + Sync {
    fn unix_timestamp(&self) -> i64;
}

#[cfg(feature = "webhook-core")]
struct SystemClock;

#[cfg(feature = "webhook-core")]
impl Clock for SystemClock {
    fn unix_timestamp(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
            })
    }
}

#[cfg(all(
    test,
    feature = "stream",
    feature = "webhook-core",
    feature = "webhook-axum"
))]
#[expect(
    clippy::tests_outside_test_module,
    reason = "feature-gated tests live in a cfg(all(test, feature = ...)) module"
)]
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
    use bytes::BytesMut;
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
        SubscribeEventsStream, WebhookService, decode_grpc_response, testutil,
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
        async fn subscribe_events(
            &mut self,
            _request: Request<SubscribeEventsRequest>,
        ) -> Result<Box<dyn SubscribeEventsStream + Send>, Status> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            match self.streams.pop_front() {
                Some(Ok(stream)) => Ok(Box::new(stream)),
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

    #[test]
    fn grpc_decoder_waits_for_complete_frame() {
        let response = SubscribeEventsResponse {
            events: vec![event_with_type(EventType::Unspecified)],
        };
        let payload = response.encode_to_vec();
        let payload_len = match u32::try_from(payload.len()) {
            Ok(payload_len) => payload_len,
            Err(error) => panic!("payload length did not fit into u32: {error}"),
        };

        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&payload);

        let mut pending = BytesMut::new();
        let (partial_header, payload_frame) = frame.split_at(4);
        pending.extend_from_slice(partial_header);
        assert!(matches!(decode_grpc_response(&mut pending), Ok(None)));

        pending.extend_from_slice(payload_frame);
        let decoded = decode_grpc_response(&mut pending);

        assert!(matches!(
            decoded,
            Ok(Some(SubscribeEventsResponse { events, .. }))
                if events.len() == 1
                    && events
                        .first()
                        .is_some_and(|event| event.event_type == EventType::Unspecified as i32)
        ));
        assert!(pending.is_empty());
    }

    #[test]
    fn grpc_decoder_rejects_compressed_frames() {
        let mut pending = BytesMut::from(&[1, 0, 0, 0, 0][..]);
        let result = decode_grpc_response(&mut pending);

        assert!(matches!(
            result,
            Err(status) if status.code() == tonic::Code::Unimplemented
        ));
    }
}
