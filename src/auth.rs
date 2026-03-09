//! Authentication support for the mixi2 Rust SDK.

use std::{
    error::Error,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use oauth2::{
    ClientId, ClientSecret, TokenResponse, TokenUrl, basic::BasicClient,
    reqwest::Client as HttpClient, url::ParseError,
};
use tokio::sync::Mutex;
use tonic::metadata::{MetadataMap, MetadataValue, errors::InvalidMetadataValue};

const EXPIRY_BUFFER: Duration = Duration::from_secs(60);

/// Errors returned by the mixi2 authentication layer.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("token URL is invalid")]
    InvalidTokenUrl(#[source] ParseError),
    #[error("failed to request access token")]
    RequestToken(#[source] Box<dyn Error + Send + Sync>),
    #[error("authorization metadata contains invalid ASCII")]
    InvalidMetadata(#[source] InvalidMetadataValue),
}

impl AuthError {
    fn request_token<E>(error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::RequestToken(Box::new(error))
    }
}

/// Async token provider used by the gRPC wrappers in this workspace.
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Returns a valid access token, refreshing it when the cached token is expired.
    async fn access_token(&self) -> Result<String, AuthError>;

    /// Inserts the required authentication metadata for a gRPC request.
    async fn authorize(&self, metadata: &mut MetadataMap) -> Result<(), AuthError>;
}

/// Builder for a client-credentials authenticator.
#[derive(Clone, Debug)]
pub struct AuthenticatorBuilder {
    auth_key: Option<String>,
    client_id: String,
    client_secret: String,
    http_client: Option<HttpClient>,
    token_url: String,
}

impl AuthenticatorBuilder {
    /// Creates a new builder for the given `OAuth2` client credentials.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        Self {
            auth_key: None,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            http_client: None,
            token_url: token_url.into(),
        }
    }

    /// Adds the optional `x-auth-key` metadata to authorized requests.
    #[must_use]
    pub fn auth_key(mut self, auth_key: impl Into<String>) -> Self {
        self.auth_key = Some(auth_key.into());
        self
    }

    /// Uses the provided reusable reqwest client for token requests.
    #[must_use]
    pub fn http_client(mut self, http_client: HttpClient) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Builds the authenticator and performs the initial token acquisition.
    ///
    /// # Errors
    ///
    /// Returns an error when the token URL is invalid or the initial token
    /// request fails.
    pub async fn build(self) -> Result<ClientCredentialsAuthenticator, AuthError> {
        let authenticator = ClientCredentialsAuthenticator {
            inner: Arc::new(Inner {
                auth_key: self.auth_key,
                client_id: self.client_id,
                client_secret: self.client_secret,
                http_client: self.http_client.unwrap_or_default(),
                state: Mutex::new(TokenState::default()),
                token_url: self.token_url,
            }),
        };

        let _token = authenticator.access_token().await?;

        Ok(authenticator)
    }
}

/// `OAuth2` client-credentials authenticator for the mixi2 API.
#[derive(Clone, Debug)]
pub struct ClientCredentialsAuthenticator {
    inner: Arc<Inner>,
}

impl ClientCredentialsAuthenticator {
    /// Creates a new builder for the given `OAuth2` client credentials.
    #[must_use]
    pub fn builder(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        token_url: impl Into<String>,
    ) -> AuthenticatorBuilder {
        AuthenticatorBuilder::new(client_id, client_secret, token_url)
    }

    /// Builds an authenticator and performs the initial token acquisition.
    ///
    /// # Errors
    ///
    /// Returns an error when the token URL is invalid or the initial token
    /// request fails.
    pub async fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Result<Self, AuthError> {
        Self::builder(client_id, client_secret, token_url)
            .build()
            .await
    }
}

#[async_trait]
impl Authenticator for ClientCredentialsAuthenticator {
    async fn access_token(&self) -> Result<String, AuthError> {
        self.inner.access_token().await
    }

    async fn authorize(&self, metadata: &mut MetadataMap) -> Result<(), AuthError> {
        let access_token = self.access_token().await?;
        let authorization = format!("Bearer {access_token}");
        let authorization =
            MetadataValue::try_from(authorization).map_err(AuthError::InvalidMetadata)?;
        metadata.insert("authorization", authorization);

        if let Some(auth_key) = &self.inner.auth_key {
            let auth_key =
                MetadataValue::try_from(auth_key.as_str()).map_err(AuthError::InvalidMetadata)?;
            metadata.insert("x-auth-key", auth_key);
        }

        Ok(())
    }
}

#[derive(Debug)]
struct Inner {
    auth_key: Option<String>,
    client_id: String,
    client_secret: String,
    http_client: HttpClient,
    state: Mutex<TokenState>,
    token_url: String,
}

impl Inner {
    async fn access_token(&self) -> Result<String, AuthError> {
        let mut state = self.state.lock().await;
        if let Some(access_token) = state.cached_token() {
            return Ok(access_token.to_owned());
        }

        let client = BasicClient::new(ClientId::new(self.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.client_secret.clone()))
            .set_token_uri(
                TokenUrl::new(self.token_url.clone()).map_err(AuthError::InvalidTokenUrl)?,
            );

        let token = client
            .exchange_client_credentials()
            .request_async(&self.http_client)
            .await
            .map_err(AuthError::request_token)?;

        let access_token = token.access_token().secret().to_owned();
        state.access_token = Some(access_token.clone());
        state.buffered_expires_at = token
            .expires_in()
            .map(|duration| Instant::now() + duration.saturating_sub(EXPIRY_BUFFER));
        drop(state);

        Ok(access_token)
    }
}

#[derive(Debug, Default)]
struct TokenState {
    access_token: Option<String>,
    buffered_expires_at: Option<Instant>,
}

impl TokenState {
    fn cached_token(&self) -> Option<&str> {
        match (&self.access_token, self.buffered_expires_at) {
            (Some(access_token), Some(expires_at)) if Instant::now() < expires_at => {
                Some(access_token.as_str())
            }
            (Some(access_token), None) => Some(access_token.as_str()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::{Authenticator, AuthenticatorBuilder, ClientCredentialsAuthenticator};
    use axum::{
        Json, Router,
        extract::State,
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::post,
    };
    use serde_json::{Value, json};
    use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle, time::sleep};
    use tonic::metadata::MetadataMap;

    #[derive(Clone, Debug)]
    struct ResponseSpec {
        body: Value,
        status: StatusCode,
    }

    #[derive(Clone, Debug)]
    struct TokenServerState {
        call_count: Arc<AtomicUsize>,
        responses: Arc<Mutex<VecDeque<ResponseSpec>>>,
    }

    #[derive(Debug)]
    struct TestServer {
        _task: JoinHandle<()>,
        call_count: Arc<AtomicUsize>,
        token_url: String,
    }

    impl TestServer {
        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    async fn token_handler(State(state): State<TokenServerState>) -> Response {
        state.call_count.fetch_add(1, Ordering::SeqCst);
        let response = {
            let mut responses = state.responses.lock().await;
            responses.pop_front().unwrap_or_else(|| ResponseSpec {
                body: json!({
                    "access_token": "test-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }),
                status: StatusCode::OK,
            })
        };

        (response.status, Json(response.body)).into_response()
    }

    async fn spawn_token_server(responses: Vec<ResponseSpec>) -> TestServer {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => panic!("failed to bind test server: {error}"),
        };
        let address = match listener.local_addr() {
            Ok(address) => address,
            Err(error) => panic!("failed to read local addr: {error}"),
        };
        let state = TokenServerState {
            call_count: Arc::new(AtomicUsize::new(0)),
            responses: Arc::new(Mutex::new(VecDeque::from(responses))),
        };
        let call_count = Arc::clone(&state.call_count);
        let app = Router::new()
            .route("/token", post(token_handler))
            .with_state(state);
        let task = tokio::spawn(async move {
            let result = axum::serve(listener, app).await;
            assert!(result.is_ok(), "test server failed: {result:?}");
        });

        TestServer {
            _task: task,
            call_count,
            token_url: format!("http://{address}/token"),
        }
    }

    fn success_response(access_token: &str, expires_in: u64) -> ResponseSpec {
        ResponseSpec {
            body: json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
            }),
            status: StatusCode::OK,
        }
    }

    fn error_response() -> ResponseSpec {
        ResponseSpec {
            body: json!({
                "error": "invalid_client",
                "error_description": "Client authentication failed",
            }),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    async fn build_authenticator(server: &TestServer) -> ClientCredentialsAuthenticator {
        match AuthenticatorBuilder::new("client-id", "client-secret", &server.token_url)
            .build()
            .await
        {
            Ok(authenticator) => authenticator,
            Err(error) => panic!("failed to build authenticator: {error}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_authenticator_fetches_initial_token() {
        let server = spawn_token_server(vec![success_response("test-access-token", 3600)]).await;

        let authenticator =
            ClientCredentialsAuthenticator::new("client-id", "client-secret", &server.token_url)
                .await;

        assert!(authenticator.is_ok());
        assert_eq!(server.call_count(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_authenticator_returns_initial_error() {
        let server = spawn_token_server(vec![error_response()]).await;

        let authenticator =
            ClientCredentialsAuthenticator::new("client-id", "client-secret", &server.token_url)
                .await;

        assert!(authenticator.is_err());
        assert_eq!(server.call_count(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn access_token_uses_cached_token() {
        let server = spawn_token_server(vec![success_response("test-access-token", 3600)]).await;
        let authenticator = build_authenticator(&server).await;

        let token_1 = authenticator.access_token().await;
        let token_2 = authenticator.access_token().await;

        assert!(matches!(token_1.as_deref(), Ok("test-access-token")));
        assert!(matches!(token_2.as_deref(), Ok("test-access-token")));
        assert_eq!(server.call_count(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authorize_adds_bearer_metadata() {
        let server = spawn_token_server(vec![success_response("test-access-token", 3600)]).await;
        let authenticator = build_authenticator(&server).await;
        let mut metadata = MetadataMap::new();

        let result = authenticator.authorize(&mut metadata).await;

        assert!(result.is_ok());
        let authorization = metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        assert_eq!(authorization, Some("Bearer test-access-token"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authorize_adds_optional_auth_key() {
        let server = spawn_token_server(vec![success_response("test-access-token", 3600)]).await;
        let authenticator =
            match AuthenticatorBuilder::new("client-id", "client-secret", &server.token_url)
                .auth_key("test-auth-key")
                .build()
                .await
            {
                Ok(authenticator) => authenticator,
                Err(error) => panic!("failed to build authenticator: {error}"),
            };
        let mut metadata = MetadataMap::new();

        let result = authenticator.authorize(&mut metadata).await;

        assert!(result.is_ok());
        let authorization = metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        let auth_key = metadata
            .get("x-auth-key")
            .and_then(|value| value.to_str().ok());
        assert_eq!(authorization, Some("Bearer test-access-token"));
        assert_eq!(auth_key, Some("test-auth-key"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn access_token_refreshes_after_buffered_expiry() {
        let server = spawn_token_server(vec![
            success_response("initial-token", 1),
            success_response("refreshed-token", 3600),
        ])
        .await;
        let authenticator = build_authenticator(&server).await;

        sleep(Duration::from_secs(2)).await;
        let token = authenticator.access_token().await;

        assert!(matches!(token.as_deref(), Ok("refreshed-token")));
        assert_eq!(server.call_count(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_refresh_is_serialized() {
        let server = spawn_token_server(vec![
            success_response("initial-token", 1),
            success_response("refreshed-token", 3600),
        ])
        .await;
        let authenticator = build_authenticator(&server).await;

        sleep(Duration::from_secs(2)).await;

        let auth_1 = authenticator.clone();
        let auth_2 = authenticator.clone();
        let task_1 = tokio::spawn(async move { auth_1.access_token().await });
        let task_2 = tokio::spawn(async move { auth_2.access_token().await });
        let token_1 = match task_1.await {
            Ok(result) => result,
            Err(error) => panic!("task failed: {error}"),
        };
        let token_2 = match task_2.await {
            Ok(result) => result,
            Err(error) => panic!("task failed: {error}"),
        };

        assert!(matches!(token_1.as_deref(), Ok("refreshed-token")));
        assert!(matches!(token_2.as_deref(), Ok("refreshed-token")));
        assert_eq!(server.call_count(), 2);
    }
}
