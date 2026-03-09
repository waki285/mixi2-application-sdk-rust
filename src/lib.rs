//! Async Rust SDK for the mixi2 Application API.
//!
//! This crate combines the complete SDK surface into a single package:
//! - OAuth2 client-credentials authentication via [`ClientCredentialsAuthenticator`]
//! - Authenticated unary gRPC access via [`ApiClient`] and [`ApiClientBuilder`]
//! - Webhook and streaming event helpers via [`WebhookService`], [`WebhookServer`], and
//!   [`StreamClientBuilder`]
//! - Raw generated `prost` and `tonic` types under [`social`] plus [`FILE_DESCRIPTOR_SET`]
//!
//! The public API is async-only and designed for Tokio runtimes. Generated protobuf types remain
//! visible so callers can keep full protocol fidelity, while the builders in this crate add
//! validation only where the mixi2 API requires it.
//!
//! # Quick Start
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use mixi2::{
//!     ApiClientBuilder, ClientCredentialsAuthenticator, GetStampsRequestBuilder,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let authenticator = Arc::new(
//!         ClientCredentialsAuthenticator::new(
//!             "client-id",
//!             "client-secret",
//!             "https://mixi2.example.com/oauth/token",
//!         )
//!         .await?,
//!     );
//!
//!     let mut client = ApiClientBuilder::new(authenticator)
//!         .with_endpoint("https://mixi2.example.com")
//!         .build()
//!         .await?;
//!
//!     let _stamps = client
//!         .get_stamps(GetStampsRequestBuilder::new().build())
//!         .await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Raw Protocol Types
//!
//! The generated protobuf and gRPC types are re-exported under [`social`]. Reach for them when you
//! need direct access to the mixi2 schema or an RPC/request shape that does not need a convenience
//! builder.
//!
//! # Event Delivery
//!
//! Use [`WebhookService`] and [`WebhookServer`] for signed webhook delivery, or
//! [`StreamClientBuilder`] together with [`EventHandler`] for long-lived gRPC event streams.

#![cfg_attr(docsrs, feature(doc_cfg))]

use std::sync::Arc;

mod auth;
mod events;
mod proto;

use crate::{
    auth::{AuthError as AuthLayerError, Authenticator as AuthenticatorTrait},
    events::StreamWatcher as EventStreamWatcher,
    proto::social::mixi::application::{
        r#const::v1::{LanguageCode, PostPublishingType},
        model::v1::PostMask,
        service::{
            application_api::v1::{
                self as application_api_v1, AddStampToPostRequest, AddStampToPostResponse,
                CreatePostRequest, CreatePostResponse, GetPostMediaStatusRequest,
                GetPostMediaStatusResponse, GetPostsRequest, GetPostsResponse, GetStampsRequest,
                GetStampsResponse, GetUsersRequest, GetUsersResponse,
                InitiatePostMediaUploadRequest, InitiatePostMediaUploadResponse,
                SendChatMessageRequest, SendChatMessageResponse,
                application_service_client::ApplicationServiceClient as RawApiClient,
            },
            application_stream::v1::application_service_client::ApplicationServiceClient as RawStreamClient,
        },
    },
};
use thiserror::Error;
use tonic::{
    IntoRequest, Request, Response, Status,
    body::Body as TransportBody,
    client::GrpcService,
    codegen::{Body, Bytes as TonicBytes, StdError},
    transport::{Channel, Endpoint, Error as TransportError},
};

pub use crate::auth::{
    AuthError, Authenticator, AuthenticatorBuilder, ClientCredentialsAuthenticator,
};
pub use crate::events::{
    BoxError, DispatchMode, EventHandler, StreamWatcher, StreamWatcherError, WebhookError,
    WebhookServer, WebhookService, testutil,
};
pub use crate::proto::{FILE_DESCRIPTOR_SET, social};

/// Validation errors returned by the high-level request builders.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RequestValidationError {
    #[error("in_reply_to_post_id and quoted_post_id cannot both be set")]
    ConflictingPostTargets,
    #[error("media_id_list can contain at most 4 entries")]
    TooManyMediaIds,
    #[error("room_id must not be empty")]
    EmptyRoomId,
    #[error("post_id must not be empty")]
    EmptyPostId,
    #[error("stamp_id must not be empty")]
    EmptyStampId,
    #[error("send chat message requires text or media_id")]
    MissingChatPayload,
    #[error("content_type must not be empty")]
    EmptyContentType,
    #[error("data_size must be greater than zero")]
    EmptyUploadSize,
    #[error("media_type must not be unspecified")]
    UnspecifiedUploadType,
}

/// Transport setup errors returned by the top-level builders.
#[derive(Debug, Error)]
pub enum ClientBuildError {
    #[error("no transport source was configured")]
    MissingTransport,
    #[error("channel and endpoint are mutually exclusive")]
    ConflictingTransport,
    #[error("failed to configure transport endpoint")]
    Transport(#[source] TransportError),
}

/// Authenticated façade over the raw unary gRPC client.
pub struct ApiClient<T> {
    authenticator: Arc<dyn AuthenticatorTrait>,
    inner: RawApiClient<T>,
}

impl<T> ApiClient<T>
where
    T: GrpcService<TransportBody> + Send + Sync,
    T::Error: Into<StdError>,
    T::Future: Send,
    T::ResponseBody: Body<Data = TonicBytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    /// Creates a new authenticated API client wrapper.
    #[must_use]
    pub fn new(inner: RawApiClient<T>, authenticator: Arc<dyn AuthenticatorTrait>) -> Self {
        Self {
            authenticator,
            inner,
        }
    }

    /// Returns a shared reference to the raw client.
    #[must_use]
    pub const fn inner(&self) -> &RawApiClient<T> {
        &self.inner
    }

    /// Returns a mutable reference to the raw client.
    #[must_use]
    pub const fn inner_mut(&mut self) -> &mut RawApiClient<T> {
        &mut self.inner
    }

    /// Consumes the wrapper and returns the raw client.
    #[must_use]
    pub fn into_inner(self) -> RawApiClient<T> {
        self.inner
    }

    /// Calls `GetUsers`.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` when token acquisition fails, or the RPC status
    /// returned by the upstream server.
    pub async fn get_users(
        &mut self,
        request: impl IntoRequest<GetUsersRequest> + Send,
    ) -> Result<Response<GetUsersResponse>, Status> {
        let request = self.authorize_request(request).await?;
        self.inner.get_users(request).await
    }

    /// Calls `GetPosts`.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` when token acquisition fails, or the RPC status
    /// returned by the upstream server.
    pub async fn get_posts(
        &mut self,
        request: impl IntoRequest<GetPostsRequest> + Send,
    ) -> Result<Response<GetPostsResponse>, Status> {
        let request = self.authorize_request(request).await?;
        self.inner.get_posts(request).await
    }

    /// Calls `CreatePost`.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` when token acquisition fails, or the RPC status
    /// returned by the upstream server.
    pub async fn create_post(
        &mut self,
        request: impl IntoRequest<CreatePostRequest> + Send,
    ) -> Result<Response<CreatePostResponse>, Status> {
        let request = self.authorize_request(request).await?;
        self.inner.create_post(request).await
    }

    /// Calls `InitiatePostMediaUpload`.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` when token acquisition fails, or the RPC status
    /// returned by the upstream server.
    pub async fn initiate_post_media_upload(
        &mut self,
        request: impl IntoRequest<InitiatePostMediaUploadRequest> + Send,
    ) -> Result<Response<InitiatePostMediaUploadResponse>, Status> {
        let request = self.authorize_request(request).await?;
        self.inner.initiate_post_media_upload(request).await
    }

    /// Calls `GetPostMediaStatus`.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` when token acquisition fails, or the RPC status
    /// returned by the upstream server.
    pub async fn get_post_media_status(
        &mut self,
        request: impl IntoRequest<GetPostMediaStatusRequest> + Send,
    ) -> Result<Response<GetPostMediaStatusResponse>, Status> {
        let request = self.authorize_request(request).await?;
        self.inner.get_post_media_status(request).await
    }

    /// Calls `SendChatMessage`.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` when token acquisition fails, or the RPC status
    /// returned by the upstream server.
    pub async fn send_chat_message(
        &mut self,
        request: impl IntoRequest<SendChatMessageRequest> + Send,
    ) -> Result<Response<SendChatMessageResponse>, Status> {
        let request = self.authorize_request(request).await?;
        self.inner.send_chat_message(request).await
    }

    /// Calls `GetStamps`.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` when token acquisition fails, or the RPC status
    /// returned by the upstream server.
    pub async fn get_stamps(
        &mut self,
        request: impl IntoRequest<GetStampsRequest> + Send,
    ) -> Result<Response<GetStampsResponse>, Status> {
        let request = self.authorize_request(request).await?;
        self.inner.get_stamps(request).await
    }

    /// Calls `AddStampToPost`.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` when token acquisition fails, or the RPC status
    /// returned by the upstream server.
    pub async fn add_stamp_to_post(
        &mut self,
        request: impl IntoRequest<AddStampToPostRequest> + Send,
    ) -> Result<Response<AddStampToPostResponse>, Status> {
        let request = self.authorize_request(request).await?;
        self.inner.add_stamp_to_post(request).await
    }

    async fn authorize_request<R: Send>(
        &self,
        request: impl IntoRequest<R> + Send,
    ) -> Result<Request<R>, Status> {
        let mut request = request.into_request();
        self.authenticator
            .authorize(request.metadata_mut())
            .await
            .map_err(|error| auth_error_to_status(&error))?;
        Ok(request)
    }
}

/// Builder for an authenticated unary client.
pub struct ApiClientBuilder {
    authenticator: Arc<dyn AuthenticatorTrait>,
    channel: Option<Channel>,
    endpoint: Option<String>,
}

impl ApiClientBuilder {
    /// Creates a new builder for the given authenticator.
    #[must_use]
    pub fn new(authenticator: Arc<dyn AuthenticatorTrait>) -> Self {
        Self {
            authenticator,
            channel: None,
            endpoint: None,
        }
    }

    /// Injects an already-connected channel.
    #[must_use]
    pub fn with_channel(mut self, channel: Channel) -> Self {
        self.channel = Some(channel);
        self
    }

    /// Connects to the given endpoint when `build` is called.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Builds the authenticated unary client wrapper.
    ///
    /// # Errors
    ///
    /// Returns an error when no transport was configured, when both channel and endpoint
    /// were configured, or when endpoint connection setup fails.
    pub async fn build(self) -> Result<ApiClient<Channel>, ClientBuildError> {
        let channel = resolve_channel(self.channel, self.endpoint).await?;
        let raw_client = RawApiClient::new(channel);
        Ok(ApiClient::new(raw_client, self.authenticator))
    }
}

/// Builder for an authenticated stream watcher.
pub struct StreamClientBuilder {
    authenticator: Arc<dyn AuthenticatorTrait>,
    channel: Option<Channel>,
    endpoint: Option<String>,
}

impl StreamClientBuilder {
    /// Creates a new builder for the given authenticator.
    #[must_use]
    pub fn new(authenticator: Arc<dyn AuthenticatorTrait>) -> Self {
        Self {
            authenticator,
            channel: None,
            endpoint: None,
        }
    }

    /// Injects an already-connected channel.
    #[must_use]
    pub fn with_channel(mut self, channel: Channel) -> Self {
        self.channel = Some(channel);
        self
    }

    /// Connects to the given endpoint when `build` is called.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Builds the stream watcher.
    ///
    /// # Errors
    ///
    /// Returns an error when no transport was configured, when both channel and endpoint
    /// were configured, or when endpoint connection setup fails.
    pub async fn build(
        self,
    ) -> Result<EventStreamWatcher<RawStreamClient<Channel>>, ClientBuildError> {
        let channel = resolve_channel(self.channel, self.endpoint).await?;
        let raw_client = RawStreamClient::new(channel);
        Ok(EventStreamWatcher::new(raw_client, self.authenticator))
    }
}

/// Builder for `CreatePostRequest`.
#[derive(Clone, Debug)]
pub struct CreatePostRequestBuilder {
    request: CreatePostRequest,
}

impl CreatePostRequestBuilder {
    /// Creates a new builder with the required post text field.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            request: CreatePostRequest {
                text: text.into(),
                in_reply_to_post_id: None,
                quoted_post_id: None,
                media_id_list: Vec::new(),
                post_mask: None,
                publishing_type: None,
            },
        }
    }

    /// Sets the reply target.
    #[must_use]
    pub fn in_reply_to_post_id(mut self, post_id: impl Into<String>) -> Self {
        self.request.in_reply_to_post_id = Some(post_id.into());
        self
    }

    /// Sets the quoted post target.
    #[must_use]
    pub fn quoted_post_id(mut self, post_id: impl Into<String>) -> Self {
        self.request.quoted_post_id = Some(post_id.into());
        self
    }

    /// Appends one media identifier.
    #[must_use]
    pub fn push_media_id(mut self, media_id: impl Into<String>) -> Self {
        self.request.media_id_list.push(media_id.into());
        self
    }

    /// Replaces the media identifier list.
    #[must_use]
    pub fn media_ids<I, S>(mut self, media_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.request.media_id_list = media_ids.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the optional post mask.
    #[must_use]
    pub fn post_mask(mut self, post_mask: PostMask) -> Self {
        self.request.post_mask = Some(post_mask);
        self
    }

    /// Sets the optional publishing type.
    #[must_use]
    pub const fn publishing_type(mut self, publishing_type: PostPublishingType) -> Self {
        self.request.publishing_type = Some(publishing_type as i32);
        self
    }

    /// Finalizes the validated request.
    ///
    /// # Errors
    ///
    /// Returns an error when both reply and quote targets are set, or when more than
    /// four media identifiers are attached.
    pub fn build(self) -> Result<CreatePostRequest, RequestValidationError> {
        if self.request.in_reply_to_post_id.is_some() && self.request.quoted_post_id.is_some() {
            return Err(RequestValidationError::ConflictingPostTargets);
        }
        if self.request.media_id_list.len() > 4 {
            return Err(RequestValidationError::TooManyMediaIds);
        }
        Ok(self.request)
    }
}

/// Builder for `SendChatMessageRequest`.
#[derive(Clone, Debug)]
pub struct SendChatMessageRequestBuilder {
    request: SendChatMessageRequest,
}

impl SendChatMessageRequestBuilder {
    /// Creates a new builder with the required room identifier.
    #[must_use]
    pub fn new(room_id: impl Into<String>) -> Self {
        Self {
            request: SendChatMessageRequest {
                room_id: room_id.into(),
                text: None,
                media_id: None,
            },
        }
    }

    /// Sets the message text.
    #[must_use]
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.request.text = Some(text.into());
        self
    }

    /// Sets the optional media attachment.
    #[must_use]
    pub fn media_id(mut self, media_id: impl Into<String>) -> Self {
        self.request.media_id = Some(media_id.into());
        self
    }

    /// Finalizes the validated request.
    ///
    /// # Errors
    ///
    /// Returns an error when `room_id` is empty or both `text` and `media_id` are missing.
    pub fn build(self) -> Result<SendChatMessageRequest, RequestValidationError> {
        if self.request.room_id.is_empty() {
            return Err(RequestValidationError::EmptyRoomId);
        }
        if self.request.text.is_none() && self.request.media_id.is_none() {
            return Err(RequestValidationError::MissingChatPayload);
        }
        Ok(self.request)
    }
}

/// Builder for `InitiatePostMediaUploadRequest`.
#[derive(Clone, Debug)]
pub struct InitiatePostMediaUploadRequestBuilder {
    request: InitiatePostMediaUploadRequest,
}

impl InitiatePostMediaUploadRequestBuilder {
    /// Creates a new builder with the required upload metadata.
    #[must_use]
    pub fn new(
        content_type: impl Into<String>,
        data_size: u64,
        media_type: application_api_v1::initiate_post_media_upload_request::Type,
    ) -> Self {
        Self {
            request: InitiatePostMediaUploadRequest {
                content_type: content_type.into(),
                data_size,
                media_type: media_type as i32,
                description: None,
            },
        }
    }

    /// Sets the optional description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.request.description = Some(description.into());
        self
    }

    /// Finalizes the validated request.
    ///
    /// # Errors
    ///
    /// Returns an error when `content_type` is empty, `data_size` is zero, or the
    /// media type is unspecified.
    pub fn build(self) -> Result<InitiatePostMediaUploadRequest, RequestValidationError> {
        if self.request.content_type.is_empty() {
            return Err(RequestValidationError::EmptyContentType);
        }
        if self.request.data_size == 0 {
            return Err(RequestValidationError::EmptyUploadSize);
        }
        if self.request.media_type
            == application_api_v1::initiate_post_media_upload_request::Type::Unspecified as i32
        {
            return Err(RequestValidationError::UnspecifiedUploadType);
        }
        Ok(self.request)
    }
}

/// Builder for `GetStampsRequest`.
#[derive(Clone, Copy, Debug, Default)]
pub struct GetStampsRequestBuilder {
    request: GetStampsRequest,
}

impl GetStampsRequestBuilder {
    /// Creates a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            request: GetStampsRequest {
                official_stamp_language: None,
            },
        }
    }

    /// Sets the optional official stamp language.
    #[must_use]
    pub const fn official_stamp_language(mut self, language: LanguageCode) -> Self {
        self.request.official_stamp_language = Some(language as i32);
        self
    }

    /// Finalizes the request.
    #[must_use]
    pub const fn build(self) -> GetStampsRequest {
        self.request
    }
}

/// Builder for `AddStampToPostRequest`.
#[derive(Clone, Debug)]
pub struct AddStampToPostRequestBuilder {
    request: AddStampToPostRequest,
}

impl AddStampToPostRequestBuilder {
    /// Creates a new builder with the required identifiers.
    #[must_use]
    pub fn new(post_id: impl Into<String>, stamp_id: impl Into<String>) -> Self {
        Self {
            request: AddStampToPostRequest {
                post_id: post_id.into(),
                stamp_id: stamp_id.into(),
            },
        }
    }

    /// Overrides the target post identifier.
    #[must_use]
    pub fn post_id(mut self, post_id: impl Into<String>) -> Self {
        self.request.post_id = post_id.into();
        self
    }

    /// Overrides the stamp identifier.
    #[must_use]
    pub fn stamp_id(mut self, stamp_id: impl Into<String>) -> Self {
        self.request.stamp_id = stamp_id.into();
        self
    }

    /// Finalizes the validated request.
    ///
    /// # Errors
    ///
    /// Returns an error when either `post_id` or `stamp_id` is empty.
    pub fn build(self) -> Result<AddStampToPostRequest, RequestValidationError> {
        if self.request.post_id.is_empty() {
            return Err(RequestValidationError::EmptyPostId);
        }
        if self.request.stamp_id.is_empty() {
            return Err(RequestValidationError::EmptyStampId);
        }
        Ok(self.request)
    }
}

fn auth_error_to_status(error: &AuthLayerError) -> Status {
    Status::unauthenticated(error.to_string())
}

async fn resolve_channel(
    channel: Option<Channel>,
    endpoint: Option<String>,
) -> Result<Channel, ClientBuildError> {
    match (channel, endpoint) {
        (Some(_), Some(_)) => Err(ClientBuildError::ConflictingTransport),
        (None, None) => Err(ClientBuildError::MissingTransport),
        (Some(channel), None) => Ok(channel),
        (None, Some(endpoint)) => {
            let endpoint = Endpoint::new(endpoint).map_err(ClientBuildError::Transport)?;
            endpoint
                .connect()
                .await
                .map_err(ClientBuildError::Transport)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::social::mixi::application::{
        r#const::v1::{LanguageCode, PostMaskType, PostPublishingType},
        model::v1::PostMask,
        service::application_api::v1::initiate_post_media_upload_request::Type as UploadType,
    };

    use super::{
        AddStampToPostRequestBuilder, CreatePostRequestBuilder, GetStampsRequestBuilder,
        InitiatePostMediaUploadRequestBuilder, RequestValidationError,
        SendChatMessageRequestBuilder,
    };

    #[test]
    fn create_post_builder_rejects_conflicting_targets() {
        let result = CreatePostRequestBuilder::new("hello")
            .in_reply_to_post_id("reply")
            .quoted_post_id("quote")
            .build();

        assert_eq!(result, Err(RequestValidationError::ConflictingPostTargets));
    }

    #[test]
    fn create_post_builder_rejects_too_many_media_ids() {
        let result = CreatePostRequestBuilder::new("hello")
            .media_ids(["1", "2", "3", "4", "5"])
            .build();

        assert_eq!(result, Err(RequestValidationError::TooManyMediaIds));
    }

    #[test]
    fn create_post_builder_accepts_optional_fields() {
        let result = CreatePostRequestBuilder::new("hello")
            .push_media_id("media-id")
            .post_mask(PostMask {
                mask_type: PostMaskType::Sensitive as i32,
                caption: String::from("spoilers"),
            })
            .publishing_type(PostPublishingType::NotPublishing)
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn send_chat_message_builder_requires_payload() {
        let result = SendChatMessageRequestBuilder::new("room-id").build();

        assert_eq!(result, Err(RequestValidationError::MissingChatPayload));
    }

    #[test]
    fn send_chat_message_builder_requires_room_id() {
        let result = SendChatMessageRequestBuilder::new("").text("hello").build();

        assert_eq!(result, Err(RequestValidationError::EmptyRoomId));
    }

    #[test]
    fn initiate_upload_builder_requires_non_empty_content_type() {
        let result = InitiatePostMediaUploadRequestBuilder::new("", 128, UploadType::Image).build();

        assert_eq!(result, Err(RequestValidationError::EmptyContentType));
    }

    #[test]
    fn initiate_upload_builder_requires_non_zero_size() {
        let result =
            InitiatePostMediaUploadRequestBuilder::new("image/png", 0, UploadType::Image).build();

        assert_eq!(result, Err(RequestValidationError::EmptyUploadSize));
    }

    #[test]
    fn initiate_upload_builder_rejects_unspecified_type() {
        let result =
            InitiatePostMediaUploadRequestBuilder::new("image/png", 128, UploadType::Unspecified)
                .build();

        assert_eq!(result, Err(RequestValidationError::UnspecifiedUploadType));
    }

    #[test]
    fn get_stamps_builder_sets_optional_language() {
        let request = GetStampsRequestBuilder::new()
            .official_stamp_language(LanguageCode::En)
            .build();

        assert_eq!(
            request.official_stamp_language,
            Some(LanguageCode::En as i32)
        );
    }

    #[test]
    fn add_stamp_to_post_builder_requires_post_id() {
        let result = AddStampToPostRequestBuilder::new("", "stamp-id").build();

        assert_eq!(result, Err(RequestValidationError::EmptyPostId));
    }

    #[test]
    fn add_stamp_to_post_builder_requires_stamp_id() {
        let result = AddStampToPostRequestBuilder::new("post-id", "").build();

        assert_eq!(result, Err(RequestValidationError::EmptyStampId));
    }

    #[test]
    fn add_stamp_to_post_builder_accepts_identifiers() {
        let result = AddStampToPostRequestBuilder::new("post-id", "stamp-id").build();

        assert!(result.is_ok());
    }
}
