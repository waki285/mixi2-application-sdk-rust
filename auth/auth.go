// Package auth provides OAuth2 Client Credentials authentication for the mixi2 API.
package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc/metadata"
)

// Authenticator manages OAuth2 access tokens for API authentication.
// It handles token acquisition, caching, and automatic refresh.
type Authenticator interface {
	// GetAccessToken returns a valid access token, refreshing if necessary.
	GetAccessToken(ctx context.Context) (string, error)

	// AuthorizedContext returns a new context with authorization metadata for gRPC requests.
	AuthorizedContext(ctx context.Context) (context.Context, error)
}

type authenticator struct {
	config              *clientcredentials.Config
	authenticatorConfig *AuthenticatorConfig
	mu                  sync.Mutex
	accessToken         string
	bufferedExpiresAt   *time.Time
	authKey             string
}

// AuthenticatorConfig holds optional configuration for the Authenticator.
type AuthenticatorConfig struct {
	AuthKey string
}

// AuthenticatorOption is a function that configures an AuthenticatorConfig.
type AuthenticatorOption func(*AuthenticatorConfig) *AuthenticatorConfig

// WithAuthKey sets an optional authentication key header for requests.
func WithAuthKey(authKey string) AuthenticatorOption {
	return func(c *AuthenticatorConfig) *AuthenticatorConfig {
		c.AuthKey = authKey
		return c
	}
}

// NewAuthenticator creates a new Authenticator with the given OAuth2 Client Credentials.
//
// The clientSecret should be loaded from secure sources (environment variables,
// secret managers) and not hardcoded in source code.
//
// Returns an error if the initial token acquisition fails.
func NewAuthenticator(clientID, clientSecret, tokenURL string, options ...AuthenticatorOption) (Authenticator, error) {
	aConfig := &AuthenticatorConfig{}
	for _, option := range options {
		aConfig = option(aConfig)
	}
	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		Scopes:       []string{},
		AuthStyle:    oauth2.AuthStyleInHeader,
	}
	auth := &authenticator{
		config:  config,
		mu:      sync.Mutex{},
		authKey: aConfig.AuthKey,
	}
	_, err := auth.GetAccessToken(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to acquire initial access token: %w", err)
	}
	return auth, nil
}

func (a *authenticator) GetAccessToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bufferedExpiresAt != nil && time.Now().Before(*a.bufferedExpiresAt) {
		return a.accessToken, nil
	}
	token, err := a.config.Token(ctx)
	if err != nil {
		return "", err
	}
	a.accessToken = token.AccessToken
	newBufferedExpiresAt := token.Expiry.Add(-time.Minute)
	a.bufferedExpiresAt = &newBufferedExpiresAt
	return token.AccessToken, nil
}

func (a *authenticator) AuthorizedContext(ctx context.Context) (context.Context, error) {
	accessToken, err := a.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	if len(a.authKey) > 0 {
		md := metadata.New(map[string]string{"x-auth-key": a.authKey})
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	ctxWithAT := metadata.AppendToOutgoingContext(ctx, "Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return ctxWithAT, nil
}
