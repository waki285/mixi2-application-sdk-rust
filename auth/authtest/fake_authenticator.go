// Package authtest provides testing utilities for authentication.
package authtest

import (
	"context"

	"github.com/mixigroup/mixi2-application-sdk-go/auth"
)

// FakeAuthenticator is a stub Authenticator implementation for testing.
//
// It returns the configured Token or Err for all calls.
// This is useful for testing code that depends on auth.Authenticator.
type FakeAuthenticator struct {
	// Token is the access token to return from GetAccessToken.
	// Defaults to "test-token" if empty.
	Token string

	// Err is the error to return from GetAccessToken and AuthorizedContext.
	// If nil, no error is returned.
	Err error
}

// GetAccessToken returns the configured Token or Err.
func (a *FakeAuthenticator) GetAccessToken(ctx context.Context) (string, error) {
	if a.Err != nil {
		return "", a.Err
	}
	if a.Token == "" {
		return "test-token", nil
	}
	return a.Token, nil
}

// AuthorizedContext returns the context as-is or Err.
// Note: This simplified implementation does not add metadata to the context.
// For tests that need to verify metadata, use a real Authenticator with httptest.
func (a *FakeAuthenticator) AuthorizedContext(ctx context.Context) (context.Context, error) {
	if a.Err != nil {
		return nil, a.Err
	}
	return ctx, nil
}

var _ auth.Authenticator = (*FakeAuthenticator)(nil)
