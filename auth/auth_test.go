package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mixigroup/mixi2-application-sdk-go/auth"
	"google.golang.org/grpc/metadata"
)

func TestNewAuthenticator(t *testing.T) {
	// Mock OAuth2 token server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/token" {
			t.Errorf("expected /token path, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	authenticator, err := auth.NewAuthenticator("client-id", "client-secret", server.URL+"/token")
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}
	if authenticator == nil {
		t.Fatal("NewAuthenticator returned nil")
	}
}

func TestNewAuthenticator_Error(t *testing.T) {
	// Mock OAuth2 token server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_client",
			"error_description": "Client authentication failed",
		})
	}))
	defer server.Close()

	_, err := auth.NewAuthenticator("invalid-client", "invalid-secret", server.URL+"/token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAuthenticator_GetAccessToken(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	authenticator, err := auth.NewAuthenticator("client-id", "client-secret", server.URL+"/token")
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	// First call should use cached token from NewAuthenticator
	token, err := authenticator.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}
	if token != "test-access-token" {
		t.Errorf("expected 'test-access-token', got '%s'", token)
	}

	// Second call should also use cached token
	token2, err := authenticator.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}
	if token2 != "test-access-token" {
		t.Errorf("expected 'test-access-token', got '%s'", token2)
	}

	// Should only have called the token endpoint once (during NewAuthenticator)
	if callCount != 1 {
		t.Errorf("expected 1 token request, got %d", callCount)
	}
}

func TestAuthenticator_AuthorizedContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	authenticator, err := auth.NewAuthenticator("client-id", "client-secret", server.URL+"/token")
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	ctx, err := authenticator.AuthorizedContext(context.Background())
	if err != nil {
		t.Fatalf("AuthorizedContext failed: %v", err)
	}
	if ctx == nil {
		t.Fatal("AuthorizedContext returned nil context")
	}

	// Verify Authorization header in metadata
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("no metadata in context")
	}
	authHeaders := md.Get("authorization")
	if len(authHeaders) != 1 || authHeaders[0] != "Bearer test-access-token" {
		t.Errorf("expected 'Bearer test-access-token', got %v", authHeaders)
	}
}

func TestAuthenticator_WithAuthKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	authenticator, err := auth.NewAuthenticator(
		"client-id",
		"client-secret",
		server.URL+"/token",
		auth.WithAuthKey("test-auth-key"),
	)
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	ctx, err := authenticator.AuthorizedContext(context.Background())
	if err != nil {
		t.Fatalf("AuthorizedContext failed: %v", err)
	}
	if ctx == nil {
		t.Fatal("AuthorizedContext returned nil context")
	}

	// Verify Authorization header in metadata
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("no metadata in context")
	}
	authHeaders := md.Get("authorization")
	if len(authHeaders) != 1 || authHeaders[0] != "Bearer test-access-token" {
		t.Errorf("expected 'Bearer test-access-token', got %v", authHeaders)
	}

	// Verify x-auth-key header in metadata
	authKeyHeaders := md.Get("x-auth-key")
	if len(authKeyHeaders) != 1 || authKeyHeaders[0] != "test-auth-key" {
		t.Errorf("expected 'test-auth-key', got %v", authKeyHeaders)
	}
}

func TestAuthenticator_TokenRefresh(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		// Return token that expires immediately
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   1, // 1 second
		})
	}))
	defer server.Close()

	authenticator, err := auth.NewAuthenticator("client-id", "client-secret", server.URL+"/token")
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}

	// Wait for token to expire (plus buffer time)
	time.Sleep(2 * time.Second)

	// This should trigger a token refresh
	_, err = authenticator.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}

	// Should have called the token endpoint twice
	if callCount != 2 {
		t.Errorf("expected 2 token requests, got %d", callCount)
	}
}
