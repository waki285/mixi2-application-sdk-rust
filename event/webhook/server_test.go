package webhook_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/mixigroup/mixi2-application-sdk-go/event/eventtest"
	"github.com/mixigroup/mixi2-application-sdk-go/event/testutil"
	"github.com/mixigroup/mixi2-application-sdk-go/event/webhook"
	constv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/const/v1"
	modelv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/model/v1"
	client_endpointv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/service/client_endpoint/v1"
	"google.golang.org/protobuf/proto"
)

func getFreeAddr(t *testing.T) string {
	t.Helper()

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()
	return addr
}

func startTestServer(t *testing.T, srv *webhook.Server, addr string) string {
	t.Helper()

	// Start server in background
	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			t.Logf("server error: %v", err)
		}
	}()

	// Wait for server to start
	baseURL := "http://" + addr
	for i := 0; i < 50; i++ {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Stop server
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})

	return baseURL
}

func TestServer_MissingSignature(t *testing.T) {
	publicKey, _ := testutil.GenerateKeyPair(t)
	addr := getFreeAddr(t)
	srv := webhook.NewServer(addr, publicKey, &eventtest.MockEventHandler{})
	baseURL := startTestServer(t, srv, addr)

	resp, err := http.Post(baseURL+"/events", "application/octet-stream", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestServer_MissingTimestamp(t *testing.T) {
	publicKey, privateKey := testutil.GenerateKeyPair(t)
	addr := getFreeAddr(t)
	srv := webhook.NewServer(addr, publicKey, &eventtest.MockEventHandler{})
	baseURL := startTestServer(t, srv, addr)

	body := []byte("test body")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := testutil.SignRequest(body, timestamp, privateKey)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/events", bytes.NewReader(body))
	req.Header.Set("x-mixi2-application-event-signature", signature)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestServer_TimestampTooOld(t *testing.T) {
	publicKey, privateKey := testutil.GenerateKeyPair(t)
	addr := getFreeAddr(t)
	srv := webhook.NewServer(addr, publicKey, &eventtest.MockEventHandler{})
	baseURL := startTestServer(t, srv, addr)

	body := []byte("test body")
	oldTimestamp := strconv.FormatInt(time.Now().Unix()-400, 10)
	signature := testutil.SignRequest(body, oldTimestamp, privateKey)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/events", bytes.NewReader(body))
	req.Header.Set("x-mixi2-application-event-signature", signature)
	req.Header.Set("x-mixi2-application-event-timestamp", oldTimestamp)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestServer_InvalidSignature(t *testing.T) {
	publicKey, _ := testutil.GenerateKeyPair(t)
	_, wrongPrivateKey := testutil.GenerateKeyPair(t) // Generate different key pair
	addr := getFreeAddr(t)
	srv := webhook.NewServer(addr, publicKey, &eventtest.MockEventHandler{})
	baseURL := startTestServer(t, srv, addr)

	body := []byte("test body")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	// Sign with wrong private key to create invalid signature
	invalidSignature := testutil.SignRequest(body, timestamp, wrongPrivateKey)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/events", bytes.NewReader(body))
	req.Header.Set("x-mixi2-application-event-signature", invalidSignature)
	req.Header.Set("x-mixi2-application-event-timestamp", timestamp)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestServer_ValidRequest(t *testing.T) {
	publicKey, privateKey := testutil.GenerateKeyPair(t)
	mockHandler := &eventtest.MockEventHandler{}
	addr := getFreeAddr(t)
	srv := webhook.NewServer(addr, publicKey, mockHandler)
	baseURL := startTestServer(t, srv, addr)

	eventRequest := &client_endpointv1.SendEventRequest{
		Events: []*modelv1.Event{
			{
				EventType: constv1.EventType_EVENT_TYPE_UNSPECIFIED,
			},
		},
	}
	body, err := proto.Marshal(eventRequest)
	if err != nil {
		t.Fatalf("failed to marshal event request: %v", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := testutil.SignRequest(body, timestamp, privateKey)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/events", bytes.NewReader(body))
	req.Header.Set("x-mixi2-application-event-signature", signature)
	req.Header.Set("x-mixi2-application-event-timestamp", timestamp)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	// Wait for async event handling
	time.Sleep(100 * time.Millisecond)

	if len(mockHandler.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(mockHandler.Events))
	}
}

func TestServer_PingEventIgnored(t *testing.T) {
	publicKey, privateKey := testutil.GenerateKeyPair(t)
	mockHandler := &eventtest.MockEventHandler{}
	addr := getFreeAddr(t)
	srv := webhook.NewServer(addr, publicKey, mockHandler)
	baseURL := startTestServer(t, srv, addr)

	eventRequest := &client_endpointv1.SendEventRequest{
		Events: []*modelv1.Event{
			{
				EventType: constv1.EventType_EVENT_TYPE_PING,
			},
		},
	}
	body, err := proto.Marshal(eventRequest)
	if err != nil {
		t.Fatalf("failed to marshal event request: %v", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := testutil.SignRequest(body, timestamp, privateKey)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/events", bytes.NewReader(body))
	req.Header.Set("x-mixi2-application-event-signature", signature)
	req.Header.Set("x-mixi2-application-event-timestamp", timestamp)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	// Wait for async event handling
	time.Sleep(100 * time.Millisecond)

	if len(mockHandler.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(mockHandler.Events))
	}
}
