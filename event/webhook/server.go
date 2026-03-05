// Package webhook provides an HTTP server for receiving webhook events from mixi2.
//
// The server verifies event signatures using Ed25519 and validates timestamps
// to prevent replay attacks.
package webhook

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/mixigroup/mixi2-application-sdk-go/event"
	constv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/const/v1"
	modelv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/model/v1"
	client_endpointv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/service/client_endpoint/v1"
	"google.golang.org/protobuf/proto"
)

const (
	// timestampTolerance is the maximum allowed difference (in seconds) between
	// the event timestamp and the current time. Events outside this range are rejected.
	timestampTolerance = 300
)

type handler struct {
	eventHandler event.EventHandler
	publicKey    ed25519.PublicKey
	logger       *slog.Logger
	syncHandling bool
}

func (h *handler) ReceiveEvent(w http.ResponseWriter, req *http.Request) {
	signatureBase64 := req.Header.Get("x-mixi2-application-event-signature")
	if signatureBase64 == "" {
		http.Error(w, "missing x-mixi2-application-event-signature", http.StatusUnauthorized)
		return
	}
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		http.Error(w, "x-mixi2-application-event-signature is invalid", http.StatusUnauthorized)
		return
	}
	timestamp := req.Header.Get("x-mixi2-application-event-timestamp")
	if timestamp == "" {
		http.Error(w, "missing x-mixi2-application-event-timestamp", http.StatusUnauthorized)
		return
	} else {
		unixTime, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			http.Error(w, "x-mixi2-application-event-timestamp is invalid", http.StatusUnauthorized)
			return
		}
		diff := time.Now().Unix() - unixTime
		if diff > timestampTolerance {
			http.Error(w, "x-mixi2-application-event-timestamp is too old", http.StatusUnauthorized)
			return
		}
		if diff < -timestampTolerance {
			http.Error(w, "x-mixi2-application-event-timestamp is in the future", http.StatusUnauthorized)
			return
		}
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer req.Body.Close()

	dataToVerify := append(body, []byte(timestamp)...)

	if !ed25519.Verify(h.publicKey, dataToVerify, signature) {
		http.Error(w, "Signature is invalid", http.StatusUnauthorized)
		return
	}

	var eventRequest client_endpointv1.SendEventRequest
	if err := proto.Unmarshal(body, &eventRequest); err != nil {
		http.Error(w, "Failed to parse request body", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)

	for _, ev := range eventRequest.Events {
		switch ev.EventType {
		case constv1.EventType_EVENT_TYPE_PING:
			continue
		default:
			if h.syncHandling {
				if err := h.eventHandler.Handle(context.Background(), ev); err != nil {
					h.logger.Error("failed to handle event", slog.Any("error", err))
				}
			} else {
				go func(event *modelv1.Event) {
					if err := h.eventHandler.Handle(context.Background(), event); err != nil {
						h.logger.Error("failed to handle event", slog.Any("error", err))
					}
				}(ev)
			}
		}
	}
}

// Server is an HTTP server that receives webhook events from mixi2.
type Server struct {
	server       *http.Server
	logger       *slog.Logger
	eventHandler *handler
	syncHandling bool
}

// Option is a function that configures a Server.
type Option func(*Server)

// WithLogger sets a custom logger for the server.
// If not provided, slog.Default() is used.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

// WithSyncEventHandling configures the server to handle events synchronously.
// By default, events are handled asynchronously in goroutines so that the
// HTTP response (204) is returned immediately. In serverless environments
// (e.g. Vercel, AWS Lambda), the function may be terminated after the response
// is sent, preventing async goroutines from completing. Use this option to
// ensure event handling completes before the function exits.
func WithSyncEventHandling() Option {
	return func(s *Server) {
		s.syncHandling = true
	}
}

// Start starts the HTTP server and blocks until the server stops.
// Returns an error if the server fails to start or encounters an error while running.
func (s *Server) Start() error {
	s.logger.Info("server starting", slog.String("addr", s.server.Addr))
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server without interrupting any active connections.
// It waits for active connections to finish or for the context to be canceled.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("server shutting down")
	return s.server.Shutdown(ctx)
}

// Addr returns the server's listening address.
func (s *Server) Addr() string {
	return s.server.Addr
}

// Handler returns the server's http.Handler.
// This is useful for serverless environments (e.g. Vercel) where you need
// to pass the handler directly instead of starting a full HTTP server.
func (s *Server) Handler() http.Handler {
	return s.server.Handler
}

// EventHandlerFunc returns the webhook event handler as an http.HandlerFunc.
// Unlike Handler(), this does not use a ServeMux and can be called directly
// without path matching. This is useful for serverless platforms where the
// routing is handled externally.
func (s *Server) EventHandlerFunc() http.HandlerFunc {
	return s.eventHandler.ReceiveEvent
}

// NewServer creates a new webhook server.
//
// The publicKey is used to verify event signatures.
// The eventHandler is called for each received event (except ping events).
// The addr should include host and port (for example, ":8080" or "127.0.0.1:8080").
func NewServer(
	addr string,
	publicKey ed25519.PublicKey,
	eventHandler event.EventHandler,
	opts ...Option,
) *Server {
	s := &Server{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}

	h := &handler{
		eventHandler: eventHandler,
		publicKey:    publicKey,
		logger:       s.logger,
		syncHandling: s.syncHandling,
	}
	s.eventHandler = h

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/events", h.ReceiveEvent)

	server := http.Server{
		Addr:    addr,
		Handler: mux,
	}

	s.server = &server
	return s
}
