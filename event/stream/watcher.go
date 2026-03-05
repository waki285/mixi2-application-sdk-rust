// Package stream provides gRPC streaming for receiving events from mixi2.
//
// The EventWatcher maintains a persistent connection and automatically reconnects
// on connection failures with exponential backoff.
package stream

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/mixigroup/mixi2-application-sdk-go/auth"
	"github.com/mixigroup/mixi2-application-sdk-go/event"
	constv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/const/v1"
	application_streamv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/service/application_stream/v1"
)

// EventWatcher watches for events from mixi2 via gRPC streaming.
type EventWatcher struct {
	streamClient  application_streamv1.ApplicationServiceClient
	authenticator auth.Authenticator
	logger        *slog.Logger
}

// Option is a function that configures an EventWatcher.
type Option func(*EventWatcher)

// WithLogger sets a custom logger for the watcher.
// If not provided, slog.Default() is used.
func WithLogger(logger *slog.Logger) Option {
	return func(w *EventWatcher) {
		w.logger = logger
	}
}

// NewStreamWatcher creates a new EventWatcher.
//
// The client should be a gRPC client for the ApplicationService.
// The authenticator is used to add authorization headers to the stream.
func NewStreamWatcher(
	client application_streamv1.ApplicationServiceClient,
	authenticator auth.Authenticator,
	opts ...Option,
) *EventWatcher {
	w := &EventWatcher{
		streamClient:  client,
		authenticator: authenticator,
		logger:        slog.Default(),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// recvResult holds the result of a stream.Recv() call.
type recvResult struct {
	resp *application_streamv1.SubscribeEventsResponse
	err  error
}

// Watch starts watching for events and calls the handler for each event.
// This method blocks until the context is cancelled or an unrecoverable error occurs.
// It automatically reconnects on connection failures.
func (w *EventWatcher) Watch(ctx context.Context, h event.EventHandler) error {
	stream, err := w.connect(ctx)
	if err != nil {
		return err
	}

	recvCh := make(chan recvResult, 1)

	for {
		go func() {
			resp, err := stream.Recv()
			recvCh <- recvResult{resp: resp, err: err}
		}()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-recvCh:
			if result.err == io.EOF {
				return nil
			}
			if result.err != nil {
				w.logger.Debug("stream error, attempting reconnect", slog.Any("error", result.err))
				stream, err = w.reconnect(ctx)
				if err != nil {
					return err
				}
				continue
			}

			for _, ev := range result.resp.Events {
				switch ev.EventType {
				case constv1.EventType_EVENT_TYPE_PING:
					w.logger.Debug("received ping event")
				default:
					go func() {
						if err := h.Handle(ctx, ev); err != nil {
							w.logger.Error("failed to handle event", slog.Any("error", err))
						}
					}()
				}
			}
		}
	}
}

func (w *EventWatcher) connect(ctx context.Context) (application_streamv1.ApplicationService_SubscribeEventsClient, error) {
	ctxWithAT, err := w.authenticator.AuthorizedContext(ctx)
	if err != nil {
		return nil, err
	}
	return w.streamClient.SubscribeEvents(ctxWithAT, &application_streamv1.SubscribeEventsRequest{})
}

func (w *EventWatcher) reconnect(ctx context.Context) (application_streamv1.ApplicationService_SubscribeEventsClient, error) {
	const maxRetries = 3
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<i) * time.Second): // 1s, 2s, 4s
		}

		stream, err := w.connect(ctx)
		if err == nil {
			w.logger.Info("reconnected to stream")
			return stream, nil
		}
		lastErr = err
		w.logger.Warn("reconnect attempt failed",
			slog.Int("attempt", i+1),
			slog.Int("max_retries", maxRetries),
			slog.Any("error", err))
	}

	return nil, lastErr
}
