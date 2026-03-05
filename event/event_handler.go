// Package event provides event handling interfaces and implementations for mixi2.
//
// This package defines the core EventHandler interface that is used by webhook and stream subpackages.
package event

import (
	"context"

	modelv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/model/v1"
)

// EventHandler processes events from mixi2.
//
// Implementations should handle events asynchronously and not block.
// Errors returned from Handle are logged but do not affect event acknowledgment.
type EventHandler interface {
	// Handle processes a single event.
	Handle(ctx context.Context, event *modelv1.Event) error
}
