// Package eventtest provides testing utilities for event handling.
package eventtest

import (
	"context"

	"github.com/mixigroup/mixi2-application-sdk-go/event"
	modelv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/model/v1"
)

// MockEventHandler is a simple in-memory EventHandler implementation for testing.
//
// It records all events passed to Handle() in the Events slice.
// This is useful for verifying that events are correctly processed in tests.
type MockEventHandler struct {
	Events []*modelv1.Event
}

// Handle records the event in the Events slice.
func (m *MockEventHandler) Handle(ctx context.Context, ev *modelv1.Event) error {
	m.Events = append(m.Events, ev)
	return nil
}

var _ event.EventHandler = (*MockEventHandler)(nil)

// ChannelHandler is an EventHandler that sends events to a channel.
//
// This is useful for tests that need to wait for events asynchronously.
type ChannelHandler struct {
	Ch chan *modelv1.Event
}

// NewChannelHandler creates a new ChannelHandler with a buffered channel.
func NewChannelHandler(bufferSize int) *ChannelHandler {
	return &ChannelHandler{Ch: make(chan *modelv1.Event, bufferSize)}
}

// Handle sends the event to the channel.
func (h *ChannelHandler) Handle(ctx context.Context, ev *modelv1.Event) error {
	h.Ch <- ev
	return nil
}

var _ event.EventHandler = (*ChannelHandler)(nil)
