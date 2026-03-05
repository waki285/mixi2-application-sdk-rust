package stream

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/mixigroup/mixi2-application-sdk-go/auth/authtest"
	"github.com/mixigroup/mixi2-application-sdk-go/event/eventtest"
	constv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/const/v1"
	modelv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/model/v1"
	application_streamv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/service/application_stream/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type fakeStream struct {
	ctx     context.Context
	results []recvResult
	index   int
}

func (s *fakeStream) Recv() (*application_streamv1.SubscribeEventsResponse, error) {
	if s.index >= len(s.results) {
		return nil, io.EOF
	}
	result := s.results[s.index]
	s.index++
	return result.resp, result.err
}

func (s *fakeStream) Header() (metadata.MD, error) {
	return nil, nil
}

func (s *fakeStream) Trailer() metadata.MD {
	return nil
}

func (s *fakeStream) CloseSend() error {
	return nil
}

func (s *fakeStream) Context() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

func (s *fakeStream) SendMsg(m any) error {
	return nil
}

func (s *fakeStream) RecvMsg(m any) error {
	return nil
}

type fakeApplicationServiceClient struct {
	streams   []application_streamv1.ApplicationService_SubscribeEventsClient
	callCount int
}

func (c *fakeApplicationServiceClient) SubscribeEvents(ctx context.Context, in *application_streamv1.SubscribeEventsRequest, opts ...grpc.CallOption) (application_streamv1.ApplicationService_SubscribeEventsClient, error) {
	if c.callCount >= len(c.streams) {
		return nil, errors.New("no stream configured")
	}
	stream := c.streams[c.callCount]
	c.callCount++
	return stream, nil
}

func TestEventWatcher_Watch_HandlesEventsAndIgnoresPing(t *testing.T) {
	stream := &fakeStream{
		results: []recvResult{
			{
				resp: &application_streamv1.SubscribeEventsResponse{
					Events: []*modelv1.Event{
						{EventType: constv1.EventType_EVENT_TYPE_PING},
						{EventType: constv1.EventType_EVENT_TYPE_UNSPECIFIED},
					},
				},
			},
		},
	}
	client := &fakeApplicationServiceClient{
		streams: []application_streamv1.ApplicationService_SubscribeEventsClient{stream},
	}
	watcher := NewStreamWatcher(client, &authtest.FakeAuthenticator{})
	handler := eventtest.NewChannelHandler(1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- watcher.Watch(ctx, handler)
	}()

	select {
	case ev := <-handler.Ch:
		if ev.EventType != constv1.EventType_EVENT_TYPE_UNSPECIFIED {
			t.Fatalf("expected non-ping event, got %v", ev.EventType)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected event to be handled")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("watch returned error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("watch did not return after EOF")
	}
}

func TestEventWatcher_Watch_ReconnectsOnError(t *testing.T) {
	stream1 := &fakeStream{
		results: []recvResult{
			{err: errors.New("stream error")},
		},
	}
	stream2 := &fakeStream{
		results: []recvResult{
			{
				resp: &application_streamv1.SubscribeEventsResponse{
					Events: []*modelv1.Event{
						{EventType: constv1.EventType_EVENT_TYPE_UNSPECIFIED},
					},
				},
			},
		},
	}
	client := &fakeApplicationServiceClient{
		streams: []application_streamv1.ApplicationService_SubscribeEventsClient{stream1, stream2},
	}
	watcher := NewStreamWatcher(client, &authtest.FakeAuthenticator{})
	handler := eventtest.NewChannelHandler(1)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- watcher.Watch(ctx, handler)
	}()

	select {
	case <-handler.Ch:
	case <-time.After(2 * time.Second):
		t.Fatal("expected event to be handled after reconnect")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("watch returned error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("watch did not return after EOF")
	}

	if client.callCount < 2 {
		t.Fatalf("expected reconnect attempt, got %d subscribe calls", client.callCount)
	}
}
