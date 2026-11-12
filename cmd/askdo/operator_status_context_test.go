package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestHostStatusHonorsBrokerContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	for _, ctx := range []context.Context{cancelled, expired} {
		text, err := gatewayStatusAt(ctx, "hosts", filepath.Join(t.TempDir(), "never-read-config.json"))
		if !errors.Is(err, ctx.Err()) || text != "" {
			t.Fatalf("status ignored broker context: text=%q err=%v want=%v", text, err, ctx.Err())
		}
	}
}
