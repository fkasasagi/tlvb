package tier2

import (
	"context"
	"testing"
	"time"
)

// An already-spent parent deadline must NOT bleed into the overall-synthesis
// call: that was the root cause of the executive summary failing instantly
// ("context deadline exceeded" at ~0s) and degrading to the fallback stitch.
func TestDetachedDeadlineContextIgnoresExpiredParentDeadline(t *testing.T) {
	parent, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()
	if parent.Err() != context.DeadlineExceeded {
		t.Fatalf("parent should already be expired, got %v", parent.Err())
	}

	ctx, c := detachedDeadlineContext(parent, time.Minute)
	defer c()

	if err := ctx.Err(); err != nil {
		t.Fatalf("detached ctx should be live despite expired parent, got %v", err)
	}
	dl, ok := ctx.Deadline()
	if !ok || time.Until(dl) <= 0 {
		t.Fatalf("detached ctx should carry its own future deadline, ok=%v until=%v", ok, time.Until(dl))
	}
	// Give the watcher goroutine a moment; it must not cancel on a parent that
	// merely timed out.
	time.Sleep(20 * time.Millisecond)
	if err := ctx.Err(); err != nil {
		t.Fatalf("detached ctx cancelled by an expired (not cancelled) parent: %v", err)
	}
}

// A genuine cancellation of the parent (Ctrl-C / superseded job) MUST still
// stop the overall call.
func TestDetachedDeadlineContextPropagatesCancel(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx, c := detachedDeadlineContext(parent, time.Minute)
	defer c()

	cancelParent()

	select {
	case <-ctx.Done():
		if ctx.Err() != context.Canceled {
			t.Fatalf("want Canceled, got %v", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("detached ctx did not propagate parent cancellation")
	}
}
