package certmanager

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type staticIssuer struct {
	bundle *Bundle
	err    error
	calls  *int32
}

func (s staticIssuer) Issue(_ context.Context) (*Bundle, error) {
	if s.calls != nil {
		atomic.AddInt32(s.calls, 1)
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.bundle, nil
}

func TestRefreshSchedulesAtTwoThirdsTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	bundle := &Bundle{NotAfter: now.Add(90 * time.Second)}
	mgr := NewWithOptions(staticIssuer{bundle: bundle}, Options{
		Now: func() time.Time { return now },
	})

	_, next, err := mgr.refresh(context.Background())
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	want := now.Add(60 * time.Second)
	if !next.Equal(want) {
		t.Fatalf("next refresh = %s, want %s", next, want)
	}
}

func TestOnRotateTimeoutAsync(t *testing.T) {
	t.Parallel()

	var gotCtx context.Context
	ctxCh := make(chan struct{})
	doneCh := make(chan struct{})

	mgr := NewWithOptions(staticIssuer{}, Options{
		HookTimeout: 10 * time.Millisecond,
		OnRotate: func(ctx context.Context, _ BundleInfo) {
			gotCtx = ctx
			close(ctxCh)
			<-ctx.Done()
			close(doneCh)
		},
	})

	mgr.onRotate(&Bundle{NotAfter: time.Now().Add(time.Minute)})

	select {
	case <-ctxCh:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("OnRotate was not invoked")
	}

	deadline, ok := gotCtx.Deadline()
	if !ok {
		t.Fatal("OnRotate ctx missing deadline")
	}
	if time.Until(deadline) > 50*time.Millisecond {
		t.Fatal("OnRotate ctx deadline too far in the future")
	}

	select {
	case <-doneCh:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("OnRotate did not return after context deadline")
	}
}

func TestRunIntegrationWithIssuer(t *testing.T) {
	var calls int32
	issuer := staticIssuer{
		bundle: &Bundle{NotAfter: time.Now().Add(5 * time.Millisecond)},
		calls:  &calls,
	}

	var rotations int32
	mgr := NewWithOptions(issuer, Options{
		MinRefresh:  1 * time.Millisecond,
		HookTimeout: 5 * time.Millisecond,
		OnRotate: func(ctx context.Context, _ BundleInfo) {
			atomic.AddInt32(&rotations, 1)
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	go mgr.Run(ctx)
	<-ctx.Done()

	if atomic.LoadInt32(&calls) == 0 {
		t.Fatal("expected issuer to be called at least once")
	}
	if atomic.LoadInt32(&rotations) == 0 {
		t.Fatal("expected at least one rotation callback")
	}
	if _, err := mgr.Current(); err != nil {
		t.Fatalf("expected current bundle to be set: %v", err)
	}
}
