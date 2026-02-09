package vault

import (
	"io"
	"net/http"
)

type trackingReadCloser struct {
	r      io.Reader
	closed *bool
}

func (t trackingReadCloser) Read(p []byte) (int, error) {
	return t.r.Read(p)
}

func (t trackingReadCloser) Close() error {
	*t.closed = true
	return nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
