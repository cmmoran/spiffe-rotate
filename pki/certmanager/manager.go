package certmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"time"
)

var ErrNotReady = errors.New("cert bundle not ready")

// Bundle holds the active leaf cert and the trust pool.
type Bundle struct {
	Cert     *tls.Certificate
	CA       *x509.CertPool
	NotAfter time.Time
}

// BundleInfo is a read-only view of a bundle for hooks.
type BundleInfo struct {
	NotAfter     time.Time
	CommonName   string
	SerialNumber string
	DNSNames     []string
	URIs         []string
}

// Issuer produces a new cert bundle.
type Issuer interface {
	Issue(ctx context.Context) (*Bundle, error)
}

type Options struct {
	MinRefresh   time.Duration
	ErrorBackoff time.Duration
	HookTimeout  time.Duration
	// OnRotate is a best-effort notification hook. BundleInfo is read-only.
	OnRotate func(context.Context, BundleInfo)
	// OnError is a best-effort notification hook.
	OnError func(context.Context, error)
	Now     func() time.Time
}

// Manager rotates certs in-process and swaps them atomically.
type Manager struct {
	issuer Issuer
	curr   atomic.Value // *Bundle
	opts   Options
}

func New(issuer Issuer) *Manager {
	return NewWithOptions(issuer, Options{})
}

func NewWithOptions(issuer Issuer, opts Options) *Manager {
	if opts.MinRefresh <= 0 {
		opts.MinRefresh = 30 * time.Second
	}
	if opts.ErrorBackoff <= 0 {
		opts.ErrorBackoff = 15 * time.Second
	}
	if opts.HookTimeout <= 0 {
		opts.HookTimeout = 2 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Manager{
		issuer: issuer,
		opts:   opts,
	}
}

// Current returns the current bundle or ErrNotReady.
func (m *Manager) Current() (*Bundle, error) {
	if v := m.curr.Load(); v != nil {
		return v.(*Bundle), nil
	}
	return nil, ErrNotReady
}

// Start fetches the initial bundle.
func (m *Manager) Start(ctx context.Context) error {
	_, _, err := m.refresh(ctx)
	return err
}

// Run continuously refreshes the bundle until ctx is canceled.
func (m *Manager) Run(ctx context.Context) {
	if _, err := m.Current(); err != nil {
		if _, _, err := m.refresh(ctx); err != nil {
			m.onError(err)
		}
	}

	for {
		bundle, next, err := m.refresh(ctx)
		if err != nil {
			m.onError(err)
			if !m.sleep(ctx, m.opts.ErrorBackoff) {
				return
			}
			continue
		}
		m.onRotate(bundle)

		wait := next.Sub(m.opts.Now())
		if wait < m.opts.MinRefresh {
			wait = m.opts.MinRefresh
		}
		jitter := time.Duration(m.opts.Now().UnixNano() % int64(wait/10+1))
		wait += jitter

		if !m.sleep(ctx, wait) {
			return
		}
	}
}

// GetCertificate is a tls.Config GetCertificate callback.
func (m *Manager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	b, err := m.Current()
	if err != nil {
		return nil, err
	}
	return b.Cert, nil
}

// GetClientCertificate is a tls.Config GetClientCertificate callback.
func (m *Manager) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	b, err := m.Current()
	if err != nil {
		return nil, err
	}
	return b.Cert, nil
}

func (m *Manager) refresh(ctx context.Context) (*Bundle, time.Time, error) {
	bundle, err := m.issuer.Issue(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	m.curr.Store(bundle)

	now := m.opts.Now()
	ttl := bundle.NotAfter.Sub(now)
	return bundle, now.Add(ttl * 2 / 3), nil
}

func (m *Manager) onRotate(bundle *Bundle) {
	if m.opts.OnRotate == nil || bundle == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.opts.HookTimeout)
	info := bundleInfo(bundle)
	go func() {
		defer cancel()
		m.opts.OnRotate(ctx, info)
	}()
}

func (m *Manager) onError(err error) {
	if m.opts.OnError == nil || err == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.opts.HookTimeout)
	go func() {
		defer cancel()
		m.opts.OnError(ctx, err)
	}()
}

func (m *Manager) sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

func bundleInfo(bundle *Bundle) BundleInfo {
	info := BundleInfo{
		NotAfter: bundle.NotAfter,
	}
	if bundle.Cert == nil {
		return info
	}
	leaf := bundle.Cert.Leaf
	if leaf == nil && len(bundle.Cert.Certificate) > 0 {
		if parsed, err := x509.ParseCertificate(bundle.Cert.Certificate[0]); err == nil {
			leaf = parsed
		}
	}
	if leaf == nil {
		return info
	}
	info.CommonName = leaf.Subject.CommonName
	info.SerialNumber = leaf.SerialNumber.String()
	info.DNSNames = append([]string(nil), leaf.DNSNames...)
	if len(leaf.URIs) > 0 {
		uris := make([]string, 0, len(leaf.URIs))
		for _, u := range leaf.URIs {
			if u != nil {
				uris = append(uris, u.String())
			}
		}
		info.URIs = uris
	}
	return info
}
