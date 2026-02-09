package spiffe

import (
	"crypto/x509"
	"net/url"
	"testing"
)

func TestAuthorizerVerifyPeerCertificate(t *testing.T) {
	cert := &x509.Certificate{
		URIs: []*url.URL{
			mustURL(t, "spiffe://corp/prod/stack/payments/service/api"),
		},
	}

	auth := Authorizer{
		AllowedExact: []string{"spiffe://corp/prod/stack/payments/service/api"},
	}
	if err := auth.VerifyPeerCertificate(nil, [][]*x509.Certificate{{cert}}); err != nil {
		t.Fatalf("expected exact match to pass: %v", err)
	}

	auth = Authorizer{
		AllowedPrefixes: []string{"spiffe://corp/prod/stack/payments/"},
	}
	if err := auth.VerifyPeerCertificate(nil, [][]*x509.Certificate{{cert}}); err != nil {
		t.Fatalf("expected prefix match to pass: %v", err)
	}

	auth = Authorizer{
		AllowedGlobs: []string{"spiffe://corp/prod/stack/+/service/+"},
	}
	if err := auth.VerifyPeerCertificate(nil, [][]*x509.Certificate{{cert}}); err != nil {
		t.Fatalf("expected glob match to pass: %v", err)
	}
}

func TestAuthorizerRejectsNonSpiffeURIs(t *testing.T) {
	cert := &x509.Certificate{
		URIs: []*url.URL{
			mustURL(t, "https://corp/prod/stack/payments/service/api"),
		},
	}
	auth := Authorizer{
		AllowedPrefixes: []string{"https://corp/prod/stack/"},
	}
	if err := auth.VerifyPeerCertificate(nil, [][]*x509.Certificate{{cert}}); err == nil {
		t.Fatal("expected non-spiffe URI to be rejected")
	}
}

func TestMatchGlobEdgeCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern string
		value   string
		match   bool
	}{
		{"", "spiffe://corp/prod", false},
		{"spiffe://corp/*/bad", "spiffe://corp/prod/bad", false}, // '*' only allowed at end
		{"spiffe://corp/**", "spiffe://corp/prod", false},        // multiple '*'
		{"spiffe://corp/prod/*", "spiffe://corp/prod", true},
		{"spiffe://corp/+/svc", "spiffe://corp//svc", false}, // '+' must be non-empty
		{"spiffe://corp/+/svc", "spiffe://corp/prod/svc", true},
		{"spiffe://corp/prod", "spiffe://corp/prod/extra", false},
	}

	for _, c := range cases {
		if got := matchGlob(c.pattern, c.value); got != c.match {
			t.Fatalf("matchGlob(%q, %q) = %v, want %v", c.pattern, c.value, got, c.match)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}
