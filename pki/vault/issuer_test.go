package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIssuerRejectsInvalidCAPEM(t *testing.T) {
	t.Parallel()

	caPEM, leafPEM, keyPEM := newTestCerts(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pki/issue/role" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate": string(leafPEM),
				"private_key": string(keyPEM),
				"issuing_ca":  "not pem",
			},
		})
	}))
	t.Cleanup(server.Close)

	issuer := &Issuer{
		Client:  &Client{Addr: server.URL, Token: "tok"},
		PKIPath: "pki",
		Role:    "role",
	}
	_, err := issuer.Issue(context.Background())
	if err == nil {
		t.Fatal("expected invalid issuing_ca PEM to return error")
	}

	_ = caPEM
}

func TestIssuerAcceptsValidCAPEM(t *testing.T) {
	t.Parallel()

	caPEM, leafPEM, keyPEM := newTestCerts(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pki/issue/role" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate": string(leafPEM),
				"private_key": string(keyPEM),
				"issuing_ca":  string(caPEM),
			},
		})
	}))
	t.Cleanup(server.Close)

	issuer := &Issuer{
		Client:  &Client{Addr: server.URL, Token: "tok"},
		PKIPath: "pki",
		Role:    "role",
	}
	bundle, err := issuer.Issue(context.Background())
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		t.Fatal("failed to decode leaf PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       bundle.CA,
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("expected CA pool to verify leaf: %v", err)
	}
}

func TestIssuerRequireCA(t *testing.T) {
	t.Parallel()

	_, leafPEM, keyPEM := newTestCerts(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pki/issue/role" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate": string(leafPEM),
				"private_key": string(keyPEM),
			},
		})
	}))
	t.Cleanup(server.Close)

	issuer := &Issuer{
		Client:    &Client{Addr: server.URL, Token: "tok"},
		PKIPath:   "pki",
		Role:      "role",
		RequireCA: true,
	}
	_, err := issuer.Issue(context.Background())
	if err == nil {
		t.Fatal("expected missing ca_chain/issuing_ca to return error when RequireCA=true")
	}
}

func TestIssuerAllowMissingCAWhenNotRequired(t *testing.T) {
	t.Parallel()

	_, leafPEM, keyPEM := newTestCerts(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pki/issue/role" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate": string(leafPEM),
				"private_key": string(keyPEM),
			},
		})
	}))
	t.Cleanup(server.Close)

	issuer := &Issuer{
		Client:  &Client{Addr: server.URL, Token: "tok"},
		PKIPath: "pki",
		Role:    "role",
	}
	if _, err := issuer.Issue(context.Background()); err != nil {
		t.Fatalf("expected missing ca_chain/issuing_ca to be allowed: %v", err)
	}
}

func newTestCerts(t *testing.T) (caPEM, leafPEM, keyPEM []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leafPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return caPEM, leafPEM, keyPEM
}
