package vault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseNotAfter(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now()
	expiry := now.Add(30 * time.Minute).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     expiry,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	got, err := parseNotAfter(pemBytes)
	if err != nil {
		t.Fatalf("parseNotAfter failed: %v", err)
	}
	if !got.Equal(expiry) {
		t.Fatalf("parseNotAfter = %s, want %s", got, expiry)
	}
}
