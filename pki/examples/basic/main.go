package main

import (
	"context"
	"crypto/tls"
	"log"
	"os"
	"time"

	"github.com/cmmoran/spiffe-rotate/pki/certmanager"
	"github.com/cmmoran/spiffe-rotate/pki/spiffe"
	"github.com/cmmoran/spiffe-rotate/pki/vault"
)

func main() {
	ctx := context.Background()

	issuer := &vault.Issuer{
		Client: &vault.Client{
			Addr:     os.Getenv("VAULT_ADDR"),
			Token:    os.Getenv("VAULT_TOKEN"),
			RoleID:   os.Getenv("VAULT_ROLE_ID"),
			SecretID: os.Getenv("VAULT_SECRET_ID"),
		},
		PKIPath:    "pki",
		Role:       "mtls-service",
		CommonName: "service",
		URISANs: []string{
			"spiffe://corp/prod/stack/payments/service/api",
		},
		TTL: 6 * time.Hour,
	}

	mgr := certmanager.New(issuer)
	if err := mgr.Start(ctx); err != nil {
		log.Fatal(err)
	}
	go mgr.Run(ctx)

	srvTLS := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		GetCertificate: mgr.GetCertificate,
		VerifyPeerCertificate: spiffe.Authorizer{
			AllowedPrefixes: []string{
				"spiffe://corp/prod/stack/payments/",
			},
		}.VerifyPeerCertificate,
	}
	_ = srvTLS

	clientTLS := &tls.Config{
		MinVersion:           tls.VersionTLS12,
		GetClientCertificate: mgr.GetClientCertificate,
	}
	_ = clientTLS
}
