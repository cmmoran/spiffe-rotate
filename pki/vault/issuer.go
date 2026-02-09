package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/cmmoran/spiffe-rotate/pki/certmanager"
)

type Issuer struct {
	Client  *Client
	PKIPath string
	Role    string

	CommonName string
	AltNames   []string
	URISANs    []string
	TTL        time.Duration
	// RequireCA enforces that the issuer returns a CA chain or issuing CA.
	RequireCA bool
}

func (i *Issuer) Issue(ctx context.Context) (*certmanager.Bundle, error) {
	if i.Client == nil {
		return nil, errors.New("vault client required")
	}

	req := IssueRequest{
		CommonName: i.CommonName,
		AltNames:   i.AltNames,
		URISANs:    i.URISANs,
	}
	if i.TTL > 0 {
		req.TTL = i.TTL.String()
	}

	resp, err := i.Client.Issue(ctx, i.PKIPath, i.Role, req)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair([]byte(resp.Certificate), []byte(resp.PrivateKey))
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	for _, pem := range resp.CAChain {
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return nil, errors.New("vault ca_chain contained invalid PEM")
		}
	}
	if len(resp.CAChain) == 0 && resp.IssuingCA != "" {
		if !pool.AppendCertsFromPEM([]byte(resp.IssuingCA)) {
			return nil, errors.New("vault issuing_ca contained invalid PEM")
		}
	}
	if i.RequireCA && len(resp.CAChain) == 0 && resp.IssuingCA == "" {
		return nil, errors.New("vault issue response missing ca_chain/issuing_ca")
	}

	notAfter, err := parseNotAfter([]byte(resp.Certificate))
	if err != nil {
		return nil, err
	}

	return &certmanager.Bundle{
		Cert:     &cert,
		CA:       pool,
		NotAfter: notAfter,
	}, nil
}
