package vault

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

func parseNotAfter(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, errors.New("invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}
