package spiffe

import (
	"crypto/x509"
	"errors"
	"strings"
)

type Authorizer struct {
	// AllowedExact matches full SPIFFE IDs only.
	AllowedExact []string
	// AllowedPrefixes matches SPIFFE IDs with the given prefix.
	AllowedPrefixes []string
	// AllowedGlobs supports `+` for single segment and trailing `*` for suffixes.
	AllowedGlobs []string
}

// VerifyPeerCertificate can be used as tls.Config.VerifyPeerCertificate.
func (a Authorizer) VerifyPeerCertificate(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	// We trust verifiedChains (already validated by TLS) and ignore rawCerts.
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return errors.New("no verified chain")
	}
	leaf := verifiedChains[0][0]
	for _, uri := range leaf.URIs {
		if uri.Scheme != "spiffe" {
			continue
		}
		id := uri.String()
		for _, exact := range a.AllowedExact {
			if id == exact {
				return nil
			}
		}
		for _, prefix := range a.AllowedPrefixes {
			if strings.HasPrefix(id, prefix) {
				return nil
			}
		}
		for _, glob := range a.AllowedGlobs {
			if matchGlob(glob, id) {
				return nil
			}
		}
	}
	return errors.New("client SPIFFE ID not allowed")
}

func matchGlob(pattern, value string) bool {
	// Glob rules:
	// - '*' is only allowed at the end and matches any remaining path segments.
	// - '+' matches exactly one path segment.
	if pattern == "" || value == "" {
		return false
	}
	if strings.Count(pattern, "*") > 1 {
		return false
	}
	if strings.Contains(pattern, "*") && !strings.HasSuffix(pattern, "*") {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		base := strings.TrimSuffix(pattern, "*")
		return matchSegments(base, value, true)
	}
	return matchSegments(pattern, value, false)
}

func matchSegments(pattern, value string, prefix bool) bool {
	psegs := strings.Split(pattern, "/")
	vsegs := strings.Split(value, "/")
	if prefix && len(psegs) > 0 && psegs[len(psegs)-1] == "" {
		psegs = psegs[:len(psegs)-1]
	}
	if !prefix && len(psegs) != len(vsegs) {
		return false
	}
	if prefix && len(psegs) > len(vsegs) {
		return false
	}
	for i, pseg := range psegs {
		if pseg == "+" {
			if vsegs[i] == "" {
				return false
			}
			continue
		}
		if pseg != vsegs[i] {
			return false
		}
	}
	return true
}
