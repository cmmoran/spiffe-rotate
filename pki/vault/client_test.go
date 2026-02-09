package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIssueRefreshesTokenOnAuthError(t *testing.T) {
	t.Parallel()

	var issueCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "good"},
			})
		case "/v1/pki/issue/role":
			issueCalls++
			if r.Header.Get("X-Vault-Token") != "good" {
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"certificate": "-----BEGIN CERTIFICATE-----\nMIIBbDCCARSgAwIBAgIRAKoM\n-----END CERTIFICATE-----",
					"private_key": "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := &Client{
		Addr:     server.URL,
		Token:    "bad",
		RoleID:   "role-id",
		SecretID: "secret-id",
	}

	_, err := client.Issue(context.Background(), "pki", "role", IssueRequest{CommonName: "svc"})
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if issueCalls != 2 {
		t.Fatalf("expected 2 issue attempts, got %d", issueCalls)
	}
}

func TestEnsureTokenClosesBody(t *testing.T) {
	t.Parallel()

	var closed bool
	client := &Client{
		RoleID:   "role-id",
		SecretID: "secret-id",
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body: trackingReadCloser{
			r:      strings.NewReader(`{"auth":{"client_token":"tok"}}`),
			closed: &closed,
		},
	}

	client.HTTPClient = &http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return resp, nil
		}),
	}
	client.Addr = "http://vault.test"

	if err := client.ensureToken(context.Background()); err != nil {
		t.Fatalf("ensureToken failed: %v", err)
	}
	if !closed {
		t.Fatal("expected response body to be closed")
	}
}
