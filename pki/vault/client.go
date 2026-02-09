package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

var (
	ErrAuthRequired = errors.New("vault auth required")
)

type Client struct {
	Addr      string
	Namespace string
	Token     string

	RoleID   string
	SecretID string
	AuthPath string // default: auth/approle/login

	HTTPClient *http.Client

	mu sync.RWMutex
}

func (c *Client) Issue(ctx context.Context, pkiPath, role string, req IssueRequest) (*IssueResponse, error) {
	if c.Addr == "" {
		return nil, errors.New("vault addr required")
	}
	if pkiPath == "" {
		return nil, errors.New("pki path required")
	}
	if role == "" {
		return nil, errors.New("pki role required")
	}

	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	endpoint := c.url(path.Join("v1", pkiPath, "issue", role))
	resp, err := c.doJSON(ctx, http.MethodPost, endpoint, req, true)
	if err == nil {
		return decodeIssue(resp)
	}

	// If auth failed, retry once with fresh login.
	if isAuthError(err) && c.RoleID != "" && c.SecretID != "" {
		c.setToken("")
		if err := c.ensureToken(ctx); err != nil {
			return nil, err
		}
		resp, err2 := c.doJSON(ctx, http.MethodPost, endpoint, req, true)
		if err2 != nil {
			return nil, err2
		}
		return decodeIssue(resp)
	}

	return nil, err
}

func (c *Client) ensureToken(ctx context.Context) error {
	if c.token() != "" {
		return nil
	}
	if c.RoleID == "" || c.SecretID == "" {
		return ErrAuthRequired
	}

	authPath := c.AuthPath
	if authPath == "" {
		authPath = "auth/approle/login"
	}
	endpoint := c.url(path.Join("v1", authPath))
	payload := map[string]string{
		"role_id":   c.RoleID,
		"secret_id": c.SecretID,
	}
	resp, err := c.doJSON(ctx, http.MethodPost, endpoint, payload, false)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Auth.ClientToken == "" {
		return errors.New("vault approle auth returned empty token")
	}
	c.setToken(out.Auth.ClientToken)
	return nil
}

func (c *Client) doJSON(ctx context.Context, method, url string, body any, requireAuth bool) (*http.Response, error) {
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		buf = bytes.NewBuffer(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.Namespace)
	}
	if requireAuth {
		token := c.token()
		if token == "" {
			return nil, ErrAuthRequired
		}
		req.Header.Set("X-Vault-Token", token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}

	defer func() { _ = resp.Body.Close() }()
	msg, _ := io.ReadAll(resp.Body)
	return nil, fmt.Errorf("vault http %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

func (c *Client) token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Token
}

func (c *Client) setToken(token string) {
	c.mu.Lock()
	c.Token = token
	c.mu.Unlock()
}

func (c *Client) url(p string) string {
	base := strings.TrimRight(c.Addr, "/")
	p = strings.TrimLeft(p, "/")
	return base + "/" + p
}

func isAuthError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "permission denied") || strings.Contains(s, "http 403") || strings.Contains(s, "http 401")
}
