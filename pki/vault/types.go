package vault

import (
	"encoding/json"
	"errors"
	"net/http"
)

type IssueRequest struct {
	CommonName string   `json:"common_name,omitempty"`
	AltNames   []string `json:"alt_names,omitempty"`
	URISANs    []string `json:"uri_sans,omitempty"`
	TTL        string   `json:"ttl,omitempty"`
}

type IssueResponse struct {
	Certificate string
	PrivateKey  string
	CAChain     []string
	IssuingCA   string
}

func decodeIssue(respBody *http.Response) (*IssueResponse, error) {
	defer func() {
		_ = respBody.Body.Close()
	}()

	var out struct {
		Data struct {
			Certificate string   `json:"certificate"`
			PrivateKey  string   `json:"private_key"`
			IssuingCA   string   `json:"issuing_ca"`
			CAChain     []string `json:"ca_chain"`
		} `json:"data"`
	}
	if err := json.NewDecoder(respBody.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Data.Certificate == "" || out.Data.PrivateKey == "" {
		return nil, errors.New("vault issue response missing certificate/private_key")
	}
	return &IssueResponse{
		Certificate: out.Data.Certificate,
		PrivateKey:  out.Data.PrivateKey,
		IssuingCA:   out.Data.IssuingCA,
		CAChain:     out.Data.CAChain,
	}, nil
}
