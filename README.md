# spiffe-rotate

Minimal in-process mTLS certificate rotation for Go services, with Vault/OpenBao PKI support.

Key ideas:
- Use Docker secrets only for auth bootstrap (token or AppRole role_id/secret_id).
- Fetch and rotate short-lived mTLS certs in-process.
- Swap certs atomically without restarts.
- Authorize clients using SPIFFE-style URI SANs.

## Layout
- `certmanager`: in-memory rotation and atomic swap of cert bundles.
- `vault`: Vault/OpenBao PKI issuer (HTTP only, stdlib).
- `spiffe`: minimal SPIFFE URI SAN authorizer.

## Quick usage
```go
import (
    "github.com/cmmoran/spiffe-rotate/pki/certmanager"
    "github.com/cmmoran/spiffe-rotate/pki/spiffe"
    "github.com/cmmoran/spiffe-rotate/pki/vault"
)

issuer := &vault.Issuer{
    Client: &vault.Client{
        Addr:     "https://vault.service:8200",
        PKIPath:  "pki",
        Role:     "mtls-service",
        Token:    os.Getenv("VAULT_TOKEN"),
        // Or AppRole bootstrap:
        // RoleID: os.Getenv("VAULT_ROLE_ID"),
        // SecretID: os.Getenv("VAULT_SECRET_ID"),
    },
    CommonName: "service", // optional
    URISANs: []string{
        "spiffe://corp/prod/stack/payments/service/api",
    },
    TTL: 6 * time.Hour,
}

mgr := certmanager.New(issuer)
go mgr.Run(ctx) // Run performs the initial fetch and refreshes continuously.

srvTLS := &tls.Config{
    MinVersion: tls.VersionTLS12,
    ClientAuth: tls.RequireAndVerifyClientCert,
    GetCertificate: mgr.GetCertificate,
    VerifyPeerCertificate: spiffe.Authorizer{
        AllowedPrefixes: []string{"spiffe://corp/prod/stack/payments/"},
    }.VerifyPeerCertificate,
}

clientTLS := &tls.Config{
    MinVersion: tls.VersionTLS12,
    GetClientCertificate: mgr.GetClientCertificate,
}
```

## Hooks
You can register best-effort notification hooks for rotations and errors. Hooks receive a read-only view of the bundle and may time out via context.
```go
mgr := certmanager.NewWithOptions(issuer, certmanager.Options{
    OnRotate: func(ctx context.Context, info certmanager.BundleInfo) {
        // metrics/logging using info.NotAfter, info.URIs, etc.
    },
    OnError: func(ctx context.Context, err error) {
        // metrics/logging
    },
})
go mgr.Run(ctx)
```

## Vault/OpenBao CA chain requirements
If your PKI role does not return `ca_chain` or `issuing_ca`, set `RequireCA: false` and provide your own CA pool in the TLS config. If you need to enforce a chain, set `RequireCA: true`.
If you leave `ClientCAs`/`RootCAs` unset, Go will fall back to the system roots; for private CAs, you should explicitly configure the pool.

## SPIFFE matching
Authorizer supports exact, prefix, and glob patterns.
Glob rules follow vault path conventions:
- `*` is only allowed at the end of the pattern and means prefix match for any remaining path segments.
- `+` matches exactly one path segment (up to the next `/`).

Examples:
```go
spiffe.Authorizer{
    AllowedExact: []string{
        "spiffe://corp/prod/stack/payments/service/api",
    },
    AllowedPrefixes: []string{
        "spiffe://corp/prod/stack/payments/",
    },
    AllowedGlobs: []string{
        "spiffe://corp/prod/stack/+/service/+",
        "spiffe://corp/prod/stack/payments/*",
    },
}
```

## Notes
- OpenBao uses the same HTTP API as Vault for PKI and AppRole, so the `vault` package works for both. Set `Client.AuthPath` if AppRole is mounted at a non-default path and `Issuer.PKIPath` if PKI is mounted elsewhere.
- For Swarm, DNS SANs are often unusable; prefer URI SANs with SPIFFE-style IDs.
- Rotate certs in memory, avoid restarts.
- The Vault/OpenBao issuer builds a trust pool from `ca_chain` or `issuing_ca`. If neither is returned, the pool will be empty, so ensure your PKI role returns a chain or provide your own CA pool for peer verification.
- This module is intentionally small and dependency-free.

Example: override the CA pool if your issuer does not return a chain.
```go
bundle, err := mgr.Current()
if err != nil {
    return err
}

pool := x509.NewCertPool()
if !pool.AppendCertsFromPEM([]byte(os.Getenv("MTLS_CA_PEM"))) {
    return fmt.Errorf("failed to load MTLS_CA_PEM")
}

srvTLS := &tls.Config{
    MinVersion: tls.VersionTLS12,
    ClientAuth: tls.RequireAndVerifyClientCert,
    ClientCAs:  pool, // override (otherwise system roots are used)
    GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
        return bundle.Cert, nil
    },
}
```
