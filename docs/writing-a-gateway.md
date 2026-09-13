# Writing a gateway

A gateway is a standalone process that teaches CertPilot how to talk to one
certificate authority. The core knows nothing about ACME, Vault, or any specific
CA — it only knows the gRPC contract in
[`provider.proto`](https://github.com/certpilot/certpilot-gateway-sdk/blob/main/proto/provider/v1/provider.proto).

That means a gateway can be written in any language with gRPC support, run
anywhere the core can reach, and be deployed and upgraded independently.

## The contract

```protobuf
service CertificateProviderService {
  // Lifecycle
  rpc IssueCertificate(IssueCertificateRequest) returns (IssueCertificateResponse);
  rpc RenewCertificate(RenewCertificateRequest) returns (RenewCertificateResponse);
  rpc RevokeCertificate(RevokeCertificateRequest) returns (RevokeCertificateResponse);

  // Status
  rpc GetCertificateStatus(GetCertificateStatusRequest) returns (GetCertificateStatusResponse);
  rpc GetCAInfo(GetCAInfoRequest) returns (GetCAInfoResponse);

  // Metadata
  rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse);
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
  rpc ValidateConfig(ValidateConfigRequest) returns (ValidateConfigResponse);
}
```

Gateways are **stateless with respect to CertPilot's data**. Every request
carries the CA account configuration it needs in `provider_config`, as JSON. The
core stores that configuration encrypted and decrypts it only to populate a
single call.

A gateway may keep its own local state — the ACME gateway persists account keys
in `--state-dir`, because an ACME account must be stable across restarts — but
it never reads CertPilot's database.

## Rules that matter

These are not style preferences. Each one corresponds to a way a gateway can
quietly corrupt the system it plugs into.

**Never report success for work you did not do.** If revocation is not
implemented, return `codes.Unimplemented`. Returning `{success: true}` tells an
operator a compromised certificate is dead when it is live, which is worse than
having no tool at all.

**Return a certificate, or return an error.** `IssueCertificate` must return a
parseable X.509 certificate in `certificate_pem`. The core parses it before
storing and rejects anything else, but a gateway that returns a CSR or a partial
result is broken regardless of what the core catches.

**Return the private key only if you generated it.** When the caller supplies
`csr_pem`, the key lives with whoever made the CSR and must not be invented.
When you do generate one, put it in `private_key_pem` — the core seals it before
storage, and omitting it produces a certificate nobody can use.

**Describe only what you implement.** `GetCapabilities` drives configuration
validation and UI affordances. Advertising `tls-alpn-01` without a solver turns
a clear configuration-time error into a mysterious failure at renewal.

**Validate configuration properly.** `ValidateConfig` runs before a CA account
is saved. Check credentials, reach the CA, and return specific messages. This is
the cheapest possible moment to catch a wrong API token; the alternative is
finding out during an unattended renewal.

**Use meaningful gRPC codes.** The core maps them to retry behaviour:

| Code | Use for |
|:---|:---|
| `InvalidArgument` | Bad request or configuration — do not retry |
| `FailedPrecondition` | Validation failed, no usable challenge — do not retry blindly |
| `ResourceExhausted` | Rate limited — back off |
| `Unavailable` | CA unreachable or timed out — retry later |
| `Internal` | Anything else |

**Never log `provider_config`.** It carries API tokens and account keys.

## A minimal Go gateway

**In your own repository.** There is no longer a `gateways/` directory in the
core to add one to — the three CertPilot maintains each live in a repository of
their own, and so does yours. The contract is a published Go module and the
channel is gRPC over the network, so nothing about being outside this project
makes your gateway second-class.

```bash
mkdir -p certpilot-gateway-my-ca/cmd && cd certpilot-gateway-my-ca
go mod init github.com/you/certpilot-gateway-my-ca
go get github.com/certpilot/certpilot-gateway-sdk
```

The `certpilot-gateway-` prefix is worth keeping: it is what makes a gateway
findable on a GitHub search, and what lets this project point at community
gateways without vouching for them.

Then implement the service:

```go
package myca

import (
    "context"
    "fmt"

    commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
    providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
    "github.com/certpilot/certpilot-gateway-sdk/x509util"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
    "google.golang.org/protobuf/types/known/timestamppb"
)

type Config struct {
    Endpoint string `json:"endpoint"`
    APIToken string `json:"api_token"`
}

type Provider struct {
    providerv1.UnimplementedCertificateProviderServiceServer
}

func (p *Provider) IssueCertificate(
    ctx context.Context,
    req *providerv1.IssueCertificateRequest,
) (*providerv1.IssueCertificateResponse, error) {
    cfg, err := parseConfig(req.ProviderConfig)
    if err != nil {
        return nil, status.Error(codes.InvalidArgument, err.Error())
    }

    // Ask your CA for a certificate.
    certPEM, chainPEM, err := callYourCA(ctx, cfg, req.CsrPem, req.Domains)
    if err != nil {
        return nil, status.Error(codes.Unavailable, err.Error())
    }

    // Parse what came back rather than trusting it.
    info, err := x509util.ParseCertificatePEM(certPEM)
    if err != nil {
        return nil, status.Error(codes.Internal,
            fmt.Sprintf("CA returned something that is not a certificate: %v", err))
    }

    return &providerv1.IssueCertificateResponse{
        Certificate: &commonv1.CertificateInfo{
            CommonName:        info.CommonName,
            Sans:              info.SANs,
            SerialNumber:      info.SerialNumber,
            IssuerDn:          info.IssuerDN,
            NotBefore:         timestamppb.New(info.NotBefore),
            NotAfter:          timestamppb.New(info.NotAfter),
            KeyType:           info.KeyType,
            KeySize:           int32(info.KeySize),
            FingerprintSha256: info.FingerprintSHA256,
            CertificatePem:    certPEM,
            ChainPem:          chainPEM,
            // PrivateKeyPem only when this gateway generated the key.
        },
        ProviderCertificateId: info.SerialNumber,
    }, nil
}
```

Then the entrypoint. `grpckit` from the gateway SDK handles mTLS, health, and keepalives:

```go
func main() {
    port := flag.Int("port", 9094, "gRPC server port")
    tlsCert := flag.String("tls-cert", "", "this gateway's TLS certificate")
    tlsKey := flag.String("tls-key", "", "this gateway's TLS private key")
    tlsCA := flag.String("tls-ca", "", "CA bundle used to verify the core")
    insecure := flag.Bool("insecure", false, "serve without TLS — development only")
    flag.Parse()

    tlsCfg := grpckit.TLSConfig{
        CertFile: *tlsCert, KeyFile: *tlsKey, CAFile: *tlsCA, Insecure: *insecure,
    }

    opts := grpckit.DefaultServerOptions()
    opts.Port = *port
    opts.TLS = tlsCfg

    server, err := grpckit.NewServer(opts)
    if err != nil {
        slog.Error("failed to create gRPC server", "error", err)
        os.Exit(1)
    }

    providerv1.RegisterCertificateProviderServiceServer(server, &myca.Provider{})

    if err := grpckit.Serve(server, *port); err != nil {
        slog.Error("gateway failed", "error", err)
        os.Exit(1)
    }
}
```

## Transport security

The core-to-gateway channel carries CSRs, private keys, and CA credentials, so
it is mutually authenticated by default: TLS 1.3, both ends verified against a
shared CA, `RequireAndVerifyClientCert` on the server.

For development, `make dev-certs` writes usable material into `.certpilot/pki/`.
In production, issue the gateway a certificate from your own internal CA and
point `--tls-ca` at that CA. `--insecure` exists for local work and is refused
by the core in production mode.

Non-Go gateways need the same: TLS 1.3, client certificate required, verified
against the CertPilot control-plane CA.

## Registering it

```bash
curl -X POST localhost:8080/api/v1/ca-accounts \
  -H 'Content-Type: application/json' -d '{
    "name": "my-custom-ca",
    "provider_type": "custom",
    "gateway_addr": "localhost:9094",
    "server_name": "localhost",
    "config": {"endpoint": "https://ca.internal", "api_token": "..."}
  }'
```

The core connects, calls `GetCapabilities`, then `ValidateConfig`. If validation
fails, nothing is stored and the errors come back to the operator.

## Testing

Test the provider directly — it is a plain gRPC service, so no server is needed:

```go
func TestIssueRejectsBadConfig(t *testing.T) {
    p := &Provider{}
    _, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
        Domains:        []string{"example.com"},
        ProviderConfig: `{"endpoint": ""}`,
    })
    if status.Code(err) != codes.InvalidArgument {
        t.Fatalf("code = %s, want InvalidArgument", status.Code(err))
    }
}
```

Worth covering explicitly, because these are the failure modes that damage the
core rather than just failing:

- Missing or malformed `provider_config`
- A CA that returns something that is not a certificate
- Whether unimplemented operations return `Unimplemented` rather than success
- That `GetCapabilities` lists only what is actually implemented

[`certpilot-gateway-selfsigned`](https://github.com/certpilot/certpilot-gateway-selfsigned) is the smallest complete
example. [`certpilot-gateway-acme`](https://github.com/certpilot/certpilot-gateway-acme) is the realistic public-CA one:
challenge solvers, persistent account state, External Account Binding, and RFC
9773 renewal information. [`certpilot-gateway-vault`](https://github.com/certpilot/certpilot-gateway-vault) is the private-CA
one, and the only gateway that implements `GetCAInfo` — worth reading for how it
translates a CA's own refusals into sentences that name the cause, and for the
live test suite that runs against a real Vault rather than a stub.

## Wanted gateways

In rough order of demand: Microsoft AD CS, AWS Private CA, Google Cloud CAS,
EJBCA, DigiCert, Sectigo, Entrust, and step-ca. HashiCorp Vault PKI is
[built](https://github.com/certpilot/certpilot-gateway-vault).

The private-CA gateways are also where post-quantum issuance is possible today —
AWS Private CA has had ML-DSA generally available since November 2025, while
publicly trusted ACME CAs cannot issue post-quantum certificates at all yet.

## Check it before you trust it

```bash
go run github.com/certpilot/certpilot-gateway-sdk/cmd/conformance@latest \
    -addr localhost:9094 -insecure -domain test.example.com
```

The three gateways in this project are kept honest by live tests against a real
Vault and a real ACME server, which you cannot run. This is the substitute: it
makes real calls against your gateway and prints what it got wrong.

The check to read first is `IssueCertificate (honours csr_pem)`. It generates a
CSR, asks you to sign it, and compares the public key in the certificate you
return against the key it asked you to sign. A gateway that generates its own
key instead passes every test its author is likely to write, and fails much
later as a certificate that does not match its private key.

## Registering it with a core

A gateway is reachable over the network, so the core does not need to have heard
of it and there is no plugin registry to be listed in:

```
POST /api/v1/ca-accounts   { "gateway_addr": "gateway-my-ca.internal:9094", ... }
```

**What CertPilot will not do for you:** there is no discovery mechanism, and no
compatibility testing of gateways this project does not build. The conformance
probe above is what you have, and it is deliberately the same one the three
in-house gateways run in their own CI.
