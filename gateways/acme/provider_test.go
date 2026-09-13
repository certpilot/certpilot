package acme

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"

	certcrypto "github.com/certpilot/certpilot-gateway-sdk/crypto"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testProvider(t *testing.T) *Provider {
	t.Helper()
	return NewProvider(Options{
		DefaultDirectory: LetsEncryptStaging,
		StateDir:         t.TempDir(),
		HTTP01Addr:       "127.0.0.1:0",
	})
}

func TestCapabilities(t *testing.T) {
	p := testProvider(t)

	resp, err := p.GetCapabilities(context.Background(), &providerv1.GetCapabilitiesRequest{})
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}

	caps := resp.Capabilities
	if caps.ProviderName != "acme" {
		t.Errorf("provider name = %q, want acme", caps.ProviderName)
	}
	if !caps.SupportsWildcard {
		t.Error("ACME supports wildcards over dns-01")
	}

	// Capabilities must describe what is implemented. Advertising tls-alpn-01
	// without a solver for it is how a request fails at the CA instead of at
	// configuration time.
	for _, challenge := range caps.SupportedChallenges {
		switch challenge {
		case "dns-01", "http-01":
		default:
			t.Errorf("advertised challenge %q has no solver implementation", challenge)
		}
	}
}

// Issuance must not be attempted without a CA account configuration, and must
// never report success without a real certificate.
func TestIssueRequiresConfiguration(t *testing.T) {
	p := testProvider(t)

	cases := []struct {
		name string
		req  *providerv1.IssueCertificateRequest
	}{
		{
			name: "no domains",
			req:  &providerv1.IssueCertificateRequest{ProviderConfig: `{"email":"a@example.com"}`},
		},
		{
			name: "dns-01 without a provider",
			req: &providerv1.IssueCertificateRequest{
				Domains:        []string{"example.com"},
				ProviderConfig: `{"email":"a@example.com","challenge":"dns-01"}`,
			},
		},
		{
			name: "cloudflare without a token",
			req: &providerv1.IssueCertificateRequest{
				Domains:        []string{"example.com"},
				ProviderConfig: `{"email":"a@example.com","challenge":"dns-01","dns_provider":"cloudflare"}`,
			},
		},
		{
			name: "malformed configuration JSON",
			req: &providerv1.IssueCertificateRequest{
				Domains:        []string{"example.com"},
				ProviderConfig: `{not json`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := p.IssueCertificate(context.Background(), tc.req)
			if err == nil {
				t.Fatalf("expected an error, got a response: %+v", resp)
			}
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %s, want InvalidArgument (%v)", status.Code(err), err)
			}
		})
	}
}

func TestRevokeRequiresCertificateBytes(t *testing.T) {
	p := testProvider(t)

	_, err := p.RevokeCertificate(context.Background(), &providerv1.RevokeCertificateRequest{
		ProviderCertificateId: "some-id",
		ProviderConfig:        `{"email":"a@example.com","challenge":"http-01"}`,
	})
	if err == nil {
		t.Fatal("revocation without the certificate must fail: ACME identifies the certificate by its bytes")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %s, want InvalidArgument", status.Code(err))
	}
}

// The previous implementation returned success unconditionally. Revocation of
// a certificate that cannot even be parsed must fail loudly.
func TestRevokeRejectsGarbage(t *testing.T) {
	p := testProvider(t)

	_, err := p.RevokeCertificate(context.Background(), &providerv1.RevokeCertificateRequest{
		CertificatePem: []byte("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"),
		ProviderConfig: `{"email":"a@example.com","challenge":"http-01"}`,
	})
	if err == nil {
		t.Fatal("revoking an unparseable certificate must not report success")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %s, want InvalidArgument", status.Code(err))
	}
}

func TestGetCertificateStatusRequiresCertificate(t *testing.T) {
	p := testProvider(t)

	_, err := p.GetCertificateStatus(context.Background(), &providerv1.GetCertificateStatusRequest{
		ProviderCertificateId: "id-only",
	})
	if err == nil {
		t.Fatal("expected an error when no certificate is supplied")
	}
}

func TestNormalizeDomains(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{"lowercases", []string{"Example.COM"}, []string{"example.com"}, false},
		{"deduplicates", []string{"example.com", "EXAMPLE.com", "www.example.com"}, []string{"example.com", "www.example.com"}, false},
		{"keeps wildcards", []string{"*.example.com", "example.com"}, []string{"*.example.com", "example.com"}, false},
		{"drops blanks", []string{"", "  ", "example.com"}, []string{"example.com"}, false},
		{"rejects empty input", []string{}, nil, true},
		{"rejects a URL", []string{"https://example.com"}, nil, true},
		{"rejects host:port", []string{"example.com:443"}, nil, true},
		{"rejects embedded spaces", []string{"exa mple.com"}, nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeDomains(tc.in, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeDomainsFallsBackToCSR(t *testing.T) {
	key, err := certcrypto.GenerateKeyPair(certcrypto.KeyTypeECDSA, 256)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	csrPEM, err := certcrypto.GenerateCSR(key, "example.com", []string{"example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	got, err := normalizeDomains(nil, csrPEM)
	if err != nil {
		t.Fatalf("normalizeDomains: %v", err)
	}
	if len(got) != 2 || got[0] != "example.com" {
		t.Fatalf("got %v, want the CSR's identifiers", got)
	}
}

func TestPrepareCSRGeneratesAKey(t *testing.T) {
	p := testProvider(t)

	csrDER, keyPEM, keyType, keySize, err := p.prepareCSR(nil, "ECDSA", 256, []string{"example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("prepareCSR: %v", err)
	}
	if len(csrDER) == 0 {
		t.Fatal("expected a CSR")
	}
	if len(keyPEM) == 0 {
		t.Fatal("expected a generated private key: without it the certificate is unusable")
	}
	if keyType != "ECDSA" || keySize != 256 {
		t.Fatalf("keyType/keySize = %s/%d, want ECDSA/256", keyType, keySize)
	}
	if block, _ := pem.Decode(keyPEM); block == nil {
		t.Fatal("generated key is not valid PEM")
	}
}

// When the caller supplies a CSR the key stays wherever it was generated, so
// the gateway must not invent one.
func TestPrepareCSRWithSuppliedCSRReturnsNoKey(t *testing.T) {
	p := testProvider(t)

	key, err := certcrypto.GenerateKeyPair(certcrypto.KeyTypeECDSA, 256)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	csrPEM, err := certcrypto.GenerateCSR(key, "example.com", []string{"example.com"})
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	csrDER, keyPEM, keyType, _, err := p.prepareCSR(csrPEM, "", 0, []string{"example.com"})
	if err != nil {
		t.Fatalf("prepareCSR: %v", err)
	}
	if len(csrDER) == 0 {
		t.Fatal("expected the supplied CSR to be passed through")
	}
	if keyPEM != nil {
		t.Fatal("the gateway must not return a private key when the caller supplied a CSR")
	}
	if keyType != "ECDSA" {
		t.Fatalf("keyType = %q, want ECDSA as read from the CSR", keyType)
	}
}

func TestPrepareCSRRejectsBadInput(t *testing.T) {
	p := testProvider(t)

	cases := map[string][]byte{
		"not PEM":     []byte("just some text"),
		"empty block": []byte("-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"),
		"not a CSR":   []byte("-----BEGIN CERTIFICATE REQUEST-----\nbm90IGEgY3Ny\n-----END CERTIFICATE REQUEST-----\n"),
	}

	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, _, err := p.prepareCSR(csr, "", 0, []string{"example.com"}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// Ed25519 is a legitimate key type that no publicly trusted ACME CA will issue
// for. Saying so beats a confusing rejection from the CA.
func TestPrepareCSRRejectsEd25519(t *testing.T) {
	p := testProvider(t)

	_, _, _, _, err := p.prepareCSR(nil, "Ed25519", 256, []string{"example.com"})
	if err == nil {
		t.Fatal("expected Ed25519 to be rejected")
	}
	if !strings.Contains(err.Error(), "Ed25519") {
		t.Fatalf("error should name the key type: %v", err)
	}
}

func TestIssuanceErrorCodeMapping(t *testing.T) {
	cases := map[string]codes.Code{
		"rate limit exceeded for account":  codes.ResourceExhausted,
		"ACME directory unreachable":       codes.Unavailable,
		"context deadline exceeded":        codes.Unavailable,
		"domain control validation failed": codes.FailedPrecondition,
		"no usable challenge for host":     codes.FailedPrecondition,
		"something else entirely":          codes.Internal,
	}

	for msg, want := range cases {
		t.Run(msg, func(t *testing.T) {
			if got := issuanceErrorCode(errString(msg)); got != want {
				t.Fatalf("code = %s, want %s", got, want)
			}
		})
	}
}

type errString string

func (e errString) Error() string { return string(e) }
