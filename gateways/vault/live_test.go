package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These tests run against a real Vault, and are skipped without one.
//
// The fake in fakevault_test.go implements Vault's behaviour as this gateway
// understands it, which is exactly the thing that can be wrong. Everything
// here — the shape of an issuer listing, the wording of the refusal to sign
// past a CA's expiry, whether a no_store role 400s or 404s — is a fact about
// Vault rather than about this package, and only Vault can settle it.
//
// To run:
//
//	vault server -dev -dev-root-token-id=certpilot-dev-root
//	./scripts/lab-vault.sh
//	CERTPILOT_TEST_VAULT_ADDR=http://127.0.0.1:8200 \
//	CERTPILOT_TEST_VAULT_ROLE_ID=... CERTPILOT_TEST_VAULT_SECRET_ID=... \
//	go test ./gateways/vault/ -run Live -v
const (
	envVaultAddr     = "CERTPILOT_TEST_VAULT_ADDR"
	envVaultRoleID   = "CERTPILOT_TEST_VAULT_ROLE_ID"
	envVaultSecretID = "CERTPILOT_TEST_VAULT_SECRET_ID"
)

// liveConfig builds a provider configuration for a mount and role on the
// Vault named by the environment, skipping the test when there is none.
func liveConfig(t *testing.T, mount, role string) string {
	t.Helper()
	address := os.Getenv(envVaultAddr)
	if address == "" {
		t.Skipf("set %s to run this against a real Vault", envVaultAddr)
	}
	roleID, secretID := os.Getenv(envVaultRoleID), os.Getenv(envVaultSecretID)
	if roleID == "" || secretID == "" {
		t.Skipf("set %s and %s as well", envVaultRoleID, envVaultSecretID)
	}
	return fmt.Sprintf(
		`{"address":%q,"mount":%q,"role":%q,"auth_method":"approle","role_id":%q,"secret_id":%q}`,
		address, mount, role, roleID, secretID)
}

// TestLiveIssuanceAgainstVault takes a certificate all the way through and
// checks the one thing a fake cannot: that what came back is a certificate a
// verifier accepts, signed by the CA the mount claims to have.
func TestLiveIssuanceAgainstVault(t *testing.T) {
	config := liveConfig(t, "pki-int", "web")
	p := NewProvider(Options{})
	ctx := context.Background()

	resp, err := p.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		CsrPem:         makeCSR(t, "live.example.com", "alias.example.com"),
		Domains:        []string{"live.example.com", "alias.example.com"},
		ValidityDays:   30,
		ProviderConfig: config,
	})
	if err != nil {
		t.Fatalf("issuing from Vault: %v", err)
	}
	if len(resp.Certificate.PrivateKeyPem) != 0 {
		t.Fatalf("Vault returned a private key for a CSR it was given")
	}

	leaf := parsePEM(t, resp.Certificate.CertificatePem)
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, block := range splitPEM(resp.Certificate.ChainPem) {
		cert := parsePEM(t, block)
		if cert.Issuer.String() == cert.Subject.String() {
			roots.AddCert(cert)
			continue
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "live.example.com",
	}); err != nil {
		t.Fatalf("the certificate Vault issued does not verify against the chain it returned: %v", err)
	}

	if got := len(leaf.DNSNames); got != 2 {
		t.Fatalf("SANs = %v, want both names", leaf.DNSNames)
	}
	t.Logf("issued %s, serial %s, expires %s",
		leaf.Subject.CommonName, resp.ProviderCertificateId, leaf.NotAfter.Format(time.RFC3339))
}

// TestLiveGeneratedKeyMatchesTheCertificate proves the key Vault returned is
// the key in the certificate. Returning a mismatched pair is a failure that
// looks like success everywhere except the listener that tries to serve it.
func TestLiveGeneratedKeyMatchesTheCertificate(t *testing.T) {
	config := liveConfig(t, "pki-int", "web")
	p := NewProvider(Options{})

	resp, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		Domains:        []string{"generated.example.com"},
		ValidityDays:   30,
		ProviderConfig: config,
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if len(resp.Certificate.PrivateKeyPem) == 0 {
		t.Fatalf("Vault generated the key and none came back")
	}

	block, _ := pem.Decode(resp.Certificate.PrivateKeyPem)
	if block == nil {
		t.Fatalf("the private key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the key Vault generated: %v", err)
	}
	leaf := parsePEM(t, resp.Certificate.CertificatePem)
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the certificate does not carry an EC key")
	}
	if !key.PublicKey.Equal(public) {
		t.Fatalf("the private key Vault returned is not the key in the certificate")
	}
}

// TestLiveRevocationLifecycle walks issue → valid → revoke → revoked against
// Vault's own CRL machinery.
func TestLiveRevocationLifecycle(t *testing.T) {
	config := liveConfig(t, "pki-int", "web")
	p := NewProvider(Options{})
	ctx := context.Background()

	issued, err := p.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		Domains:        []string{"revokeme.example.com"},
		ValidityDays:   30,
		ProviderConfig: config,
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}

	before, err := p.GetCertificateStatus(ctx, &providerv1.GetCertificateStatusRequest{
		ProviderCertificateId: issued.ProviderCertificateId,
		ProviderConfig:        config,
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if before.Status != providerv1.CertStatus_CERT_STATUS_VALID {
		t.Fatalf("status before revocation = %s: %s", before.Status, before.Message)
	}

	if _, err := p.RevokeCertificate(ctx, &providerv1.RevokeCertificateRequest{
		CertificatePem:        issued.Certificate.CertificatePem,
		ProviderCertificateId: issued.ProviderCertificateId,
		Reason:                1,
		ProviderConfig:        config,
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	after, err := p.GetCertificateStatus(ctx, &providerv1.GetCertificateStatusRequest{
		ProviderCertificateId: issued.ProviderCertificateId,
		ProviderConfig:        config,
	})
	if err != nil {
		t.Fatalf("status after revocation: %v", err)
	}
	if after.Status != providerv1.CertStatus_CERT_STATUS_REVOKED {
		t.Fatalf("status after revocation = %s: %s", after.Status, after.Message)
	}
	t.Logf("%s", after.Message)
}

// TestLiveExpiringIssuerIsExplained is the one that had to be checked against
// Vault. The translation matches on Vault's own wording, and wording is
// exactly the kind of thing a fake gets right by construction and a real
// system changes between versions.
func TestLiveExpiringIssuerIsExplained(t *testing.T) {
	config := liveConfig(t, "pki-expiry", "web")
	p := NewProvider(Options{})

	_, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		Domains:        []string{"doomed.example.com"},
		ValidityDays:   60,
		ProviderConfig: config,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition: %v", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "Expiring Issuing") {
		t.Fatalf("the refusal does not name the CA that caused it: %v", err)
	}
	t.Logf("%v", err)
}

// TestLiveNoStoreRevocationNeedsTheCertificate is what a real Vault taught
// this package. The belief it started with — that a no_store role cannot be
// revoked — was wrong in the direction that matters: Vault verifies a
// certificate it is handed and revokes it whether or not it stored one. Only
// the serial-alone path genuinely cannot work.
func TestLiveNoStoreRevocationNeedsTheCertificate(t *testing.T) {
	config := liveConfig(t, "pki-int", "ephemeral")
	p := NewProvider(Options{})
	ctx := context.Background()

	issued, err := p.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		Domains:        []string{"ephemeral.example.com"},
		ValidityDays:   10,
		ProviderConfig: config,
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}

	before, err := p.GetCertificateStatus(ctx, &providerv1.GetCertificateStatusRequest{
		ProviderCertificateId: issued.ProviderCertificateId,
		ProviderConfig:        config,
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if before.Status != providerv1.CertStatus_CERT_STATUS_UNKNOWN {
		t.Fatalf("status = %s, want UNKNOWN for a certificate Vault never stored", before.Status)
	}

	// The serial on its own: nothing to look it up by.
	_, err = p.RevokeCertificate(ctx, &providerv1.RevokeCertificateRequest{
		ProviderCertificateId: issued.ProviderCertificateId,
		ProviderConfig:        config,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition: %v", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "no_store") {
		t.Fatalf("the refusal does not name the cause: %v", err)
	}
	t.Logf("%v", err)

	// The certificate itself: Vault verifies it and revokes it.
	if _, err := p.RevokeCertificate(ctx, &providerv1.RevokeCertificateRequest{
		CertificatePem:        issued.Certificate.CertificatePem,
		ProviderCertificateId: issued.ProviderCertificateId,
		ProviderConfig:        config,
	}); err != nil {
		t.Fatalf("revoking with the certificate in hand: %v", err)
	}

	after, err := p.GetCertificateStatus(ctx, &providerv1.GetCertificateStatusRequest{
		ProviderCertificateId: issued.ProviderCertificateId,
		ProviderConfig:        config,
	})
	if err != nil {
		t.Fatalf("status after revocation: %v", err)
	}
	if after.Status != providerv1.CertStatus_CERT_STATUS_REVOKED {
		t.Fatalf("status after revocation = %s: %s", after.Status, after.Message)
	}
}

// TestLiveCAInfoReportsWhatVaultHolds is the RPC no other gateway can answer.
func TestLiveCAInfoReportsWhatVaultHolds(t *testing.T) {
	config := liveConfig(t, "pki-int", "web")
	p := NewProvider(Options{})

	resp, err := p.GetCAInfo(context.Background(), &providerv1.GetCAInfoRequest{ProviderConfig: config})
	if err != nil {
		t.Fatalf("CA info: %v", err)
	}
	if len(resp.CaChain) == 0 {
		t.Fatalf("no issuers came back from a mount that has one")
	}
	for _, authority := range resp.CaChain {
		if authority.SubjectDn == "" || authority.FingerprintSha256 == "" {
			t.Fatalf("issuer %q came back without the material needed to track it", authority.Name)
		}
		if authority.NotAfter == nil {
			t.Fatalf("issuer %q has no expiry, which is the whole reason to track it", authority.Name)
		}
		t.Logf("%s: %s, %d days remaining, CRL %q",
			authority.CaType, authority.Name, authority.DaysRemaining, authority.CrlUrl)
	}
}

// TestLiveValidateConfigChecksVault is the cheapest moment to find each of
// these, and the test asserts it is actually taken.
func TestLiveValidateConfigChecksVault(t *testing.T) {
	p := NewProvider(Options{})
	ctx := context.Background()

	healthy, err := p.ValidateConfig(ctx, &providerv1.ValidateConfigRequest{
		ConfigJson: liveConfig(t, "pki-int", "web"),
	})
	if err != nil {
		t.Fatalf("validating: %v", err)
	}
	if !healthy.Valid {
		t.Fatalf("a working account was rejected: %v", healthy.Errors)
	}
	t.Logf("healthy account warnings: %s", strings.Join(healthy.Warnings, " | "))

	missing, err := p.ValidateConfig(ctx, &providerv1.ValidateConfigRequest{
		ConfigJson: liveConfig(t, "pki-int", "does-not-exist"),
	})
	if err != nil {
		t.Fatalf("validating: %v", err)
	}
	if missing.Valid {
		t.Fatalf("an account naming a role that does not exist was accepted")
	}

	expiring, err := p.ValidateConfig(ctx, &providerv1.ValidateConfigRequest{
		ConfigJson: liveConfig(t, "pki-expiry", "web"),
	})
	if err != nil {
		t.Fatalf("validating: %v", err)
	}
	joined := strings.Join(expiring.Warnings, " | ")
	if !strings.Contains(joined, "Expiring Issuing") {
		t.Fatalf("no warning names the CA that is about to take the mount down: %s", joined)
	}
	t.Logf("expiring account warnings: %s", joined)
}

func parsePEM(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("not PEM: %q", string(raw))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing a certificate: %v", err)
	}
	return cert
}

// splitPEM separates a bundle into its blocks, which is how a chain arrives.
func splitPEM(bundle []byte) [][]byte {
	var out [][]byte
	rest := bundle
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			return out
		}
		out = append(out, pem.EncodeToMemory(block))
		rest = remainder
	}
}
