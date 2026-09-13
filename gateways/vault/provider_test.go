package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func makeCSR(t *testing.T, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: names[0]},
		DNSNames: names,
	}, key)
	if err != nil {
		t.Fatalf("creating a CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestSigningACSRReturnsNoPrivateKey holds the gateway to the rule that
// separates it from every system that emails you a .pfx: when the caller made
// the CSR, the key is theirs, it was never here, and there is nothing to
// return. A field populated on this path would mean Vault had generated a key
// for a request that already had one.
func TestSigningACSRReturnsNoPrivateKey(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})

	resp, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		CsrPem:         makeCSR(t, "app.example.com"),
		Domains:        []string{"app.example.com"},
		ValidityDays:   30,
		ProviderConfig: fake.config(),
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if len(resp.Certificate.PrivateKeyPem) != 0 {
		t.Fatalf("a signed CSR came back with a private key attached")
	}
	if resp.Certificate.CommonName != "app.example.com" {
		t.Fatalf("common name = %q", resp.Certificate.CommonName)
	}
	if len(resp.Certificate.ChainPem) == 0 {
		t.Fatalf("no chain returned; a certificate without its issuers does not verify")
	}
	if resp.ProviderCertificateId == "" || !strings.Contains(resp.ProviderCertificateId, ":") {
		t.Fatalf("provider certificate ID = %q, want Vault's colon-separated serial",
			resp.ProviderCertificateId)
	}
}

// TestIssuingWithoutACSRReturnsTheKeyVaultGenerated is the other half: with no
// CSR the key was generated in Vault, and omitting it would leave a
// certificate nobody can use.
func TestIssuingWithoutACSRReturnsTheKeyVaultGenerated(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})

	resp, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		Domains:        []string{"api.example.com", "www.example.com"},
		ValidityDays:   30,
		ProviderConfig: fake.config(),
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if len(resp.Certificate.PrivateKeyPem) == 0 {
		t.Fatalf("Vault generated the key and the gateway did not return it")
	}
	info, err := x509util.ParseCertificatePEM(resp.Certificate.CertificatePem)
	if err != nil {
		t.Fatalf("parsing what came back: %v", err)
	}
	if len(info.SANs) != 2 {
		t.Fatalf("SANs = %v, want both names requested", info.SANs)
	}
}

// TestNamesMissingFromTheCSRAreRefused covers the quiet one. A Vault role uses
// the CSR's own names by default, so asking for an extra name in the request
// produces a certificate that does not carry it — while CertPilot records the
// certificate as covering it.
func TestNamesMissingFromTheCSRAreRefused(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})

	_, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		CsrPem:         makeCSR(t, "app.example.com"),
		Domains:        []string{"app.example.com", "extra.example.com"},
		ProviderConfig: fake.config(),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %s, want InvalidArgument (error: %v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "use_csr_sans") {
		t.Fatalf("the refusal does not name the role setting that causes it: %v", err)
	}
}

// TestAnExpiringIssuerIsNamedInTheRefusal is why this gateway exists in the
// shape it does. Vault does not shorten a certificate that would outlive its
// issuer — it refuses, with a message about a notAfter date that says nothing
// about the CA. On the day it starts, it starts for every renewal at once.
func TestAnExpiringIssuerIsNamedInTheRefusal(t *testing.T) {
	fake := newFakeVault(t, 10*24*time.Hour)
	p := NewProvider(Options{})

	_, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		CsrPem:         makeCSR(t, "app.example.com"),
		Domains:        []string{"app.example.com"},
		ValidityDays:   90,
		ProviderConfig: fake.config(),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition — retrying this cannot help (error: %v)",
			status.Code(err), err)
	}
	for _, want := range []string{"outlive the CA signing it", "CertPilot Test Issuing", "rotated"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not say %q:\n%v", want, err)
		}
	}
}

// TestTheTokenIsObtainedOnceAndReused keeps the gateway from being hostile to
// the Vault it depends on. A login per request means a token per certificate,
// each with its own lease, and a fleet renewal that grows Vault's storage.
func TestTheTokenIsObtainedOnceAndReused(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})

	for i := 0; i < 3; i++ {
		if _, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
			Domains:        []string{"api.example.com"},
			ProviderConfig: fake.config(),
		}); err != nil {
			t.Fatalf("issuance %d: %v", i, err)
		}
	}

	logins, signs := fake.counts()
	if signs != 3 {
		t.Fatalf("signs = %d, want 3", signs)
	}
	if logins != 1 {
		t.Fatalf("logins = %d, want 1: the token should be reused across issuances", logins)
	}
}

// TestARefusedTokenIsReplacedOnce covers the failure that appears weeks after
// deployment, unattended, when a cached token reaches its TTL.
func TestARefusedTokenIsReplacedOnce(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})

	if _, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		Domains:        []string{"api.example.com"},
		ProviderConfig: fake.config(),
	}); err != nil {
		t.Fatalf("first issuance: %v", err)
	}

	// Vault now refuses the token it handed out, exactly as it does when the
	// token's lease has run out.
	fake.mu.Lock()
	fake.rejectN = 1
	fake.mu.Unlock()

	if _, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		Domains:        []string{"api.example.com"},
		ProviderConfig: fake.config(),
	}); err != nil {
		t.Fatalf("the gateway did not recover from a rejected token: %v", err)
	}

	if logins, _ := fake.counts(); logins != 2 {
		t.Fatalf("logins = %d, want 2: one at the start and one after the rejection", logins)
	}
}

// TestAnUnknownSerialIsUnknownNotRevoked is the rule that a gateway must never
// state more than it knows. Vault having no record is not evidence of
// revocation, and reporting it as such would mark live certificates dead.
func TestAnUnknownSerialIsUnknownNotRevoked(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})

	resp, err := p.GetCertificateStatus(context.Background(), &providerv1.GetCertificateStatusRequest{
		ProviderCertificateId: "de:ad:be:ef",
		ProviderConfig:        fake.config(),
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if resp.Status != providerv1.CertStatus_CERT_STATUS_UNKNOWN {
		t.Fatalf("status = %s, want UNKNOWN", resp.Status)
	}
	if !strings.Contains(resp.Message, "no_store") {
		t.Fatalf("the message does not offer the usual cause: %q", resp.Message)
	}
}

// TestRevokingThenCheckingReportsRevoked walks the lifecycle end to end.
func TestRevokingThenCheckingReportsRevoked(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})
	ctx := context.Background()

	issued, err := p.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		Domains:        []string{"api.example.com"},
		ProviderConfig: fake.config(),
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}

	before, err := p.GetCertificateStatus(ctx, &providerv1.GetCertificateStatusRequest{
		ProviderCertificateId: issued.ProviderCertificateId,
		ProviderConfig:        fake.config(),
	})
	if err != nil {
		t.Fatalf("status before revocation: %v", err)
	}
	if before.Status != providerv1.CertStatus_CERT_STATUS_VALID {
		t.Fatalf("status before revocation = %s, want VALID", before.Status)
	}

	revoked, err := p.RevokeCertificate(ctx, &providerv1.RevokeCertificateRequest{
		CertificatePem:        issued.Certificate.CertificatePem,
		ProviderCertificateId: issued.ProviderCertificateId,
		Reason:                1,
		ProviderConfig:        fake.config(),
	})
	if err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if !revoked.Success {
		t.Fatalf("revocation reported failure: %s", revoked.Message)
	}
	// Vault has no field for a reason code, so the gateway says so rather than
	// letting an operator believe keyCompromise reached the CRL.
	if !strings.Contains(revoked.Message, "does not record a revocation reason") {
		t.Fatalf("the reason code was dropped silently: %q", revoked.Message)
	}

	after, err := p.GetCertificateStatus(ctx, &providerv1.GetCertificateStatusRequest{
		ProviderCertificateId: issued.ProviderCertificateId,
		ProviderConfig:        fake.config(),
	})
	if err != nil {
		t.Fatalf("status after revocation: %v", err)
	}
	if after.Status != providerv1.CertStatus_CERT_STATUS_REVOKED {
		t.Fatalf("status after revocation = %s, want REVOKED", after.Status)
	}
}

// TestRevokingTwiceIsNotAFailure keeps a retry from becoming an incident.
func TestRevokingTwiceIsNotAFailure(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})
	ctx := context.Background()

	issued, err := p.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		Domains:        []string{"api.example.com"},
		ProviderConfig: fake.config(),
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	request := &providerv1.RevokeCertificateRequest{
		CertificatePem: issued.Certificate.CertificatePem,
		ProviderConfig: fake.config(),
	}
	if _, err := p.RevokeCertificate(ctx, request); err != nil {
		t.Fatalf("first revocation: %v", err)
	}
	second, err := p.RevokeCertificate(ctx, request)
	if err != nil {
		t.Fatalf("second revocation: %v", err)
	}
	if !second.Success {
		t.Fatalf("revoking an already-revoked certificate reported failure: %s", second.Message)
	}
}

// TestRevokingBySerialAloneIsRefusedWhenVaultKeptNoCopy is the promise not to
// report work that was not done — narrowed to the case where it is true.
//
// The first version of this test asserted that a no_store role could not be
// revoked at all. A real Vault disagreed: it will verify a certificate it is
// handed and revoke it whether or not it ever stored it. What it cannot do is
// find one by a serial it never recorded.
func TestRevokingBySerialAloneIsRefusedWhenVaultKeptNoCopy(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	fake.role["no_store"] = true
	p := NewProvider(Options{})

	_, err := p.RevokeCertificate(context.Background(), &providerv1.RevokeCertificateRequest{
		ProviderCertificateId: "de:ad:be:ef",
		ProviderConfig:        fake.config(),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition (error: %v)", status.Code(err), err)
	}
	for _, want := range []string{"no_store", "given the certificate itself"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not say %q: %v", want, err)
		}
	}
}

// TestANoStoreCertificateIsRevokedWithTheCertificate is the other half, and
// the reason the refusal above had to be narrowed: CertPilot holds the
// certificate, so this is the path it actually takes.
func TestANoStoreCertificateIsRevokedWithTheCertificate(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	fake.role["no_store"] = true
	p := NewProvider(Options{})
	ctx := context.Background()

	issued, err := p.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		Domains:        []string{"ephemeral.example.com"},
		ProviderConfig: fake.config(),
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}

	// Vault kept no copy, so it has nothing to say about it yet.
	before, err := p.GetCertificateStatus(ctx, &providerv1.GetCertificateStatusRequest{
		ProviderCertificateId: issued.ProviderCertificateId,
		ProviderConfig:        fake.config(),
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if before.Status != providerv1.CertStatus_CERT_STATUS_UNKNOWN {
		t.Fatalf("status = %s, want UNKNOWN for a certificate Vault never stored", before.Status)
	}

	revoked, err := p.RevokeCertificate(ctx, &providerv1.RevokeCertificateRequest{
		CertificatePem:        issued.Certificate.CertificatePem,
		ProviderCertificateId: issued.ProviderCertificateId,
		ProviderConfig:        fake.config(),
	})
	if err != nil {
		t.Fatalf("revoking a no_store certificate with the certificate in hand: %v", err)
	}
	if !revoked.Success {
		t.Fatalf("revocation reported failure: %s", revoked.Message)
	}
}

// TestGetCAInfoReportsTheMountsIssuers is the RPC that puts the CA signing an
// estate into the same inventory as the estate.
func TestGetCAInfoReportsTheMountsIssuers(t *testing.T) {
	fake := newFakeVault(t, 45*24*time.Hour)
	p := NewProvider(Options{})

	resp, err := p.GetCAInfo(context.Background(), &providerv1.GetCAInfoRequest{
		ProviderConfig: fake.config(),
	})
	if err != nil {
		t.Fatalf("CA info: %v", err)
	}
	if len(resp.CaChain) != 2 {
		t.Fatalf("issuers = %d, want 2", len(resp.CaChain))
	}
	if resp.CaChain[0].CaType != "ROOT" {
		t.Fatalf("first issuer is %s, want the root first", resp.CaChain[0].CaType)
	}
	issuing := resp.CaChain[1]
	if issuing.CaType != "INTERMEDIATE" {
		t.Fatalf("second issuer is %s", issuing.CaType)
	}
	if issuing.DaysRemaining > 45 || issuing.DaysRemaining < 43 {
		t.Fatalf("days remaining = %d, want about 45", issuing.DaysRemaining)
	}
	if !strings.HasPrefix(issuing.Name, "pki/") {
		t.Fatalf("name = %q, want it qualified by the mount", issuing.Name)
	}
	if len(issuing.CertificatePem) == 0 || issuing.FingerprintSha256 == "" {
		t.Fatalf("an issuer came back without the material needed to track it")
	}
}

// TestValidateConfigWarnsBeforeTheIssuerExpires says it at the only moment
// that helps: before the certificates are depending on it.
func TestValidateConfigWarnsBeforeTheIssuerExpires(t *testing.T) {
	fake := newFakeVault(t, 45*24*time.Hour)
	p := NewProvider(Options{})

	resp, err := p.ValidateConfig(context.Background(), &providerv1.ValidateConfigRequest{
		ConfigJson: fake.config(),
	})
	if err != nil {
		t.Fatalf("validating: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("a working configuration was rejected: %v", resp.Errors)
	}
	joined := strings.Join(resp.Warnings, "\n")
	if !strings.Contains(joined, "CertPilot Test Issuing") {
		t.Fatalf("no warning names the expiring issuer:\n%s", joined)
	}
	if !strings.Contains(joined, "caps validity at 90 days") {
		t.Fatalf("no warning reports the role's max_ttl:\n%s", joined)
	}
}

// TestValidateConfigFailsOnARoleThatDoesNotExist catches the commonest typo at
// the cheapest moment.
func TestValidateConfigFailsOnARoleThatDoesNotExist(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})

	resp, err := p.ValidateConfig(context.Background(), &providerv1.ValidateConfigRequest{
		ConfigJson: fake.configFor("typo"),
	})
	if err != nil {
		t.Fatalf("validating: %v", err)
	}
	if resp.Valid {
		t.Fatalf("a configuration naming a role that does not exist was accepted")
	}
	if !strings.Contains(strings.Join(resp.Errors, " "), `role "typo"`) {
		t.Fatalf("errors do not name the role: %v", resp.Errors)
	}
}

// TestCapabilitiesDescribeOnlyWhatIsImplemented follows the gateway rule that
// advertising something turns a configuration-time error into a mystery at
// renewal.
func TestCapabilitiesDescribeOnlyWhatIsImplemented(t *testing.T) {
	p := NewProvider(Options{})
	resp, err := p.GetCapabilities(context.Background(), &providerv1.GetCapabilitiesRequest{})
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	caps := resp.Capabilities
	if len(caps.SupportedChallenges) != 0 {
		t.Fatalf("challenges = %v, want none: Vault performs no domain control validation",
			caps.SupportedChallenges)
	}
	if !caps.SupportsRevocation {
		t.Fatalf("revocation is implemented and not advertised")
	}
	if !caps.SupportsCaInfo {
		t.Fatalf("CA info is implemented and not advertised")
	}
	if caps.ProviderType != "vault" {
		t.Fatalf("provider type = %q", caps.ProviderType)
	}
}

// TestAStandbyVaultIsHealthy covers a status code that means something other
// than failure. Vault answers 429 on a standby node, and a gateway that read
// that as rate limiting would back off from a Vault that is working.
func TestAStandbyVaultIsHealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":true}`))
	}))
	defer server.Close()

	p := NewProvider(Options{DefaultAddress: server.URL})
	resp, err := p.HealthCheck(context.Background(), &providerv1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if resp.Status.String() != "HEALTH_STATUS_HEALTHY" {
		t.Fatalf("status = %s, want healthy: %s", resp.Status, resp.Message)
	}
	if !strings.Contains(resp.Message, "standby") {
		t.Fatalf("message = %q", resp.Message)
	}
}

// TestASealedVaultIsUnhealthy is the other side: reachable, answering, and
// unable to issue anything.
func TestASealedVaultIsUnhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":true}`))
	}))
	defer server.Close()

	p := NewProvider(Options{DefaultAddress: server.URL})
	resp, err := p.HealthCheck(context.Background(), &providerv1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if resp.Status.String() != "HEALTH_STATUS_UNHEALTHY" {
		t.Fatalf("status = %s, want unhealthy", resp.Status)
	}
	if !strings.Contains(resp.Message, "sealed") {
		t.Fatalf("message = %q", resp.Message)
	}
}

// TestRenewalKeepsTheNamesOfTheCertificateItReplaces covers a renewal that
// arrives with no domains, which is how the core asks for "the same again".
func TestRenewalKeepsTheNamesOfTheCertificateItReplaces(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})
	ctx := context.Background()

	issued, err := p.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		Domains:        []string{"api.example.com", "www.example.com"},
		ProviderConfig: fake.config(),
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}

	renewed, err := p.RenewCertificate(ctx, &providerv1.RenewCertificateRequest{
		ProviderCertificateId: issued.ProviderCertificateId,
		CurrentCertificatePem: issued.Certificate.CertificatePem,
		ProviderConfig:        fake.config(),
	})
	if err != nil {
		t.Fatalf("renewing: %v", err)
	}
	if renewed.ProviderCertificateId == issued.ProviderCertificateId {
		t.Fatalf("the renewal reused the serial of the certificate it replaced")
	}
	info, err := x509util.ParseCertificatePEM(renewed.Certificate.CertificatePem)
	if err != nil {
		t.Fatalf("parsing the renewal: %v", err)
	}
	if len(info.SANs) != 2 {
		t.Fatalf("the renewal covers %v, want the names of the certificate it replaced", info.SANs)
	}
}

// TestAMissingConfigurationIsRefusedBeforeVaultIsAsked keeps a configuration
// error from arriving as a Vault error about something else.
func TestAMissingConfigurationIsRefusedBeforeVaultIsAsked(t *testing.T) {
	p := NewProvider(Options{})
	for name, config := range map[string]string{
		"no address": `{"role":"web","token":"t"}`,
		"no role":    `{"address":"https://vault.example.com","token":"t"}`,
		"not JSON":   `{`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
				Domains:        []string{"api.example.com"},
				ProviderConfig: config,
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %s, want InvalidArgument (error: %v)", status.Code(err), err)
			}
		})
	}
}
