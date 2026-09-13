package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	"google.golang.org/grpc"
)

// stubGateway is a gateway that reports whatever a test tells it to.
type stubGateway struct {
	providerv1.UnimplementedCertificateProviderServiceServer
	supportsCAInfo bool
	chain          []*commonv1.CAAuthorityInfo
	calls          int
}

func (g *stubGateway) GetCapabilities(
	ctx context.Context, req *providerv1.GetCapabilitiesRequest,
) (*providerv1.GetCapabilitiesResponse, error) {
	return &providerv1.GetCapabilitiesResponse{
		Capabilities: &commonv1.ProviderCapabilities{
			ProviderName:   "stub",
			ProviderType:   "stub",
			SupportsCaInfo: g.supportsCAInfo,
		},
	}, nil
}

func (g *stubGateway) GetCAInfo(
	ctx context.Context, req *providerv1.GetCAInfoRequest,
) (*providerv1.GetCAInfoResponse, error) {
	g.calls++
	return &providerv1.GetCAInfoResponse{CaChain: g.chain}, nil
}

// connect starts the stub on a real gRPC listener and registers it, so the
// importer goes through the plugin manager exactly as it does in production —
// including the capability negotiation that decides whether it asks at all.
func connect(t *testing.T, gateway *stubGateway) *pluginmgr.Manager {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	server := grpc.NewServer()
	providerv1.RegisterCertificateProviderServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	manager := pluginmgr.NewManager(grpckit.TLSConfig{Insecure: true})
	t.Cleanup(manager.Close)
	if _, err := manager.RegisterGateway(
		context.Background(), "stub-ca", listener.Addr().String(), "stub", ""); err != nil {
		t.Fatalf("registering the stub gateway: %v", err)
	}
	return manager
}

// account returns a CA account pointing at the stub, with no sealed
// configuration — there is nothing to decrypt and nothing to hide.
func account(t *testing.T, s store.Store) *store.CAAccount {
	t.Helper()
	acc := &store.CAAccount{
		Name:         "stub-ca",
		ProviderType: "stub",
		GatewayAddr:  "127.0.0.1:0",
		Status:       "CONNECTED",
	}
	if err := s.CreateCAAccount(context.Background(), acc); err != nil {
		t.Fatalf("creating the CA account: %v", err)
	}
	return acc
}

// authority builds a CA certificate and the wire message a gateway would send
// for it.
func authority(t *testing.T, commonName string, expiresIn time.Duration, parent *authorityFixture) *authorityFixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatalf("generating a serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(expiresIn),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("creating a CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	info, err := x509util.ParseCertificatePEM(pemBytes)
	if err != nil {
		t.Fatalf("describing: %v", err)
	}

	return &authorityFixture{
		cert: cert,
		key:  key,
		info: info,
		message: &commonv1.CAAuthorityInfo{
			Name:              "pki/" + commonName,
			SubjectDn:         info.SubjectDN,
			CertificatePem:    pemBytes,
			CaType:            "INTERMEDIATE",
			FingerprintSha256: info.FingerprintSHA256,
		},
	}
}

type authorityFixture struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	info    *x509util.CertInfo
	message *commonv1.CAAuthorityInfo
}

func newImporter(t *testing.T, gateway *stubGateway, broker *events.Broker) (*Importer, store.Store) {
	t.Helper()
	s := store.NewMemoryStore()
	return NewImporter(s, connect(t, gateway), nil, broker), s
}

// TestAnIssuerReportedByAGatewayEntersTheInventory is the whole point. The RPC
// has been in the contract since the first proto file; this is the first thing
// that writes down what it returns.
func TestAnIssuerReportedByAGatewayEntersTheInventory(t *testing.T) {
	issuing := authority(t, "Corp Issuing CA", 400*24*time.Hour, nil)
	gateway := &stubGateway{supportsCAInfo: true, chain: []*commonv1.CAAuthorityInfo{issuing.message}}
	importer, s := newImporter(t, gateway, nil)
	acc := account(t, s)

	result := importer.ImportAccount(context.Background(), acc)
	if result.Error != "" {
		t.Fatalf("importing: %s", result.Error)
	}
	if result.Added() != 1 {
		t.Fatalf("added %d, want 1 (%+v)", result.Added(), result.Outcomes)
	}

	stored, err := s.GetCAAuthorityByFingerprint(context.Background(), issuing.info.FingerprintSHA256)
	if err != nil || stored == nil {
		t.Fatalf("the CA was reported as added and is not in the inventory: %v", err)
	}
	if stored.Source != store.CASourceGateway {
		t.Fatalf("source = %q, want %q", stored.Source, store.CASourceGateway)
	}
	if stored.CAAccountID == nil || *stored.CAAccountID != acc.ID {
		t.Fatalf("the CA is not linked to the account that reported it")
	}
	if stored.LastSeenAt == nil {
		t.Fatalf("nothing recorded when this CA was last offered")
	}
	if stored.NotAfter.Unix() != issuing.cert.NotAfter.Unix() {
		t.Fatalf("expiry = %s, want the certificate's own", stored.NotAfter)
	}
}

// TestACANamedWithoutACertificateIsNotRecorded covers what the ACME gateway
// actually returns: a placeholder, because ACME publishes no endpoint listing
// issuer certificates. A row built from it would look like a monitored CA and
// would have no expiry to monitor.
func TestACANamedWithoutACertificateIsNotRecorded(t *testing.T) {
	gateway := &stubGateway{supportsCAInfo: true, chain: []*commonv1.CAAuthorityInfo{{
		Name:      "Let's Encrypt",
		SubjectDn: "https://acme-v02.api.letsencrypt.org/directory",
		CaType:    "ISSUING",
	}}}
	importer, s := newImporter(t, gateway, nil)

	result := importer.ImportAccount(context.Background(), account(t, s))
	if result.Added() != 0 {
		t.Fatalf("a CA with no certificate was recorded")
	}
	if len(result.Outcomes) != 1 || result.Outcomes[0].Action != ActionSkipped {
		t.Fatalf("outcomes = %+v, want one skip", result.Outcomes)
	}
	if !strings.Contains(result.Outcomes[0].Reason, "did not send its certificate") {
		t.Fatalf("the reason does not say what was missing: %q", result.Outcomes[0].Reason)
	}
}

// TestTheCertificateIsBelievedOverTheGateway. A gateway's account of a CA is
// hearsay about a document CertPilot has been handed; the document is right.
func TestTheCertificateIsBelievedOverTheGateway(t *testing.T) {
	issuing := authority(t, "Corp Issuing CA", 40*24*time.Hour, nil)
	// A self-signed certificate is a root whatever the gateway calls it, and
	// the expiry is 40 days away whatever the gateway says.
	issuing.message.CaType = "ISSUING"
	issuing.message.DaysRemaining = 9999
	issuing.message.NotAfter = nil
	issuing.message.SubjectDn = "CN=Something Else Entirely"

	gateway := &stubGateway{supportsCAInfo: true, chain: []*commonv1.CAAuthorityInfo{issuing.message}}
	importer, s := newImporter(t, gateway, nil)
	importer.ImportAccount(context.Background(), account(t, s))

	stored, err := s.GetCAAuthorityByFingerprint(context.Background(), issuing.info.FingerprintSHA256)
	if err != nil || stored == nil {
		t.Fatalf("not recorded: %v", err)
	}
	if stored.CAType != "ROOT" {
		t.Fatalf("ca_type = %q, want ROOT: the certificate is self-signed", stored.CAType)
	}
	if stored.DaysRemaining > 41 || stored.DaysRemaining < 38 {
		t.Fatalf("days remaining = %d, want about 40 from the certificate", stored.DaysRemaining)
	}
	if stored.SubjectDN != issuing.info.SubjectDN {
		t.Fatalf("subject = %q, want the certificate's", stored.SubjectDN)
	}
	if stored.Status != "WARNING" {
		t.Fatalf("status = %q, want WARNING at 40 days", stored.Status)
	}
}

// TestASecondSweepRefreshesAndLeavesOperatorChoicesAlone is what makes running
// this on a timer safe. A sweep that reset a name or a threshold every twelve
// hours would be worse than not running at all.
func TestASecondSweepRefreshesAndLeavesOperatorChoicesAlone(t *testing.T) {
	issuing := authority(t, "Corp Issuing CA", 400*24*time.Hour, nil)
	gateway := &stubGateway{supportsCAInfo: true, chain: []*commonv1.CAAuthorityInfo{issuing.message}}
	importer, s := newImporter(t, gateway, nil)
	acc := account(t, s)
	ctx := context.Background()

	importer.ImportAccount(ctx, acc)

	// An operator renames it, tunes its thresholds, and puts a team on it.
	stored, _ := s.GetCAAuthorityByFingerprint(ctx, issuing.info.FingerprintSHA256)
	team := "platform-security"
	stored.Name = "The One That Matters"
	stored.AlertThresholds = "[400, 200]"
	stored.OwnerTeam = &team
	stored.Notes = "rotate before March"
	if err := s.UpdateCAAuthority(ctx, stored); err != nil {
		t.Fatalf("recording the operator's changes: %v", err)
	}

	result := importer.ImportAccount(ctx, acc)
	if result.Added() != 0 || result.Refreshed() != 1 {
		t.Fatalf("second sweep added %d and refreshed %d, want 0 and 1",
			result.Added(), result.Refreshed())
	}

	after, _ := s.GetCAAuthorityByFingerprint(ctx, issuing.info.FingerprintSHA256)
	if after.Name != "The One That Matters" {
		t.Fatalf("name = %q, want the operator's", after.Name)
	}
	if after.AlertThresholds != "[400, 200]" {
		t.Fatalf("thresholds = %q, want the operator's", after.AlertThresholds)
	}
	if after.OwnerTeam == nil || *after.OwnerTeam != team {
		t.Fatalf("owning team was lost")
	}
	if after.Notes != "rotate before March" {
		t.Fatalf("notes = %q, want the operator's", after.Notes)
	}
}

// TestAnIntermediateIsLinkedToItsRoot builds the chain the hierarchy view and
// the CA health list are drawn from.
func TestAnIntermediateIsLinkedToItsRoot(t *testing.T) {
	root := authority(t, "Corp Root CA", 3650*24*time.Hour, nil)
	root.message.CaType = "ROOT"
	issuing := authority(t, "Corp Issuing CA", 400*24*time.Hour, root)

	// Listed child first, which is the order a gateway is free to use.
	gateway := &stubGateway{supportsCAInfo: true,
		chain: []*commonv1.CAAuthorityInfo{issuing.message, root.message}}
	importer, s := newImporter(t, gateway, nil)
	ctx := context.Background()

	importer.ImportAccount(ctx, account(t, s))

	child, _ := s.GetCAAuthorityByFingerprint(ctx, issuing.info.FingerprintSHA256)
	parent, _ := s.GetCAAuthorityByFingerprint(ctx, root.info.FingerprintSHA256)
	if child == nil || parent == nil {
		t.Fatalf("both CAs should have been recorded")
	}
	if child.ParentCAID == nil || *child.ParentCAID != parent.ID {
		t.Fatalf("the intermediate is not linked to the root that signed it")
	}
	if parent.ParentCAID != nil {
		t.Fatalf("a self-signed root was given a parent, which makes the chain a cycle")
	}
}

// TestAGatewayThatCannotReportIssuersIsNotAsked. Asking one that does not
// implement the RPC produces an error per account, on a timer, for ever.
func TestAGatewayThatCannotReportIssuersIsNotAsked(t *testing.T) {
	gateway := &stubGateway{supportsCAInfo: false}
	importer, s := newImporter(t, gateway, nil)

	result := importer.ImportAccount(context.Background(), account(t, s))
	if result.Error != "" {
		t.Fatalf("a gateway without the capability produced an error: %s", result.Error)
	}
	if gateway.calls != 0 {
		t.Fatalf("the gateway was asked %d times despite saying it cannot answer", gateway.calls)
	}
}

// TestACADiscoveredNearItsExpiryIsCritical. A CA nobody was watching that
// turns out to be weeks from expiry is not a discovery, it is an incident that
// has been running silently.
func TestACADiscoveredNearItsExpiryIsCritical(t *testing.T) {
	broker := events.NewBroker()
	defer broker.Stop()
	subscription := broker.Subscribe(events.TopicCADiscovered)
	defer subscription.Close()

	issuing := authority(t, "Corp Issuing CA", 20*24*time.Hour, nil)
	gateway := &stubGateway{supportsCAInfo: true, chain: []*commonv1.CAAuthorityInfo{issuing.message}}
	importer, s := newImporter(t, gateway, broker)

	importer.ImportAccount(context.Background(), account(t, s))

	select {
	case evt := <-subscription.Events():
		if evt.Severity != events.SeverityCritical {
			t.Fatalf("severity = %s, want CRITICAL for a CA with 20 days left", evt.Severity)
		}
		payload, ok := evt.Payload.(map[string]any)
		if !ok {
			t.Fatalf("payload = %T, want a map", evt.Payload)
		}
		if payload["ca_account"] != "stub-ca" {
			t.Fatalf("the event does not name the account it came from: %v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no event was published for a newly discovered CA")
	}
}
