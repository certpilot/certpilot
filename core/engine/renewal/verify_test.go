package renewal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// swappableServer is a TLS endpoint whose certificate can be changed while it
// runs — a deployment, in miniature. One port for the whole test, because a
// certificate is identified by where it is served as much as by what it is.
type swappableServer struct {
	listener net.Listener
	mu       sync.RWMutex
	cert     tls.Certificate
	done     chan struct{}
}

func newSwappableServer(t *testing.T, cert tls.Certificate) *swappableServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &swappableServer{listener: ln, cert: cert, done: make(chan struct{})}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			held := s.cert
			return &held, nil
		},
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-s.done:
					return
				default:
					return
				}
			}
			go func() {
				tlsConn := tls.Server(conn, tlsCfg)
				_ = tlsConn.Handshake()
				_ = tlsConn.Close()
			}()
		}
	}()

	t.Cleanup(func() { close(s.done); _ = ln.Close() })
	return s
}

func (s *swappableServer) deploy(cert tls.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cert = cert
}

func (s *swappableServer) addr() string { return s.listener.Addr().String() }

// issueCert returns a certificate and its fingerprint.
func issueCert(t *testing.T, cn string) (tls.Certificate, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		x509util.CertInfoFromX509(parsed).FingerprintSHA256,
		string(pemBytes)
}

// seed builds the state a renewal leaves behind: a certificate carrying the new
// fingerprint and the old one, and a discovery result saying where the old one
// was seen.
func seed(t *testing.T, st store.Store, cn, addr, newFP, oldFP string) *store.Certificate {
	t.Helper()
	ctx := context.Background()

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	cert := &store.Certificate{
		CommonName: cn, FingerprintSHA256: newFP, PreviousFingerprint: oldFP,
		NotAfter: &notAfter, DaysRemaining: 90, Status: "ISSUED",
		VerificationState: store.VerificationPending,
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	scan := &store.DiscoveryScan{ScanType: store.ScanTypeNetwork}
	if err := st.CreateDiscoveryScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDiscoveryResults(ctx, []*store.DiscoveryResult{{
		ScanID: scan.ID, Host: host, Port: port, Reachable: true,
		FingerprintSHA256: oldFP, ManagementState: store.DiscoveryManaged,
		ScannedAt: time.Now(),
	}}); err != nil {
		t.Fatal(err)
	}
	return cert
}

func newVerifier(t *testing.T, st store.Store, broker *events.Broker) *Verifier {
	t.Helper()
	scanner := discovery.NewScanner(st, discovery.WithDialTimeout(3*time.Second))
	return NewVerifier(st, scanner, broker)
}

// The finding this step exists for: the renewal succeeded, the record is
// healthy, and the server is still handing users the old certificate.
func TestARenewalThatNeverReachedTheServerIsCaught(t *testing.T) {
	oldCert, oldFP, _ := issueCert(t, "shop.example.com")
	_, newFP, _ := issueCert(t, "shop.example.com")

	server := newSwappableServer(t, oldCert)
	st := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicCertNotDeployed)
	defer sub.Close()

	cert := seed(t, st, "shop.example.com", server.addr(), newFP, oldFP)
	newVerifier(t, st, broker).Verify(context.Background(), cert)

	after, _ := st.GetCertificate(context.Background(), cert.ID)
	if after.VerificationState != store.VerificationStale {
		t.Fatalf("state = %q, want STALE — the server is still on the old certificate", after.VerificationState)
	}
	if !contains(after.VerificationDetail, "still serving the certificate this renewal replaced") {
		t.Errorf("detail does not say what is wrong: %q", after.VerificationDetail)
	}
	if !contains(after.VerificationDetail, server.addr()) {
		t.Errorf("detail does not name the endpoint: %q", after.VerificationDetail)
	}

	select {
	case evt := <-sub.Events():
		if evt.Severity != events.SeverityCritical {
			t.Errorf("severity = %s, want CRITICAL", evt.Severity)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a renewal that never reached the server produced no alert")
	}
}

// And once it is deployed, it verifies and stops being asked about.
func TestDeployingTheCertificateResolvesIt(t *testing.T) {
	oldCert, oldFP, _ := issueCert(t, "shop.example.com")
	newCert, newFP, _ := issueCert(t, "shop.example.com")

	server := newSwappableServer(t, oldCert)
	st := store.NewMemoryStore()
	cert := seed(t, st, "shop.example.com", server.addr(), newFP, oldFP)
	v := newVerifier(t, st, nil)

	v.Verify(context.Background(), cert)
	stale, _ := st.GetCertificate(context.Background(), cert.ID)
	if stale.VerificationState != store.VerificationStale {
		t.Fatalf("state = %q, want STALE first", stale.VerificationState)
	}
	if stale.VerifyAfter == nil {
		t.Error("an unresolved certificate was not scheduled for another look")
	}

	server.deploy(newCert)
	v.Verify(context.Background(), stale)

	after, _ := st.GetCertificate(context.Background(), cert.ID)
	if after.VerificationState != store.VerificationVerified {
		t.Fatalf("state = %q after deployment, want VERIFIED: %s", after.VerificationState, after.VerificationDetail)
	}
	if after.VerifyAfter != nil {
		t.Error("a verified certificate is still scheduled to be probed again")
	}
}

// Announced on the first stale check only. The second and third messages would
// say the same thing about the same certificate to people already told.
func TestTheNotDeployedAlertFiresOnce(t *testing.T) {
	oldCert, oldFP, _ := issueCert(t, "shop.example.com")
	_, newFP, _ := issueCert(t, "shop.example.com")

	server := newSwappableServer(t, oldCert)
	st := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicCertNotDeployed)
	defer sub.Close()

	cert := seed(t, st, "shop.example.com", server.addr(), newFP, oldFP)
	v := newVerifier(t, st, broker)

	for i := 0; i < 3; i++ {
		current, _ := st.GetCertificate(context.Background(), cert.ID)
		v.Verify(context.Background(), current)
	}

	published := 0
	for {
		select {
		case <-sub.Events():
			published++
			continue
		case <-time.After(300 * time.Millisecond):
		}
		break
	}
	if published != 1 {
		t.Fatalf("%d alerts for one undeployed certificate, want exactly 1", published)
	}
}

// An endpoint serving some third certificate is a different problem from one
// still on the old certificate, and deserves different words.
func TestAThirdCertificateIsReportedAsSomethingElse(t *testing.T) {
	strangerCert, _, _ := issueCert(t, "someone-else.example.com")
	_, oldFP, _ := issueCert(t, "shop.example.com")
	_, newFP, _ := issueCert(t, "shop.example.com")

	server := newSwappableServer(t, strangerCert)
	st := store.NewMemoryStore()
	cert := seed(t, st, "shop.example.com", server.addr(), newFP, oldFP)
	newVerifier(t, st, nil).Verify(context.Background(), cert)

	after, _ := st.GetCertificate(context.Background(), cert.ID)
	if after.VerificationState != store.VerificationStale {
		t.Fatalf("state = %q, want STALE", after.VerificationState)
	}
	if !contains(after.VerificationDetail, "a different name entirely") {
		t.Errorf("a stranger certificate was reported as the old one: %q", after.VerificationDetail)
	}
}

// Two renewals without a deployment leaves the server further back than the
// certificate the last renewal replaced. That is not a stranger, and calling it
// one sends somebody hunting a rogue service that does not exist.
//
// Found live: after renewing twice, the endpoint still had the original
// certificate and was reported as "something else is terminating TLS there".
func TestAnOlderCertificateForTheSameNameIsNotAStranger(t *testing.T) {
	originalCert, originalFP, _ := issueCert(t, "shop.example.com")
	_, replacedFP, _ := issueCert(t, "shop.example.com")
	_, newFP, _ := issueCert(t, "shop.example.com")

	// The server never moved off the original; the record has been renewed
	// twice, so what it thinks it replaced is the middle one.
	server := newSwappableServer(t, originalCert)
	st := store.NewMemoryStore()
	cert := seed(t, st, "shop.example.com", server.addr(), newFP, replacedFP)
	_ = originalFP

	newVerifier(t, st, nil).Verify(context.Background(), cert)

	after, _ := st.GetCertificate(context.Background(), cert.ID)
	if after.VerificationState != store.VerificationStale {
		t.Fatalf("state = %q, want STALE", after.VerificationState)
	}
	if contains(after.VerificationDetail, "different name entirely") {
		t.Fatalf("an older certificate for the same name was reported as a stranger: %q", after.VerificationDetail)
	}
	if !contains(after.VerificationDetail, "older certificate for this name") {
		t.Errorf("the detail does not say what is actually there: %q", after.VerificationDetail)
	}
	if !contains(after.VerificationDetail, "reaching nothing") {
		t.Errorf("the detail does not say renewals have been landing nowhere: %q", after.VerificationDetail)
	}
}

// An endpoint that does not answer is not a verified endpoint. Silence is the
// one answer that must never be read as success.
func TestAnUnreachableEndpointIsNotVerified(t *testing.T) {
	_, oldFP, _ := issueCert(t, "gone.example.com")
	_, newFP, _ := issueCert(t, "gone.example.com")

	// A port nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	st := store.NewMemoryStore()
	cert := seed(t, st, "gone.example.com", addr, newFP, oldFP)
	newVerifier(t, st, nil).Verify(context.Background(), cert)

	after, _ := st.GetCertificate(context.Background(), cert.ID)
	if after.VerificationState != store.VerificationUnreachable {
		t.Fatalf("state = %q, want UNREACHABLE", after.VerificationState)
	}
	if !contains(after.VerificationDetail, "not the same as confirming") {
		t.Errorf("silence was reported as something other than unknown: %q", after.VerificationDetail)
	}
}

// A certificate nothing has ever observed cannot be verified, and saying so is
// better than guessing at hostnames out of its SANs.
func TestACertificateNobodyHasSeenIsReportedAsUnverifiable(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	cert := &store.Certificate{
		CommonName: "never-scanned.example.com", FingerprintSHA256: "new-fp",
		PreviousFingerprint: "old-fp", NotAfter: &notAfter, Status: "ISSUED",
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}

	newVerifier(t, st, nil).Verify(ctx, cert)

	after, _ := st.GetCertificate(ctx, cert.ID)
	if after.VerificationState != store.VerificationNoEndpoints {
		t.Fatalf("state = %q, want NO_ENDPOINTS", after.VerificationState)
	}
	if !contains(after.VerificationDetail, "Run a discovery scan") {
		t.Errorf("the detail does not say how to make this verifiable: %q", after.VerificationDetail)
	}
	// And it is dropped rather than probed hourly forever.
	if after.VerifyAfter != nil {
		t.Error("a certificate with nowhere to check is still scheduled for checking")
	}
}

// The verifier stops asking eventually. It does not stop reporting: the state
// stays on the record.
func TestVerificationGivesUpAskingButNotReporting(t *testing.T) {
	oldCert, oldFP, _ := issueCert(t, "stuck.example.com")
	_, newFP, _ := issueCert(t, "stuck.example.com")

	server := newSwappableServer(t, oldCert)
	st := store.NewMemoryStore()
	cert := seed(t, st, "stuck.example.com", server.addr(), newFP, oldFP)
	v := newVerifier(t, st, nil)

	for i := 0; i < verifyMaxAttempts+1; i++ {
		current, _ := st.GetCertificate(context.Background(), cert.ID)
		v.Verify(context.Background(), current)
	}

	after, _ := st.GetCertificate(context.Background(), cert.ID)
	if after.VerifyAfter != nil {
		t.Error("the verifier is still probing an endpoint that has not changed in six attempts")
	}
	if after.VerificationState != store.VerificationStale {
		t.Errorf("state = %q; giving up asking must not clear the finding", after.VerificationState)
	}
}

// A renewal schedules its own verification, with a grace period. Checking in
// the same second would report every renewal as undeployed, which is true and
// useless.
func TestRenewalSchedulesVerificationAfterAGracePeriod(t *testing.T) {
	if VerifyGrace < 5*time.Minute {
		t.Errorf("the grace period is %s; a deployment done by hand does not happen in that time", VerifyGrace)
	}
}

func TestStoppingTheVerifierTwiceIsSafe(t *testing.T) {
	v := NewVerifier(store.NewMemoryStore(), discovery.NewScanner(store.NewMemoryStore()), nil,
		WithVerifyTick(10*time.Millisecond))
	v.Start()
	v.Start()
	v.Stop()
	v.Stop()
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// A renewal has to schedule its own verification, through a writer that
// actually persists it.
//
// The first version set these as fields on the certificate and saved it with
// UpdateCertificate, whose explicit column list did not include them — so the
// values were dropped in silence against PostgreSQL. Every test passed, because
// the in-memory store keeps whole structs and cannot express a dropped column.
// Found by renewing a real certificate and seeing previous_fingerprint come
// back empty.
func TestRenewalSchedulesItsOwnVerification(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	cert := &store.Certificate{
		CommonName: "scheduled.example.com", FingerprintSHA256: "new-fingerprint",
		NotAfter: &notAfter, Status: "ISSUED",
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}

	// What the executor does after a successful renewal.
	verifyAt := time.Now().Add(VerifyGrace)
	if err := st.UpdateCertificateVerification(ctx, cert.ID, store.VerificationUpdate{
		State:               store.VerificationPending,
		CheckedAt:           time.Now(),
		VerifyAfter:         &verifyAt,
		PreviousFingerprint: "old-fingerprint",
	}); err != nil {
		t.Fatal(err)
	}

	after, _ := st.GetCertificate(ctx, cert.ID)
	if after.PreviousFingerprint != "old-fingerprint" {
		t.Fatalf("previous_fingerprint = %q; without it a stale endpoint cannot be told from a stranger",
			after.PreviousFingerprint)
	}
	if after.VerificationState != store.VerificationPending || after.VerifyAfter == nil {
		t.Fatalf("verification was not scheduled: state=%q verify_after=%v",
			after.VerificationState, after.VerifyAfter)
	}

	// And every later pass must keep it rather than blanking it.
	if err := st.UpdateCertificateVerification(ctx, cert.ID, store.VerificationUpdate{
		State: store.VerificationStale, Detail: "still on the old one", CheckedAt: time.Now(), Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	later, _ := st.GetCertificate(ctx, cert.ID)
	if later.PreviousFingerprint != "old-fingerprint" {
		t.Error("a verification pass blanked the fingerprint the renewal replaced")
	}
}
