package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// installFixture is a store with one agent and one certificate on it.
func installFixture(t *testing.T) (*store.MemoryStore, *store.Agent, *store.Certificate) {
	t.Helper()
	st := store.NewMemoryStore()
	ctx := context.Background()

	agent := &store.Agent{Name: "web-01", Hostname: "web-01.internal", Status: store.AgentActive}
	if err := st.CreateAgent(ctx, agent); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	pem := "-----BEGIN CERTIFICATE-----\nnot really\n-----END CERTIFICATE-----\n"
	cert := &store.Certificate{
		CommonName:        "shop.example.com",
		FingerprintSHA256: "aaaa",
		Status:            "ISSUED",
		CertificatePEM:    &pem,
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return st, agent, cert
}

func reportOf(installs ...agentapi.Installation) agentapi.InstallationReport {
	return agentapi.InstallationReport{
		ReportedAt: time.Now(), SpecPath: "/etc/certpilot/installs.json",
		Installations: installs,
	}
}

func installed(name, certID string) agentapi.Installation {
	at := time.Now()
	return agentapi.Installation{
		Name: name, Certificate: "shop.example.com", CertificateID: certID,
		Fingerprint: "aaaa", Status: agentapi.InstallInstalled,
		Paths: []string{"/etc/nginx/ssl/shop.crt"}, InstalledAt: &at,
		ReloadCommand: "/usr/sbin/nginx -s reload",
	}
}

// TestAHostThatInstallsBecomesADeploymentTarget.
//
// The point of the step. Everything a central team already reads about where a
// certificate is deployed — the binding, the fingerprint that place is holding,
// the target's last outcome — has to work for a host behind two firewalls the
// same way it works for a load balancer with an API.
func TestAHostThatInstallsBecomesADeploymentTarget(t *testing.T) {
	st, agent, cert := installFixture(t)
	ctx := context.Background()

	result, err := NewInstalls(st, nil).Record(ctx, agent, reportOf(installed("nginx", cert.ID)))
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if result.TargetID == "" || result.Installed != 1 {
		t.Fatalf("expected one installed destination and a target, got %+v", result)
	}

	target, err := st.GetDeploymentTarget(ctx, result.TargetID)
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	if target.AgentID == nil || *target.AgentID != agent.ID {
		t.Fatal("the target should belong to the agent that reported it")
	}
	// Not a default. The key was generated on that host and is already there,
	// so an agent host must never appear in the answer to "where does this
	// organisation ship private keys".
	if target.DeploysPrivateKey {
		t.Fatal("an agent target must not be recorded as receiving private key material")
	}

	bindings, err := st.ListCertificateDeployments(ctx, cert.ID)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("expected one binding, got %d (%v)", len(bindings), err)
	}
	if bindings[0].LastStatus != store.DeploymentDeployed || bindings[0].DeployedFingerprint != "aaaa" {
		t.Fatalf("the binding should record what that place is holding, got %+v", bindings[0])
	}
}

// TestAHostThatKeepsReportingTheSameThingDoesNotKeepChangingIt.
//
// A host reports every few minutes. Rewriting the outcome each time would push
// deployed_at forward for ever, turning "when this place took the certificate"
// into "when this host last spoke" — two facts that look identical in a column.
func TestAHostThatKeepsReportingTheSameThingDoesNotKeepChangingIt(t *testing.T) {
	st, agent, cert := installFixture(t)
	ctx := context.Background()
	installs := NewInstalls(st, nil)

	if _, err := installs.Record(ctx, agent, reportOf(installed("nginx", cert.ID))); err != nil {
		t.Fatalf("first report: %v", err)
	}
	first, _ := st.ListCertificateDeployments(ctx, cert.ID)
	firstAt := first[0].DeployedAt

	time.Sleep(5 * time.Millisecond)
	if _, err := installs.Record(ctx, agent, reportOf(installed("nginx", cert.ID))); err != nil {
		t.Fatalf("second report: %v", err)
	}
	second, _ := st.ListCertificateDeployments(ctx, cert.ID)

	if firstAt == nil || second[0].DeployedAt == nil || !second[0].DeployedAt.Equal(*firstAt) {
		t.Fatalf("an unchanged report moved deployed_at from %v to %v", firstAt, second[0].DeployedAt)
	}
}

// TestAFailedInstallIsAnnouncedOnceAndSaysWhetherItRolledBack.
func TestAFailedInstallIsAnnouncedOnceAndSaysWhetherItRolledBack(t *testing.T) {
	st, agent, cert := installFixture(t)
	ctx := context.Background()

	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicAgentInstallFailed)
	defer sub.Close()

	failure := installed("nginx", cert.ID)
	failure.Status = agentapi.InstallFailed
	failure.Error = "/usr/sbin/nginx -t refused the new certificate"
	failure.RolledBack = true

	installs := NewInstalls(st, broker)
	for i := 0; i < 3; i++ {
		if _, err := installs.Record(ctx, agent, reportOf(failure)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	// Once, not three times. A destination failing since Tuesday must not send
	// a message every cycle until somebody mutes the channel that also carries
	// CA expiry alerts.
	got := drain(sub)
	if len(got) != 1 {
		t.Fatalf("expected one event for a failure reported three times, got %d", len(got))
	}
	if got[0].Severity != events.SeverityWarning {
		t.Fatalf("a rolled-back failure is a deployment to fix, not an outage: got %s", got[0].Severity)
	}

	// The binding keeps saying what that place is really holding.
	bindings, _ := st.ListCertificateDeployments(ctx, cert.ID)
	if bindings[0].LastStatus != store.DeploymentFailed {
		t.Fatalf("expected FAILED, got %q", bindings[0].LastStatus)
	}
	if bindings[0].DeployedFingerprint != "" {
		t.Fatal("a failed install must not record a fingerprint that never landed")
	}
}

// TestAnInstallThatCouldNotBeRolledBackIsCritical.
//
// The difference between an inconvenience and an outage: nobody knows what that
// listener is serving.
func TestAnInstallThatCouldNotBeRolledBackIsCritical(t *testing.T) {
	st, agent, cert := installFixture(t)
	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicAgentInstallFailed)
	defer sub.Close()

	failure := installed("nginx", cert.ID)
	failure.Status = agentapi.InstallFailed
	failure.Error = "the reload failed"
	failure.RolledBack = false

	if _, err := NewInstalls(st, broker).Record(context.Background(), agent, reportOf(failure)); err != nil {
		t.Fatalf("record: %v", err)
	}
	got := drain(sub)
	if len(got) != 1 || got[0].Severity != events.SeverityCritical {
		t.Fatalf("expected one CRITICAL, got %+v", got)
	}
}

// TestADestinationForACertificateNobodyGrantedIsReported.
//
// The finding no other view in this system can produce. There is no binding, no
// certificate and no failed attempt — just a machine that will do nothing at
// all when the renewal it is waiting for never arrives.
func TestADestinationForACertificateNobodyGrantedIsReported(t *testing.T) {
	st, agent, _ := installFixture(t)
	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicAgentInstallUnfulfilled)
	defer sub.Close()

	orphan := agentapi.Installation{
		Name: "nginx", Certificate: "shop.exmaple.com",
		Status: agentapi.InstallUnfulfilled,
		Detail: "this host holds no certificate for shop.exmaple.com",
	}

	installs := NewInstalls(st, broker)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		result, err := installs.Record(ctx, agent, reportOf(orphan))
		if err != nil {
			t.Fatalf("record: %v", err)
		}
		if result.Unfulfilled != 1 {
			t.Fatalf("expected one unfulfilled destination, got %+v", result)
		}
	}

	if got := drain(sub); len(got) != 1 {
		t.Fatalf("expected one event for the same problem reported twice, got %d", len(got))
	}

	rows, total, err := st.ListAgentInstallations(ctx, store.AgentInstallationFilter{NeedsAttention: true})
	if err != nil || total != 1 {
		t.Fatalf("expected one row needing attention, got %d (%v)", total, err)
	}
	if rows[0].CertificateID != nil {
		t.Fatal("an unfulfilled destination has no certificate")
	}
}

// TestARenewedCertificateLeavesNoSecondBindingBehind.
//
// An agent renews by obtaining a new certificate rather than replacing one in
// place, so without pruning, the binding for the certificate it replaced sits
// beside the new one — and a live run showed both saying "All 1 target hold the
// current certificate" about a host with one file. Two confident sentences, one
// of them false.
func TestARenewedCertificateLeavesNoSecondBindingBehind(t *testing.T) {
	st, agent, first := installFixture(t)
	ctx := context.Background()
	installs := NewInstalls(st, nil)

	if _, err := installs.Record(ctx, agent, reportOf(installed("nginx", first.ID))); err != nil {
		t.Fatalf("first: %v", err)
	}

	pem := "-----BEGIN CERTIFICATE-----\nnewer\n-----END CERTIFICATE-----\n"
	second := &store.Certificate{
		CommonName: "shop.example.com", FingerprintSHA256: "bbbb",
		Status: "ISSUED", CertificatePEM: &pem,
	}
	if err := st.CreateCertificate(ctx, second); err != nil {
		t.Fatalf("create: %v", err)
	}

	rotated := installed("nginx", second.ID)
	rotated.Fingerprint = "bbbb"
	if _, err := installs.Record(ctx, agent, reportOf(rotated)); err != nil {
		t.Fatalf("second: %v", err)
	}

	if old, _ := st.ListCertificateDeployments(ctx, first.ID); len(old) != 0 {
		t.Fatalf("the replaced certificate still claims to be installed somewhere: %+v", old[0])
	}
	current, _ := st.ListCertificateDeployments(ctx, second.ID)
	if len(current) != 1 || current[0].DeployedFingerprint != "bbbb" {
		t.Fatalf("expected one binding holding the new certificate, got %+v", current)
	}
}

// TestADestinationTheHostNoLongerDeclaresIsRemoved.
func TestADestinationTheHostNoLongerDeclaresIsRemoved(t *testing.T) {
	st, agent, cert := installFixture(t)
	ctx := context.Background()
	installs := NewInstalls(st, nil)

	if _, err := installs.Record(ctx, agent,
		reportOf(installed("nginx", cert.ID), installed("haproxy", cert.ID))); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, total, _ := st.ListAgentInstallations(ctx, store.AgentInstallationFilter{}); total != 2 {
		t.Fatalf("expected two destinations, got %d", total)
	}

	if _, err := installs.Record(ctx, agent, reportOf(installed("nginx", cert.ID))); err != nil {
		t.Fatalf("second record: %v", err)
	}
	rows, total, _ := st.ListAgentInstallations(ctx, store.AgentInstallationFilter{})
	if total != 1 || rows[0].Name != "nginx" {
		t.Fatalf("a destination removed from the spec should stop being shown, got %d rows", total)
	}
}

// TestOneDeletedCertificateDoesNotSinkTheWholeReport.
//
// A host holds what it was issued. A certificate deleted centrally since then
// must not take the nine destinations that were fine down with the one that was
// not.
func TestOneDeletedCertificateDoesNotSinkTheWholeReport(t *testing.T) {
	st, agent, cert := installFixture(t)
	ctx := context.Background()

	ghost := installed("haproxy", "00000000-0000-0000-0000-000000000000")
	result, err := NewInstalls(st, nil).Record(ctx, agent, reportOf(installed("nginx", cert.ID), ghost))
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if result.Destinations != 2 || result.Bindings != 1 {
		t.Fatalf("expected two destinations and one binding, got %+v", result)
	}

	rows, _, _ := st.ListAgentInstallations(ctx, store.AgentInstallationFilter{AgentID: agent.ID})
	for _, row := range rows {
		if row.Name == "haproxy" && row.CertificateID != nil {
			t.Fatal("a certificate the core no longer has should not be recorded as one it does")
		}
	}
}

// TestAnUnknownStatusFromAnOldAgentIsNotRecordedAsSuccess.
//
// This binary runs on hosts nobody upgrades for years, so an agent speaking a
// dialect this core does not know is the ordinary case. Whatever it meant, it
// is not evidence that a certificate is installed.
func TestAnUnknownStatusFromAnOldAgentIsNotRecordedAsSuccess(t *testing.T) {
	st, agent, cert := installFixture(t)
	odd := installed("nginx", cert.ID)
	odd.Status = "PARTIALLY_INSTALLED"

	result, err := NewInstalls(st, nil).Record(context.Background(), agent, reportOf(odd))
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if result.Installed != 0 || result.Unfulfilled != 1 {
		t.Fatalf("an unknown status should not count as installed, got %+v", result)
	}
}
