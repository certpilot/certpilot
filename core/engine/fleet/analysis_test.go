package fleet

import (
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

func codes(findings []store.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Code)
	}
	return out
}

func has(findings []store.Finding, code string) *store.Finding {
	for i := range findings {
		if findings[i].Code == code {
			return &findings[i]
		}
	}
	return nil
}

// TestAReadableKeyIsTheFindingNothingElseCanMake, and it is critical whoever
// can read it.
func TestAReadableKeyIsTheFindingNothingElseCanMake(t *testing.T) {
	cases := map[string]struct {
		mode     string
		want     bool
		mentions string
	}{
		"world readable":   {"0644", true, "any account on the host"},
		"group readable":   {"0640", true, "its group"},
		"owner only":       {"0600", false, ""},
		"owner write only": {"0200", false, ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			findings := assess(&store.AgentCertificate{
				Kind: agentapi.KindLeaf, Path: "/etc/ssl/site.crt",
				PrivateKeyPath: "/etc/ssl/site.key", PrivateKeyMode: tc.mode,
				PrivateKeyMatches: true, ManagementState: store.DiscoveryManaged,
			}, false, nil, time.Now())

			found := has(findings, FindingKeyReadable)
			if tc.want && found == nil {
				t.Fatalf("mode %s should be reported, got %v", tc.mode, codes(findings))
			}
			if !tc.want && found != nil {
				t.Fatalf("mode %s should not be reported", tc.mode)
			}
			if !tc.want {
				return
			}
			if found.Severity != events.SeverityCritical {
				t.Fatalf("an exposed key is critical, got %s", found.Severity)
			}
			if !strings.Contains(found.Detail, tc.mentions) {
				t.Fatalf("the detail should say who can read it, got: %s", found.Detail)
			}
			// The instinct on reading this is to renew, and renewing leaves the
			// exposure exactly where it was.
			if !strings.Contains(found.Detail, "reissued") {
				t.Fatalf("the detail should say the certificate has to be reissued: %s", found.Detail)
			}
		})
	}
}

// TestAnExpiryMattersMoreWhenSomethingReadsTheFile. The same date is clutter or
// an outage depending on whether a configuration names it, and the two must not
// sort together.
func TestAnExpiryMattersMoreWhenSomethingReadsTheFile(t *testing.T) {
	expired := time.Now().Add(-24 * time.Hour)

	loose := assess(&store.AgentCertificate{
		Kind: agentapi.KindLeaf, Path: "/tmp/old.crt", NotAfter: &expired,
		ManagementState: store.DiscoveryManaged,
	}, true, nil, time.Now())
	served := assess(&store.AgentCertificate{
		Kind: agentapi.KindLeaf, Path: "/etc/nginx/site.crt", NotAfter: &expired,
		ReferencedBy: []string{"/etc/nginx/nginx.conf"}, ManagementState: store.DiscoveryManaged,
	}, true, nil, time.Now())

	if got := has(loose, FindingExpired); got == nil || got.Severity != events.SeverityWarning {
		t.Fatalf("an expired file nothing reads is a warning, got %+v", got)
	}
	if got := has(served, FindingExpired); got == nil || got.Severity != events.SeverityCritical {
		t.Fatalf("an expired file nginx is configured to serve is critical, got %+v", got)
	}
}

// TestTheSupersededFindingConnectsToRenewal. This file holds the certificate a
// renewal already replaced — post-renewal verification's finding arriving from
// a third direction, needing no scan to have ever reached this host.
func TestTheSupersededFindingConnectsToRenewal(t *testing.T) {
	findings := assess(&store.AgentCertificate{
		Kind: agentapi.KindLeaf, Path: "/etc/nginx/site.crt",
		ReferencedBy:    []string{"/etc/nginx/nginx.conf"},
		ManagementState: store.DiscoveryManaged,
	}, true, &store.Certificate{CommonName: "site.example.com"}, time.Now())

	found := has(findings, FindingSuperseded)
	if found == nil {
		t.Fatalf("expected a superseded finding, got %v", codes(findings))
	}
	if found.Severity != events.SeverityCritical {
		t.Fatalf("a superseded file something is configured to serve is critical, got %s", found.Severity)
	}
	if !strings.Contains(found.Detail, "site.example.com") {
		t.Fatalf("the detail should name the certificate: %s", found.Detail)
	}
	if !strings.Contains(found.Detail, "nginx.conf") {
		t.Fatalf("the detail should name what reads it: %s", found.Detail)
	}
}

// TestATrustStoreProducesNothing. A hundred findings about distribution roots
// is how the real findings on a host stop being read.
func TestATrustStoreProducesNothing(t *testing.T) {
	expired := time.Now().Add(-24 * time.Hour)
	findings := assess(&store.AgentCertificate{
		Kind: agentapi.KindBundle, Path: "/etc/ssl/certs/ca-certificates.crt",
		CertificateCount: 143, NotAfter: &expired, ManagementState: store.DiscoveryUnmanaged,
	}, true, nil, time.Now())

	if len(findings) != 0 {
		t.Fatalf("a trust store should produce no findings, got %v", codes(findings))
	}
}

// TestUnreferencedIsOnlyClaimedWhenTheHeuristicWorked.
//
// On a host where no configuration was matched at all, "nothing names this
// file" is a finding about this code rather than about the host — and reporting
// it against every file teaches its reader to ignore the category.
func TestUnreferencedIsOnlyClaimedWhenTheHeuristicWorked(t *testing.T) {
	record := func() *store.AgentCertificate {
		return &store.AgentCertificate{
			Kind: agentapi.KindLeaf, Path: "/etc/ssl/site.crt",
			PrivateKeyPath: "/etc/ssl/site.key", PrivateKeyMode: "0600",
			PrivateKeyMatches: true, ManagementState: store.DiscoveryManaged,
		}
	}

	if has(assess(record(), false, nil, time.Now()), FindingUnreferenced) != nil {
		t.Fatal("nothing should be called unreferenced on a host where no config was matched")
	}
	if has(assess(record(), true, nil, time.Now()), FindingUnreferenced) == nil {
		t.Fatal("on a host where the heuristic worked, an unmatched file is worth noting")
	}
}

// TestAKeylessCertificateIsSaidOnceQuietly. Most often a copy left behind by a
// migration, and never something to page anybody about.
func TestAKeylessCertificateIsSaidOnceQuietly(t *testing.T) {
	findings := assess(&store.AgentCertificate{
		Kind: agentapi.KindLeaf, Path: "/etc/ssl/leftover.crt",
		ManagementState: store.DiscoveryManaged,
	}, false, nil, time.Now())

	found := has(findings, FindingKeyMissing)
	if found == nil {
		t.Fatalf("expected the missing-key note, got %v", codes(findings))
	}
	if found.Severity != events.SeverityInfo {
		t.Fatalf("a certificate with no key is information, not an alert, got %s", found.Severity)
	}
}
