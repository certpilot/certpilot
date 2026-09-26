package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// #109. A lead time is configured once, as a number of days, and applied to
// certificates of every lifetime. The default is 30. A certificate shorter than
// that was due for renewal the moment it was issued: an agent was handed a
// renew_after 24 days before its certificate existed and renewed on every
// five-minute cycle, and the core's own sweep would have renewed one it held
// on every pass.

const day = 24 * time.Hour

func TestTheLeadTimeIsBoundedByTheCertificatesOwnLifetime(t *testing.T) {
	issued := time.Date(2026, 9, 22, 21, 30, 7, 0, time.UTC)

	cases := []struct {
		name     string
		lifetime time.Duration
		leadDays int
		want     time.Duration
	}{
		{"a 90-day certificate keeps its 30-day lead", 90 * day, 30, 30 * day},
		{"a 47-day certificate keeps its 30-day lead, renewing at day 17", 47 * day, 30, 30 * day},
		{"a lead of exactly two thirds of the lifetime is kept", 45 * day, 30, 30 * day},
		{"a 30-day certificate renews when a third remains, at day 20", 30 * day, 30, 10 * day},
		{"the 6-day certificate from #109 renews when a third remains, at day 4", 6 * day, 30, 2 * day},
		{"a 7-day safety floor on a 6-day certificate is bounded the same way", 6 * day, 7, 2 * day},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RenewalLead(issued, issued.Add(tc.lifetime), tc.leadDays); got != tc.want {
				t.Errorf("RenewalLead(%v lifetime, %d days) = %v, want %v", tc.lifetime, tc.leadDays, got, tc.want)
			}
		})
	}
}

// When the lifetime cannot be known, the configured lead is all there is. A
// certificate recorded without a not_before must keep renewing exactly as it
// did before this existed, not stop.
func TestAnUnknownLifetimeKeepsTheConfiguredLead(t *testing.T) {
	notAfter := time.Date(2026, 12, 21, 0, 0, 0, 0, time.UTC)
	if got := RenewalLead(time.Time{}, notAfter, 30); got != 30*day {
		t.Errorf("no not_before: lead = %v, want the configured 30 days", got)
	}
	if got := RenewalLead(notAfter, notAfter, 30); got != 30*day {
		t.Errorf("not_before == not_after: lead = %v, want the configured 30 days", got)
	}
}

// The invariant #109 asks for, over every combination rather than the cases
// somebody thought of: a renewal never falls before the certificate exists,
// never at or after it expires, and never in the first third of its life.
func TestNoRenewalFallsInTheFirstThirdOfACertificatesLife(t *testing.T) {
	notBefore := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	lifetimes := []time.Duration{time.Hour, 6 * time.Hour, day, 6 * day, 7 * day, 10 * day,
		30 * day, 45 * day, 47 * day, 90 * day, 100 * day, 200 * day, 398 * day}
	for _, life := range lifetimes {
		for leadDays := 1; leadDays <= 400; leadDays++ {
			notAfter := notBefore.Add(life)
			renewAt := notAfter.Add(-RenewalLead(notBefore, notAfter, leadDays))
			if !renewAt.After(notBefore) || !renewAt.Before(notAfter) {
				t.Fatalf("lifetime %v, lead %d days: renews at %v, outside the certificate's own window %v to %v",
					life, leadDays, renewAt, notBefore, notAfter)
			}
			if renewAt.Sub(notBefore) < life/3 {
				t.Fatalf("lifetime %v, lead %d days: renews %v after issue, inside the first third of its life",
					life, leadDays, renewAt.Sub(notBefore))
			}
		}
	}
}

// The same rule in both stores' due-for-renewal queries, which is where the
// core decides what its own sweep renews. The SQL cannot call the Go function,
// so this is what keeps the two from drifting apart.
func TestAShortLivedCertificateIsNotDueTheMomentItIsIssued(t *testing.T) {
	type certCase struct {
		name      string
		issuedAgo time.Duration
		lifetime  time.Duration
		// ariIn sets a CA-advised renewal time this far from now.
		ariIn *time.Duration
		due   bool
	}
	threeDays := 3 * day
	cases := []certCase{
		{name: "fresh-6-day", issuedAgo: time.Hour, lifetime: 6 * day, due: false},
		{name: "aged-6-day", issuedAgo: 5 * day, lifetime: 6 * day, due: true},
		{name: "fresh-47-day", issuedAgo: time.Hour, lifetime: 47 * day, due: false},
		{name: "day-18-of-47", issuedAgo: 18 * day, lifetime: 47 * day, due: true},
		{name: "day-50-of-90", issuedAgo: 50 * day, lifetime: 90 * day, due: false},
		{name: "day-61-of-90", issuedAgo: 61 * day, lifetime: 90 * day, due: true},
		// The CA's advice is day 4. The seven-day safety floor, unbounded, was
		// longer than this certificate's whole life and made it due at once.
		{name: "fresh-6-day-with-ca-advice", issuedAgo: time.Hour, lifetime: 6 * day, ariIn: &threeDays, due: false},
	}

	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()
		for i, tc := range cases {
			notBefore := now.Add(-tc.issuedAgo)
			notAfter := notBefore.Add(tc.lifetime)
			cert := &Certificate{
				CommonName:        tc.name + ".example.com",
				SerialNumber:      fmt.Sprintf("10%02d", i),
				FingerprintSHA256: "fingerprint-" + tc.name,
				Status:            "ISSUED",
				AutoRenew:         true,
				KeyCustody:        KeyCustodyCertPilot,
				DiscoveredVia:     "REQUESTED",
				KeyType:           "ECDSA",
				NotBefore:         &notBefore,
				NotAfter:          &notAfter,
				DaysRemaining:     int(time.Until(notAfter) / day),
				RenewalLeadDays:   30,
			}
			if err := s.CreateCertificate(ctx, cert); err != nil {
				t.Fatalf("%s: CreateCertificate: %v", tc.name, err)
			}
			if tc.ariIn != nil {
				at := now.Add(*tc.ariIn)
				if err := s.UpdateCertificateRenewalInfo(ctx, cert.ID, RenewalInfoUpdate{RenewalScheduledAt: &at}); err != nil {
					t.Fatalf("%s: UpdateCertificateRenewalInfo: %v", tc.name, err)
				}
			}
		}

		due, err := s.GetCertificatesDueForRenewal(ctx, 30)
		if err != nil {
			t.Fatalf("GetCertificatesDueForRenewal: %v", err)
		}
		isDue := map[string]bool{}
		for _, c := range due {
			isDue[c.CommonName] = true
		}
		for _, tc := range cases {
			if got := isDue[tc.name+".example.com"]; got != tc.due {
				t.Errorf("%s: due = %v, want %v", tc.name, got, tc.due)
			}
		}
	})
}
