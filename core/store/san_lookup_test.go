package store

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// #108. A certificate with no subject common name — SAN only, which is what
// Pebble issues by default and where the Baseline Requirements are heading —
// was recorded correctly and then could not be found by name. Both stores
// filtered the common_name column and neither looked at the SANs.
func TestACertificateCanBeFoundByAnyOfItsNames(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		notAfter := time.Now().Add(90 * 24 * time.Hour)
		for _, c := range []*Certificate{
			// What Pebble signed in #108: an empty subject, the name only in the SANs.
			{CommonName: "", SANs: []string{"web.pebble.test"}, SerialNumber: "5a01"},
			// The common name and more names beside it.
			{CommonName: "api.prod.sanlookup.test", SANs: []string{"api.prod.sanlookup.test", "gateway.prod.sanlookup.test"}, SerialNumber: "5a02"},
			{CommonName: "auth.prod.sanlookup.test", SANs: []string{"auth.prod.sanlookup.test"}, SerialNumber: "5a03"},
		} {
			c.FingerprintSHA256 = "fingerprint-" + c.SerialNumber
			c.Status = "ISSUED"
			c.DiscoveredVia = "REQUESTED"
			c.KeyType = "ECDSA"
			c.NotAfter = &notAfter
			if err := s.CreateCertificate(ctx, c); err != nil {
				t.Fatalf("CreateCertificate %s: %v", c.SerialNumber, err)
			}
		}

		cases := map[string][]string{
			"web.pebble.test":        {"5a01"},         // the SAN-only certificate, by its only name
			"pebble":                 {"5a01"},         // a fragment, as the column filter always allowed
			"WEB.PEBBLE":             {"5a01"},         // case-insensitively, as ILIKE always was
			"gateway.prod.sanlookup": {"5a02"},         // a name that is only a SAN, beside a common name
			"prod.sanlookup":         {"5a02", "5a03"}, // one match per certificate, not per name
			"nowhere.sanlookup.test": nil,
		}
		for query, want := range cases {
			got, _, err := s.ListCertificates(ctx, CertificateFilter{CommonName: query})
			if err != nil {
				t.Fatalf("%q: ListCertificates: %v", query, err)
			}
			serials := make([]string, 0, len(got))
			for _, c := range got {
				serials = append(serials, c.SerialNumber)
			}
			sort.Strings(serials)
			if strings.Join(serials, ",") != strings.Join(want, ",") {
				t.Errorf("name filter %q found %v, want %v", query, serials, want)
			}
		}
	})
}
