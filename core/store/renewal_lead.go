package store

import "time"

// RenewalLead is how long before expiry a certificate is renewed: the
// configured lead time, unless that is more than two thirds of the
// certificate's own lifetime, in which case a third of the lifetime.
//
// A lead time is configured once, in days, and applied to certificates of every
// lifetime. The default is 30. Without a bound, a certificate shorter than its
// lead time was due the moment it was issued: an agent was handed a renew_after
// 24 days before its six-day certificate existed and renewed it on every
// five-minute cycle, 288 orders a day for one name (#109). The core's own sweep
// had the same arithmetic for the certificates it holds.
//
// Bounded rather than rescaled, so a lead that makes sense for the certificate
// is kept exactly. A 47-day certificate with the default 30 still renews at day
// 17, as configured. Only a lead that would renew a certificate in the first
// third of its life is replaced, and then by renewing when a third of the life
// remains, which is the convention cert-manager and certbot use: a six-day
// certificate renews at day four.
//
// The same bound applies to RenewalSafetyFloorDays, whose seven days are longer
// than a six-day certificate's whole life and made one with a CA's renewal
// advice due at once.
//
// A lifetime that cannot be known, because not_before was never recorded, keeps
// the configured lead: those certificates renewed that way before this existed
// and must not stop.
//
// renewalLeadSQL is the same rule for the PostgreSQL store, and
// TestAShortLivedCertificateIsNotDueTheMomentItIsIssued holds the two together.
func RenewalLead(notBefore, notAfter time.Time, leadDays int) time.Duration {
	lead := time.Duration(leadDays) * 24 * time.Hour
	if notBefore.IsZero() || !notAfter.After(notBefore) {
		return lead
	}
	life := notAfter.Sub(notBefore)
	if lead*3 > life*2 {
		return life / 3
	}
	return lead
}

// renewalLeadSQL is RenewalLead as a PostgreSQL interval expression over the
// certificates table, for a lead given as an SQL expression in days.
func renewalLeadSQL(leadDays string) string {
	lead := "make_interval(days => " + leadDays + ")"
	return `(CASE WHEN not_before IS NOT NULL AND not_after > not_before
	              AND ` + lead + ` * 3 > (not_after - not_before) * 2
	         THEN (not_after - not_before) / 3
	         ELSE ` + lead + ` END)`
}
