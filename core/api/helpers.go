package api

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/gin-gonic/gin"
)

// unexpectedQuery returns the first query parameter this endpoint does not
// understand, or "".
//
// Used by list endpoints whose results get acted on. A filter that is silently
// dropped turns "the three certificates matching this name" into "every
// certificate", which is a difference nothing downstream can detect and which
// a delete loop cannot survive.
func unexpectedQuery(c *gin.Context, allowed ...string) string {
	known := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		known[name] = true
	}
	// display_token is a credential, not a filter. A wall display that cannot
	// set headers presents it in the query string — which is the whole reason
	// the query form exists — and this guard was rejecting it as an unknown
	// filter, so `GET /certificates?display_token=...` was a 400 for exactly
	// the client the parameter was added for.
	//
	// Exempted here rather than in each caller's allow-list because the next
	// endpoint to adopt this guard would otherwise reintroduce the same bug,
	// and would do so silently: the failure only appears for kiosk clients.
	known["display_token"] = true
	for name := range c.Request.URL.Query() {
		if !known[name] {
			return name
		}
	}
	return ""
}

// certificateEnvironments are the values the certificates table accepts.
//
// The schema has enforced these since migration 001, and until now nothing
// checked them before issuing. The order that mattered was the wrong way
// round: the CA signed, the row was refused by a check constraint, and the
// operator got a raw SQLSTATE — while a real certificate existed at the CA
// that CertPilot had no record of, counted against the account's rate limit,
// and would never be renewed or revoked because nothing knew it was there.
var certificateEnvironments = []string{"production", "staging", "development"}

// normalizeEnvironment canonicalises an environment, or explains what the
// choices are.
//
// Case is forgiven because "Production" is a typo with no other possible
// meaning. An unknown value is not: guessing which of three environments
// somebody meant is how a certificate ends up labelled as something it is not.
func normalizeEnvironment(environment string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(environment))
	if trimmed == "" {
		return "", nil
	}
	for _, allowed := range certificateEnvironments {
		if trimmed == allowed {
			return trimmed, nil
		}
	}
	return "", fmt.Errorf(
		"environment %q is not one of %s. Refusing here rather than at the database, because by then the CA has already issued a certificate that nothing would have a record of",
		environment, strings.Join(certificateEnvironments, ", "))
}

// boolQuery reads an explicit opt-in from the query string.
//
// Only "true" counts. A parameter that is present but says something else is
// not an opt-in, and treating "?forget=maybe" as consent for an irreversible
// operation is the kind of leniency that gets used by accident.
func boolQuery(c *gin.Context, name string) bool {
	return c.Query(name) == "true"
}

// randomIndex returns a uniform index below n, from the cryptographic source.
//
// crypto/rand rather than math/rand: this picks characters for passwords that
// are handed to people, and a predictable sequence there is a credential an
// attacker can regenerate.
func randomIndex(n int) (int, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}
