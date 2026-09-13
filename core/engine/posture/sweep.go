package posture

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/store"
)

// Sweep pacing.
const (
	sweepInterval = 15 * time.Minute
	sweepBatch    = 200
)

// Assessor works out the cryptographic posture of every certificate in the
// inventory.
//
// A sweep rather than a hook at issuance, because there are six ways a
// certificate arrives here — issued, renewed, imported, found by a network
// scan, found in a CT log, found in a cloud store, found on a host by the agent
// — and a hook on each would be six places to forget. A sweep is one place, and
// it is correct for certificates that were already in the database before this
// existed.
//
// The claim is "never assessed, or assessed before the row last changed", so a
// steady state costs one query that returns nothing.
type Assessor struct {
	store store.Store
	now   func() time.Time

	interval time.Duration
	batch    int

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
}

// NewAssessor creates the sweep.
func NewAssessor(s store.Store) *Assessor {
	return &Assessor{
		store: s, now: time.Now,
		interval: sweepInterval, batch: sweepBatch,
		stopCh: make(chan struct{}),
	}
}

// Start begins sweeping. Safe on every replica: two of them assessing the same
// certificate write the same answer, so there is nothing to coordinate and no
// leader to elect.
func (a *Assessor) Start() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started {
		return
	}
	a.started = true

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ticker := time.NewTicker(a.interval)
		defer ticker.Stop()

		// Once at startup, so a fresh deployment against an existing database
		// has answers before the first quarter of an hour is up.
		a.Run(context.Background())
		for {
			select {
			case <-a.stopCh:
				return
			case <-ticker.C:
				a.Run(context.Background())
			}
		}
	}()
	slog.Info("cryptographic posture assessment started", "interval", a.interval)
}

// Stop ends the sweep.
func (a *Assessor) Stop() {
	a.stopped.Do(func() { close(a.stopCh) })
	a.wg.Wait()
}

// Run assesses one batch and returns how many it wrote.
func (a *Assessor) Run(ctx context.Context) int {
	certs, err := a.store.ListCertificatesForAssessment(ctx, a.batch)
	if err != nil {
		slog.Error("could not read certificates for cryptographic assessment", "error", err)
		return 0
	}

	assessed := 0
	for _, cert := range certs {
		update, err := a.assess(cert)
		if err != nil {
			// A certificate whose body will not parse is worth one line and no
			// retry storm. It is recorded as assessed so the sweep does not
			// pick it up for ever, with a verdict that says what happened.
			slog.Warn("could not assess a certificate's cryptography",
				"common_name", cert.CommonName, "error", err)
			update = store.CertificatePostureUpdate{
				Verdict:    "UNKNOWN",
				Summary:    "This certificate's body could not be parsed, so nothing can be said about its algorithms: " + err.Error(),
				AssessedAt: a.now(),
			}
		}
		if err := a.store.UpdateCertificatePosture(ctx, cert.ID, update); err != nil {
			slog.Error("could not record a certificate's cryptographic posture",
				"common_name", cert.CommonName, "error", err)
			continue
		}
		assessed++
	}

	if assessed > 0 {
		slog.Info("assessed cryptographic posture", "certificates", assessed)
	}
	return assessed
}

// assess reads a certificate's own bytes rather than trusting the row.
//
// key_type and key_size are what something wrote when the certificate arrived,
// and the signature algorithm is not recorded on most of them at all. The
// certificate itself is the only account of its own cryptography that cannot
// have drifted.
func (a *Assessor) assess(cert *store.Certificate) (store.CertificatePostureUpdate, error) {
	if cert.CertificatePEM == nil || *cert.CertificatePEM == "" {
		return store.CertificatePostureUpdate{}, errNoBody
	}
	info, err := x509util.ParseCertificatePEM([]byte(*cert.CertificatePEM))
	if err != nil {
		return store.CertificatePostureUpdate{}, err
	}

	assessment := Certificate(info.KeyType, info.KeySize, info.SignatureAlgorithm)
	requirements, err := json.Marshal(assessment.Requirements)
	if err != nil {
		return store.CertificatePostureUpdate{}, err
	}

	return store.CertificatePostureUpdate{
		Verdict:            assessment.Verdict,
		Summary:            assessment.Summary,
		Score:              assessment.Score,
		Requirements:       requirements,
		SignatureAlgorithm: info.SignatureAlgorithm,
		PublicKeyAlgorithm: info.PublicKeyAlgorithm,
		AssessedAt:         a.now(),
	}, nil
}

var errNoBody = errNoBodyType{}

type errNoBodyType struct{}

func (errNoBodyType) Error() string {
	return "no certificate body is stored, so its algorithms are unknown. A certificate found by a scan is recorded from what an endpoint presented and may not include one"
}
