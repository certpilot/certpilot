package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// RenewalHandler exposes the renewal queue.
type RenewalHandler struct {
	store    store.Store
	sched    *renewal.Scheduler
	ari      *renewal.ARIPoller
	verifier *renewal.Verifier
}

// NewRenewalHandler creates the handler.
func NewRenewalHandler(s store.Store, sched *renewal.Scheduler, ari *renewal.ARIPoller, v *renewal.Verifier) *RenewalHandler {
	return &RenewalHandler{store: s, sched: sched, ari: ari, verifier: v}
}

// Verify handles POST /api/v1/certificates/:id/verify.
//
// Checks now whether the servers this certificate is deployed to are actually
// presenting it. Synchronous, because the answer is the point and it takes a
// handful of TLS handshakes.
func (h *RenewalHandler) Verify(c *gin.Context) {
	cert, err := h.store.GetCertificate(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "certificate")
		return
	}

	// Bounded under the server's write timeout, as everywhere else that reaches
	// out during a request: a truncated response reads as "nothing happened",
	// which here would read as "nothing is wrong".
	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	h.verifier.Verify(ctx, cert)

	updated, err := h.store.GetCertificate(c.Request.Context(), cert.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	body := gin.H{
		"data":    updated,
		"state":   updated.VerificationState,
		"summary": updated.VerificationDetail,
	}
	// A certificate the servers never picked up is not a 200-and-carry-on. The
	// status code has to carry the same news the body does, because a script
	// that only checks the code is the one most likely to be running this in a
	// pipeline.
	if updated.VerificationState == store.VerificationStale {
		c.JSON(http.StatusConflict, body)
		return
	}
	c.JSON(http.StatusOK, body)
}

// RefreshRenewalInfo handles POST /api/v1/certificates/:id/renewal-info.
//
// Synchronous, because the answer is the point: somebody checking whether their
// CA has moved a window wants to know now, not at the next poll.
func (h *RenewalHandler) RefreshRenewalInfo(c *gin.Context) {
	cert, err := h.store.GetCertificate(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "certificate")
		return
	}
	if cert.CAAccountID == nil || cert.CertificatePEM == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "this certificate has no CA account or no stored body, so there is no CA to ask about it",
		})
		return
	}

	h.ari.Refresh(c.Request.Context(), cert)

	updated, err := h.store.GetCertificate(c.Request.Context(), cert.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":    updated,
		"summary": summarizeRenewalInfo(updated, time.Now()),
	})
}

// summarizeRenewalInfo says what the CA's advice amounts to.
//
// The three-valued support flag is the reason this is a sentence rather than a
// field: "never asked", "asked and this CA says nothing", and "asked and here
// is the window" are three different states, and only the last one means the
// renewal date on screen came from the CA.
func summarizeRenewalInfo(cert *store.Certificate, now time.Time) string {
	switch {
	case cert.ARISupported == nil:
		return "This certificate's CA has not been asked for renewal advice yet, so the renewal date comes from the configured lead time."
	case !*cert.ARISupported:
		return "This CA does not publish renewal information (RFC 9773), so the renewal date comes from the configured lead time. It will not be able to warn you if it revokes this certificate in bulk."
	case cert.RenewalScheduledAt == nil:
		return "The CA published a window but no renewal time was recorded from it."
	case !cert.RenewalScheduledAt.After(now):
		return "The CA wants this certificate replaced now. It is queued for renewal."
	default:
		return fmt.Sprintf("The CA suggests renewing this certificate in %s, and CertPilot picked a random moment inside its window rather than the start so that renewals do not cluster.",
			humanUntil(*cert.RenewalScheduledAt, now))
	}
}

// List handles GET /api/v1/renewals.
//
// The queue is worth showing rather than inferring from logs, because it is the
// only place in this system that is about to change something. Two numbers are
// surfaced alongside the rows: how many renewals are outstanding, and how many
// have failed often enough that somebody needs to look — the second being the
// one that means work.
func (h *RenewalHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	filter := store.RenewalJobFilter{
		CertificateID: c.Query("certificate_id"),
		Status:        strings.ToUpper(c.Query("status")),
		// Default to the queue rather than its history: the question is almost
		// always "what is about to happen", not "what happened last month".
		OutstandingOnly: c.DefaultQuery("outstanding", "true") == "true",
		EscalatedOnly:   c.Query("escalated") == "true",
		Limit:           limit,
		Offset:          offset,
	}

	jobs, total, err := h.store.ListRenewalJobs(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	stuck := make([]string, 0)
	for _, job := range jobs {
		if job.EscalatedAt == nil || !job.Outstanding() {
			continue
		}
		// Looked up per stuck job rather than joined for the whole page. By
		// definition there are few of these — if there are many, the lookups
		// are the least of the problems.
		name := ""
		if cert, err := h.store.GetCertificate(c.Request.Context(), job.CertificateID); err == nil {
			name = cert.CommonName
		}
		stuck = append(stuck, describeJob(job, name, now))
	}

	// Counted separately, because they mean opposite things. A waiting renewal
	// is the pacing working; a stuck one is a certificate on a countdown.
	waiting := 0
	for _, job := range jobs {
		if last, ok := lastAttempt(job); ok && last.Deferred && job.Outstanding() {
			waiting++
		}
	}

	body := gin.H{"data": jobs, "total": total, "waiting_on_rate_limit": waiting}
	if len(stuck) > 0 {
		body["warning"] = fmt.Sprintf(
			"%d renewal(s) have been failing long enough to need attention: %s. Each of these is a certificate on a countdown.",
			len(stuck), strings.Join(stuck, "; "))
	}
	c.JSON(http.StatusOK, body)
}

// Get handles GET /api/v1/renewals/:id.
//
// Returns the whole attempt log. "This has failed eleven times in six days with
// the same DNS error" is a sentence somebody can act on; the last error alone
// cannot tell a blip from a fortnight of silence.
func (h *RenewalHandler) Get(c *gin.Context) {
	job, err := h.store.GetRenewalJob(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "renewal job")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":    job,
		"summary": summarizeRenewal(job, time.Now()),
	})
}

// Cancel handles DELETE /api/v1/renewals/:id.
func (h *RenewalHandler) Cancel(c *gin.Context) {
	id := c.Param("id")

	job, err := h.store.GetRenewalJob(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "renewal job")
		return
	}
	if err := h.store.CancelRenewalJob(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cert.renewal_cancelled",
		EntityType: "certificate",
		EntityID:   &job.CertificateID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details:    fmt.Sprintf(`{"job_id":%q,"attempts":%d}`, job.ID, job.Attempts),
	})

	// The response says what cancelling costs, because it is not obvious: the
	// certificate goes back to expiring on its own with nothing scheduled to
	// stop it, and the next sweep will only re-queue it if it is still inside
	// the lead window.
	c.JSON(http.StatusOK, gin.H{
		"message": "Renewal cancelled. Nothing is now scheduled to replace this certificate before it expires.",
	})
}

// describeJob names a stuck renewal the way somebody would have to look for it.
//
// By common name, not by id. The whole point of the warning is that a person
// reads it and goes and does something; "88cabcc1-ae85-4250-ba27-9236bdc6af57
// has failed 3 times" tells them a renewal is broken and gives them no way to
// know which certificate it is without a second lookup.
func describeJob(job *store.RenewalJob, name string, now time.Time) string {
	if name == "" {
		name = job.CertificateID
	}
	switch {
	case job.NotAfter == nil:
		return fmt.Sprintf("%s (%d attempts)", name, job.Attempts)
	case job.RunwayHours(now) <= 0:
		return fmt.Sprintf("%s (%d attempts, already expired)", name, job.Attempts)
	default:
		return fmt.Sprintf("%s (%d attempts, %s left)", name, job.Attempts, humanRunway(job.RunwayHours(now)))
	}
}

// humanRunway says "12 days" rather than "8759 hours".
//
// Hours are the right unit for the last day and useless beyond it: a live
// warning that read "8759 hours left" is a number nobody parses at a glance,
// which in a list of things needing attention means it does not get read at all.
func humanRunway(hours float64) string {
	switch {
	case hours >= 48:
		days := int(hours / 24)
		if days >= 60 {
			return fmt.Sprintf("%d months", days/30)
		}
		return fmt.Sprintf("%d days", days)
	case hours >= 2:
		return fmt.Sprintf("%d hours", int(hours))
	case hours >= 1:
		return "1 hour"
	default:
		return fmt.Sprintf("%d minutes", int(hours*60))
	}
}

// summarizeRenewal states where a job stands in a sentence.
//
// Counts alone cannot separate "queued and about to run" from "failing every
// few minutes for a week", and those are the two states somebody reading this
// is trying to tell apart.
func summarizeRenewal(job *store.RenewalJob, now time.Time) string {
	runway := job.RunwayHours(now)

	switch job.Status {
	case store.RenewalSucceeded:
		return "Renewed."
	case store.RenewalCancelled:
		return "Cancelled. Nothing is scheduled to replace this certificate before it expires."
	case store.RenewalRunning:
		return fmt.Sprintf("Attempt %d is running now.", job.Attempts)
	}

	// A deferral is not a failure and must not read as one. A job waiting for a
	// CA's quota is the system working — it declined to spend a limit that
	// would have suspended issuance for everyone — and reporting it as "failed
	// 0 times, retrying" would send somebody looking for a fault.
	if last, ok := lastAttempt(job); ok && last.Deferred {
		return fmt.Sprintf("Waiting for the CA's rate limit, not failing. %s Next try %s.",
			last.Reason, "in "+humanUntil(job.RunAfter, now))
	}

	if job.Attempts == 0 {
		return "Queued, not attempted yet."
	}

	when := "in " + humanUntil(job.RunAfter, now)
	if !job.RunAfter.After(now) {
		when = "as soon as a worker is free"
	}

	switch {
	case job.NotAfter != nil && runway <= 0:
		return fmt.Sprintf(
			"Failed %d time(s) and the certificate has already expired. It is still being retried %s, but whatever is serving it is failing now.",
			job.Attempts, when)
	case job.NotAfter != nil && job.EscalatedAt != nil:
		return fmt.Sprintf(
			"Failed %d time(s), with %s left before this certificate expires. Retrying %s. The most recent error was: %s",
			job.Attempts, humanRunway(runway), when, fallbackError(job.LastError))
	default:
		return fmt.Sprintf("Failed %d time(s), retrying %s. The most recent error was: %s",
			job.Attempts, when, fallbackError(job.LastError))
	}
}

func fallbackError(err string) string {
	if strings.TrimSpace(err) == "" {
		return "not recorded"
	}
	return err
}

// humanUntil says "4 minutes" rather than a timestamp somebody has to subtract
// from now.
func humanUntil(t, now time.Time) string {
	d := t.Sub(now)
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// lastAttempt returns the most recent entry in a job's log.
func lastAttempt(job *store.RenewalJob) (store.RenewalAttempt, bool) {
	if job == nil || len(job.AttemptLog) == 0 {
		return store.RenewalAttempt{}, false
	}
	return job.AttemptLog[len(job.AttemptLog)-1], true
}
