package renewal

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// fakeRenewer stands in for the gateway, so the queue's own behaviour — leases,
// retries, escalation, the crash guard — is tested without a CA or a network.
type fakeRenewer struct {
	mu    sync.Mutex
	calls []string
	err   error
	// onCall runs inside the renewal, so a test can change the world midway —
	// which is what the crash guard is about.
	onCall func(certID string)
}

func (f *fakeRenewer) RenewCertificate(_ context.Context, certID string) (*store.Certificate, error) {
	f.mu.Lock()
	f.calls = append(f.calls, certID)
	f.mu.Unlock()
	if f.onCall != nil {
		f.onCall(certID)
	}
	return nil, f.err
}

func (f *fakeRenewer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func testCertificate(t *testing.T, st store.Store, cn string, expiresIn time.Duration) *store.Certificate {
	t.Helper()
	notAfter := time.Now().Add(expiresIn)
	cert := &store.Certificate{
		CommonName:        cn,
		SerialNumber:      "abc" + cn,
		FingerprintSHA256: "fingerprint-" + cn,
		NotAfter:          &notAfter,
		Status:            "ISSUED",
	}
	if err := st.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return cert
}

// The claim that replaces leader election: two schedulers running the same
// sweep produce one job, not two certificates issued against a weekly limit.
func TestTwoSchedulersEnqueueOneJob(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "shop.example.com", 10*24*time.Hour)

	replicaA := NewScheduler(st, 30)
	replicaB := NewScheduler(st, 30)

	createdA, err := replicaA.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	createdB, err := replicaB.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !createdA {
		t.Error("the first enqueue did not create a job")
	}
	if createdB {
		t.Error("the second replica created a duplicate job; two workers would now renew the same certificate")
	}

	jobs, total, err := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: cert.ID})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(jobs) != 1 {
		t.Fatalf("got %d jobs for one certificate, want 1", total)
	}
}

// Two workers claiming at the same time must never take the same job.
func TestTwoWorkersNeverTakeTheSameJob(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "one.example.com", 10*24*time.Hour)
	sched := NewScheduler(st, 30)
	if _, err := sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	first, err := st.ClaimRenewalJob(ctx, "worker-a", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("the first worker claimed nothing from a queue with one ready job")
	}

	second, err := st.ClaimRenewalJob(ctx, "worker-b", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if second != nil {
		t.Fatalf("a second worker claimed the job already held by the first: %s", second.ID)
	}
}

// A worker that is killed must not strand a certificate. Its claim expires and
// somebody else picks the job up — that is the whole reason for the lease.
func TestAnExpiredLeaseIsReclaimed(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "stranded.example.com", 10*24*time.Hour)
	sched := NewScheduler(st, 30)
	if _, err := sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	claimed, err := st.ClaimRenewalJob(ctx, "worker-that-dies", time.Minute, start)
	if err != nil || claimed == nil {
		t.Fatalf("first claim: %v", err)
	}

	// Still held: nobody else may take it.
	if again, _ := st.ClaimRenewalJob(ctx, "worker-b", time.Minute, start.Add(30*time.Second)); again != nil {
		t.Fatal("a live lease was stolen")
	}

	// Lease expired: it must become available again without anything having to
	// notice the first worker died.
	reclaimed, err := st.ClaimRenewalJob(ctx, "worker-b", time.Minute, start.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed == nil {
		t.Fatal("a job held by a dead worker was never reclaimed; that certificate is now stuck forever")
	}
	if reclaimed.Attempts != 2 {
		t.Errorf("attempts = %d, want 2 — the abandoned attempt still happened", reclaimed.Attempts)
	}
	if reclaimed.LockedBy == nil || *reclaimed.LockedBy != "worker-b" {
		t.Errorf("locked_by = %v, want worker-b", reclaimed.LockedBy)
	}
}

// A worker whose lease already expired must not be able to extend it back out
// from under whoever took the job.
func TestALostLeaseCannotBeExtended(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "lease.example.com", 10*24*time.Hour)
	sched := NewScheduler(st, 30)
	_, _ = sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)

	start := time.Now()
	job, _ := st.ClaimRenewalJob(ctx, "worker-a", time.Minute, start)
	if _, err := st.ClaimRenewalJob(ctx, "worker-b", time.Minute, start.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}

	if err := st.ExtendRenewalLease(ctx, job.ID, "worker-a", start.Add(10*time.Minute)); err == nil {
		t.Fatal("the old holder extended a lease that had already moved to another worker")
	}
	if err := st.ExtendRenewalLease(ctx, job.ID, "worker-b", start.Add(10*time.Minute)); err != nil {
		t.Errorf("the current holder could not extend its own lease: %v", err)
	}
}

// The queue is ordered by the deadline being raced, not by age. A certificate
// expiring tomorrow outranks one enqueued earlier with a month left.
func TestTheMostUrgentJobIsClaimedFirst(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	sched := NewScheduler(st, 30)

	relaxed := testCertificate(t, st, "relaxed.example.com", 30*24*time.Hour)
	urgent := testCertificate(t, st, "urgent.example.com", 24*time.Hour)

	// Enqueued in the wrong order on purpose.
	_, _ = sched.Enqueue(ctx, relaxed, store.RenewalReasonScheduled, nil, nil)
	_, _ = sched.Enqueue(ctx, urgent, store.RenewalReasonScheduled, nil, nil)

	claimed, err := st.ClaimRenewalJob(ctx, "worker", time.Minute, time.Now())
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed.CertificateID != urgent.ID {
		t.Error("the queue ran the certificate with a month left before the one expiring tomorrow")
	}
}

// The crash guard. A worker that finalised an order and died before writing the
// result must not issue a second certificate on the retry.
func TestARenewalThatAlreadyHappenedIsNotRepeated(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "crashed.example.com", 10*24*time.Hour)
	sched := NewScheduler(st, 30)
	_, _ = sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)

	// Simulate the crash: the certificate was renewed, so its fingerprint has
	// moved, but the job was never marked done.
	renewed, _ := st.GetCertificate(ctx, cert.ID)
	renewed.FingerprintSHA256 = "fingerprint-after-the-renewal-that-did-happen"
	if err := st.UpdateCertificate(ctx, renewed); err != nil {
		t.Fatal(err)
	}

	gateway := &fakeRenewer{}
	q := NewQueue(st, gateway, nil)
	if !q.RunOnce(ctx) {
		t.Fatal("the queue claimed nothing")
	}

	if gateway.callCount() != 0 {
		t.Fatal("a certificate that had already been renewed was renewed again; that is two certificates against one rate limit")
	}

	jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: cert.ID})
	if jobs[0].Status != store.RenewalSucceeded {
		t.Errorf("status = %s, want SUCCEEDED — the renewal did happen", jobs[0].Status)
	}
}

// A failed attempt stays outstanding. There is no attempt count at which a
// certificate stops needing to be renewed, and a queue that gives up on its own
// goes quiet exactly when it matters.
func TestAFailedAttemptKeepsTheJobAndRecordsWhy(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "failing.example.com", 30*24*time.Hour)
	sched := NewScheduler(st, 30)
	_, _ = sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)

	gateway := &fakeRenewer{err: errors.New("DNS challenge did not propagate")}
	q := NewQueue(st, gateway, nil)

	before := time.Now()
	if !q.RunOnce(ctx) {
		t.Fatal("the queue claimed nothing")
	}

	jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: cert.ID})
	job := jobs[0]

	if job.Status != store.RenewalPending {
		t.Errorf("status = %s, want PENDING — a renewal nobody cancelled keeps trying", job.Status)
	}
	if !job.RunAfter.After(before) {
		t.Error("run_after was not moved forward, so the next poll would retry instantly and hammer the CA")
	}
	if len(job.AttemptLog) != 1 {
		t.Fatalf("attempt log has %d entries, want 1", len(job.AttemptLog))
	}
	if job.AttemptLog[0].Error != "DNS challenge did not propagate" {
		t.Errorf("the attempt did not record what went wrong: %+v", job.AttemptLog[0])
	}
	if job.AttemptLog[0].Worker == "" {
		t.Error("the attempt does not say which replica made it; one failing replica and every replica failing are different problems")
	}
	if job.LockedBy != nil {
		t.Error("the lease was not released after the attempt finished")
	}
}

// Escalation fires once. A renewal retrying every few minutes for a fortnight
// would otherwise put thousands of CRITICAL messages in the channel that also
// carries CA expiry alerts.
func TestEscalationIsAnnouncedOnceNotPerAttempt(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "stuck.example.com", 60*24*time.Hour)
	sched := NewScheduler(st, 30)
	_, _ = sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)

	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicCertRenewFail)
	defer sub.Close()

	gateway := &fakeRenewer{err: errors.New("the gateway is not connected")}
	q := NewQueue(st, gateway, broker)

	// Five attempts, well past the escalation threshold. run_after is reset
	// each time so the queue keeps finding the job ready.
	for i := 0; i < 5; i++ {
		jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: cert.ID})
		if len(jobs) > 0 {
			_ = st.CompleteRenewalJob(ctx, jobs[0].ID, store.RenewalPending,
				store.RenewalAttempt{}, time.Now().Add(-time.Second), false)
		}
		if !q.RunOnce(ctx) {
			t.Fatalf("attempt %d claimed nothing", i+1)
		}
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
		t.Fatalf("%d escalation alerts for one stuck renewal, want exactly 1", published)
	}

	jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: cert.ID, EscalatedOnly: true})
	if len(jobs) != 1 {
		t.Fatal("the job was not marked as needing attention")
	}
}

// Close to expiry, one failure is already enough: there may not be room for
// many more attempts, and finding out on the third is finding out late.
func TestOneFailureEscalatesWhenTimeIsShort(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "tomorrow.example.com", 24*time.Hour)
	sched := NewScheduler(st, 30)
	_, _ = sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)

	gateway := &fakeRenewer{err: errors.New("connection refused")}
	q := NewQueue(st, gateway, nil)
	if !q.RunOnce(ctx) {
		t.Fatal("the queue claimed nothing")
	}

	jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: cert.ID})
	if jobs[0].EscalatedAt == nil {
		t.Fatal("a certificate expiring in a day failed to renew and nobody was told")
	}
}

// A renewal for a certificate somebody deleted is cancelled, not failed. Nobody
// needs an alert about a certificate they removed on purpose.
func TestAJobThatOutlivesItsCertificateIsCancelled(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "deleted.example.com", 10*24*time.Hour)
	sched := NewScheduler(st, 30)
	_, _ = sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)

	if err := st.DeleteCertificate(ctx, cert.ID); err != nil {
		t.Fatal(err)
	}

	gateway := &fakeRenewer{}
	q := NewQueue(st, gateway, nil)
	if !q.RunOnce(ctx) {
		t.Fatal("the queue claimed nothing")
	}

	jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: cert.ID})
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(jobs))
	}
	if jobs[0].Status != store.RenewalCancelled {
		t.Errorf("status = %s, want CANCELLED", jobs[0].Status)
	}
	if gateway.callCount() != 0 {
		t.Error("a deleted certificate was sent to the gateway for renewal")
	}
}

// #107. A job for a certificate whose key is held elsewhere can never succeed
// here, because whoever holds the key is the one who renews it. Left pending, it
// would be retried for ever and escalated as a failing renewal, paging somebody
// about a certificate that is being renewed correctly by the only party able to.
func TestAJobForAKeyHeldElsewhereIsCancelledWithoutAskingTheCA(t *testing.T) {
	for _, custody := range []string{store.KeyCustodyAgent, store.KeyCustodyExternal} {
		t.Run(custody, func(t *testing.T) {
			st := store.NewMemoryStore()
			ctx := context.Background()
			cert := testCertificate(t, st, "held.example.com", 10*24*time.Hour)
			cert.KeyCustody = custody
			if err := st.UpdateCertificate(ctx, cert); err != nil {
				t.Fatal(err)
			}
			_, _ = NewScheduler(st, 30).Enqueue(ctx, cert, store.RenewalReasonManual, nil, nil)

			gateway := &fakeRenewer{}
			q := NewQueue(st, gateway, nil)
			if !q.RunOnce(ctx) {
				t.Fatal("the queue claimed nothing")
			}

			jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: cert.ID})
			if len(jobs) != 1 {
				t.Fatalf("got %d jobs, want 1", len(jobs))
			}
			if jobs[0].Status != store.RenewalCancelled {
				t.Errorf("status = %s, want CANCELLED", jobs[0].Status)
			}
			if gateway.callCount() != 0 {
				t.Errorf("a certificate whose key is held elsewhere (%s) was sent to the gateway for renewal", custody)
			}
		})
	}
}

// A success closes the job so the next sweep can enqueue a fresh one when the
// certificate comes due again.
func TestASuccessfulRenewalClosesTheJob(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "works.example.com", 10*24*time.Hour)
	sched := NewScheduler(st, 30)
	_, _ = sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)

	gateway := &fakeRenewer{}
	q := NewQueue(st, gateway, nil)
	if !q.RunOnce(ctx) {
		t.Fatal("the queue claimed nothing")
	}

	outstanding, total, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{OutstandingOnly: true})
	if total != 0 {
		t.Errorf("%d jobs still outstanding after a successful renewal: %+v", total, outstanding)
	}

	// And a later sweep can queue it again — a closed job must not block the
	// certificate's next renewal.
	created, err := sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("a completed job blocked the certificate from ever being renewed again")
	}
}

// The attempt log is bounded, so a renewal retrying for weeks does not grow
// without limit inside a row that is read on every dashboard refresh.
func TestTheAttemptLogIsBounded(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	cert := testCertificate(t, st, "chatty.example.com", 60*24*time.Hour)
	sched := NewScheduler(st, 30)
	_, _ = sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)

	jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: cert.ID})
	id := jobs[0].ID

	for i := 0; i < 70; i++ {
		if err := st.CompleteRenewalJob(ctx, id, store.RenewalPending,
			store.RenewalAttempt{Number: i, Error: "still failing"}, time.Now(), false); err != nil {
			t.Fatal(err)
		}
	}

	job, _ := st.GetRenewalJob(ctx, id)
	if len(job.AttemptLog) > 50 {
		t.Fatalf("attempt log grew to %d entries", len(job.AttemptLog))
	}
	// The newest are the ones kept: what a job is doing now matters more than
	// what it did a fortnight ago.
	if job.AttemptLog[len(job.AttemptLog)-1].Number != 69 {
		t.Errorf("the most recent attempt was trimmed away: %+v", job.AttemptLog[len(job.AttemptLog)-1])
	}
}

// Backoff has to be jittered. Forty renewals failing against one CA outage
// coming back at the same instant is how a transient failure becomes a
// rate-limit suspension.
func TestRetryDelaysAreSpreadOut(t *testing.T) {
	q := NewQueue(store.NewMemoryStore(), &fakeRenewer{}, nil)
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	job := &store.RenewalJob{Attempts: 3}

	seen := map[time.Time]bool{}
	for i := 0; i < 20; i++ {
		seen[q.retryAt(job, now)] = true
	}
	if len(seen) < 15 {
		t.Errorf("20 retries produced only %d distinct times; a CA outage would bring them all back together", len(seen))
	}

	// And it must grow, then stop growing.
	early := q.retryAt(&store.RenewalJob{Attempts: 1}, now).Sub(now)
	later := q.retryAt(&store.RenewalJob{Attempts: 5}, now).Sub(now)
	capped := q.retryAt(&store.RenewalJob{Attempts: 40}, now).Sub(now)
	if later <= early {
		t.Errorf("backoff did not grow: attempt 1 = %s, attempt 5 = %s", early, later)
	}
	if capped > maxRetryDelay+maxRetryDelay/4 {
		t.Errorf("backoff is unbounded: attempt 40 = %s", capped)
	}
}

// Stopping twice must not panic. The scheduler this replaced used a bare close,
// so a double shutdown crashed the process it was trying to end cleanly.
func TestStoppingTwiceIsSafe(t *testing.T) {
	q := NewQueue(store.NewMemoryStore(), &fakeRenewer{}, nil, WithPollInterval(10*time.Millisecond))
	q.Start()
	q.Start() // also idempotent
	q.Stop()
	q.Stop()

	sched := NewScheduler(store.NewMemoryStore(), 30)
	sched.Start(10 * time.Millisecond)
	sched.Stop()
	sched.Stop()
}
