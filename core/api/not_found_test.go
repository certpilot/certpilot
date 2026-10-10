package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
)

var errDatabaseGone = errors.New("failed to connect to `host=db user=certpilot`: dial error")

// brokenStore answers lookups by id the way a database that has gone away, or
// lacks a column after a skipped migration, does: with an error that is not
// ErrNotFound.
type brokenStore struct{ *store.MemoryStore }

func (brokenStore) GetCertificate(context.Context, string) (*store.Certificate, error) {
	return nil, errDatabaseGone
}
func (brokenStore) GetCAAuthority(context.Context, string) (*store.CAAuthority, error) {
	return nil, errDatabaseGone
}
func (brokenStore) GetDiscoveryScan(context.Context, string) (*store.DiscoveryScan, error) {
	return nil, errDatabaseGone
}
func (brokenStore) GetRenewalJob(context.Context, string) (*store.RenewalJob, error) {
	return nil, errDatabaseGone
}
func (brokenStore) GetDeploymentJob(context.Context, string) (*store.DeploymentJob, error) {
	return nil, errDatabaseGone
}
func (brokenStore) GetAgent(context.Context, string) (*store.Agent, error) {
	return nil, errDatabaseGone
}
func (brokenStore) GetPolicy(context.Context, string) (*store.Policy, error) {
	return nil, errDatabaseGone
}
func (brokenStore) GetCertificateTemplate(context.Context, string) (*store.CertificateTemplate, error) {
	return nil, errDatabaseGone
}

var lookupRoutes = []string{
	"/api/v1/certificates/%s",
	"/api/v1/pki/authorities/%s",
	"/api/v1/discovery/scans/%s",
	"/api/v1/renewals/%s",
	"/api/v1/deployments/%s",
	"/api/v1/agents/%s",
	"/api/v1/policies/%s",
	"/api/v1/certificate-templates/%s",
}

const absentID = "6f9d0f6e-0000-4000-8000-000000000000"

// TestAFailedReadIsNotReportedAsNotFound (#135).
//
// Every lookup used to answer 404 for any error at all. A v0.2.1 core started
// on an unmigrated database said a certificate that existed was not found,
// because its query failed on a missing column. A database outage reads the
// same way: as though the record had been deleted.
func TestAFailedReadIsNotReportedAsNotFound(t *testing.T) {
	r, _, _ := realRouterOn(t, brokenStore{store.NewMemoryStore()})
	for _, route := range lookupRoutes {
		path := strings.Replace(route, "%s", absentID, 1)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusInternalServerError {
			t.Errorf("GET %s with the database gone answered %d, want 500", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "dial error") {
			t.Errorf("GET %s returned the database's own error to the client: %s", path, w.Body.String())
		}
	}
}

// TestAMissingRecordIsStillNotFound keeps the other half: a record that does
// not exist is 404, not 500.
func TestAMissingRecordIsStillNotFound(t *testing.T) {
	r, _ := realRouter(t)
	for _, route := range lookupRoutes {
		path := strings.Replace(route, "%s", absentID, 1)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s for a record that does not exist answered %d, want 404", path, w.Code)
		}
	}
}

// TestNoHandlerAnswersNotFoundForEveryStoreError reads the handlers rather
// than calling them. The routes above are a sample; this covers the rest, and
// the next handler somebody writes. An error goes to respondLookup, which tells
// a missing record from a failed read. Answering 404 with err.Error() means
// any error at all reads as "not found".
func TestNoHandlerAnswersNotFoundForEveryStoreError(t *testing.T) {
	blanket := regexp.MustCompile(`StatusNotFound,\s*gin\.H\{"error":\s*err\.Error\(\)\}`)

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var offenders []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "lookup.go" {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			if !blanket.MatchString(line) {
				continue
			}
			// The one legitimate shape: the error was already shown to be
			// ErrNotFound a few lines up.
			guarded := false
			for j := i - 1; j >= 0 && j >= i-6; j-- {
				if strings.Contains(lines[j], "store.ErrNotFound") {
					guarded = true
					break
				}
			}
			if !guarded {
				offenders = append(offenders, f+":"+strconv.Itoa(i+1))
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("%d handler(s) answer 404 for any error; use respondLookup:\n  %s",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}
