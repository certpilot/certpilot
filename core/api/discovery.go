package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// maxTargetsPerScan bounds the entries in one request, before expansion.
//
// A scan is an outbound connection to somebody's infrastructure, made on behalf
// of whoever called this endpoint. Without a cap, a single request with a
// generated list is a port scanner with CertPilot's return address on it. The
// limit is deliberately low enough that reaching it is a prompt to think about
// what is being scanned rather than an obstacle to a legitimate run.
const maxTargetsPerScan = 256

// syncScanLimit is how many endpoints are scanned while the caller waits.
//
// Above it the run goes to the background and the response is a 202 with the
// scan id. The threshold is set by what a person will sit through, not by what
// the server can manage: a handful of endpoints comes back in a second or two,
// and a /24 is seven hundred handshakes that no HTTP client will wait for and
// no proxy would hold open if it did.
const syncScanLimit = 32

// DiscoveryHandler handles network TLS scanning and certificate discovery.
//
// It does not publish anything itself. The findings are published by the
// scanner, because a background run has to alert on what it found long after
// the request that started it has been answered.
type DiscoveryHandler struct {
	store   store.Store
	scanner *discovery.Scanner
}

// NewDiscoveryHandler creates a new DiscoveryHandler.
func NewDiscoveryHandler(s store.Store, sc *discovery.Scanner) *DiscoveryHandler {
	return &DiscoveryHandler{store: s, scanner: sc}
}

// ScanEndpointInput defines the payload to scan one or more endpoints.
type ScanEndpointInput struct {
	// Targets accepts hosts, host:port, CIDR networks, and address ranges —
	// see discovery.ExpandTargets.
	Targets []string `json:"targets"`
	// Host is the single-target form, kept because it is what the existing
	// dashboard sends.
	Host string `json:"host"`
	// Port applies to any target that does not name its own.
	Port int `json:"port"`
	// Ports scans every target on more than one port. Multiplies the endpoint
	// count, which is why the expansion limit is enforced after it is applied.
	Ports []int `json:"ports"`
}

// Scan handles POST /api/v1/discovery/scan.
//
// Small scans finish while the caller waits and return 200 with the results.
// Anything wider goes to the background and returns 202 with the scan id, and
// the response says which happened — `scan.status` is COMPLETED or RUNNING, so
// a client does not have to infer it from the status code.
//
// Two behaviours from one endpoint is a deliberate trade. The alternative is
// either making someone hold a connection open for seven hundred handshakes, or
// making every three-host scan a poll — and the second would push people toward
// not scanning at all.
func (h *DiscoveryHandler) Scan(c *gin.Context) {
	var input ScanEndpointInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	raw := append([]string{}, input.Targets...)
	if strings.TrimSpace(input.Host) != "" {
		raw = append(raw, input.Host)
	}
	if len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "give at least one target, as `targets: [\"host\"]` or `host: \"…\"`",
		})
		return
	}
	if len(raw) > maxTargetsPerScan {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("a single scan is limited to %d entries; %d were given", maxTargetsPerScan, len(raw)),
		})
		return
	}

	ports := input.Ports
	if len(ports) == 0 && input.Port > 0 {
		ports = []int{input.Port}
	}

	// Everything is expanded and checked before anything is connected to. A run
	// that scanned nine hosts and then rejected the tenth would leave the
	// operator unable to say which part of their list was actually looked at —
	// and expansion is where a typo turns a /24 into a /8.
	targets, err := discovery.ExpandTargets(raw, ports, discovery.DefaultExpansionLimit)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	req := discovery.ScanRequest{Targets: targets, Specs: raw}
	if actorID != "" {
		req.TriggeredBy = &actorID
	}
	if actorEmail != "" {
		req.ActorEmail = &actorEmail
	}

	if len(targets) > syncScanLimit {
		scan, err := h.scanner.Start(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		h.auditScan(c, scan, len(targets))

		c.JSON(http.StatusAccepted, gin.H{
			"scan":  scan,
			"data":  []*store.DiscoveryResult{},
			"total": 0,
			"summary": fmt.Sprintf(
				"Scanning %d endpoints in the background. Results appear as they are found.", len(targets)),
			"poll":         "/api/v1/discovery/scans/" + scan.ID,
			"target_count": len(targets),
		})
		return
	}

	scan, results, err := h.scanner.Scan(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.auditScan(c, scan, len(targets))

	c.JSON(http.StatusOK, gin.H{
		"scan":         scan,
		"data":         results,
		"total":        len(results),
		"summary":      summarize(scan),
		"target_count": len(targets),
	})
}

// CancelScan handles POST /api/v1/discovery/scans/:id/cancel.
//
// Everything found so far is kept. A cancel that discarded results would be a
// cancel nobody uses, and a range scan somebody started by mistake would then
// run to completion against a network they did not mean to touch.
func (h *DiscoveryHandler) CancelScan(c *gin.Context) {
	id := c.Param("id")

	scan, err := h.store.GetDiscoveryScan(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if !h.scanner.Cancel(id) {
		// Not an error: the usual reason is that it finished a moment ago.
		c.JSON(http.StatusOK, gin.H{
			"scan":    scan,
			"message": fmt.Sprintf("That scan is not running here — its status is %s.", scan.Status),
		})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "discovery.cancelled",
		EntityType: "discovery_scan",
		EntityID:   &id,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details:    fmt.Sprintf(`{"scanned_when_cancelled":%d,"targets":%s}`, scan.ResultsCount, jsonStringArray(scan.Targets)),
	})

	c.JSON(http.StatusOK, gin.H{
		"message": "Cancelled. Everything the scan had already found is kept.",
	})
}

// summarize states the outcome in a sentence, because the counts alone are
// ambiguous in the one direction that matters: zero unmanaged certificates and
// zero reachable endpoints look identical on a tile and mean opposite things.
func summarize(scan *store.DiscoveryScan) string {
	switch {
	case scan.Status == store.ScanRunning:
		return fmt.Sprintf("Still running: %d of %d endpoints looked at, %d serving certificates CertPilot does not manage.",
			scan.ResultsCount, scan.TargetCount, scan.UnmanagedCount)
	case scan.Status == store.ScanCancelled:
		// Names what was *not* reached as well as what was. A cancelled scan
		// that only reported its findings would read as a clean result for a
		// range most of which was never asked.
		return fmt.Sprintf("Stopped after %d of %d endpoints. %d were serving certificates CertPilot does not manage; the remaining %d were never looked at.",
			scan.ResultsCount, scan.TargetCount, scan.UnmanagedCount, scan.TargetCount-scan.ResultsCount)
	case scan.ResultsCount == 0:
		return "Nothing was scanned."
	case scan.UnreachableCount == scan.ResultsCount:
		return fmt.Sprintf("None of the %d endpoints answered, so nothing was learned about them.", scan.ResultsCount)
	case scan.UnmanagedCount == 0:
		return fmt.Sprintf("Every certificate found is already managed (%d of %d endpoints answered).",
			scan.ResultsCount-scan.UnreachableCount, scan.ResultsCount)
	default:
		return fmt.Sprintf("%d certificate(s) are being served that CertPilot does not manage. Nothing renews them.",
			scan.UnmanagedCount)
	}
}

// ListScans handles GET /api/v1/discovery/scans.
func (h *DiscoveryHandler) ListScans(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	scans, total, err := h.store.ListDiscoveryScans(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": scans, "total": total})
}

// GetScan handles GET /api/v1/discovery/scans/:id, returning the run and its
// results.
func (h *DiscoveryHandler) GetScan(c *gin.Context) {
	scan, err := h.store.GetDiscoveryScan(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	results, total, err := h.store.ListDiscoveryResults(c.Request.Context(), store.DiscoveryResultFilter{
		ScanID:          scan.ID,
		ManagementState: strings.ToUpper(c.Query("management_state")),
		TrustState:      strings.ToUpper(c.Query("trust_state")),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan":         scan,
		"data":         results,
		"total":        total,
		"summary":      summarize(scan),
		"target_count": scan.TargetCount,
	})
}

// ListResults handles GET /api/v1/discovery/results — findings across every
// scan, which is how "everything we have ever found and not adopted" is asked.
func (h *DiscoveryHandler) ListResults(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	// See the note on the same check in the cloud handler: scan_id lands in a
	// uuid column, and an unvalidated one turned a typo into a 500 with the
	// driver's error in the body.
	if raw := c.Query("scan_id"); raw != "" && !isUUID(raw) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan_id must be a uuid"})
		return
	}

	filter := store.DiscoveryResultFilter{
		ScanID:          c.Query("scan_id"),
		ManagementState: strings.ToUpper(c.Query("management_state")),
		TrustState:      strings.ToUpper(c.Query("trust_state")),
		Host:            c.Query("host"),
		UnimportedOnly:  c.Query("unimported") == "true",
		// Defaults to the latest observation per endpoint. A nightly schedule
		// records the same unmanaged certificate every night, and a list that
		// counted each of those as a separate finding would turn one problem
		// into thirty and stop meaning anything. `latest=false` asks for the
		// full history, which is what an investigation wants.
		LatestPerEndpoint: c.DefaultQuery("latest", "true") == "true",
		Limit:             limit,
		Offset:            offset,
	}

	results, total, err := h.store.ListDiscoveryResults(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": results, "total": total})
}

// ImportDiscoveredInput adopts a discovered certificate into managed inventory.
type ImportDiscoveredInput struct {
	// ResultID adopts something a scan found, which is the normal path — it
	// carries the chain and the endpoint it was seen on.
	ResultID string `json:"result_id"`
	// CertificatePEM adopts a certificate someone has in hand instead.
	CertificatePEM  string `json:"certificate_pem"`
	CAAccountID     string `json:"ca_account_id"`
	AutoRenew       bool   `json:"auto_renew"`
	RenewalLeadDays int    `json:"renewal_lead_days"`
	Environment     string `json:"environment"`
	Team            string `json:"team"`
}

// Import handles POST /api/v1/discovery/import.
//
// What this does *not* do is give the certificate a renewal path. CertPilot
// holds no private key for something it merely observed, so an imported
// certificate is watched and reported on, and renewing it still means issuing a
// new one. Saying so in the response matters: `auto_renew` on a record with no
// key is a promise the system cannot keep, and finding that out at expiry is
// worse than never having imported it.
func (h *DiscoveryHandler) Import(c *gin.Context) {
	var input ImportDiscoveredInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	environment, err := normalizeEnvironment(input.Environment)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Environment = environment

	var result *store.DiscoveryResult
	certPEM := strings.TrimSpace(input.CertificatePEM)

	switch {
	case input.ResultID != "":
		var err error
		result, err = h.store.GetDiscoveryResult(c.Request.Context(), input.ResultID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if result.CertificatePEM == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "that result holds no certificate — the endpoint did not complete a handshake",
			})
			return
		}
		certPEM = result.CertificatePEM
	case certPEM == "":
		c.JSON(http.StatusBadRequest, gin.H{"error": "give either result_id or certificate_pem"})
		return
	}

	info, err := x509util.ParseCertificatePEM([]byte(certPEM))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("that is not a readable certificate: %v", err)})
		return
	}

	// Already-managed is a success, not a conflict. Two people adopting the
	// same finding should converge on one record rather than one of them
	// getting an error they have to interpret.
	if existing, err := h.store.GetCertificateByFingerprint(c.Request.Context(), info.FingerprintSHA256); err == nil && existing != nil {
		if result != nil {
			_ = h.store.MarkDiscoveryResultImported(c.Request.Context(), result.ID, existing.ID)
		}
		c.JSON(http.StatusOK, gin.H{
			"data":    existing,
			"message": fmt.Sprintf("This certificate was already managed as %q; the discovery result now points at it.", existing.CommonName),
		})
		return
	}

	notBefore, notAfter := info.NotBefore, info.NotAfter
	pemCopy := certPEM
	actorID := c.GetString(middleware.ContextUserID)
	var createdBy *string
	if actorID != "" {
		createdBy = &actorID
	}

	cert := &store.Certificate{
		FingerprintSHA256: info.FingerprintSHA256,
		CommonName:        info.CommonName,
		SANs:              info.SANs,
		SerialNumber:      info.SerialNumber,
		IssuerDN:          info.IssuerDN,
		NotBefore:         &notBefore,
		NotAfter:          &notAfter,
		DaysRemaining:     info.DaysRemaining,
		KeyType:           info.KeyType,
		KeySize:           info.KeySize,
		Status:            importedStatus(info.NotAfter, time.Now()),
		// Never true on import, whatever was asked for. Renewal needs a private
		// key and a CA account; an observed certificate has neither, and a
		// record that claims it will renew itself is the failure mode this
		// whole product exists to prevent.
		AutoRenew:       false,
		RenewalLeadDays: input.RenewalLeadDays,
		CertificatePEM:  &pemCopy,
		DiscoveredVia:   "SCAN",
		Environment:     input.Environment,
		Team:            input.Team,
		CreatedBy:       createdBy,
	}
	if result != nil && result.ChainPEM != "" {
		chain := result.ChainPEM
		cert.ChainPEM = &chain
	}
	if input.CAAccountID != "" {
		cert.CAAccountID = &input.CAAccountID
	}

	if err := h.store.CreateCertificate(c.Request.Context(), cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result != nil {
		if err := h.store.MarkDiscoveryResultImported(c.Request.Context(), result.ID, cert.ID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("the certificate was imported as %s but the discovery result could not be linked to it: %v", cert.ID, err),
			})
			return
		}
	}

	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "discovery.imported",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		ActorID:    createdBy,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"cn":%q,"fingerprint":%q,"not_after":%q,"source":%q}`,
			cert.CommonName, cert.FingerprintSHA256, notAfter.Format(time.RFC3339), importSource(result)),
	})

	c.JSON(http.StatusCreated, gin.H{
		"data": cert,
		"message": "Imported and now watched for expiry. CertPilot holds no private key for it, " +
			"so it cannot be renewed automatically — replacing it means issuing a new certificate.",
	})
}

// importedStatus reports where an observed certificate sits in its life, which
// is not always ISSUED: plenty of what a first scan finds is already expired.
func importedStatus(notAfter, now time.Time) string {
	switch {
	case now.After(notAfter):
		return "EXPIRED"
	case notAfter.Sub(now) <= 30*24*time.Hour:
		return "EXPIRING"
	default:
		return "ISSUED"
	}
}

func importSource(result *store.DiscoveryResult) string {
	if result == nil {
		return "pasted"
	}
	return fmt.Sprintf("%s:%d", result.Host, result.Port)
}

func (h *DiscoveryHandler) auditScan(c *gin.Context, scan *store.DiscoveryScan, endpoints int) {
	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	id := scan.ID

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "discovery.scan",
		EntityType: "discovery_scan",
		EntityID:   &id,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		// The targets are the point of this entry. Scanning is an outbound act
		// against third-party infrastructure, and "who asked us to connect to
		// that" has to be answerable afterwards.
		// The targets are recorded as they were given, not as they expanded:
		// "10.0.0.0/24" is what someone typed and what they will search for,
		// and 254 addresses in an audit entry is unreadable. The endpoint count
		// says how far that expanded.
		Details: fmt.Sprintf(`{"targets":%s,"endpoints":%d,"results":%d,"unmanaged":%d,"unreachable":%d}`,
			jsonStringArray(scan.Targets), endpoints, scan.ResultsCount, scan.UnmanagedCount, scan.UnreachableCount),
	})
}

func jsonStringArray(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, strconv.Quote(v))
	}
	return "[" + strings.Join(quoted, ",") + "]"
}
