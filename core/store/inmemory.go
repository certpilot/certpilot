package store

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStore provides a thread-safe in-memory store for local testing without external database dependencies.
//
// Every read returns copies of the stored records, never the stored pointers.
// PostgresStore has no choice about this — a row scanned out of the database is
// already a copy — and the in-memory store handing out live pointers made the
// two behave differently in the one way that matters: the CA health sweep reads
// every authority and mutates it field by field, while the event stream reads
// the same records to build a snapshot. Sharing pointers between those two made
// a data race out of an ordinary dashboard refresh.
type MemoryStore struct {
	mu             sync.RWMutex
	auditChain     *AuditChainer
	auditChainHead int64
	// agentSignatures is the replay guard, mirroring the table PostgreSQL uses.
	// Present here so the conformance suite can hold both to the same rule.
	agentSignatures map[agentSignatureKey]time.Time
	certificates    map[string]*Certificate
	caAuthorities   map[string]*CAAuthority
	caAccounts      map[string]*CAAccount
	targets         map[string]*DeploymentTarget
	policies        map[string]*Policy
	displayTokens   map[string]*DisplayToken
	metadataFields  map[string]*MetadataField
	users           map[string]*User
	sessions        map[string]*Session
	passwordHashes  map[string]string
	loginFailures   map[string]*loginState
	notifChannels   map[string]*NotificationChannel
	// acks is append-only, newest last. Who acknowledged what and when is the
	// record an incident review reads, so an acknowledgement is never
	// overwritten by the next one.
	acks      []*AlertAcknowledgement
	auditLogs []*AuditLog
	// Discovery runs and their results, both append-only and newest last.
	discoveryScans     []*DiscoveryScan
	discoveryResults   []*DiscoveryResult
	discoverySchedules map[string]*DiscoverySchedule
	ctMonitors         map[string]*CTMonitor
	ctCertificates     []*CTCertificate
	cloudConnections   map[string]*CloudConnection
	cloudCertificates  []*CloudCertificate
	renewalJobs        []*RenewalJob
	// Where certificates go, and the queue that puts them there.
	deployments    map[string]*CertificateDeployment
	deploymentJobs []*DeploymentJob
	agents         map[string]*Agent
	enrolTokens    map[string]*AgentEnrolToken
	agentCerts     []*AgentCertificate
	templateGrants map[string]*TemplateGrant

	certificateTemplates map[string]*CertificateTemplate
	agentInstalls        []*AgentInstallation
	tlsPosture           map[string]*EndpointTLSPosture
}

// clone returns a shallow copy of a stored record.
//
// Shallow is sufficient here. The pointer and slice fields on these models
// (*time.Time, *string, []string) are only ever replaced wholesale, never
// written through, so no caller can reach back into the store's copy.
func clone[T any](v *T) *T {
	c := *v
	return &c
}

// NewMemoryStore creates a new in-memory store pre-populated with sample demonstration data.
func NewMemoryStore() *MemoryStore {
	now := time.Now()
	rootExpiry := now.Add(3650 * 24 * time.Hour)
	interExpiry := now.Add(730 * 24 * time.Hour)
	expiringDate := now.Add(14 * 24 * time.Hour)
	validDate := now.Add(85 * 24 * time.Hour)

	rootID := uuid.New().String()
	interID := uuid.New().String()

	rootCA := &CAAuthority{
		ID:                      rootID,
		Name:                    "CertPilot Global Root CA 2026",
		CAType:                  "ROOT",
		SubjectDN:               "CN=CertPilot Global Root CA 2026, O=CertPilot OSS, C=US",
		IssuerDN:                "CN=CertPilot Global Root CA 2026, O=CertPilot OSS, C=US",
		SerialNumber:            "01a4f892bc901e88",
		NotBefore:               now.Add(-30 * 24 * time.Hour),
		NotAfter:                rootExpiry,
		DaysRemaining:           3620,
		KeyType:                 "RSA",
		KeySize:                 4096,
		FingerprintSHA256:       "a3f9e4b108c992d19f88e102bc450091884711823901eabbc38210398492019a",
		CRLDistributionURL:      "http://crl.certpilot.local/root.crl",
		OCSPResponderURL:        "http://ocsp.certpilot.local",
		IsCRLFresh:              true,
		IsOCSPResponsive:        true,
		CertificatesIssuedCount: 1420,
		Status:                  "HEALTHY",
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	interCA := &CAAuthority{
		ID:                      interID,
		Name:                    "CertPilot Production Intermediate CA G1",
		CAType:                  "INTERMEDIATE",
		SubjectDN:               "CN=CertPilot Production Intermediate CA G1, O=CertPilot OSS, C=US",
		IssuerDN:                "CN=CertPilot Global Root CA 2026, O=CertPilot OSS, C=US",
		ParentCAID:              &rootID,
		SerialNumber:            "0284f183cc919a02",
		NotBefore:               now.Add(-10 * 24 * time.Hour),
		NotAfter:                interExpiry,
		DaysRemaining:           720,
		KeyType:                 "ECDSA",
		KeySize:                 384,
		FingerprintSHA256:       "c81048f02919abccde0192849102948201948291039482019482019384910294",
		CRLDistributionURL:      "http://crl.certpilot.local/intermediate.crl",
		OCSPResponderURL:        "http://ocsp.certpilot.local",
		IsCRLFresh:              true,
		IsOCSPResponsive:        true,
		CertificatesIssuedCount: 850,
		Status:                  "HEALTHY",
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	accSelfSignedID := uuid.New().String()
	accSelfSigned := &CAAccount{
		ID:           accSelfSignedID,
		Name:         "selfsigned-dev",
		ProviderType: "selfsigned",
		GatewayAddr:  "localhost:9091",
		IsDefault:    true,
		Status:       "CONNECTED",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	cert1ID := uuid.New().String()
	cert1 := &Certificate{
		ID:                cert1ID,
		FingerprintSHA256: "9482019482019384910294820194820194820193849102948201948201938491",
		CommonName:        "api.prod.example.com",
		SANs:              []string{"api.prod.example.com", "gateway.prod.example.com"},
		SerialNumber:      "74892019482019482",
		IssuerDN:          "CN=CertPilot Production Intermediate CA G1",
		NotBefore:         &now,
		NotAfter:          &validDate,
		DaysRemaining:     85,
		KeyType:           "RSA",
		KeySize:           2048,
		Status:            "ISSUED",
		AutoRenew:         true,
		RenewalLeadDays:   30,
		CAAccountID:       &accSelfSignedID,
		CAAuthorityID:     &interID,
		Environment:       "production",
		Team:              "Platform Engineering",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	cert2ID := uuid.New().String()
	cert2 := &Certificate{
		ID:                cert2ID,
		FingerprintSHA256: "1029482019482019384910294820194820194820193849102948201948201938",
		CommonName:        "auth.prod.example.com",
		SANs:              []string{"auth.prod.example.com"},
		SerialNumber:      "84920194820194833",
		IssuerDN:          "CN=CertPilot Production Intermediate CA G1",
		NotBefore:         &now,
		NotAfter:          &expiringDate,
		DaysRemaining:     14,
		KeyType:           "ECDSA",
		KeySize:           256,
		Status:            "EXPIRING",
		AutoRenew:         true,
		RenewalLeadDays:   30,
		CAAccountID:       &accSelfSignedID,
		CAAuthorityID:     &interID,
		Environment:       "production",
		Team:              "Security & IAM",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	polID := uuid.New().String()
	policy1 := &Policy{
		ID:            polID,
		Name:          "Enforce RSA >= 2048 bits",
		Description:   "Blocks certificate issuance for weak RSA keys under 2048 bits",
		IsEnabled:     true,
		RuleType:      "key_size",
		RuleConfig:    `{"min_key_size": 2048}`,
		DomainPattern: "*",
		Severity:      "BLOCK",
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	log1 := &AuditLog{
		ID:         uuid.New().String(),
		Action:     "cert.issued",
		EntityType: "certificate",
		EntityID:   &cert1ID,
		ActorEmail: strPtr("admin@certpilot.local"),
		Details:    `{"cn": "api.prod.example.com", "gateway": "selfsigned-dev"}`,
		CreatedAt:  now.Add(-2 * time.Hour),
	}

	return &MemoryStore{
		certificates: map[string]*Certificate{
			cert1ID: cert1,
			cert2ID: cert2,
		},
		caAuthorities: map[string]*CAAuthority{
			rootID:  rootCA,
			interID: interCA,
		},
		caAccounts: map[string]*CAAccount{
			accSelfSignedID: accSelfSigned,
		},
		targets:        make(map[string]*DeploymentTarget),
		policies:       map[string]*Policy{polID: policy1},
		metadataFields: map[string]*MetadataField{},
		users:          map[string]*User{},
		sessions:       map[string]*Session{},
		passwordHashes: map[string]string{},
		loginFailures:  map[string]*loginState{},
		// Deliberately empty. Every other map here carries sample data so a
		// first run has something to render, but a seeded credential is a
		// credential someone forgets to remove.
		displayTokens: make(map[string]*DisplayToken),
		// Also empty, for the same reason: a channel's config holds a Slack
		// webhook URL or an SMTP password.
		notifChannels: make(map[string]*NotificationChannel),
		auditLogs:     []*AuditLog{log1},
		// Empty: a schedule is an outbound action on a timer, and seeding one
		// would have a fresh install scanning something nobody asked it to.
		discoverySchedules: make(map[string]*DiscoverySchedule),
		// Also empty. A monitor is an outbound query on a timer, and a seeded
		// one would have a fresh install polling a public service about a
		// domain nobody asked it to watch.
		ctMonitors:       make(map[string]*CTMonitor),
		cloudConnections: make(map[string]*CloudConnection),
		// Empty: a deployment target is a place this system writes to, and a
		// seeded one would have a fresh install pushing certificates somewhere
		// nobody configured.
		deployments: make(map[string]*CertificateDeployment),
		// Empty for the same reason display tokens are: a seeded credential is
		// a credential somebody forgets to remove.
		agents:         make(map[string]*Agent),
		enrolTokens:    make(map[string]*AgentEnrolToken),
		templateGrants: make(map[string]*TemplateGrant),

		certificateTemplates: make(map[string]*CertificateTemplate),
		tlsPosture:           make(map[string]*EndpointTLSPosture),
	}
}

func (m *MemoryStore) Close() {}

func (m *MemoryStore) ListCertificates(ctx context.Context, filter CertificateFilter) ([]*Certificate, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Certificate, 0)
	for _, c := range m.certificates {
		if filter.Status != "" && c.Status != filter.Status {
			continue
		}
		if filter.Environment != "" && c.Environment != filter.Environment {
			continue
		}
		if filter.CommonName != "" && !strings.Contains(strings.ToLower(c.CommonName), strings.ToLower(filter.CommonName)) {
			continue
		}
		// Previously ignored, while Postgres honoured it — so a filtered view
		// looked correct in development and changed meaning in production.
		if filter.CAAccountID != "" && (c.CAAccountID == nil || *c.CAAccountID != filter.CAAccountID) {
			continue
		}
		result = append(result, clone(c))
	}

	// Soonest expiry first, matching the Postgres ORDER BY. Map iteration order
	// is randomised, so without this the same request returns the same rows in
	// a different order every time.
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].NotAfter, result[j].NotAfter
		switch {
		case a == nil && b == nil:
			return result[i].ID < result[j].ID
		case a == nil:
			return false // NULLS LAST
		case b == nil:
			return true
		case a.Equal(*b):
			return result[i].ID < result[j].ID
		default:
			return a.Before(*b)
		}
	})

	// The total is the size of the filtered set, before the page is taken.
	total := int64(len(result))
	return paginate(result, filter.Limit, filter.Offset), total, nil
}

// paginate applies limit and offset with the same defaults as PostgresStore.
func paginate[T any](items []T, limit, offset int) []T {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

func (m *MemoryStore) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.certificates[id]
	if !ok {
		return nil, fmt.Errorf("certificate %s not found", id)
	}
	return clone(c), nil
}

func (m *MemoryStore) GetCertificateByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.certificates {
		if c.FingerprintSHA256 == fingerprint {
			return clone(c), nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) CreateCertificate(ctx context.Context, cert *Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cert.ID == "" {
		cert.ID = uuid.New().String()
	}
	now := time.Now()
	cert.CreatedAt = now
	cert.UpdatedAt = now
	if cert.NotAfter != nil {
		d := time.Until(*cert.NotAfter).Hours() / 24
		if d > 0 {
			cert.DaysRemaining = int(d)
		}
	}
	m.certificates[cert.ID] = clone(cert)
	return nil
}

func (m *MemoryStore) UpdateCertificate(ctx context.Context, cert *Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert.UpdatedAt = time.Now()
	if cert.NotAfter != nil {
		d := time.Until(*cert.NotAfter).Hours() / 24
		if d > 0 {
			cert.DaysRemaining = int(d)
		}
	}
	stored := clone(cert)
	// Matches the COALESCE in PostgresStore.UpdateCertificate: a supplied key
	// replaces the stored one, an absent key leaves it alone. No read path
	// populates this field, so without the second half every ordinary update
	// would destroy the key.
	if stored.PrivateKeyEncrypted == nil {
		if prev, ok := m.certificates[cert.ID]; ok {
			stored.PrivateKeyEncrypted = prev.PrivateKeyEncrypted
		}
	}
	m.certificates[cert.ID] = stored
	return nil
}

func (m *MemoryStore) DeleteCertificate(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.certificates, id)
	return nil
}

func (m *MemoryStore) GetCertificatesDueForRenewal(ctx context.Context, leadDays int) ([]*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	floor := now.Add(RenewalSafetyFloorDays * 24 * time.Hour)

	due := make([]*Certificate, 0)
	for _, c := range m.certificates {
		if !c.AutoRenew {
			continue
		}
		// A certificate whose key CertPilot does not hold cannot be renewed from
		// here: renewing means generating a key, and for these the point is that
		// this process never has one. An agent renews its own by sending a new
		// request; an externally held key is renewed by whoever holds it.
		//
		// An empty custody stays eligible, matching the SQL: it means nobody
		// recorded one, not that somebody else holds the key.
		if c.KeyCustody == KeyCustodyAgent || c.KeyCustody == KeyCustodyExternal {
			continue
		}
		// The CA's advice takes precedence over the lead time when there is
		// any — it is better information, because the CA knows things about the
		// certificate that the certificate does not say.
		//
		// But never off a cliff: however far out the advice points, a
		// certificate inside the safety floor renews anyway. A bad window, or a
		// stale one left behind by a poller that stopped running, must not talk
		// this system out of renewing something about to stop working.
		if c.RenewalScheduledAt != nil {
			if !c.RenewalScheduledAt.After(now) || (c.NotAfter != nil && !c.NotAfter.After(floor)) {
				due = append(due, clone(c))
			}
			continue
		}
		if c.DaysRemaining <= leadDays || c.Status == "EXPIRING" || c.Status == "RENEWAL_FAILED" {
			due = append(due, clone(c))
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].DaysRemaining < due[j].DaysRemaining })
	return due, nil
}

func (m *MemoryStore) GetCertificatePrivateKey(ctx context.Context, id string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.certificates[id]
	if !ok {
		return "", fmt.Errorf("certificate %s not found", id)
	}
	if c.PrivateKeyEncrypted == nil {
		return "", nil
	}
	return *c.PrivateKeyEncrypted, nil
}

func (m *MemoryStore) ListCAAuthorities(ctx context.Context, filter CAFilter) ([]*CAAuthority, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	list := make([]*CAAuthority, 0)
	for _, ca := range m.caAuthorities {
		if filter.Status != "" && ca.Status != filter.Status {
			continue
		}
		// Against NotAfter, matching the Postgres predicate. Filtering on the
		// cached DaysRemaining here would have made the two stores disagree
		// about which CAs are urgent whenever a sweep was overdue.
		if filter.ExpiringWithinDays > 0 {
			cutoff := now.AddDate(0, 0, filter.ExpiringWithinDays)
			if ca.NotAfter.After(cutoff) {
				continue
			}
		}
		if filter.ExcludeExpired && !ca.NotAfter.After(now) {
			continue
		}

		c := clone(ca)
		if !filter.IncludePEM {
			c.CertificatePEM = ""
		}
		list = append(list, c)
	}

	if filter.Sort == CASortUrgency {
		sort.Slice(list, func(i, j int) bool {
			if list[i].NotAfter.Equal(list[j].NotAfter) {
				return list[i].Name < list[j].Name
			}
			return list[i].NotAfter.Before(list[j].NotAfter)
		})
	} else {
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	}
	return list, nil
}

func (m *MemoryStore) GetCAAuthority(ctx context.Context, id string) (*CAAuthority, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ca, ok := m.caAuthorities[id]
	if !ok {
		return nil, fmt.Errorf("CA authority %s not found", id)
	}
	return clone(ca), nil
}

// GetCAAuthorityByFingerprint finds a CA by the certificate itself.
//
// Nothing found is nil, nil rather than an error, matching PostgresStore: the
// importer asks this about every issuer a gateway offers, and most of the
// answers are "not yet".
func (m *MemoryStore) GetCAAuthorityByFingerprint(ctx context.Context, fingerprint string) (*CAAuthority, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ca := range m.caAuthorities {
		if ca.FingerprintSHA256 == fingerprint {
			return clone(ca), nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) CreateCAAuthority(ctx context.Context, ca *CAAuthority) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ca.ID == "" {
		ca.ID = uuid.New().String()
	}
	// Defaulted here as well as in PostgresStore, because the two stores
	// disagreeing about what an unset field means is the defect class this
	// suite exists for.
	if strings.TrimSpace(ca.Source) == "" {
		ca.Source = CASourceManual
	}
	now := time.Now()
	ca.CreatedAt = now
	ca.UpdatedAt = now
	m.caAuthorities[ca.ID] = clone(ca)
	return nil
}

func (m *MemoryStore) UpdateCAAuthority(ctx context.Context, ca *CAAuthority) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ca.UpdatedAt = time.Now()
	if strings.TrimSpace(ca.Source) == "" {
		ca.Source = CASourceManual
	}
	stored := clone(ca)
	// The stored PEM survives the update, because PostgresStore's UPDATE does
	// not include the column. A caller that listed without CAFilter.IncludePEM
	// holds a record whose PEM is blank; writing that back would destroy the
	// only copy of the CA certificate the system has, and the next health sweep
	// would report the CA as UNKNOWN rather than as expiring.
	if prev, ok := m.caAuthorities[ca.ID]; ok {
		stored.CertificatePEM = prev.CertificatePEM
	}
	m.caAuthorities[ca.ID] = stored
	return nil
}

func (m *MemoryStore) DeleteCAAuthority(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.caAuthorities, id)
	return nil
}

func (m *MemoryStore) GetCAChain(ctx context.Context, id string) ([]*CAAuthority, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	chain := []*CAAuthority{}
	currID := id
	visited := make(map[string]bool)

	for currID != "" && !visited[currID] {
		visited[currID] = true
		ca, ok := m.caAuthorities[currID]
		if !ok {
			break
		}
		chain = append(chain, clone(ca))
		if ca.ParentCAID != nil && *ca.ParentCAID != "" {
			currID = *ca.ParentCAID
		} else {
			break
		}
	}
	return chain, nil
}

func (m *MemoryStore) ListCAAccounts(ctx context.Context) ([]*CAAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*CAAccount, 0, len(m.caAccounts))
	for _, acc := range m.caAccounts {
		list = append(list, clone(acc))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func (m *MemoryStore) GetCAAccount(ctx context.Context, id string) (*CAAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	acc, ok := m.caAccounts[id]
	if ok {
		return clone(acc), nil
	}
	for _, a := range m.caAccounts {
		if a.Name == id {
			return clone(a), nil
		}
	}
	return nil, fmt.Errorf("CA account %s not found", id)
}

func (m *MemoryStore) CreateCAAccount(ctx context.Context, acc *CAAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if acc.ID == "" {
		acc.ID = uuid.New().String()
	}
	now := time.Now()
	acc.CreatedAt = now
	acc.UpdatedAt = now
	m.caAccounts[acc.ID] = clone(acc)
	return nil
}

func (m *MemoryStore) UpdateCAAccount(ctx context.Context, acc *CAAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	acc.UpdatedAt = time.Now()
	m.caAccounts[acc.ID] = clone(acc)
	return nil
}

func (m *MemoryStore) DeleteCAAccount(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.caAccounts, id)
	return nil
}

func (m *MemoryStore) ListDeploymentTargets(ctx context.Context) ([]*DeploymentTarget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*DeploymentTarget, 0, len(m.targets))
	for _, t := range m.targets {
		list = append(list, clone(t))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func (m *MemoryStore) GetDeploymentTarget(ctx context.Context, id string) (*DeploymentTarget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.targets[id]
	if !ok {
		return nil, fmt.Errorf("target %s not found", id)
	}
	return clone(t), nil
}

func (m *MemoryStore) CreateDeploymentTarget(ctx context.Context, target *DeploymentTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if target.ID == "" {
		target.ID = uuid.New().String()
	}
	now := time.Now()
	if target.CreatedAt.IsZero() {
		target.CreatedAt = now
	}
	target.UpdatedAt = now
	m.targets[target.ID] = clone(target)
	return nil
}

func (m *MemoryStore) UpdateDeploymentTarget(ctx context.Context, target *DeploymentTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[target.ID]; !ok {
		return fmt.Errorf("deployment target %s not found", target.ID)
	}
	target.UpdatedAt = time.Now()
	m.targets[target.ID] = clone(target)
	return nil
}

func (m *MemoryStore) MarkDeploymentTargetUsed(ctx context.Context, id string,
	at time.Time, success bool, detail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.targets[id]
	if !ok {
		return fmt.Errorf("deployment target %s not found", id)
	}

	when := at
	status := DeploymentFailed
	t.LastDeploymentError = detail
	if success {
		status = DeploymentDeployed
		t.LastDeploymentError = ""
		t.LastSuccessAt = &when
	}
	t.LastDeploymentAt = &when
	t.LastDeploymentStatus = &status
	t.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) DeleteDeploymentTarget(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.targets, id)
	// The bindings go with it. In PostgreSQL this is an ON DELETE CASCADE;
	// leaving them here would let a certificate keep a deployment pointing at a
	// target that no longer exists.
	for did, d := range m.deployments {
		if d.TargetID == id {
			delete(m.deployments, did)
		}
	}
	return nil
}

func (m *MemoryStore) ListPolicies(ctx context.Context) ([]*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*Policy, 0, len(m.policies))
	for _, p := range m.policies {
		list = append(list, clone(p))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func (m *MemoryStore) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy %s not found", id)
	}
	return clone(p), nil
}

func (m *MemoryStore) CreatePolicy(ctx context.Context, p *Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	m.policies[p.ID] = clone(p)
	return nil
}

func (m *MemoryStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p.UpdatedAt = time.Now()
	m.policies[p.ID] = clone(p)
	return nil
}

func (m *MemoryStore) DeletePolicy(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, id)
	return nil
}

// ── Display Tokens ──────────────────────────────────────

func (m *MemoryStore) ListDisplayTokens(ctx context.Context) ([]*DisplayToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*DisplayToken, 0, len(m.displayTokens))
	for _, t := range m.displayTokens {
		clone := *t
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// GetDisplayTokenByHash finds a token by its hash.
//
// The comparison walks every token in constant time rather than indexing a map.
// A map lookup would return as soon as the first differing byte was found, and
// with a handful of tokens the difference is measurable; the linear scan costs
// nothing at this scale. Postgres reaches the same place by comparing a hash
// rather than the secret itself.
func (m *MemoryStore) GetDisplayTokenByHash(ctx context.Context, tokenHash string) (*DisplayToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var found *DisplayToken
	want := []byte(tokenHash)
	for _, t := range m.displayTokens {
		if subtle.ConstantTimeCompare([]byte(t.TokenHash), want) == 1 {
			found = t
		}
	}
	if found == nil {
		return nil, fmt.Errorf("display token not found")
	}
	clone := *found
	return &clone, nil
}

func (m *MemoryStore) CreateDisplayToken(ctx context.Context, t *DisplayToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.displayTokens {
		if existing.Name == t.Name {
			return fmt.Errorf("a display token named %q already exists", t.Name)
		}
	}
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	t.CreatedAt = time.Now()
	clone := *t
	m.displayTokens[t.ID] = &clone
	return nil
}

func (m *MemoryStore) RevokeDisplayToken(ctx context.Context, id string, revokedBy *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.displayTokens[id]
	if !ok {
		return fmt.Errorf("display token %s not found", id)
	}
	// Revoking twice is not an error. The caller wants the token dead, and it
	// is; failing here would only encourage retry loops.
	if t.RevokedAt == nil {
		now := time.Now()
		t.RevokedAt = &now
		t.RevokedBy = revokedBy
	}
	return nil
}

func (m *MemoryStore) TouchDisplayToken(ctx context.Context, id string, seenAt time.Time, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.displayTokens[id]
	if !ok {
		return fmt.Errorf("display token %s not found", id)
	}
	t.LastSeenAt = &seenAt
	if ip != "" {
		t.LastSeenIP = &ip
	}
	return nil
}

func (m *MemoryStore) UseAuditChain(chainer *AuditChainer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auditChain = chainer
}

func (m *MemoryStore) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if log.ID == "" {
		log.ID = uuid.New().String()
	}
	// Truncated to microseconds even though nothing here needs it to be, so
	// that an entry written to this store and one written to PostgreSQL cover
	// the same bytes. A chain that only verifies in memory is exactly the class
	// of defect this project keeps finding.
	log.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)

	if m.auditChain != nil {
		// The mutex is doing what the advisory lock does in PostgreSQL: the head
		// read and the append are one atomic step, so concurrent writers cannot
		// chain from the same predecessor.
		// Counted, not derived from the slice length: this store seeds a
		// sample entry, and any entry written before the chainer arrived is
		// unchained. Numbering from the slice length would leave a permanent
		// off-by-one that reads as a deleted record.
		log.Seq = m.auditChainHead + 1
		prev := append([]byte(nil), AuditChainZeroPrev...)
		if len(m.auditLogs) > 0 {
			// auditLogs is newest-first.
			if head := m.auditLogs[0]; len(head.EntryHash) > 0 {
				prev = append([]byte(nil), head.EntryHash...)
			}
		}
		keyID, tag, err := m.auditChain.Link(log, prev)
		if err != nil {
			return err
		}
		log.PrevHash = prev
		log.EntryHash = tag
		log.ChainKeyID = keyID
		m.auditChainHead = log.Seq
	}

	m.auditLogs = append([]*AuditLog{clone(log)}, m.auditLogs...)
	return nil
}

func (m *MemoryStore) VerifyAuditChain(ctx context.Context, from int64, limit int) (*AuditChainReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if from < 1 {
		from = 1
	}

	var unchained int64
	// auditLogs is newest-first; the chain walks the other way.
	ascending := make([]*AuditLog, 0, len(m.auditLogs))
	for i := len(m.auditLogs) - 1; i >= 0; i-- {
		l := m.auditLogs[i]
		if l.Seq == 0 {
			unchained++
			continue
		}
		if l.Seq < from {
			continue
		}
		// clone is a shallow struct copy, so the tags would otherwise be the
		// store's own backing arrays handed to a caller that outlives the lock.
		c := clone(l)
		c.PrevHash = append([]byte(nil), l.PrevHash...)
		c.EntryHash = append([]byte(nil), l.EntryHash...)
		ascending = append(ascending, c)
	}

	truncated := false
	if limit > 0 && len(ascending) > limit {
		ascending = ascending[:limit]
		truncated = true
	}
	return verifyAuditChainOver(ascending, m.auditChain, from, unchained, truncated), nil
}

func (m *MemoryStore) ListAuditLogs(ctx context.Context, filter AuditLogFilter) ([]*AuditLog, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// m.auditLogs is already newest-first; CreateAuditLog prepends.
	matched := make([]*AuditLog, 0)
	for _, l := range m.auditLogs {
		if len(filter.Actions) > 0 && !containsString(filter.Actions, l.Action) {
			continue
		}
		if filter.EntityType != "" && l.EntityType != filter.EntityType {
			continue
		}
		if filter.EntityID != "" && (l.EntityID == nil || *l.EntityID != filter.EntityID) {
			continue
		}
		if !filter.Since.IsZero() && l.CreatedAt.Before(filter.Since) {
			continue
		}
		// A copy, and a fresh slice. This previously returned a subslice of the
		// live backing array: the caller held memory that CreateAuditLog would
		// go on to write through, so reading a returned entry raced every
		// subsequent audit write. Harmless while nothing read audit logs
		// concurrently — which stopped being true the moment the event stream
		// arrived.
		matched = append(matched, clone(l))
	}

	total := int64(len(matched))
	return paginate(matched, filter.Limit, filter.Offset), total, nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// ── Notification Channels ───────────────────────────────

func (m *MemoryStore) ListNotificationChannels(ctx context.Context) ([]*NotificationChannel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*NotificationChannel, 0, len(m.notifChannels))
	for _, ch := range m.notifChannels {
		list = append(list, clone(ch))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func (m *MemoryStore) GetNotificationChannel(ctx context.Context, id string) (*NotificationChannel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ch, ok := m.notifChannels[id]
	if !ok {
		return nil, fmt.Errorf("notification channel %s not found", id)
	}
	return clone(ch), nil
}

func (m *MemoryStore) CreateNotificationChannel(ctx context.Context, ch *NotificationChannel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.notifChannels {
		if existing.Name == ch.Name {
			return fmt.Errorf("a notification channel named %q already exists", ch.Name)
		}
	}
	if ch.ID == "" {
		ch.ID = uuid.New().String()
	}
	now := time.Now()
	ch.CreatedAt = now
	ch.UpdatedAt = now
	stored := clone(ch)
	stored.Topics = normalizeTopics(ch.Topics)
	m.notifChannels[ch.ID] = stored
	return nil
}

func (m *MemoryStore) UpdateNotificationChannel(ctx context.Context, ch *NotificationChannel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	prev, ok := m.notifChannels[ch.ID]
	if !ok {
		return fmt.Errorf("notification channel %s not found", ch.ID)
	}
	ch.UpdatedAt = time.Now()
	stored := clone(ch)
	stored.Topics = normalizeTopics(ch.Topics)
	// last_sent_at belongs to the dispatcher, matching PostgresStore.
	stored.LastSentAt = prev.LastSentAt
	m.notifChannels[ch.ID] = stored
	return nil
}

func (m *MemoryStore) DeleteNotificationChannel(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.notifChannels, id)
	return nil
}

func (m *MemoryStore) MarkNotificationChannelSent(ctx context.Context, id string, sentAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.notifChannels[id]
	if !ok {
		return fmt.Errorf("notification channel %s not found", id)
	}
	ch.LastSentAt = &sentAt
	return nil
}

func (m *MemoryStore) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stats := &DashboardStats{
		TotalCertificates: int64(len(m.certificates)),
		TotalCAs:          int64(len(m.caAuthorities)),
	}
	// Deliberately mirrors the SQL in PostgresStore.GetDashboardStats, clause
	// for clause. The expired test comes first: previously an expired
	// certificate matched the `days_remaining <= 30` branch and was reported as
	// "expiring soon", so the dashboard showed nothing expired no matter how
	// much of the estate already had.
	for _, c := range m.certificates {
		switch {
		case c.Status == "EXPIRED" || c.DaysRemaining == 0:
			stats.ExpiredCerts++
		case c.Status == "EXPIRING" || (c.Status == "ISSUED" && c.DaysRemaining <= 30):
			stats.ExpiringSoonCerts++
		case c.Status == "ISSUED" && c.DaysRemaining > 30:
			stats.HealthyCerts++
		}
	}
	for _, ca := range m.caAuthorities {
		switch ca.Status {
		case "HEALTHY":
			stats.HealthyCAs++
		case "WARNING":
			stats.WarningCAs++
		case "CRITICAL":
			stats.CriticalCAs++
		case "EXPIRED":
			stats.ExpiredCAs++
		default:
			stats.UnknownCAs++
		}
	}
	return stats, nil
}

func strPtr(s string) *string {
	return &s
}

// ── Alert Acknowledgements ──────────────────────────────

func (m *MemoryStore) CreateAcknowledgement(ctx context.Context, ack *AlertAcknowledgement) error {
	if ack.EntityType != AckEntityCAAuthority && ack.EntityType != AckEntityCertificate {
		return fmt.Errorf("unknown acknowledgement entity type %q", ack.EntityType)
	}
	if ack.EntityID == "" {
		return fmt.Errorf("an acknowledgement needs an entity id")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if ack.ID == "" {
		ack.ID = uuid.New().String()
	}
	now := time.Now()
	if ack.AcknowledgedAt.IsZero() {
		ack.AcknowledgedAt = now
	}
	ack.CreatedAt = now

	m.acks = append(m.acks, clone(ack))
	return nil
}

func (m *MemoryStore) GetActiveAcknowledgement(ctx context.Context, entityType, entityID string) (*AlertAcknowledgement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.newestActive(entityType, entityID), nil
}

// newestActive walks backwards, so the first un-revoked match is the newest.
// Callers must hold the lock.
func (m *MemoryStore) newestActive(entityType, entityID string) *AlertAcknowledgement {
	for i := len(m.acks) - 1; i >= 0; i-- {
		a := m.acks[i]
		if a.EntityType == entityType && a.EntityID == entityID && a.RevokedAt == nil {
			return clone(a)
		}
	}
	return nil
}

func (m *MemoryStore) ListAcknowledgements(ctx context.Context, entityType, entityID string) ([]*AlertAcknowledgement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Copies, not the stored pointers. Returning the live records is the defect
	// ListAuditLogs shipped with: a caller holding them races every later write.
	out := make([]*AlertAcknowledgement, 0)
	for i := len(m.acks) - 1; i >= 0; i-- {
		if a := m.acks[i]; a.EntityType == entityType && a.EntityID == entityID {
			out = append(out, clone(a))
		}
	}
	return out, nil
}

func (m *MemoryStore) GetActiveAcknowledgements(ctx context.Context, entityType string, entityIDs []string) (map[string]*AlertAcknowledgement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	wanted := make(map[string]bool, len(entityIDs))
	for _, id := range entityIDs {
		wanted[id] = true
	}

	out := make(map[string]*AlertAcknowledgement, len(entityIDs))
	for i := len(m.acks) - 1; i >= 0; i-- {
		a := m.acks[i]
		if a.EntityType != entityType || a.RevokedAt != nil || !wanted[a.EntityID] {
			continue
		}
		if _, seen := out[a.EntityID]; !seen {
			out[a.EntityID] = clone(a)
		}
	}
	return out, nil
}

func (m *MemoryStore) RevokeAcknowledgement(ctx context.Context, id string, revokedBy *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, a := range m.acks {
		if a.ID != id {
			continue
		}
		// Already revoked stays as it was: who first withdrew it is the answer
		// a review needs, not whoever pressed the button again.
		if a.RevokedAt == nil {
			now := time.Now()
			a.RevokedAt = &now
			a.RevokedBy = revokedBy
		}
		return nil
	}
	return fmt.Errorf("acknowledgement %s not found", id)
}

// ── Discovery ───────────────────────────────────────────

func (m *MemoryStore) CreateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error {
	if scan.ScanType == "" {
		return fmt.Errorf("a discovery scan needs a type")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if scan.ID == "" {
		scan.ID = uuid.New().String()
	}
	scan.CreatedAt = time.Now()
	if scan.Status == "" {
		scan.Status = ScanPending
	}
	m.discoveryScans = append(m.discoveryScans, clone(scan))
	return nil
}

func (m *MemoryStore) UpdateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, s := range m.discoveryScans {
		if s.ID == scan.ID {
			// CreatedAt is the store's, not the caller's: a scan record that
			// could be back-dated by whoever updates it is not evidence.
			updated := clone(scan)
			updated.CreatedAt = s.CreatedAt
			m.discoveryScans[i] = updated
			return nil
		}
	}
	return fmt.Errorf("discovery scan %s not found", scan.ID)
}

func (m *MemoryStore) GetDiscoveryScan(ctx context.Context, id string) (*DiscoveryScan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.discoveryScans {
		if s.ID == id {
			return clone(s), nil
		}
	}
	return nil, fmt.Errorf("discovery scan %s not found", id)
}

func (m *MemoryStore) ListDiscoveryScans(ctx context.Context, limit, offset int) ([]*DiscoveryScan, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := int64(len(m.discoveryScans))
	if limit <= 0 {
		limit = 50
	}

	// Newest first, which is the only order a scan history is ever read in.
	out := make([]*DiscoveryScan, 0)
	skipped := 0
	for i := len(m.discoveryScans) - 1; i >= 0; i-- {
		if skipped < offset {
			skipped++
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, clone(m.discoveryScans[i]))
	}
	return out, total, nil
}

func (m *MemoryStore) CreateDiscoveryResults(ctx context.Context, results []*DiscoveryResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for _, r := range results {
		if r.ScanID == "" {
			return fmt.Errorf("a discovery result needs a scan id")
		}
		if r.ID == "" {
			r.ID = uuid.New().String()
		}
		r.CreatedAt = now
		if r.ScannedAt.IsZero() {
			r.ScannedAt = now
		}
		m.discoveryResults = append(m.discoveryResults, clone(r))
	}
	return nil
}

func (m *MemoryStore) ListDiscoveryResults(ctx context.Context, filter DiscoveryResultFilter) ([]*DiscoveryResult, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := make([]*DiscoveryResult, 0)
	// Walked newest first, so the first result seen for an endpoint is its
	// latest observation.
	seenEndpoint := map[string]bool{}
	for i := len(m.discoveryResults) - 1; i >= 0; i-- {
		r := m.discoveryResults[i]
		if filter.LatestPerEndpoint {
			key := endpointKey(r.Host, r.Port)
			if seenEndpoint[key] {
				continue
			}
			seenEndpoint[key] = true
		}
		if filter.ScanID != "" && r.ScanID != filter.ScanID {
			continue
		}
		if filter.ManagementState != "" && r.ManagementState != filter.ManagementState {
			continue
		}
		if filter.TrustState != "" && r.TrustState != filter.TrustState {
			continue
		}
		if filter.Host != "" && r.Host != filter.Host {
			continue
		}
		if filter.UnimportedOnly && r.IsImported {
			continue
		}
		matched = append(matched, clone(r))
	}

	total := int64(len(matched))
	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	if filter.Offset >= len(matched) {
		return []*DiscoveryResult{}, total, nil
	}
	end := filter.Offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[filter.Offset:end], total, nil
}

func (m *MemoryStore) GetDiscoveryResult(ctx context.Context, id string) (*DiscoveryResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, r := range m.discoveryResults {
		if r.ID == id {
			return clone(r), nil
		}
	}
	return nil, fmt.Errorf("discovery result %s not found", id)
}

func (m *MemoryStore) MarkDiscoveryResultImported(ctx context.Context, id, certificateID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range m.discoveryResults {
		if r.ID != id {
			continue
		}
		certID := certificateID
		r.IsImported = true
		r.ImportedCertificateID = &certID
		// Adopting a result also settles the question it was raised about: the
		// certificate is managed from this moment on, and a results list that
		// still called it unmanaged would keep asking for work already done.
		r.ManagementState = DiscoveryManaged
		r.MatchedCertificateID = &certID
		return nil
	}
	return fmt.Errorf("discovery result %s not found", id)
}

// GetLatestDiscoveryResults returns what each endpoint was last seen serving.
func (m *MemoryStore) GetLatestDiscoveryResults(ctx context.Context, endpoints []string) (map[string]*DiscoveryResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	wanted := make(map[string]bool, len(endpoints))
	for _, e := range endpoints {
		wanted[e] = true
	}
	// Empty means every endpoint, which is how the whole estate's current state
	// is asked for.
	all := len(endpoints) == 0

	out := make(map[string]*DiscoveryResult, len(endpoints))
	for i := len(m.discoveryResults) - 1; i >= 0; i-- {
		r := m.discoveryResults[i]
		key := endpointKey(r.Host, r.Port)
		if !all && !wanted[key] {
			continue
		}
		if _, seen := out[key]; !seen {
			out[key] = clone(r)
		}
	}
	return out, nil
}

func endpointKey(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// ── Discovery schedules ─────────────────────────────────

func (m *MemoryStore) ListDiscoverySchedules(ctx context.Context) ([]*DiscoverySchedule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*DiscoverySchedule, 0, len(m.discoverySchedules))
	for _, s := range m.discoverySchedules {
		out = append(out, clone(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) GetDiscoverySchedule(ctx context.Context, id string) (*DiscoverySchedule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if s, ok := m.discoverySchedules[id]; ok {
		return clone(s), nil
	}
	return nil, fmt.Errorf("discovery schedule %s not found", id)
}

func (m *MemoryStore) CreateDiscoverySchedule(ctx context.Context, s *DiscoverySchedule) error {
	if len(s.Targets) == 0 {
		return fmt.Errorf("a discovery schedule needs at least one target")
	}
	if s.IntervalMinutes <= 0 {
		return fmt.Errorf("a discovery schedule needs a positive interval")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	now := time.Now()
	s.CreatedAt, s.UpdatedAt = now, now
	m.discoverySchedules[s.ID] = clone(s)
	return nil
}

func (m *MemoryStore) UpdateDiscoverySchedule(ctx context.Context, s *DiscoverySchedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.discoverySchedules[s.ID]
	if !ok {
		return fmt.Errorf("discovery schedule %s not found", s.ID)
	}
	updated := clone(s)
	updated.CreatedAt = existing.CreatedAt
	updated.UpdatedAt = time.Now()
	m.discoverySchedules[s.ID] = updated
	return nil
}

func (m *MemoryStore) DeleteDiscoverySchedule(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.discoverySchedules[id]; !ok {
		return fmt.Errorf("discovery schedule %s not found", id)
	}
	delete(m.discoverySchedules, id)
	return nil
}

func (m *MemoryStore) GetDueDiscoverySchedules(ctx context.Context, now time.Time) ([]*DiscoverySchedule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*DiscoverySchedule, 0)
	for _, s := range m.discoverySchedules {
		if s.Due(now) {
			out = append(out, clone(s))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) MarkDiscoveryScheduleRun(ctx context.Context, id string, ranAt, nextRunAt time.Time, scanID *string, runErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.discoverySchedules[id]
	if !ok {
		return fmt.Errorf("discovery schedule %s not found", id)
	}
	s.LastRunAt = &ranAt
	s.NextRunAt = &nextRunAt
	s.LastError = runErr
	// A failed run keeps the previous scan id rather than clearing it: "the
	// last time this worked" is the more useful fact of the two.
	if scanID != nil {
		s.LastScanID = scanID
	}
	s.UpdatedAt = time.Now()
	return nil
}

// ── Certificate Transparency ────────────────────────────

func (m *MemoryStore) ListCTMonitors(ctx context.Context) ([]*CTMonitor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*CTMonitor, 0, len(m.ctMonitors))
	for _, mon := range m.ctMonitors {
		out = append(out, clone(mon))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

func (m *MemoryStore) GetCTMonitor(ctx context.Context, id string) (*CTMonitor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if mon, ok := m.ctMonitors[id]; ok {
		return clone(mon), nil
	}
	return nil, fmt.Errorf("certificate transparency monitor %s not found", id)
}

func (m *MemoryStore) CreateCTMonitor(ctx context.Context, mon *CTMonitor) error {
	if strings.TrimSpace(mon.Domain) == "" {
		return fmt.Errorf("a monitor needs a domain")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.ctMonitors {
		if strings.EqualFold(existing.Domain, mon.Domain) {
			return fmt.Errorf("%s is already being watched", mon.Domain)
		}
	}
	if mon.ID == "" {
		mon.ID = uuid.New().String()
	}
	now := time.Now()
	mon.CreatedAt, mon.UpdatedAt = now, now
	m.ctMonitors[mon.ID] = clone(mon)
	return nil
}

func (m *MemoryStore) UpdateCTMonitor(ctx context.Context, mon *CTMonitor) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.ctMonitors[mon.ID]
	if !ok {
		return fmt.Errorf("certificate transparency monitor %s not found", mon.ID)
	}
	updated := clone(mon)
	updated.CreatedAt = existing.CreatedAt
	updated.UpdatedAt = time.Now()
	m.ctMonitors[mon.ID] = updated
	return nil
}

func (m *MemoryStore) DeleteCTMonitor(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.ctMonitors[id]; !ok {
		return fmt.Errorf("certificate transparency monitor %s not found", id)
	}
	delete(m.ctMonitors, id)

	kept := m.ctCertificates[:0]
	for _, c := range m.ctCertificates {
		if c.MonitorID != id {
			kept = append(kept, c)
		}
	}
	m.ctCertificates = kept
	return nil
}

func (m *MemoryStore) GetDueCTMonitors(ctx context.Context, now time.Time) ([]*CTMonitor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*CTMonitor, 0)
	for _, mon := range m.ctMonitors {
		if mon.Due(now) {
			out = append(out, clone(mon))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

func (m *MemoryStore) MarkCTMonitorChecked(ctx context.Context, id string, checkedAt, nextCheckAt time.Time,
	success bool, lastEntryID *int64, seen, unmanaged int, checkErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mon, ok := m.ctMonitors[id]
	if !ok {
		return fmt.Errorf("certificate transparency monitor %s not found", id)
	}
	mon.LastCheckedAt = &checkedAt
	mon.NextCheckAt = &nextCheckAt
	mon.LastError = checkErr
	if success {
		// Only a check that answered moves this. Everything on screen that says
		// "we are watching this domain" is really saying "we last heard from
		// the log at this time".
		mon.LastSuccessAt = &checkedAt
		if lastEntryID != nil {
			mon.LastEntryID = lastEntryID
		}
		mon.CertificatesSeen += seen
		mon.UnmanagedSeen += unmanaged
	}
	mon.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) RecordCTCertificates(ctx context.Context, certs []*CTCertificate) ([]*CTCertificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	known := map[string]bool{}
	for _, existing := range m.ctCertificates {
		known[ctEntryKey(existing)] = true
	}

	now := time.Now()
	added := make([]*CTCertificate, 0, len(certs))
	for _, c := range certs {
		key := ctEntryKey(c)
		if known[key] {
			continue
		}
		known[key] = true
		if c.ID == "" {
			c.ID = uuid.New().String()
		}
		if c.FirstSeenAt.IsZero() {
			c.FirstSeenAt = now
		}
		c.CreatedAt = now
		m.ctCertificates = append(m.ctCertificates, clone(c))
		added = append(added, clone(c))
	}
	return added, nil
}

func ctEntryKey(c *CTCertificate) string {
	if c.EntryID != nil {
		return fmt.Sprintf("%s/%d", c.MonitorID, *c.EntryID)
	}
	return fmt.Sprintf("%s/serial:%s", c.MonitorID, c.SerialNumber)
}

func (m *MemoryStore) ListCTCertificates(ctx context.Context, filter CTCertificateFilter) ([]*CTCertificate, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// A precertificate and its final certificate are two entries for one
	// certificate. Excluding one of them means excluding the *pre*-issuance
	// entry when the real one is also present, never the other way round.
	finalSerials := map[string]bool{}
	if filter.ExcludePrecertificates {
		for _, c := range m.ctCertificates {
			if !c.IsPrecertificate && c.SerialNumber != "" {
				finalSerials[c.SerialNumber] = true
			}
		}
	}

	matched := make([]*CTCertificate, 0)
	for i := len(m.ctCertificates) - 1; i >= 0; i-- {
		c := m.ctCertificates[i]
		if filter.MonitorID != "" && c.MonitorID != filter.MonitorID {
			continue
		}
		if filter.ManagementState != "" && c.ManagementState != filter.ManagementState {
			continue
		}
		if filter.ExcludePrecertificates && c.IsPrecertificate && finalSerials[c.SerialNumber] {
			continue
		}
		matched = append(matched, clone(c))
	}

	total := int64(len(matched))
	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	if filter.Offset >= len(matched) {
		return []*CTCertificate{}, total, nil
	}
	end := filter.Offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[filter.Offset:end], total, nil
}

// ── Cloud inventory ─────────────────────────────────────────

func (m *MemoryStore) ListCloudConnections(ctx context.Context) ([]*CloudConnection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*CloudConnection, 0, len(m.cloudConnections))
	for _, conn := range m.cloudConnections {
		out = append(out, clone(conn))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) GetCloudConnection(ctx context.Context, id string) (*CloudConnection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if conn, ok := m.cloudConnections[id]; ok {
		return clone(conn), nil
	}
	return nil, fmt.Errorf("cloud connection %s not found", id)
}

func (m *MemoryStore) CreateCloudConnection(ctx context.Context, conn *CloudConnection) error {
	if strings.TrimSpace(conn.Name) == "" {
		return fmt.Errorf("a cloud connection needs a name")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.cloudConnections {
		if strings.EqualFold(existing.Name, conn.Name) {
			return fmt.Errorf("a cloud connection named %q already exists", conn.Name)
		}
	}
	if conn.ID == "" {
		conn.ID = uuid.New().String()
	}
	if conn.Scopes == nil {
		conn.Scopes = []string{}
	}
	now := time.Now()
	conn.CreatedAt, conn.UpdatedAt = now, now
	m.cloudConnections[conn.ID] = clone(conn)
	return nil
}

func (m *MemoryStore) UpdateCloudConnection(ctx context.Context, conn *CloudConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.cloudConnections[conn.ID]
	if !ok {
		return fmt.Errorf("cloud connection %s not found", conn.ID)
	}
	updated := clone(conn)
	// Carried over rather than taken from the caller: an edit is not a sync,
	// and the credentials are only replaced when new ones were supplied.
	updated.CreatedAt = existing.CreatedAt
	updated.UpdatedAt = time.Now()
	updated.LastSyncedAt = existing.LastSyncedAt
	updated.LastSuccessAt = existing.LastSuccessAt
	updated.NextSyncAt = existing.NextSyncAt
	updated.Scopes = existing.Scopes
	updated.CertificatesSeen = existing.CertificatesSeen
	updated.UnmanagedSeen = existing.UnmanagedSeen
	if updated.ConfigEncrypted == "" {
		updated.ConfigEncrypted = existing.ConfigEncrypted
	}
	m.cloudConnections[conn.ID] = updated
	return nil
}

func (m *MemoryStore) DeleteCloudConnection(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.cloudConnections[id]; !ok {
		return fmt.Errorf("cloud connection %s not found", id)
	}
	delete(m.cloudConnections, id)

	kept := m.cloudCertificates[:0]
	for _, c := range m.cloudCertificates {
		if c.ConnectionID != id {
			kept = append(kept, c)
		}
	}
	m.cloudCertificates = kept
	return nil
}

func (m *MemoryStore) GetDueCloudConnections(ctx context.Context, now time.Time) ([]*CloudConnection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*CloudConnection, 0)
	for _, conn := range m.cloudConnections {
		if conn.Due(now) {
			out = append(out, clone(conn))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) MarkCloudConnectionSynced(ctx context.Context, id string, syncedAt, nextSyncAt time.Time,
	success bool, scopes []string, seen, unmanaged int, syncErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn, ok := m.cloudConnections[id]
	if !ok {
		return fmt.Errorf("cloud connection %s not found", id)
	}
	conn.LastSyncedAt = &syncedAt
	conn.NextSyncAt = &nextSyncAt
	conn.LastError = syncErr
	if success {
		// Only a sync that answered moves the success timestamp. This is the
		// whole reason there are two of them.
		conn.LastSuccessAt = &syncedAt
		conn.Scopes = append([]string{}, scopes...)
		conn.CertificatesSeen = seen
		conn.UnmanagedSeen = unmanaged
	}
	conn.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) UpsertCloudCertificates(ctx context.Context, certs []*CloudCertificate) ([]*CloudCertificate, error) {
	added := make([]*CloudCertificate, 0, len(certs))

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for _, c := range certs {
		var existing *CloudCertificate
		for _, stored := range m.cloudCertificates {
			if stored.ConnectionID == c.ConnectionID && stored.ResourceID == c.ResourceID {
				existing = stored
				break
			}
		}

		if existing != nil {
			first, created := existing.FirstSeenAt, existing.CreatedAt
			id := existing.ID
			imported, importedID := existing.IsImported, existing.ImportedCertificateID
			*existing = *clone(c)
			existing.ID = id
			// first_seen_at survives: a certificate that came back is the same
			// certificate returning, and when it first appeared is the part
			// worth keeping.
			existing.FirstSeenAt, existing.CreatedAt = first, created
			existing.LastSeenAt = c.LastSeenAt
			existing.RemovedAt = nil
			if imported {
				existing.IsImported, existing.ImportedCertificateID = imported, importedID
				existing.ManagementState = CloudManagedState(existing.ManagementState, true)
			}
			continue
		}

		stored := clone(c)
		if stored.ID == "" {
			stored.ID = uuid.New().String()
		}
		stored.FirstSeenAt = now
		if stored.LastSeenAt.IsZero() {
			stored.LastSeenAt = now
		}
		stored.CreatedAt = now
		m.cloudCertificates = append(m.cloudCertificates, stored)

		c.ID, c.FirstSeenAt, c.CreatedAt = stored.ID, stored.FirstSeenAt, stored.CreatedAt
		added = append(added, clone(stored))
	}
	return added, nil
}

// CloudManagedState keeps an adopted certificate managed.
//
// Exported because the two store implementations must agree on it: a sync that
// ran after somebody imported a certificate would otherwise reset the verdict
// to unmanaged and put the same work back on the list.
func CloudManagedState(state string, imported bool) string {
	if imported {
		return DiscoveryManaged
	}
	return state
}

func (m *MemoryStore) MarkCloudCertificatesRemoved(ctx context.Context, connectionID string,
	seenResourceIDs []string, at time.Time) (int, error) {
	// An empty seen list is not treated as "everything is gone". A provider
	// that answered with nothing is possible, but so is a bug, and reporting an
	// entire estate as deleted is the more expensive mistake of the two.
	if len(seenResourceIDs) == 0 {
		return 0, nil
	}

	seen := make(map[string]bool, len(seenResourceIDs))
	for _, id := range seenResourceIDs {
		seen[id] = true
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for _, c := range m.cloudCertificates {
		if c.ConnectionID != connectionID || c.RemovedAt != nil || seen[c.ResourceID] {
			continue
		}
		when := at
		c.RemovedAt = &when
		count++
	}
	return count, nil
}

func (m *MemoryStore) ListCloudCertificates(ctx context.Context, filter CloudCertificateFilter) ([]*CloudCertificate, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := make([]*CloudCertificate, 0)
	for _, c := range m.cloudCertificates {
		if filter.ConnectionID != "" && c.ConnectionID != filter.ConnectionID {
			continue
		}
		if filter.ManagementState != "" && c.ManagementState != filter.ManagementState {
			continue
		}
		if !filter.IncludeRemoved && c.RemovedAt != nil {
			continue
		}
		if filter.UnimportedOnly && c.IsImported {
			continue
		}
		if filter.FindingCode != "" && !hasFinding(c.Findings, filter.FindingCode) {
			continue
		}
		matched = append(matched, clone(c))
	}

	// Soonest to expire first: the list is read to decide what to deal with
	// today, not to browse an inventory.
	sort.Slice(matched, func(i, j int) bool {
		a, b := matched[i].NotAfter, matched[j].NotAfter
		switch {
		case a == nil && b == nil:
			return matched[i].ResourceID < matched[j].ResourceID
		case a == nil:
			return false
		case b == nil:
			return true
		case a.Equal(*b):
			return matched[i].ResourceID < matched[j].ResourceID
		}
		return a.Before(*b)
	})

	total := int64(len(matched))
	return paginate(matched, filter.Limit, filter.Offset), total, nil
}

func hasFinding(findings []Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func (m *MemoryStore) GetCloudCertificate(ctx context.Context, id string) (*CloudCertificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.cloudCertificates {
		if c.ID == id {
			return clone(c), nil
		}
	}
	return nil, fmt.Errorf("cloud certificate %s not found", id)
}

func (m *MemoryStore) MarkCloudCertificateImported(ctx context.Context, id, certificateID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, c := range m.cloudCertificates {
		if c.ID != id {
			continue
		}
		c.IsImported = true
		c.ImportedCertificateID = &certificateID
		c.ManagementState = DiscoveryManaged
		if c.MatchedCertificateID == nil {
			c.MatchedCertificateID = &certificateID
		}
		return nil
	}
	return fmt.Errorf("cloud certificate %s not found", id)
}

// ── Renewal queue ───────────────────────────────────────────

// maxAttemptLog bounds the history kept on one job, so a renewal retrying for
// weeks does not grow without limit. The newest are kept: what a job is doing
// now matters more than what it did a fortnight ago, and the attempt count
// survives separately.
const maxAttemptLog = 50

func (m *MemoryStore) EnqueueRenewal(ctx context.Context, job *RenewalJob) (bool, error) {
	if job.CertificateID == "" {
		return false, fmt.Errorf("a renewal job needs a certificate")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// The in-memory stand-in for the partial unique index: at most one
	// outstanding job per certificate.
	for _, existing := range m.renewalJobs {
		if existing.CertificateID == job.CertificateID && existing.Outstanding() {
			*job = *clone(existing)
			return false, nil
		}
	}

	stored := clone(job)
	if stored.ID == "" {
		stored.ID = uuid.New().String()
	}
	if stored.Status == "" {
		stored.Status = RenewalPending
	}
	if stored.Reason == "" {
		stored.Reason = RenewalReasonScheduled
	}
	if stored.RunAfter.IsZero() {
		stored.RunAfter = time.Now()
	}
	if stored.AttemptLog == nil {
		stored.AttemptLog = []RenewalAttempt{}
	}
	now := time.Now()
	stored.CreatedAt, stored.UpdatedAt = now, now

	m.renewalJobs = append(m.renewalJobs, stored)
	*job = *clone(stored)
	return true, nil
}

func (m *MemoryStore) ClaimRenewalJob(ctx context.Context, worker string, lease time.Duration, now time.Time) (*RenewalJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var best *RenewalJob
	for _, job := range m.renewalJobs {
		ready := (job.Status == RenewalPending && !job.RunAfter.After(now)) ||
			// A worker that was killed releases its job by the lease running
			// out rather than by anything having to reap it.
			(job.Status == RenewalRunning && job.LockedUntil != nil && job.LockedUntil.Before(now))
		if !ready {
			continue
		}
		if best == nil || moreUrgent(job, best) {
			best = job
		}
	}
	if best == nil {
		// An empty queue is the ordinary case, not an error.
		return nil, nil
	}

	until := now.Add(lease)
	holder := worker
	best.Status = RenewalRunning
	best.LockedBy = &holder
	best.LockedUntil = &until
	best.Attempts++
	if best.StartedAt == nil {
		started := now
		best.StartedAt = &started
	}
	best.UpdatedAt = time.Now()
	return clone(best), nil
}

// moreUrgent ranks by the deadline being raced rather than by age. A
// certificate expiring tomorrow outranks one enqueued an hour earlier with a
// month left.
func moreUrgent(a, b *RenewalJob) bool {
	switch {
	case a.NotAfter == nil && b.NotAfter == nil:
		return a.RunAfter.Before(b.RunAfter)
	case a.NotAfter == nil:
		return false
	case b.NotAfter == nil:
		return true
	case a.NotAfter.Equal(*b.NotAfter):
		return a.RunAfter.Before(b.RunAfter)
	}
	return a.NotAfter.Before(*b.NotAfter)
}

func (m *MemoryStore) ExtendRenewalLease(ctx context.Context, id, worker string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.renewalJobs {
		if job.ID != id {
			continue
		}
		// Scoped to the holder: a worker whose lease already expired and was
		// taken by somebody else must not extend it back out from under them.
		if job.Status != RenewalRunning || job.LockedBy == nil || *job.LockedBy != worker {
			return fmt.Errorf("renewal job %s is no longer held by %s", id, worker)
		}
		when := until
		job.LockedUntil = &when
		job.UpdatedAt = time.Now()
		return nil
	}
	return fmt.Errorf("renewal job %s not found", id)
}

func (m *MemoryStore) CompleteRenewalJob(ctx context.Context, id, status string,
	attempt RenewalAttempt, runAfter time.Time, escalate bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.renewalJobs {
		if job.ID != id {
			continue
		}
		job.Status = status
		job.LastError = attempt.Error
		job.LockedBy, job.LockedUntil = nil, nil

		log := append(append([]RenewalAttempt{}, job.AttemptLog...), attempt)
		if len(log) > maxAttemptLog {
			log = log[len(log)-maxAttemptLog:]
		}
		job.AttemptLog = log

		if status == RenewalPending {
			job.RunAfter = runAfter
		} else {
			done := time.Now()
			job.CompletedAt = &done
		}
		if escalate && job.EscalatedAt == nil {
			// Set once and left: when a job first became somebody's problem is
			// more useful than when it most recently was.
			when := time.Now()
			job.EscalatedAt = &when
		}
		job.UpdatedAt = time.Now()
		return nil
	}
	return fmt.Errorf("renewal job %s not found", id)
}

func (m *MemoryStore) GetRenewalJob(ctx context.Context, id string) (*RenewalJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, job := range m.renewalJobs {
		if job.ID == id {
			return clone(job), nil
		}
	}
	return nil, fmt.Errorf("renewal job %s not found", id)
}

func (m *MemoryStore) ListRenewalJobs(ctx context.Context, filter RenewalJobFilter) ([]*RenewalJob, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := make([]*RenewalJob, 0)
	for _, job := range m.renewalJobs {
		if filter.CertificateID != "" && job.CertificateID != filter.CertificateID {
			continue
		}
		if filter.Status != "" && job.Status != filter.Status {
			continue
		}
		if filter.OutstandingOnly && !job.Outstanding() {
			continue
		}
		if filter.EscalatedOnly && job.EscalatedAt == nil {
			continue
		}
		matched = append(matched, clone(job))
	}

	// The same order the workers claim in, so the screen agrees with what is
	// actually happening next.
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].NotAfter != nil && matched[j].NotAfter != nil &&
			!matched[i].NotAfter.Equal(*matched[j].NotAfter) {
			return matched[i].NotAfter.Before(*matched[j].NotAfter)
		}
		if (matched[i].NotAfter == nil) != (matched[j].NotAfter == nil) {
			return matched[j].NotAfter == nil
		}
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	total := int64(len(matched))
	return paginate(matched, filter.Limit, filter.Offset), total, nil
}

func (m *MemoryStore) CancelRenewalJob(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.renewalJobs {
		if job.ID != id {
			continue
		}
		if !job.Outstanding() {
			return fmt.Errorf("renewal job %s is not outstanding", id)
		}
		job.Status = RenewalCancelled
		job.LockedBy, job.LockedUntil = nil, nil
		done := time.Now()
		job.CompletedAt = &done
		job.UpdatedAt = done
		return nil
	}
	return fmt.Errorf("renewal job %s is not outstanding", id)
}

func (m *MemoryStore) DeferRenewalJob(ctx context.Context, id string, runAfter time.Time, reason string, escalate bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.renewalJobs {
		if job.ID != id {
			continue
		}
		job.Status = RenewalPending
		job.RunAfter = runAfter
		// Decremented because the claim incremented it and no renewal
		// happened. Restoring the truth rather than fiddling the number: the
		// count means "times we tried to renew this", and a deferral is exactly
		// the case where we did not.
		if job.Attempts > 0 {
			job.Attempts--
		}
		job.LockedBy, job.LockedUntil = nil, nil
		// last_error is left alone. A deferral is not an error, and overwriting
		// the real reason a job has been failing would hide the thing somebody
		// needs to fix.
		log := append(append([]RenewalAttempt{}, job.AttemptLog...), RenewalAttempt{
			StartedAt: time.Now(), Deferred: true, Reason: reason,
		})
		if len(log) > maxAttemptLog {
			log = log[len(log)-maxAttemptLog:]
		}
		job.AttemptLog = log
		if escalate && job.EscalatedAt == nil {
			// Set once and left. A quota that outlasts the certificate is
			// announced the first time it is noticed, not on every deferral
			// for the months until it expires.
			when := time.Now()
			job.EscalatedAt = &when
		}
		job.UpdatedAt = time.Now()
		return nil
	}
	return fmt.Errorf("renewal job %s not found", id)
}

func (m *MemoryStore) CountRecentRenewals(ctx context.Context, caAccountID string, since time.Time) (int, *time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	var oldest *time.Time
	for _, job := range m.renewalJobs {
		if job.Status != RenewalSucceeded || job.CompletedAt == nil {
			continue
		}
		if job.CAAccountID == nil || *job.CAAccountID != caAccountID {
			continue
		}
		if job.CompletedAt.Before(since) {
			continue
		}
		count++
		if oldest == nil || job.CompletedAt.Before(*oldest) {
			when := *job.CompletedAt
			oldest = &when
		}
	}
	return count, oldest, nil
}

func (m *MemoryStore) GetCertificatesDueForARICheck(ctx context.Context, now time.Time, limit int) ([]*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	out := make([]*Certificate, 0)
	for _, c := range m.certificates {
		// Only certificates that could act on the answer. Asking about
		// anything else spends somebody's rate limit to learn nothing.
		if !c.AutoRenew || c.CAAccountID == nil || c.CertificatePEM == nil {
			continue
		}
		if c.ARINextCheckAt != nil && c.ARINextCheckAt.After(now) {
			continue
		}
		out = append(out, clone(c))
	}
	sort.Slice(out, func(i, j int) bool {
		switch {
		case out[i].NotAfter == nil:
			return false
		case out[j].NotAfter == nil:
			return true
		}
		return out[i].NotAfter.Before(*out[j].NotAfter)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryStore) UpdateCertificateRenewalInfo(ctx context.Context, id string, info RenewalInfoUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cert, ok := m.certificates[id]
	if !ok {
		return fmt.Errorf("certificate %s not found", id)
	}
	cert.RenewalScheduledAt = info.RenewalScheduledAt
	cert.ARIWindowStart = info.WindowStart
	cert.ARIWindowEnd = info.WindowEnd
	cert.ARIExplanationURL = info.ExplanationURL
	cert.ARICheckedAt = info.CheckedAt
	cert.ARINextCheckAt = info.NextCheckAt
	cert.ARISupported = info.Supported
	cert.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) GetCertificatesDueForVerification(ctx context.Context, now time.Time, limit int) ([]*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}
	out := make([]*Certificate, 0)
	for _, c := range m.certificates {
		if c.VerifyAfter == nil || c.VerifyAfter.After(now) {
			continue
		}
		out = append(out, clone(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VerifyAfter.Before(*out[j].VerifyAfter) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryStore) UpdateCertificateVerification(ctx context.Context, id string, update VerificationUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cert, ok := m.certificates[id]
	if !ok {
		return fmt.Errorf("certificate %s not found", id)
	}
	cert.VerificationState = update.State
	cert.VerificationDetail = update.Detail
	checked := update.CheckedAt
	cert.LastVerifiedAt = &checked
	cert.VerifyAfter = update.VerifyAfter
	cert.VerificationAttempts = update.Attempts
	if update.PreviousFingerprint != "" {
		cert.PreviousFingerprint = update.PreviousFingerprint
	}
	cert.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) GetEndpointsServingCertificate(ctx context.Context, certificateID, fingerprint string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Newest observation per endpoint only. An endpoint scanned nightly for a
	// month would otherwise be probed thirty times to answer one question.
	latest := map[string]*DiscoveryResult{}
	for _, r := range m.discoveryResults {
		if !r.Reachable {
			continue
		}
		key := net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
		if prev, ok := latest[key]; !ok || r.ScannedAt.After(prev.ScannedAt) {
			latest[key] = r
		}
	}

	endpoints := make([]string, 0)
	for key, r := range latest {
		matched := r.MatchedCertificateID != nil && *r.MatchedCertificateID == certificateID
		if matched || (fingerprint != "" && r.FingerprintSHA256 == fingerprint) {
			endpoints = append(endpoints, key)
		}
	}
	sort.Strings(endpoints)
	return endpoints, nil
}

// ── Certificate ↔ target bindings ───────────────────────────

func (m *MemoryStore) ListCertificateDeployments(ctx context.Context, certificateID string) ([]*CertificateDeployment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*CertificateDeployment, 0, len(m.deployments))
	for _, d := range m.deployments {
		if certificateID != "" && d.CertificateID != certificateID {
			continue
		}
		copied := clone(d)
		m.decorateDeploymentLocked(copied)
		out = append(out, copied)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetName != out[j].TargetName {
			return out[i].TargetName < out[j].TargetName
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (m *MemoryStore) GetCertificateDeployment(ctx context.Context, id string) (*CertificateDeployment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	d, ok := m.deployments[id]
	if !ok {
		return nil, fmt.Errorf("deployment %s not found", id)
	}
	copied := clone(d)
	m.decorateDeploymentLocked(copied)
	return copied, nil
}

// decorateDeploymentLocked fills in the target fields the Postgres query joins.
// Callers hold the lock.
func (m *MemoryStore) decorateDeploymentLocked(d *CertificateDeployment) {
	if t, ok := m.targets[d.TargetID]; ok {
		d.TargetName, d.TargetType = t.Name, t.TargetType
	}
}

func (m *MemoryStore) CreateCertificateDeployment(ctx context.Context, d *CertificateDeployment) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// The in-memory stand-in for the unique constraint on (certificate, target):
	// binding a certificate to a target it is already bound to is a request for
	// a state that already holds, so the existing row is updated in place.
	for _, existing := range m.deployments {
		if existing.CertificateID == d.CertificateID && existing.TargetID == d.TargetID {
			existing.IsEnabled = d.IsEnabled
			existing.DeployOnRenewal = d.DeployOnRenewal
			existing.Options = d.Options
			existing.UpdatedAt = time.Now()
			*d = *clone(existing)
			m.decorateDeploymentLocked(d)
			return nil
		}
	}

	stored := clone(d)
	if stored.ID == "" {
		stored.ID = uuid.New().String()
	}
	now := time.Now()
	stored.CreatedAt, stored.UpdatedAt = now, now
	m.deployments[stored.ID] = stored
	*d = *clone(stored)
	m.decorateDeploymentLocked(d)
	return nil
}

func (m *MemoryStore) DeleteCertificateDeployment(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.deployments, id)
	return nil
}

func (m *MemoryStore) RecordDeploymentOutcome(ctx context.Context, id string, outcome DeploymentOutcome) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.deployments[id]
	if !ok {
		return fmt.Errorf("deployment %s not found", id)
	}
	d.LastStatus = outcome.Status
	d.LastError = outcome.Error
	// Only a success moves the fingerprint, and only to what was installed. A
	// failed deploy leaves the previous value alone: the place is still holding
	// whatever it was holding.
	if outcome.Status == DeploymentDeployed && outcome.Fingerprint != "" {
		when := outcome.At
		d.DeployedFingerprint = outcome.Fingerprint
		d.DeployedAt = &when
	}
	d.UpdatedAt = time.Now()
	return nil
}

// ── Deployment queue ────────────────────────────────────────

func (m *MemoryStore) EnqueueDeployment(ctx context.Context, job *DeploymentJob) (bool, error) {
	if job.DeploymentID == "" {
		return false, fmt.Errorf("a deployment job needs a deployment")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// The in-memory stand-in for the partial unique index: at most one
	// outstanding job per binding — per place, not per certificate.
	for _, existing := range m.deploymentJobs {
		if existing.DeploymentID == job.DeploymentID && existing.Outstanding() {
			*job = *clone(existing)
			return false, nil
		}
	}

	stored := clone(job)
	if stored.ID == "" {
		stored.ID = uuid.New().String()
	}
	if stored.Status == "" {
		stored.Status = DeployPending
	}
	if stored.Reason == "" {
		stored.Reason = DeployReasonManual
	}
	if stored.RunAfter.IsZero() {
		stored.RunAfter = time.Now()
	}
	if stored.AttemptLog == nil {
		stored.AttemptLog = []DeploymentAttempt{}
	}
	now := time.Now()
	stored.CreatedAt, stored.UpdatedAt = now, now

	m.deploymentJobs = append(m.deploymentJobs, stored)
	*job = *clone(stored)
	return true, nil
}

func (m *MemoryStore) ClaimDeploymentJob(ctx context.Context, worker string, lease time.Duration, now time.Time) (*DeploymentJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var best *DeploymentJob
	for _, job := range m.deploymentJobs {
		ready := (job.Status == DeployPending && !job.RunAfter.After(now)) ||
			(job.Status == DeployRunning && job.LockedUntil != nil && job.LockedUntil.Before(now))
		if !ready {
			continue
		}
		// Agent targets are deployed to by the host itself. See the note on the
		// same exclusion in PostgresStore.ClaimDeploymentJob.
		if target, ok := m.targets[job.TargetID]; ok && target.AgentID != nil {
			continue
		}
		if m.heldBackByAFailure(job) || m.heldBackByAnEarlierWave(job) {
			continue
		}
		if best == nil || moreUrgentDeployment(job, best) {
			best = job
		}
	}
	if best == nil {
		return nil, nil
	}

	until := now.Add(lease)
	holder := worker
	best.Status = DeployRunning
	best.LockedBy = &holder
	best.LockedUntil = &until
	best.Attempts++
	if best.StartedAt == nil {
		started := now
		best.StartedAt = &started
	}
	best.UpdatedAt = time.Now()
	return clone(best), nil
}

// moreUrgentDeployment ranks by wave and then by the expiry being raced,
// matching the queue's ORDER BY, so the screen agrees with what is actually
// happening next.
func moreUrgentDeployment(a, b *DeploymentJob) bool {
	// Wave first. The order an operator declared outranks the arithmetic.
	if a.DeployOrder != b.DeployOrder {
		return a.DeployOrder < b.DeployOrder
	}
	switch {
	case a.NotAfter == nil && b.NotAfter == nil:
		return a.RunAfter.Before(b.RunAfter)
	case a.NotAfter == nil:
		return false
	case b.NotAfter == nil:
		return true
	case a.NotAfter.Equal(*b.NotAfter):
		return a.RunAfter.Before(b.RunAfter)
	}
	return a.NotAfter.Before(*b.NotAfter)
}

func (m *MemoryStore) ExtendDeploymentLease(ctx context.Context, id, worker string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.deploymentJobs {
		if job.ID != id {
			continue
		}
		if job.Status != DeployRunning || job.LockedBy == nil || *job.LockedBy != worker {
			return fmt.Errorf("deployment job %s is no longer held by %s", id, worker)
		}
		when := until
		job.LockedUntil = &when
		job.UpdatedAt = time.Now()
		return nil
	}
	return fmt.Errorf("deployment job %s not found", id)
}

func (m *MemoryStore) CompleteDeploymentJob(ctx context.Context, id, status string,
	attempt DeploymentAttempt, runAfter time.Time, escalate bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.deploymentJobs {
		if job.ID != id {
			continue
		}
		job.Status = status
		job.LastError = attempt.Error
		job.LockedBy, job.LockedUntil = nil, nil

		log := append(append([]DeploymentAttempt{}, job.AttemptLog...), attempt)
		if len(log) > maxAttemptLog {
			log = log[len(log)-maxAttemptLog:]
		}
		job.AttemptLog = log

		if status == DeployPending {
			job.RunAfter = runAfter
		} else {
			done := time.Now()
			job.CompletedAt = &done
		}
		if escalate && job.EscalatedAt == nil {
			when := time.Now()
			job.EscalatedAt = &when
		}
		job.UpdatedAt = time.Now()
		return nil
	}
	return fmt.Errorf("deployment job %s not found", id)
}

func (m *MemoryStore) GetDeploymentJob(ctx context.Context, id string) (*DeploymentJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, job := range m.deploymentJobs {
		if job.ID == id {
			return clone(job), nil
		}
	}
	return nil, fmt.Errorf("deployment job %s not found", id)
}

func (m *MemoryStore) ListDeploymentJobs(ctx context.Context, filter DeploymentJobFilter) ([]*DeploymentJob, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := make([]*DeploymentJob, 0)
	for _, job := range m.deploymentJobs {
		if filter.CertificateID != "" && job.CertificateID != filter.CertificateID {
			continue
		}
		if filter.TargetID != "" && job.TargetID != filter.TargetID {
			continue
		}
		if filter.DeploymentID != "" && job.DeploymentID != filter.DeploymentID {
			continue
		}
		if filter.Status != "" && job.Status != filter.Status {
			continue
		}
		if filter.OutstandingOnly && !job.Outstanding() {
			continue
		}
		if filter.EscalatedOnly && job.EscalatedAt == nil {
			continue
		}
		matched = append(matched, clone(job))
	}

	sort.Slice(matched, func(i, j int) bool {
		if matched[i].NotAfter != nil && matched[j].NotAfter != nil &&
			!matched[i].NotAfter.Equal(*matched[j].NotAfter) {
			return matched[i].NotAfter.Before(*matched[j].NotAfter)
		}
		if (matched[i].NotAfter == nil) != (matched[j].NotAfter == nil) {
			return matched[j].NotAfter == nil
		}
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	total := int64(len(matched))
	return paginate(matched, filter.Limit, filter.Offset), total, nil
}

func (m *MemoryStore) CancelDeploymentJob(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.deploymentJobs {
		if job.ID != id {
			continue
		}
		if !job.Outstanding() {
			return fmt.Errorf("deployment job %s is not outstanding", id)
		}
		job.Status = DeployCancelled
		job.LockedBy, job.LockedUntil = nil, nil
		done := time.Now()
		job.CompletedAt = &done
		job.UpdatedAt = done
		return nil
	}
	return fmt.Errorf("deployment job %s is not outstanding", id)
}

// ── Agents ──────────────────────────────────────────────────

func (m *MemoryStore) ListAgents(ctx context.Context, filter AgentFilter) ([]*Agent, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	matched := make([]*Agent, 0, len(m.agents))
	for _, a := range m.agents {
		if filter.Status != "" && a.Status != filter.Status {
			continue
		}
		if filter.StaleOnly && a.MissingFor(now) <= 0 {
			continue
		}
		matched = append(matched, clone(a))
	}

	// Quiet agents first, matching the Postgres ORDER BY: the question a team
	// asks a list of agents is which hosts have stopped being maintained.
	sort.Slice(matched, func(i, j int) bool {
		li, lj := matched[i].LastSeenAt, matched[j].LastSeenAt
		switch {
		case li == nil && lj == nil:
			return matched[i].Name < matched[j].Name
		case li == nil:
			return true
		case lj == nil:
			return false
		case !li.Equal(*lj):
			return li.Before(*lj)
		}
		return matched[i].Name < matched[j].Name
	})

	total := int64(len(matched))
	return paginate(matched, filter.Limit, filter.Offset), total, nil
}

func (m *MemoryStore) GetAgent(ctx context.Context, id string) (*Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.agents[id]
	if !ok {
		return nil, fmt.Errorf("agent %s not found", id)
	}
	return clone(a), nil
}

func (m *MemoryStore) CreateAgent(ctx context.Context, a *Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored := clone(a)
	if stored.ID == "" {
		stored.ID = uuid.New().String()
	}
	if stored.Status == "" {
		stored.Status = AgentActive
	}
	if stored.HeartbeatIntervalSeconds <= 0 {
		stored.HeartbeatIntervalSeconds = defaultAgentHeartbeatSeconds
	}
	now := time.Now()
	if stored.EnrolledAt.IsZero() {
		stored.EnrolledAt = now
	}
	stored.CreatedAt, stored.UpdatedAt = now, now

	m.agents[stored.ID] = stored
	*a = *clone(stored)
	return nil
}

func (m *MemoryStore) RevokeAgent(ctx context.Context, id string, revokedBy *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := m.agents[id]
	if !ok || a.Status == AgentRevoked {
		return fmt.Errorf("agent %s is not active", id)
	}
	now := time.Now()
	a.Status = AgentRevoked
	a.RevokedAt, a.RevokedBy, a.UpdatedAt = &now, revokedBy, now
	return nil
}

func (m *MemoryStore) DeleteAgent(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.agents, id)
	return nil
}

func (m *MemoryStore) RecordAgentHeartbeat(ctx context.Context, id string, hb AgentHeartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := m.agents[id]
	if !ok || a.Status != AgentActive {
		// A revoked agent whose process has not noticed yet keeps calling.
		// Letting those calls land would make a credential somebody withdrew
		// look like a healthy host.
		return fmt.Errorf("agent %s is not active", id)
	}

	seen := hb.SeenAt
	a.LastSeenAt = &seen
	a.LastSeenIP = hb.SeenIP
	if hb.Version != "" {
		a.Version = hb.Version
	}
	if hb.Platform != "" {
		a.Platform = hb.Platform
	}
	if hb.Hostname != "" {
		a.Hostname = hb.Hostname
	}
	if hb.IntervalSeconds > 0 {
		a.HeartbeatIntervalSeconds = hb.IntervalSeconds
	}
	// Cleared on contact, so an agent that comes back is alerted on again if it
	// goes away a second time.
	a.StaleAlertedAt = nil
	a.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) GetStaleAgents(ctx context.Context, now time.Time, limit int) ([]*Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}
	out := []*Agent{}
	for _, a := range m.agents {
		if a.StaleAlertedAt != nil || a.MissingFor(now) <= 0 {
			continue
		}
		out = append(out, clone(a))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].MissingFor(now) > out[j].MissingFor(now)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryStore) MarkAgentStaleAlerted(ctx context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := m.agents[id]
	if !ok {
		return fmt.Errorf("agent %s not found", id)
	}
	when := at
	a.StaleAlertedAt = &when
	a.UpdatedAt = time.Now()
	return nil
}

// ── Agent enrolment tokens ──────────────────────────────────

func (m *MemoryStore) ListAgentEnrolTokens(ctx context.Context) ([]*AgentEnrolToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*AgentEnrolToken, 0, len(m.enrolTokens))
	for _, t := range m.enrolTokens {
		out = append(out, clone(t))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) CreateAgentEnrolToken(ctx context.Context, t *AgentEnrolToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored := clone(t)
	if stored.ID == "" {
		stored.ID = uuid.New().String()
	}
	if stored.MaxUses <= 0 {
		stored.MaxUses = 1
	}
	now := time.Now()
	stored.CreatedAt, stored.UpdatedAt = now, now
	m.enrolTokens[stored.ID] = stored
	*t = *clone(stored)
	return nil
}

func (m *MemoryStore) GetAgentEnrolTokenByHash(ctx context.Context, tokenHash string) (*AgentEnrolToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, t := range m.enrolTokens {
		if t.TokenHash == tokenHash {
			return clone(t), nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) ConsumeAgentEnrolToken(ctx context.Context, id string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.enrolTokens[id]
	if !ok {
		return false, nil
	}
	// Checked and spent under the same lock, which is the in-memory stand-in
	// for doing it in one UPDATE: two hosts from the same image enrol in the
	// same second, and a one-use token must only enrol one of them.
	if usable, _ := t.Usable(now); !usable {
		return false, nil
	}
	t.Uses++
	t.UpdatedAt = time.Now()
	return true, nil
}

// agentSignature is one seen request, keyed the way the database keys it.
type agentSignatureKey struct {
	agentID string
	hash    string
}

func (m *MemoryStore) ClaimAgentRequestSignature(ctx context.Context, agentID string, signatureHash []byte, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.agentSignatures == nil {
		m.agentSignatures = make(map[agentSignatureKey]time.Time)
	}
	key := agentSignatureKey{agentID: agentID, hash: string(signatureHash)}
	if _, seen := m.agentSignatures[key]; seen {
		return false, nil
	}
	m.agentSignatures[key] = expiresAt
	return true, nil
}

func (m *MemoryStore) SweepAgentRequestSignatures(ctx context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var removed int64
	for key, expires := range m.agentSignatures {
		if !expires.After(now) {
			delete(m.agentSignatures, key)
			removed++
		}
	}
	return removed, nil
}

func (m *MemoryStore) RevokeAgentEnrolToken(ctx context.Context, id string, revokedBy *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.enrolTokens[id]
	if !ok || t.RevokedAt != nil {
		return fmt.Errorf("enrolment token %s is already revoked", id)
	}
	now := time.Now()
	t.RevokedAt, t.RevokedBy, t.UpdatedAt = &now, revokedBy, now
	return nil
}

// ── What is on the hosts ────────────────────────────────────

func (m *MemoryStore) UpsertAgentCertificates(ctx context.Context, certs []*AgentCertificate) ([]*AgentCertificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	created := []*AgentCertificate{}

	for _, c := range certs {
		var existing *AgentCertificate
		for _, stored := range m.agentCerts {
			if stored.AgentID == c.AgentID && stored.Path == c.Path {
				existing = stored
				break
			}
		}
		if existing != nil {
			first, created0 := existing.FirstSeenAt, existing.CreatedAt
			id := existing.ID
			*existing = *clone(c)
			existing.ID, existing.FirstSeenAt, existing.CreatedAt = id, first, created0
			existing.LastSeenAt = now
			// A file that came back is not removed any more.
			existing.RemovedAt = nil
			*c = *clone(existing)
			continue
		}

		stored := clone(c)
		if stored.ID == "" {
			stored.ID = uuid.New().String()
		}
		stored.FirstSeenAt, stored.LastSeenAt, stored.CreatedAt = now, now, now
		m.agentCerts = append(m.agentCerts, stored)
		*c = *clone(stored)
		created = append(created, c)
	}
	return created, nil
}

func (m *MemoryStore) MarkAgentCertificatesRemoved(ctx context.Context, agentID string,
	seenPaths []string, at time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[string]bool, len(seenPaths))
	for _, p := range seenPaths {
		seen[p] = true
	}

	removed := 0
	when := at
	for _, c := range m.agentCerts {
		if c.AgentID != agentID || c.RemovedAt != nil || seen[c.Path] {
			continue
		}
		c.RemovedAt = &when
		removed++
	}
	return removed, nil
}

func (m *MemoryStore) ListAgentCertificates(ctx context.Context, filter AgentCertificateFilter) ([]*AgentCertificate, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := make([]*AgentCertificate, 0)
	for _, c := range m.agentCerts {
		if filter.AgentID != "" && c.AgentID != filter.AgentID {
			continue
		}
		if filter.ManagementState != "" && c.ManagementState != filter.ManagementState {
			continue
		}
		if filter.Kind != "" && c.Kind != filter.Kind {
			continue
		}
		if !filter.IncludeRemoved && c.RemovedAt != nil {
			continue
		}
		if filter.Finding != "" && !hasFinding(c.Findings, filter.Finding) {
			continue
		}
		copied := clone(c)
		if agent, ok := m.agents[c.AgentID]; ok {
			copied.AgentName = agent.Name
		}
		matched = append(matched, copied)
	}

	sort.Slice(matched, func(i, j int) bool {
		li, lj := matched[i].NotAfter, matched[j].NotAfter
		switch {
		case li == nil && lj == nil:
			return matched[i].Path < matched[j].Path
		case li == nil:
			return false
		case lj == nil:
			return true
		case !li.Equal(*lj):
			return li.Before(*lj)
		}
		return matched[i].Path < matched[j].Path
	})

	total := int64(len(matched))
	return paginate(matched, filter.Limit, filter.Offset), total, nil
}

func (m *MemoryStore) MarkAgentInventoried(ctx context.Context, id string, summary AgentInventorySummary) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	agent, ok := m.agents[id]
	if !ok {
		return fmt.Errorf("agent %s not found", id)
	}
	when := summary.ScannedAt
	agent.LastInventoryAt = &when
	agent.CertificatesSeen = summary.Seen
	agent.UnmanagedSeen = summary.Unmanaged
	agent.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) GetCertificateBySupersededFingerprint(ctx context.Context, fingerprint string) (*Certificate, error) {
	if fingerprint == "" {
		return nil, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cert := range m.certificates {
		if cert.PreviousFingerprint == fingerprint {
			return clone(cert), nil
		}
	}
	return nil, nil
}

// ── What a host may ask for ─────────────────────────────────

// cloneGrant deep-copies, where clone() shallow-copies.
//
// A grant is mostly slices, a map and six pointers. A shallow copy hands every
// caller a reference to the same backing array, so a handler appending one name
// to what it read would widen the stored grant without writing it — and against
// PostgreSQL it would not. Widening a grant by accident is the worst version of
// that bug available here.
func cloneGrant(g *TemplateGrant) *TemplateGrant {
	c := *g
	c.Names = append([]string{}, g.Names...)
	if g.LabelSelector != nil {
		c.LabelSelector = make(map[string]string, len(g.LabelSelector))
		for k, v := range g.LabelSelector {
			c.LabelSelector[k] = v
		}
	}
	for _, pair := range []struct{ from, to **string }{
		{&g.AgentID, &c.AgentID}, {&g.Role, &c.Role},
		{&g.Team, &c.Team}, {&g.UserID, &c.UserID},
		{&g.RevokedBy, &c.RevokedBy}, {&g.CreatedBy, &c.CreatedBy},
	} {
		if *pair.from != nil {
			v := **pair.from
			*pair.to = &v
		}
	}
	if g.RevokedAt != nil {
		t := *g.RevokedAt
		c.RevokedAt = &t
	}
	return &c
}

func (m *MemoryStore) ListTemplateGrants(ctx context.Context) ([]*TemplateGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*TemplateGrant, 0, len(m.templateGrants))
	for _, g := range m.templateGrants {
		out = append(out, cloneGrant(g))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) GetTemplateGrant(ctx context.Context, id string) (*TemplateGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.templateGrants[id]
	if !ok {
		return nil, fmt.Errorf("grant %s not found", id)
	}
	return cloneGrant(g), nil
}

func (m *MemoryStore) CreateTemplateGrant(ctx context.Context, g *TemplateGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored := cloneGrant(g)
	if stored.ID == "" {
		stored.ID = uuid.New().String()
	}
	now := time.Now()
	stored.CreatedAt, stored.UpdatedAt = now, now
	m.templateGrants[stored.ID] = stored
	*g = *cloneGrant(stored)
	return nil
}

func (m *MemoryStore) RevokeTemplateGrant(ctx context.Context, id string, revokedBy *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.templateGrants[id]
	if !ok || g.RevokedAt != nil {
		return fmt.Errorf("grant %s is already revoked", id)
	}
	now := time.Now()
	g.RevokedAt, g.RevokedBy, g.IsEnabled, g.UpdatedAt = &now, revokedBy, false, now
	return nil
}

func (m *MemoryStore) GetGrantsForAgent(ctx context.Context, agentID string) ([]*TemplateGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agent, ok := m.agents[agentID]
	if !ok {
		return nil, fmt.Errorf("agent %s not found", agentID)
	}

	out := []*TemplateGrant{}
	for _, g := range m.templateGrants {
		if g.AppliesTo(agent) {
			out = append(out, cloneGrant(g))
		}
	}
	// Agent-specific grants first, matching the Postgres ORDER BY, so the same
	// request resolves to the same grant whichever store is behind it.
	sort.Slice(out, func(i, j int) bool {
		if (out[i].AgentID == nil) != (out[j].AgentID == nil) {
			return out[i].AgentID != nil
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// ── What each host has installed where ──────────────────────

func (m *MemoryStore) EnsureAgentDeploymentTarget(ctx context.Context, agent *Agent) (*DeploymentTarget, error) {
	if agent == nil || agent.ID == "" {
		return nil, fmt.Errorf("an agent is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, target := range m.targets {
		if target.AgentID != nil && *target.AgentID == agent.ID {
			return clone(target), nil
		}
	}

	agentID := agent.ID
	name := agent.Name
	for _, target := range m.targets {
		if target.Name == name {
			name = fmt.Sprintf("%s (agent %s)", agent.Name, shortID(agent.ID))
			break
		}
	}

	now := time.Now()
	target := &DeploymentTarget{
		ID:         uuid.New().String(),
		Name:       name,
		TargetType: "agent",
		AgentID:    &agentID,
		IsEnabled:  true,
		Description: fmt.Sprintf(
			"The CertPilot agent on %s. Certificates are installed by the host itself, from a spec on the host.",
			agent.Name),
		CreatedAt: now,
		UpdatedAt: now,
	}
	m.targets[target.ID] = target
	return clone(target), nil
}

func (m *MemoryStore) ReplaceAgentInstallations(ctx context.Context, agentID string,
	installs []*AgentInstallation) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	kept := []*AgentInstallation{}
	for _, existing := range m.agentInstalls {
		if existing.AgentID != agentID {
			kept = append(kept, existing)
		}
	}
	now := time.Now()
	for _, inst := range installs {
		stored := clone(inst)
		stored.AgentID = agentID
		if stored.ID == "" {
			stored.ID = uuid.New().String()
		}
		if stored.CreatedAt.IsZero() {
			stored.CreatedAt = now
		}
		stored.UpdatedAt = now
		if agent, ok := m.agents[agentID]; ok {
			stored.AgentName, stored.Hostname = agent.Name, agent.Hostname
		}
		kept = append(kept, stored)
	}
	m.agentInstalls = kept
	return nil
}

func (m *MemoryStore) ListAgentInstallations(ctx context.Context,
	filter AgentInstallationFilter) ([]*AgentInstallation, int64, error) {

	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := []*AgentInstallation{}
	for _, inst := range m.agentInstalls {
		switch {
		case filter.AgentID != "" && inst.AgentID != filter.AgentID:
			continue
		case filter.CertificateID != "" && (inst.CertificateID == nil || *inst.CertificateID != filter.CertificateID):
			continue
		case filter.Status != "" && !strings.EqualFold(inst.Status, filter.Status):
			continue
		case filter.NeedsAttention && inst.Status == InstallInstalled:
			continue
		}
		matched = append(matched, clone(inst))
	}

	sort.Slice(matched, func(i, j int) bool {
		if rank(matched[i].Status) != rank(matched[j].Status) {
			return rank(matched[i].Status) < rank(matched[j].Status)
		}
		if matched[i].AgentName != matched[j].AgentName {
			return matched[i].AgentName < matched[j].AgentName
		}
		return matched[i].Name < matched[j].Name
	})

	total := int64(len(matched))
	return paginate(matched, filter.Limit, filter.Offset), total, nil
}

// rank orders a listing the way the queries do: what is broken first, then what
// is configured for something that does not exist, then everything working.
func rank(status string) int {
	switch status {
	case InstallFailed:
		return 0
	case InstallUnfulfilled:
		return 1
	default:
		return 2
	}
}

func (m *MemoryStore) EnsureCertificateDeployment(ctx context.Context,
	d *CertificateDeployment) (*CertificateDeployment, error) {

	m.mu.Lock()
	for _, existing := range m.deployments {
		if existing.CertificateID == d.CertificateID && existing.TargetID == d.TargetID {
			if d.Options != nil {
				existing.Options = d.Options
			}
			existing.UpdatedAt = time.Now()
			out := clone(existing)
			m.mu.Unlock()
			return out, nil
		}
	}
	m.mu.Unlock()

	if err := m.CreateCertificateDeployment(ctx, d); err != nil {
		return nil, err
	}
	return m.GetCertificateDeployment(ctx, d.ID)
}

func (m *MemoryStore) ClaimAgentDeploymentJobs(ctx context.Context, agentID, worker string,
	lease time.Duration, now time.Time, limit int) ([]*DeploymentJob, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	if limit <= 0 || limit > 50 {
		limit = 10
	}
	mine := map[string]bool{}
	for _, target := range m.targets {
		if target.AgentID != nil && *target.AgentID == agentID && target.IsEnabled {
			mine[target.ID] = true
		}
	}

	claimable := []*DeploymentJob{}
	for _, job := range m.deploymentJobs {
		ready := (job.Status == DeployPending && !job.RunAfter.After(now)) ||
			(job.Status == DeployRunning && job.LockedUntil != nil && job.LockedUntil.Before(now))
		if ready && mine[job.TargetID] && !m.heldBackByAFailure(job) && !m.heldBackByAnEarlierWave(job) {
			claimable = append(claimable, job)
		}
	}
	sort.Slice(claimable, func(i, j int) bool { return moreUrgentDeployment(claimable[i], claimable[j]) })
	if len(claimable) > limit {
		claimable = claimable[:limit]
	}

	until := now.Add(lease)
	out := []*DeploymentJob{}
	for _, job := range claimable {
		holder := worker
		job.Status = DeployRunning
		job.LockedBy = &holder
		job.LockedUntil = &until
		job.Attempts++
		if job.StartedAt == nil {
			started := now
			job.StartedAt = &started
		}
		job.UpdatedAt = time.Now()
		out = append(out, clone(job))
	}
	return out, nil
}

func (m *MemoryStore) PruneAgentBindings(ctx context.Context, targetID string,
	keepCertificateIDs []string) (int, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	target, ok := m.targets[targetID]
	if !ok || target.AgentID == nil {
		return 0, nil
	}
	keep := map[string]bool{}
	for _, id := range keepCertificateIDs {
		keep[id] = true
	}

	removed := 0
	for id, binding := range m.deployments {
		if binding.TargetID != targetID || keep[binding.CertificateID] {
			continue
		}
		delete(m.deployments, id)
		removed++
		kept := m.deploymentJobs[:0]
		for _, job := range m.deploymentJobs {
			if job.DeploymentID != id {
				kept = append(kept, job)
			}
		}
		m.deploymentJobs = kept
	}
	return removed, nil
}

// heldBackByAFailure reports whether this job must wait for another one.
//
// The canary, and it needs no configuration to exist. A job that has not itself
// failed waits while another job for the same certificate has, so the first
// target attempted becomes the canary on every certificate: one bad renewal
// reaches one listener rather than forty.
//
// Keyed on having failed rather than on being idle. A failing job spends part
// of every retry cycle RUNNING, and an earlier version that looked for a
// *waiting* failure found none during those seconds — so the rollout marched on
// through the estate one retry at a time. The exemption for jobs that have
// themselves failed is what stops two failures holding each other still for
// ever.
//
// Caller holds the lock.
func (m *MemoryStore) heldBackByAFailure(job *DeploymentJob) bool {
	if job.LastError != "" {
		return false
	}
	for _, other := range m.deploymentJobs {
		if other.ID == job.ID || other.CertificateID != job.CertificateID {
			continue
		}
		if other.Outstanding() && other.LastError != "" {
			return true
		}
	}
	return false
}

// isLatestJobForBinding reports whether nothing newer has been queued for the
// same place, which is what turns "has ever failed" into "is currently broken".
func (m *MemoryStore) isLatestJobForBinding(job *DeploymentJob) bool {
	for _, other := range m.deploymentJobs {
		if other.DeploymentID == job.DeploymentID && other.CreatedAt.After(job.CreatedAt) {
			return false
		}
	}
	return true
}

// heldBackByAnEarlierWave mirrors the two wave predicates in the SQL claims.
//
// Written once and used by both the core and agent claim paths here, because
// the SQL has the same rule in two statements and an in-memory store that
// enforced it in one would agree with itself while a real deployment let an
// agent target overtake its wave.
func (m *MemoryStore) heldBackByAnEarlierWave(job *DeploymentJob) bool {
	for _, other := range m.deploymentJobs {
		if other.CertificateID != job.CertificateID || other.DeployOrder >= job.DeployOrder {
			continue
		}
		// Still working: wait for it.
		if other.Outstanding() {
			return true
		}
		// Gave up: stop. Stricter than the same-wave rule on purpose — the
		// point of declaring "staging, then production" is that a certificate
		// staging would not accept must not reach production.
		//
		// Only if it is still the latest job for that place. Any failure ever
		// recorded would block production for ever, including after staging had
		// been fixed and deployed successfully since — and a terminally failed
		// job cannot be cancelled, so there was no way out.
		if other.Status == DeployFailed && m.isLatestJobForBinding(other) {
			return true
		}
	}
	return false
}

// ── Cryptographic posture ───────────────────────────────────

func (m *MemoryStore) UpsertEndpointTLSPosture(ctx context.Context, p *EndpointTLSPosture) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if p.ObservedAt.IsZero() {
		p.ObservedAt = time.Now()
	}
	key := fmt.Sprintf("%s:%d", p.Host, p.Port)
	if existing, ok := m.tlsPosture[key]; ok {
		p.ID = existing.ID
	}
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	m.tlsPosture[key] = clone(p)
	return nil
}

func (m *MemoryStore) ListEndpointTLSPosture(ctx context.Context,
	filter EndpointTLSPostureFilter) ([]*EndpointTLSPosture, int64, error) {

	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := []*EndpointTLSPosture{}
	for _, p := range m.tlsPosture {
		switch {
		case filter.Host != "" && p.Host != filter.Host:
			continue
		case filter.Verdict != "" && !strings.EqualFold(p.Verdict, filter.Verdict):
			continue
		case filter.ExposedOnly && (!p.OfferedHybrid || p.HybridKeyExchange):
			continue
		}
		matched = append(matched, clone(p))
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].HybridKeyExchange != matched[j].HybridKeyExchange {
			return !matched[i].HybridKeyExchange
		}
		if matched[i].Host != matched[j].Host {
			return matched[i].Host < matched[j].Host
		}
		return matched[i].Port < matched[j].Port
	})
	return paginate(matched, filter.Limit, filter.Offset), int64(len(matched)), nil
}

func (m *MemoryStore) CountTLSPostureByVerdict(ctx context.Context) (map[string]int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := map[string]int64{}
	for _, p := range m.tlsPosture {
		verdict := p.Verdict
		if verdict == "" {
			verdict = "UNKNOWN"
		}
		out[verdict]++
	}
	return out, nil
}

func (m *MemoryStore) ListCertificatesForAssessment(ctx context.Context, limit int) ([]*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	out := []*Certificate{}
	for _, cert := range m.certificates {
		if cert.CertificatePEM == nil || *cert.CertificatePEM == "" {
			continue
		}
		if cert.QuantumAssessedAt != nil && !cert.QuantumAssessedAt.Before(cert.UpdatedAt) {
			continue
		}
		out = append(out, clone(cert))
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryStore) UpdateCertificatePosture(ctx context.Context, id string,
	update CertificatePostureUpdate) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	cert, ok := m.certificates[id]
	if !ok {
		return fmt.Errorf("certificate %s not found", id)
	}
	assessedAt := update.AssessedAt
	if assessedAt.IsZero() {
		assessedAt = time.Now()
	}
	cert.PostureVerdict = update.Verdict
	cert.PostureSummary = update.Summary
	cert.PostureRequirements = update.Requirements
	cert.QuantumReadinessScore = &update.Score
	if update.SignatureAlgorithm != "" {
		cert.SignatureAlgorithm = update.SignatureAlgorithm
	}
	if update.PublicKeyAlgorithm != "" {
		cert.PublicKeyAlgorithm = update.PublicKeyAlgorithm
	}
	cert.QuantumAssessedAt = &assessedAt
	return nil
}

// ── Custom metadata ────────────────────────────────────────

func (s *MemoryStore) UpdateCertificateMetadata(
	_ context.Context, id string, update CertificateMetadataUpdate,
) (*Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cert, ok := s.certificates[id]
	if !ok {
		return nil, fmt.Errorf("certificate %s not found", id)
	}
	if update.Environment != nil {
		cert.Environment = *update.Environment
	}
	if update.Team != nil {
		cert.Team = *update.Team
	}
	if update.Tags != nil {
		cert.Tags = append([]string(nil), *update.Tags...)
	}
	if update.Metadata != nil {
		cert.Metadata = map[string]any{}
		for k, v := range update.Metadata {
			cert.Metadata[k] = v
		}
	}
	cert.UpdatedAt = time.Now()

	// A copy. Returning the live pointer hands the caller a record other
	// writers keep mutating under it — the same defect ListAuditLogs had.
	out := *cert
	return &out, nil
}

func (s *MemoryStore) ListMetadataFields(_ context.Context, includeArchived bool) ([]*MetadataField, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fields := []*MetadataField{}
	for _, f := range s.metadataFields {
		if !includeArchived && f.IsArchived {
			continue
		}
		copied := *f
		copied.Options = append([]MetadataOption(nil), f.Options...)
		fields = append(fields, &copied)
	}
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].SortOrder != fields[j].SortOrder {
			return fields[i].SortOrder < fields[j].SortOrder
		}
		return fields[i].Label < fields[j].Label
	})
	return fields, nil
}

func (s *MemoryStore) GetMetadataField(_ context.Context, id string) (*MetadataField, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	f, ok := s.metadataFields[id]
	if !ok {
		return nil, fmt.Errorf("metadata field %s not found", id)
	}
	copied := *f
	copied.Options = append([]MetadataOption(nil), f.Options...)
	return &copied, nil
}

func (s *MemoryStore) CreateMetadataField(_ context.Context, field *MetadataField) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// The unique constraint PostgreSQL enforces on `key`. Without it here the
	// two stores disagree about whether a duplicate key is an error, which is
	// exactly the class of drift the conformance suite exists to catch.
	for _, existing := range s.metadataFields {
		if existing.Key == field.Key {
			return fmt.Errorf("a metadata field with key %q already exists", field.Key)
		}
	}

	field.ID = uuid.New().String()
	field.CreatedAt = time.Now()
	field.UpdatedAt = field.CreatedAt
	if field.Options == nil {
		field.Options = []MetadataOption{}
	}
	copied := *field
	copied.Options = append([]MetadataOption(nil), field.Options...)
	s.metadataFields[field.ID] = &copied
	return nil
}

func (s *MemoryStore) UpdateMetadataField(_ context.Context, field *MetadataField) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.metadataFields[field.ID]
	if !ok {
		return fmt.Errorf("metadata field %s not found", field.ID)
	}
	// The key is the identity certificates store their values under, so it is
	// carried forward rather than taken from the caller.
	key := existing.Key
	copied := *field
	copied.Key = key
	copied.CreatedAt = existing.CreatedAt
	copied.UpdatedAt = time.Now()
	copied.Options = append([]MetadataOption(nil), field.Options...)
	if copied.Options == nil {
		copied.Options = []MetadataOption{}
	}
	s.metadataFields[field.ID] = &copied
	return nil
}

func (s *MemoryStore) ArchiveMetadataField(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.metadataFields[id]
	if !ok {
		return fmt.Errorf("metadata field %s not found", id)
	}
	f.IsArchived = true
	f.UpdatedAt = time.Now()
	return nil
}
