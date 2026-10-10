package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/certpilot/certpilot/core/engine/deploy"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// DeploymentHandler exposes deployment targets, the places certificates go, and
// the queue that puts them there.
type DeploymentHandler struct {
	store   store.Store
	keyring *secrets.Keyring
}

// NewDeploymentHandler creates the handler.
func NewDeploymentHandler(s store.Store, kr *secrets.Keyring) *DeploymentHandler {
	return &DeploymentHandler{store: s, keyring: kr}
}

// ── Targets ─────────────────────────────────────────────────

// ListTargets handles GET /api/v1/deployment-targets.
//
// The response never carries the sealed configuration; the model drops it at
// the JSON boundary. What it does carry is deploys_private_key, which is the
// answer to a question a security team should be able to ask without holding
// the KEK: where does this organisation send key material.
func (h *DeploymentHandler) ListTargets(c *gin.Context) {
	targets, err := h.store.ListDeploymentTargets(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	keyCarrying := 0
	for _, t := range targets {
		if t.DeploysPrivateKey {
			keyCarrying++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":                 targets,
		"count":                len(targets),
		"supported_types":      deploy.Types(),
		"carrying_private_key": keyCarrying,
	})
}

type targetRequest struct {
	Name        string         `json:"name" binding:"required"`
	Description string         `json:"description"`
	TargetType  string         `json:"target_type" binding:"required"`
	Config      map[string]any `json:"config"`
	IsEnabled   *bool          `json:"is_enabled"`
	// DeployOrder is the rollout wave. A pointer so that omitting it on an edit
	// leaves the existing wave alone — a form that posts zero for "not
	// specified" would silently move a production target into the first wave,
	// which is the one place this field must never drift.
	DeployOrder *int `json:"deploy_order"`
}

// maxDeployOrder bounds the wave number.
//
// Not a technical limit. Waves are a sequence somebody has to be able to hold
// in their head during an incident, and an estate with two hundred of them has
// expressed something nobody can reason about.
const maxDeployOrder = 100

// CreateTarget handles POST /api/v1/deployment-targets.
//
// The configuration is validated by constructing the deployer before anything
// is stored, so a bad URL or a missing signing secret is a 400 now rather than
// a failed deployment discovered during an incident.
func (h *DeploymentHandler) CreateTarget(c *gin.Context) {
	var req targetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sealed, deploysKey, err := h.sealConfig(c.Request.Context(), req.TargetType, req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	enabled := true
	if req.IsEnabled != nil {
		enabled = *req.IsEnabled
	}

	order := 0
	if req.DeployOrder != nil {
		if *req.DeployOrder < 0 || *req.DeployOrder > maxDeployOrder {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("deploy_order must be between 0 and %d", maxDeployOrder),
			})
			return
		}
		order = *req.DeployOrder
	}

	actor, _ := actorOf(c)
	target := &store.DeploymentTarget{
		Name:              strings.TrimSpace(req.Name),
		Description:       strings.TrimSpace(req.Description),
		TargetType:        strings.ToLower(strings.TrimSpace(req.TargetType)),
		ConfigEncrypted:   sealed,
		IsEnabled:         enabled,
		DeploysPrivateKey: deploysKey,
		DeployOrder:       order,
		CloudConnectionID: connectionRef(req.Config),
		CreatedBy:         actor,
	}
	if err := h.store.CreateDeploymentTarget(c.Request.Context(), target); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Audited with the key-carrying flag, because "we started sending private
	// keys to a new place on Tuesday" is exactly the sentence an audit log
	// exists to be able to produce.
	h.audit(c, "deployment_target.created", target.ID, fmt.Sprintf(
		`{"name":%q,"target_type":%q,"deploys_private_key":%t,"deploy_order":%d}`,
		target.Name, target.TargetType, target.DeploysPrivateKey, target.DeployOrder))

	c.JSON(http.StatusCreated, gin.H{"data": target})
}

// UpdateTarget handles PUT /api/v1/deployment-targets/:id.
//
// Omitting config leaves the stored credentials alone. Requiring them on every
// edit would mean an operator renaming a target has to re-enter a secret they
// may not have, and the usual result of that is the secret being kept somewhere
// convenient.
func (h *DeploymentHandler) UpdateTarget(c *gin.Context) {
	existing, err := h.store.GetDeploymentTarget(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "deployment target")
		return
	}

	var req targetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existing.Name = strings.TrimSpace(req.Name)
	existing.Description = strings.TrimSpace(req.Description)
	existing.TargetType = strings.ToLower(strings.TrimSpace(req.TargetType))
	if req.IsEnabled != nil {
		existing.IsEnabled = *req.IsEnabled
	}
	if req.DeployOrder != nil {
		if *req.DeployOrder < 0 || *req.DeployOrder > maxDeployOrder {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("deploy_order must be between 0 and %d", maxDeployOrder),
			})
			return
		}
		existing.DeployOrder = *req.DeployOrder
	}

	if len(req.Config) > 0 {
		sealed, deploysKey, err := h.sealConfig(c.Request.Context(), existing.TargetType, req.Config)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		existing.ConfigEncrypted = sealed
		existing.DeploysPrivateKey = deploysKey
		existing.CloudConnectionID = connectionRef(req.Config)
	} else if _, err := deploy.Build(existing.TargetType, ""); err != nil && existing.ConfigEncrypted == "" {
		// Changing the type without supplying a configuration would leave a
		// target whose stored config belongs to the old type.
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "changing target_type needs a config for the new type",
		})
		return
	}

	if err := h.store.UpdateDeploymentTarget(c.Request.Context(), existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "deployment_target.updated", existing.ID, fmt.Sprintf(
		// The wave is audited because moving a target between waves changes what
		// reaches production without anything else about the target changing.
		`{"name":%q,"deploys_private_key":%t,"deploy_order":%d}`,
		existing.Name, existing.DeploysPrivateKey, existing.DeployOrder))

	c.JSON(http.StatusOK, gin.H{"data": existing})
}

// DeleteTarget handles DELETE /api/v1/deployment-targets/:id.
func (h *DeploymentHandler) DeleteTarget(c *gin.Context) {
	target, err := h.store.GetDeploymentTarget(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "deployment target")
		return
	}
	if err := h.store.DeleteDeploymentTarget(c.Request.Context(), target.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "deployment_target.deleted", target.ID, fmt.Sprintf(`{"name":%q}`, target.Name))

	// Said out loud, because the bindings cascade with it. Everything that was
	// being deployed there stops being deployed anywhere, silently, and the
	// certificates keep renewing — which is the shape of problem that is only
	// noticed when something expires.
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf(
			"Target %q deleted. Any certificate that was being deployed there is no longer deployed anywhere by CertPilot; renewals will continue and will not reach it.",
			target.Name),
	})
}

// sealConfig validates a target configuration and encrypts it.
func (h *DeploymentHandler) sealConfig(ctx context.Context, targetType string, config map[string]any) (string, bool, error) {
	targetType = strings.ToLower(strings.TrimSpace(targetType))

	// A cloud target borrows a connection's credentials rather than storing its
	// own copy, so the connection has to exist and has to be the right
	// provider. Checked here because ValidateConfig cannot reach the store, and
	// checked at all because the alternative is a target that looks configured
	// and fails on its first renewal — which by then is somebody's evening.
	// Validated as the whole thing, sealed as the half the target owns.
	//
	// The deployer cannot be built from a target's config alone — the region,
	// the vault URL and the credentials all live on the connection — so a
	// target created without merging would be validated against nothing and
	// fail on its first renewal. And the merged config must never be what gets
	// stored, or registering an account twice would be discouraged rather than
	// impossible.
	validateAgainst := config
	if deploy.RequiresConnection(targetType) {
		connectionConfig, err := h.openConnection(ctx, targetType, config)
		if err != nil {
			return "", false, err
		}
		validateAgainst = deploy.MergeConnection(config, connectionConfig)
	}

	_, deploysKey, err := deploy.ValidateConfig(targetType, validateAgainst)
	if err != nil {
		return "", false, err
	}

	raw, err := json.Marshal(config)
	if err != nil {
		return "", false, err
	}
	sealed, err := h.keyring.Encrypt(raw, secrets.ContextDeploymentConfig)
	if err != nil {
		return "", false, fmt.Errorf(
			"failed to encrypt the target configuration, refusing to store it in the clear: %w", err)
	}
	return sealed, deploysKey, nil
}

// openConnection finds the cloud connection a target names and opens its
// credentials, so the target can be validated as the whole thing it will be.
func (h *DeploymentHandler) openConnection(ctx context.Context, targetType string,
	config map[string]any) (map[string]any, error) {

	id := deploy.ConnectionID(config)
	if id == "" {
		return nil, fmt.Errorf(
			"a %s target needs connection_id: the id of the cloud connection whose credentials to use. Register the account once under cloud connections rather than pasting a second copy of the same credentials here — two copies is one rotation away from a system that can read an account it can no longer write to",
			targetType)
	}

	connection, err := h.store.GetCloudConnection(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("no cloud connection with id %s: %w", id, err)
	}
	if connection.Provider != targetType {
		return nil, fmt.Errorf(
			"cloud connection %q is a %s connection, and this is a %s target",
			connection.Name, connection.Provider, targetType)
	}

	out := map[string]any{}
	if connection.ConfigEncrypted == "" {
		return out, nil
	}
	plaintext := connection.ConfigEncrypted
	if secrets.IsEnvelope(plaintext) {
		opened, err := h.keyring.DecryptString(plaintext, secrets.ContextCloudConnectionConfig)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt the credentials for %q: %w", connection.Name, err)
		}
		plaintext = opened
	}
	if err := json.Unmarshal([]byte(plaintext), &out); err != nil {
		return nil, fmt.Errorf("the stored configuration for %q is not valid JSON: %w", connection.Name, err)
	}
	return out, nil
}

// connectionRef lifts the connection id out of the config into a plain column.
//
// Stored twice on purpose: inside the sealed config because that is what gets
// handed to the deployer, and in a column because "which cloud accounts can
// this system write to" must be answerable without the KEK.
func connectionRef(config map[string]any) *string {
	id := deploy.ConnectionID(config)
	if id == "" {
		return nil
	}
	return &id
}

// ── Bindings ────────────────────────────────────────────────

// ListBindings handles GET /api/v1/certificates/:id/targets.
func (h *DeploymentHandler) ListBindings(c *gin.Context) {
	cert, err := h.store.GetCertificate(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "certificate")
		return
	}

	bindings, err := h.store.ListCertificateDeployments(c.Request.Context(), cert.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":    bindings,
		"count":   len(bindings),
		"summary": summarizeBindings(cert, bindings),
	})
}

// summarizeBindings says where this certificate stands, in one sentence.
//
// The interesting case is neither "all deployed" nor "none": it is a
// certificate whose targets are holding an older fingerprint than the one
// CertPilot has. That is the same failure post-renewal verification exists to
// catch, seen from the other end — and unlike verification it can be answered
// without opening a single connection.
func summarizeBindings(cert *store.Certificate, bindings []*store.CertificateDeployment) string {
	if len(bindings) == 0 {
		return "This certificate is not bound to any deployment target, so a renewal will update CertPilot's record and reach nothing."
	}

	current, behind, never, failing, manual := 0, 0, 0, 0, 0
	for _, b := range bindings {
		if b.LastStatus == store.DeploymentFailed {
			failing++
		}
		if b.IsEnabled && !b.DeployOnRenewal {
			manual++
		}
		switch {
		case b.DeployedFingerprint == "":
			never++
		case b.DeployedFingerprint == cert.FingerprintSHA256:
			current++
		default:
			behind++
		}
	}

	// What each place is holding, and whether the last attempt to change it
	// worked, are two different facts and both belong in the sentence.
	//
	// This first shipped reporting only the first, and a live run produced
	// "All 1 target hold the current certificate" over a deployment that had
	// failed three times and escalated — true, reassuring, and exactly the
	// half-told story this product exists to stop other tools telling.
	var state string
	switch {
	case behind == 0 && never == 0 && current == 1:
		// Its own branch rather than a plural helper, because "All 1 target
		// hold the current certificate" is what the general form produces and
		// it reads as a machine talking.
		state = "The one place this goes is holding the current certificate"
	case behind == 0 && never == 0:
		state = fmt.Sprintf("All %s hold the current certificate", placesText(current))
	case current == 0 && behind == 0:
		state = fmt.Sprintf("Bound to %s, and nothing has been deployed yet", placesText(never))
	default:
		parts := []string{}
		if current > 0 {
			parts = append(parts, fmt.Sprintf("%d up to date", current))
		}
		if behind > 0 {
			parts = append(parts, fmt.Sprintf("%d holding an older certificate", behind))
		}
		if never > 0 {
			parts = append(parts, fmt.Sprintf("%d never deployed", never))
		}
		state = fmt.Sprintf("%s: %s", placesText(len(bindings)), strings.Join(parts, ", "))
	}

	if failing > 0 {
		state = fmt.Sprintf("%s. The last deployment to %s failed", state, placesText(failing))
	}
	state += "."

	// The sentence that makes somebody act. Migration 023 switched every
	// pre-existing binding to manual so that an upgrade could not begin writing
	// to production servers on its own — and a switch nobody turns on is a
	// feature nobody has, so the cost of that choice is paid here, in words, on
	// the page an operator is already looking at.
	switch {
	case manual == 0:
	case manual == len(bindings):
		state += fmt.Sprintf(" None of them will be updated when it renews: %s deploy on renewal is switched off.",
			pickThey(manual))
	default:
		state += fmt.Sprintf(" %s will not be updated when it renews, and will hold an older certificate until deployed by hand.",
			placesText(manual))
	}
	return state
}

// pickThey keeps the "none of them" sentence grammatical for one target.
func pickThey(n int) string {
	if n == 1 {
		return "its"
	}
	return "their"
}

func placesText(n int) string {
	if n == 1 {
		return "1 target"
	}
	return fmt.Sprintf("%d targets", n)
}

type bindingRequest struct {
	TargetID  string         `json:"target_id" binding:"required"`
	Options   map[string]any `json:"options"`
	IsEnabled *bool          `json:"is_enabled"`
	// DeployOnRenewal defaults to true when omitted, because that is what a
	// binding means: install this certificate there, including when it changes.
	// A caller that wants the old behaviour has to ask for it by name.
	DeployOnRenewal *bool `json:"deploy_on_renewal"`
}

// CreateBinding handles POST /api/v1/certificates/:id/targets.
func (h *DeploymentHandler) CreateBinding(c *gin.Context) {
	cert, err := h.store.GetCertificate(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "certificate")
		return
	}

	var req bindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	target, err := h.store.GetDeploymentTarget(c.Request.Context(), req.TargetID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Refused here rather than at deploy time. A target that needs the private
	// key and a certificate that has none can be bound together quite happily
	// and will then fail on every renewal, forever, which is the kind of
	// misconfiguration that is only found the week it matters.
	if target.DeploysPrivateKey {
		key, err := h.store.GetCertificatePrivateKey(c.Request.Context(), cert.ID)
		if err == nil && key == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf(
					"target %q sends the private key, and CertPilot holds no private key for %s. A certificate that was discovered or imported has no key here until it is reissued through CertPilot",
					target.Name, cert.CommonName),
			})
			return
		}
	}

	// The most valuable validation in the deployment path, and it costs a
	// 400 now instead of a silent success later. Every cloud deployer has the
	// same failure available as one omitted field: install correctly, under an
	// identity nothing is pointing at, while the thing in front of the users
	// expires on schedule and the provider's console shows a fresh green
	// certificate.
	if err := deploy.ValidateOptions(target.TargetType, req.Options); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	enabled := true
	if req.IsEnabled != nil {
		enabled = *req.IsEnabled
	}
	onRenewal := true
	if req.DeployOnRenewal != nil {
		onRenewal = *req.DeployOnRenewal
	}

	actor, _ := actorOf(c)
	binding := &store.CertificateDeployment{
		CertificateID:   cert.ID,
		TargetID:        target.ID,
		IsEnabled:       enabled,
		DeployOnRenewal: onRenewal,
		Options:         req.Options,
		CreatedBy:       actor,
	}
	if err := h.store.CreateCertificateDeployment(c.Request.Context(), binding); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "deployment.bound", binding.ID, fmt.Sprintf(
		`{"cn":%q,"target":%q,"carries_private_key":%t,"deploy_on_renewal":%t}`,
		cert.CommonName, target.Name, target.DeploysPrivateKey, onRenewal))

	c.JSON(http.StatusCreated, gin.H{
		"data":    binding,
		"message": bindingMessage(cert, target, onRenewal),
	})
}

// bindingMessage says what binding did and, more usefully, what it did not.
//
// Binding has never installed anything by itself, and it still does not. What
// changed is what happens *next time*: a binding that deploys on renewal is a
// standing instruction that will write to somebody's machine without anybody
// pressing anything, and that is worth one sentence at the moment it is
// created rather than a surprise at the next expiry.
func bindingMessage(cert *store.Certificate, target *store.DeploymentTarget, onRenewal bool) string {
	install := fmt.Sprintf(
		"Binding does not install it now — POST /certificates/%s/deploy does.", cert.ID)
	if onRenewal {
		return fmt.Sprintf(
			"%s will be deployed to %s, and installed there automatically every time it renews. %s",
			cert.CommonName, target.Name, install)
	}
	return fmt.Sprintf(
		"%s will be deployed to %s when somebody asks. It will not be installed there when it renews, so that target will hold an older certificate until it is deployed by hand. %s",
		cert.CommonName, target.Name, install)
}

// DeleteBinding handles DELETE /api/v1/certificates/:id/targets/:bindingId.
func (h *DeploymentHandler) DeleteBinding(c *gin.Context) {
	binding, err := h.store.GetCertificateDeployment(c.Request.Context(), c.Param("bindingId"))
	if err != nil {
		respondLookup(c, err, "certificate deployment")
		return
	}
	if binding.CertificateID != c.Param("id") {
		// The binding exists but belongs to a different certificate. Refused
		// rather than followed, so a mistyped id cannot detach something else.
		c.JSON(http.StatusNotFound, gin.H{"error": "that deployment does not belong to this certificate"})
		return
	}

	if err := h.store.DeleteCertificateDeployment(c.Request.Context(), binding.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "deployment.unbound", binding.ID, fmt.Sprintf(`{"target":%q}`, binding.TargetName))

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf(
			"No longer deploying to %s. Whatever certificate is installed there stays there and stops being updated.",
			fallbackText(binding.TargetName, "that target")),
	})
}

// ── Deploying ───────────────────────────────────────────────

// Deploy handles POST /api/v1/certificates/:id/deploy.
//
// Queues rather than deploys. A certificate on eight targets is eight outbound
// calls to eight machines that may each take a reload to finish, and a
// synchronous handler would be cut off by the server's write timeout somewhere
// in the middle — leaving half an estate updated and an HTTP client with no
// idea which half.
func (h *DeploymentHandler) Deploy(c *gin.Context) {
	cert, err := h.store.GetCertificate(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "certificate")
		return
	}

	bindings, err := h.store.ListCertificateDeployments(c.Request.Context(), cert.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(bindings) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "this certificate is not bound to any deployment target. Bind one with POST /certificates/:id/targets first",
		})
		return
	}

	actor, email := actorOf(c)

	// The same planner a renewal uses. A renewal and an operator pressing this
	// button differ in exactly one field, and everything that makes deployment
	// safe has to apply identically to both — two code paths would mean the
	// automatic one eventually diverging from the one people test by hand.
	rollout, err := deploy.EnqueueFor(c.Request.Context(), h.store, cert,
		store.DeployReasonManual, actor, email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "cert.deploy_requested", cert.ID, fmt.Sprintf(
		`{"cn":%q,"queued":%d,"already_queued":%d,"switched_off":%d}`,
		cert.CommonName, rollout.Queued, rollout.Already, rollout.Skipped))

	c.JSON(http.StatusAccepted, gin.H{
		"data":    rollout.Jobs,
		"queued":  rollout.Queued,
		"message": deploy.RolloutMessage(cert.CommonName, rollout),
	})
}

// ListJobs handles GET /api/v1/deployments.
func (h *DeploymentHandler) ListJobs(c *gin.Context) {
	filter := store.DeploymentJobFilter{
		CertificateID: c.Query("certificate_id"),
		TargetID:      c.Query("target_id"),
		Status:        strings.ToUpper(c.Query("status")),
		Limit:         50,
	}
	if c.Query("outstanding") == "true" {
		filter.OutstandingOnly = true
	}
	if c.Query("escalated") == "true" {
		filter.EscalatedOnly = true
	}
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 && v <= 200 {
		filter.Limit = v
	}
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v >= 0 {
		filter.Offset = v
	}

	jobs, total, err := h.store.ListDeploymentJobs(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Counted separately from the page above, because they mean different
	// things: a queue with work in it is the ordinary steady state of an estate
	// that deploys, and a queue with escalated jobs in it is somebody's morning.
	_, outstanding, _ := h.store.ListDeploymentJobs(c.Request.Context(),
		store.DeploymentJobFilter{OutstandingOnly: true, Limit: 1})
	stuck, stuckTotal, _ := h.store.ListDeploymentJobs(c.Request.Context(),
		store.DeploymentJobFilter{EscalatedOnly: true, OutstandingOnly: true, Limit: 20})

	c.JSON(http.StatusOK, gin.H{
		"data":        jobs,
		"total":       total,
		"outstanding": outstanding,
		"escalated":   stuckTotal,
		"summary":     h.summarizeQueue(c, stuck, stuckTotal),
	})
}

// GetJob handles GET /api/v1/deployments/:id.
func (h *DeploymentHandler) GetJob(c *gin.Context) {
	job, err := h.store.GetDeploymentJob(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "deployment job")
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": job})
}

// CancelJob handles DELETE /api/v1/deployments/:id.
func (h *DeploymentHandler) CancelJob(c *gin.Context) {
	job, err := h.store.GetDeploymentJob(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "deployment job")
		return
	}
	if err := h.store.CancelDeploymentJob(c.Request.Context(), job.ID); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "deployment.cancelled", job.ID, fmt.Sprintf(`{"certificate_id":%q}`, job.CertificateID))

	c.JSON(http.StatusOK, gin.H{
		"message": "Deployment cancelled. The target keeps whatever certificate it already has, and nothing will update it.",
	})
}

// summarizeQueue turns the escalated jobs into a sentence naming what is stuck
// and where, so a dashboard does not have to render an array to be useful.
func (h *DeploymentHandler) summarizeQueue(c *gin.Context, stuck []*store.DeploymentJob, total int64) string {
	if total == 0 {
		return "No deployment is stuck."
	}

	names := make([]string, 0, len(stuck))
	for _, job := range stuck {
		name := job.CertificateID
		if cert, err := h.store.GetCertificate(c.Request.Context(), job.CertificateID); err == nil {
			name = cert.CommonName
		}
		where := ""
		if target, err := h.store.GetDeploymentTarget(c.Request.Context(), job.TargetID); err == nil {
			where = " at " + target.Name
		}
		names = append(names, fmt.Sprintf("%s%s (%d attempts)", name, where, job.Attempts))
		if len(names) == 3 {
			break
		}
	}

	subject := "1 deployment is failing"
	if total > 1 {
		subject = fmt.Sprintf("%d deployments are failing", total)
	}
	return fmt.Sprintf("%s: %s. The certificates are fine; what serves them is not being updated.",
		subject, strings.Join(names, ", "))
}

// ── Helpers ─────────────────────────────────────────────────

// actorOf pulls the acting user out of the request context.
func actorOf(c *gin.Context) (*string, *string) {
	var actor, email *string
	if id := c.GetString(middleware.ContextUserID); id != "" {
		actor = &id
	}
	if addr := c.GetString(middleware.ContextUserEmail); addr != "" {
		email = &addr
	}
	return actor, email
}

func (h *DeploymentHandler) audit(c *gin.Context, action, entityID, details string) {
	actor, email := actorOf(c)
	entity := entityID
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "deployment",
		EntityID:   &entity,
		ActorID:    actor,
		ActorEmail: email,
		Details:    details,
	})
}

func fallbackText(value, alt string) string {
	if strings.TrimSpace(value) == "" {
		return alt
	}
	return value
}
