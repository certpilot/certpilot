package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// ListSchedules handles GET /api/v1/discovery/schedules.
func (h *DiscoveryHandler) ListSchedules(c *gin.Context) {
	schedules, err := h.store.ListDiscoverySchedules(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":                 schedules,
		"total":                len(schedules),
		"min_interval_minutes": discovery.MinScheduleMinutes,
	})
}

type scheduleRequest struct {
	Name    string   `json:"name" binding:"required"`
	Targets []string `json:"targets" binding:"required"`
	Ports   []int    `json:"ports"`
	// IntervalMinutes is how often the scan runs.
	IntervalMinutes int `json:"interval_minutes"`
	// IsEnabled defaults to true on create: a schedule someone has just gone to
	// the trouble of writing is one they want running.
	IsEnabled *bool `json:"is_enabled"`
}

// CreateSchedule handles POST /api/v1/discovery/schedules.
//
// The targets are expanded and validated here, not when the schedule first
// fires. A schedule that looks configured on screen and silently never scans is
// worse than no schedule, and 3am on the night it mattered is the wrong time to
// find out its targets do not parse.
func (h *DiscoveryHandler) CreateSchedule(c *gin.Context) {
	var req scheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	schedule := &store.DiscoverySchedule{
		Name:            strings.TrimSpace(req.Name),
		Targets:         trimAll(req.Targets),
		Ports:           req.Ports,
		IntervalMinutes: req.IntervalMinutes,
		IsEnabled:       true,
	}
	if len(schedule.Ports) == 0 {
		schedule.Ports = []int{discovery.DefaultPort}
	}
	if req.IsEnabled != nil {
		schedule.IsEnabled = *req.IsEnabled
	}

	if err := discovery.ValidateSchedule(schedule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	if actorID != "" {
		schedule.CreatedBy = &actorID
	}

	if err := h.store.CreateDiscoverySchedule(c.Request.Context(), schedule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.auditSchedule(c, "discovery.schedule_created", schedule)

	c.JSON(http.StatusCreated, gin.H{
		"data": schedule,
		"next": "It will run within the minute, then every " +
			formatInterval(schedule.IntervalMinutes) + ". Check the first run before relying on it.",
	})
}

// UpdateSchedule handles PUT /api/v1/discovery/schedules/:id.
func (h *DiscoveryHandler) UpdateSchedule(c *gin.Context) {
	id := c.Param("id")

	schedule, err := h.store.GetDiscoverySchedule(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "discovery schedule")
		return
	}

	var req scheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	schedule.Name = strings.TrimSpace(req.Name)
	schedule.Targets = trimAll(req.Targets)
	schedule.IntervalMinutes = req.IntervalMinutes
	if len(req.Ports) > 0 {
		schedule.Ports = req.Ports
	}
	if req.IsEnabled != nil {
		schedule.IsEnabled = *req.IsEnabled
	}

	if err := discovery.ValidateSchedule(schedule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.store.UpdateDiscoverySchedule(c.Request.Context(), schedule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.auditSchedule(c, "discovery.schedule_updated", schedule)
	c.JSON(http.StatusOK, gin.H{"data": schedule})
}

// DeleteSchedule handles DELETE /api/v1/discovery/schedules/:id.
func (h *DiscoveryHandler) DeleteSchedule(c *gin.Context) {
	id := c.Param("id")

	schedule, err := h.store.GetDiscoverySchedule(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "discovery schedule")
		return
	}
	if err := h.store.DeleteDiscoverySchedule(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.auditSchedule(c, "discovery.schedule_deleted", schedule)
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Schedule %q deleted. Those targets are no longer being watched by anything.", schedule.Name),
	})
}

// RunSchedule handles POST /api/v1/discovery/schedules/:id/run — start it now,
// without waiting for its next window.
//
// Does not move the schedule on. Someone testing a schedule they have just
// written should not silently push its real run a day later.
func (h *DiscoveryHandler) RunSchedule(c *gin.Context) {
	id := c.Param("id")

	schedule, err := h.store.GetDiscoverySchedule(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "discovery schedule")
		return
	}

	targets, err := discovery.ExpandTargets(schedule.Targets, schedule.Ports, discovery.DefaultExpansionLimit)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	req := discovery.ScanRequest{Targets: targets, Specs: schedule.Targets}
	if actorID != "" {
		req.TriggeredBy = &actorID
	}
	if actorEmail != "" {
		req.ActorEmail = &actorEmail
	}

	scan, err := h.scanner.Start(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.auditScan(c, scan, len(targets))

	c.JSON(http.StatusAccepted, gin.H{
		"scan":         scan,
		"poll":         "/api/v1/discovery/scans/" + scan.ID,
		"target_count": len(targets),
		"summary": fmt.Sprintf("Running %q now over %d endpoints. Its schedule is unchanged.",
			schedule.Name, len(targets)),
	})
}

func (h *DiscoveryHandler) auditSchedule(c *gin.Context, action string, schedule *store.DiscoverySchedule) {
	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	id := schedule.ID

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "discovery_schedule",
		EntityID:   &id,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"name":%q,"targets":%s,"interval_minutes":%d,"enabled":%t}`,
			schedule.Name, jsonStringArray(schedule.Targets), schedule.IntervalMinutes, schedule.IsEnabled),
	})
}

func trimAll(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func formatInterval(minutes int) string {
	d := time.Duration(minutes) * time.Minute
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%d day(s)", int(d/(24*time.Hour)))
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d hour(s)", int(d/time.Hour))
	default:
		return fmt.Sprintf("%d minutes", minutes)
	}
}
