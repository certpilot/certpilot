package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/certpilot/certpilot/core/engine/notifications"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// NotificationHandler manages alert delivery channels.
type NotificationHandler struct {
	store      store.Store
	keyring    *secrets.Keyring
	dispatcher *notifications.Dispatcher
}

// NewNotificationHandler creates the handler.
func NewNotificationHandler(s store.Store, kr *secrets.Keyring, d *notifications.Dispatcher) *NotificationHandler {
	return &NotificationHandler{store: s, keyring: kr, dispatcher: d}
}

// List handles GET /api/v1/notification-channels.
//
// Configuration is never included: `ConfigEncrypted` carries `json:"-"`, and a
// Slack webhook URL or an SMTP password is a credential. What an operator needs
// from a list is which channels exist, whether they are on, what they accept,
// and when each last delivered.
func (h *NotificationHandler) List(c *gin.Context) {
	channels, err := h.store.ListNotificationChannels(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":            channels,
		"total":           len(channels),
		"supported_types": notifications.SupportedTypes(),
		"topics":          events.AllTopics(),
	})
}

type notificationChannelRequest struct {
	Name        string `json:"name" binding:"required"`
	ChannelType string `json:"channel_type" binding:"required"`
	// Config is the destination's settings — a Slack webhook URL, SMTP
	// credentials. Validated by the notifier, sealed before it is stored, and
	// never returned.
	Config map[string]any `json:"config"`
	// IsEnabled defaults to true on create: a channel someone has just gone to
	// the trouble of configuring is one they want working.
	IsEnabled         *bool    `json:"is_enabled"`
	SeverityThreshold string   `json:"severity_threshold"`
	Topics            []string `json:"topics"`
}

// Create handles POST /api/v1/notification-channels.
func (h *NotificationHandler) Create(c *gin.Context) {
	var req notificationChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	channel := &store.NotificationChannel{
		Name:        strings.TrimSpace(req.Name),
		ChannelType: strings.ToLower(strings.TrimSpace(req.ChannelType)),
		IsEnabled:   true,
	}
	if req.IsEnabled != nil {
		channel.IsEnabled = *req.IsEnabled
	}
	if err := h.applySettings(channel, req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sealed, err := h.sealConfig(channel.ChannelType, req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	channel.ConfigEncrypted = sealed

	actorID := c.GetString(middleware.ContextUserID)
	channel.CreatedBy = &actorID

	if err := h.store.CreateNotificationChannel(c.Request.Context(), channel); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "notification_channel.created", channel)
	h.dispatcher.InvalidateChannels()

	c.JSON(http.StatusCreated, gin.H{
		"data": channel,
		"next": "Send a test alert to confirm delivery works before relying on this channel.",
	})
}

// Update handles PUT /api/v1/notification-channels/:id.
func (h *NotificationHandler) Update(c *gin.Context) {
	id := c.Param("id")

	channel, err := h.store.GetNotificationChannel(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "notification channel")
		return
	}

	var req notificationChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	channel.Name = strings.TrimSpace(req.Name)
	channel.ChannelType = strings.ToLower(strings.TrimSpace(req.ChannelType))
	if req.IsEnabled != nil {
		channel.IsEnabled = *req.IsEnabled
	}
	if err := h.applySettings(channel, req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// An omitted config keeps what is stored, so an operator can change a
	// severity threshold without re-entering an SMTP password they cannot read
	// back. Sending `config` replaces it wholesale.
	if req.Config != nil {
		sealed, err := h.sealConfig(channel.ChannelType, req.Config)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		channel.ConfigEncrypted = sealed
	} else if err := h.checkStoredConfig(channel); err != nil {
		// Changing the type without supplying a config would leave a channel
		// holding settings its new notifier cannot read — configured on screen,
		// silently undeliverable in practice.
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.store.UpdateNotificationChannel(c.Request.Context(), channel); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "notification_channel.updated", channel)
	h.dispatcher.InvalidateChannels()

	c.JSON(http.StatusOK, gin.H{"data": channel})
}

// Delete handles DELETE /api/v1/notification-channels/:id.
func (h *NotificationHandler) Delete(c *gin.Context) {
	id := c.Param("id")

	channel, err := h.store.GetNotificationChannel(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "notification channel")
		return
	}
	if err := h.store.DeleteNotificationChannel(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "notification_channel.deleted", channel)
	h.dispatcher.InvalidateChannels()

	c.JSON(http.StatusOK, gin.H{"message": "notification channel deleted"})
}

// Test handles POST /api/v1/notification-channels/:id/test.
//
// The most important endpoint here. Everything else in this subsystem is a
// promise that alerts will arrive; this is the only way to find out before the
// night it matters. It sends once, does not retry, and returns the destination's
// own complaint verbatim — an operator staring at a form needs the relay's
// actual words, not "delivery failed".
func (h *NotificationHandler) Test(c *gin.Context) {
	id := c.Param("id")

	channel, err := h.store.GetNotificationChannel(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "notification channel")
		return
	}

	alert := notifications.TestAlert(channel.Name)
	if err := h.dispatcher.Deliver(c.Request.Context(), channel, alert); err != nil {
		// 502, not 500: CertPilot worked, the destination did not, and the
		// distinction is the whole content of the answer.
		c.JSON(http.StatusBadGateway, gin.H{
			"error":     err.Error(),
			"delivered": false,
		})
		return
	}

	h.audit(c, "notification_channel.tested", channel)

	c.JSON(http.StatusOK, gin.H{
		"delivered": true,
		"message":   fmt.Sprintf("A test alert was accepted by %q. Confirm it arrived at the destination.", channel.Name),
	})
}

// applySettings validates and applies the fields shared by create and update.
func (h *NotificationHandler) applySettings(channel *store.NotificationChannel, req notificationChannelRequest) error {
	if channel.Name == "" {
		return fmt.Errorf("a name is required — it is what identifies the channel in an alert failure")
	}

	supported := false
	for _, t := range notifications.SupportedTypes() {
		if channel.ChannelType == t {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("channel_type must be one of %s (got %q)",
			strings.Join(notifications.SupportedTypes(), ", "), channel.ChannelType)
	}

	threshold := strings.ToUpper(strings.TrimSpace(req.SeverityThreshold))
	if threshold == "" {
		threshold = events.SeverityWarning
	}
	switch threshold {
	case events.SeverityInfo, events.SeverityWarning, events.SeverityCritical:
	default:
		return fmt.Errorf("severity_threshold must be INFO, WARNING, or CRITICAL (got %q)", threshold)
	}
	channel.SeverityThreshold = threshold

	// Never nil. An empty slice means every topic, which is the useful default;
	// a nil one would serialise as `null` and read as "none configured".
	topics := make([]string, 0, len(req.Topics))
	known := events.AllTopics()
	for _, topic := range req.Topics {
		topic = strings.TrimSpace(topic)
		if topic == "" {
			continue
		}
		// Rejected rather than accepted-and-ignored. A typo'd topic produces a
		// channel that matches nothing, looks configured, and delivers silence.
		if !containsString(known, topic) {
			return fmt.Errorf("unknown topic %q; valid topics are %s", topic, strings.Join(known, ", "))
		}
		topics = append(topics, topic)
	}
	channel.Topics = topics

	return nil
}

// sealConfig validates a destination config and encrypts it.
func (h *NotificationHandler) sealConfig(channelType string, config map[string]any) (string, error) {
	// Validated before it is sealed, so a configuration that cannot deliver is
	// refused at the point it is entered rather than discovered by an alert
	// that never arrived.
	raw, err := notifications.ValidateConfig(channelType, config)
	if err != nil {
		return "", err
	}
	if h.keyring == nil {
		return "", fmt.Errorf("no encryption keyring is configured, so channel credentials cannot be stored safely")
	}
	return h.keyring.EncryptString(string(raw), secrets.ContextNotificationConfig)
}

// checkStoredConfig confirms the existing sealed config still builds a notifier,
// used when an update changes the type but supplies no new configuration.
func (h *NotificationHandler) checkStoredConfig(channel *store.NotificationChannel) error {
	if channel.ConfigEncrypted == "" {
		return fmt.Errorf("this channel has no stored configuration; supply config")
	}
	if h.keyring == nil {
		return fmt.Errorf("no encryption keyring is configured, so the stored configuration cannot be read")
	}
	plain, err := h.keyring.DecryptString(channel.ConfigEncrypted, secrets.ContextNotificationConfig)
	if err != nil {
		return fmt.Errorf("the stored configuration could not be read: %w", err)
	}
	if _, err := notifications.Build(channel.ChannelType, []byte(plain), nil); err != nil {
		return fmt.Errorf("the stored configuration is not valid for a %s channel: %w", channel.ChannelType, err)
	}
	return nil
}

func (h *NotificationHandler) audit(c *gin.Context, action string, channel *store.NotificationChannel) {
	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	id := channel.ID

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "notification_channel",
		EntityID:   &id,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"name":%q,"type":%q,"enabled":%t,"threshold":%q}`,
			channel.Name, channel.ChannelType, channel.IsEnabled, channel.SeverityThreshold),
	})
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
